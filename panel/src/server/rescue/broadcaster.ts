// Rescue broadcaster.
//
// Given a PoE artifact, signs and broadcasts the contained drain plan
// against the real chain — moving the at-risk funds to RESCUE_ESCROW_ADDR.
//
// Three execution modes:
//
//   * "dry-run-fork"   (default) — re-runs the drain plan on a fresh anvil
//                                  fork of mainnet to confirm the PoE still
//                                  reproduces. No real chain broadcast. The
//                                  default mode because broadcasting needs
//                                  an explicit operator confirmation.
//   * "dry-run-sign"  — signs each tx locally and serializes it, returning
//                       the raw signed payload WITHOUT broadcasting. Useful
//                       for hand-off to a hardware wallet or a separate
//                       broadcast service.
//   * "live"          — actually broadcasts. Requires every gate:
//                       RESCUE_BROADCAST_ENABLED=true, RESCUER_PRIVATE_KEY
//                       and RESCUE_ESCROW_ADDR set, and the request must
//                       carry the operator auth token RESCUE_AUTH_TOKEN.
//
// Signing uses viem (already a panel dep) so we don't add new heavy
// dependencies. We use chain-specific gas-pricing heuristics: pull
// baseFee/maxPriorityFeePerGas from eth_feeHistory when EIP-1559 is
// supported, otherwise fall back to legacy gasPrice * 1.1.

import {
  createPublicClient,
  createWalletClient,
  http,
  parseGwei,
  type Hex,
  type TransactionReceipt,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { readChainsRaw } from "../chains-store";
import { chainMetaByChainId } from "@/src/lib/chain-meta";
import { anvilPool, rpcRequest } from "../sim/anvil-pool";
import { sendFromAttacker } from "../sim/evm";
import { logRescueAction, type PoeArtifact } from "../sim/poe-store";
import { flashloanReceiverFor } from "../sim/rescue/flashloan-receiver";
import { buildAbiCalldata, type ArgValue } from "../sim/abi";

export type RescueMode = "dry-run-fork" | "dry-run-sign" | "live";

export interface RescueBroadcastResult {
  mode: RescueMode;
  ok: boolean;
  /** Per-step result; index aligns with PoeArtifact.drainPlan */
  results: Array<{
    index: number;
    asset: string;
    txHash?: string | null;
    signedRaw?: string | null;
    receipt?: Pick<TransactionReceipt, "status" | "gasUsed" | "blockNumber"> | null;
    error?: string | null;
  }>;
  rescuerAddress: string;
  escrowAddress: string;
  /** Errors detected BEFORE the per-step loop started (env missing, auth fail, ...) */
  error?: string | null;
}

const BROADCAST_ENABLED =
  String(process.env.RESCUE_BROADCAST_ENABLED ?? "false").toLowerCase() === "true";

export interface RescueRequest {
  poe: PoeArtifact;
  mode: RescueMode;
  /** Operator-supplied auth token. Must equal RESCUE_AUTH_TOKEN env (when
   *  set). Required for "live". */
  authToken?: string | null;
  /** Override the escrow address recorded in the PoE. NOT recommended for
   *  live mode — included so dry-run-fork can exercise alternate
   *  destinations during testing. */
  escrowOverride?: string;
}

export async function broadcastRescue(req: RescueRequest): Promise<RescueBroadcastResult> {
  const escrow = req.escrowOverride ?? req.poe.escrowAddress;
  const rescuerPk = process.env.RESCUER_PRIVATE_KEY ?? "";
  const account =
    rescuerPk && /^0x[0-9a-fA-F]{64}$/.test(rescuerPk)
      ? privateKeyToAccount(rescuerPk as Hex)
      : null;

  const baseResult = (override: Partial<RescueBroadcastResult> = {}): RescueBroadcastResult => ({
    mode: req.mode,
    ok: false,
    results: [],
    rescuerAddress: account?.address ?? "0x0000000000000000000000000000000000000000",
    escrowAddress: escrow,
    error: null,
    ...override,
  });

  // ---- gate checks ----
  if (req.mode === "live") {
    if (!BROADCAST_ENABLED) {
      return baseResult({
        error:
          "live broadcast is disabled (set RESCUE_BROADCAST_ENABLED=true in env). " +
          "Until then, only dry-run-fork and dry-run-sign modes will execute.",
      });
    }
    const expectedToken = process.env.RESCUE_AUTH_TOKEN ?? "";
    if (!expectedToken || req.authToken !== expectedToken) {
      logRescueAction({
        findingId: req.poe.findingId,
        attemptId: req.poe.attemptId,
        kind: "rescue-failed",
        detail: { reason: "auth-token-mismatch" },
      });
      return baseResult({ error: "RESCUE_AUTH_TOKEN missing or mismatched" });
    }
    if (!account) {
      return baseResult({ error: "RESCUER_PRIVATE_KEY not configured" });
    }
    if (!/^0x[0-9a-fA-F]{40}$/.test(escrow)) {
      return baseResult({ error: "escrowAddress is invalid" });
    }
  }

  if (req.mode === "dry-run-sign" && !account) {
    return baseResult({ error: "RESCUER_PRIVATE_KEY required for dry-run-sign mode" });
  }

  // ---- verdict gate ---------------------------------------------------------
  // v3+: refuse live broadcast for verdicts that aren't safe to broadcast as-is.
  // (v5 removed: requires_safe_signing — owner-only findings now produce
  // no_rescue_possible upstream so we never get here for them.)
  if (req.mode === "live") {
    if (req.poe.verdict === "requires_flashloan_helper") {
      // v4: if a receiver address is configured for this chain, we CAN
      // broadcast — route the drain plan through receiver.executeRescue(...).
      const receiverAddr = flashloanReceiverFor(req.poe.chainId);
      if (!receiverAddr) {
        logRescueAction({
          findingId: req.poe.findingId,
          attemptId: req.poe.attemptId,
          kind: "rescue-failed",
          detail: {
            reason: "requires-flashloan-helper",
            flashloanRequirement: req.poe.flashloanRequirement ?? null,
          },
        });
        return baseResult({
          error:
            `live broadcast refused: this PoE is verdict='requires_flashloan_helper'. The fork stub ` +
            `granted the attacker capital with anvil_setBalance — that doesn't work on mainnet. ` +
            `Deploy contracts/rescue/FlashLoanRescue.sol with Aave v3 pool ` +
            `${req.poe.flashloanRequirement?.suggestedPool ?? "(none registered for this chain)"} and ` +
            `register the deployed address in RESCUE_FLASHLOAN_RECEIVER=${req.poe.chainId}:0x...`,
        });
      }
      // We'll handle the receiver path in liveBroadcast via a special
      // routing branch (annotated below).
    }
    if (req.poe.verdict === "trapped_assets_only") {
      return baseResult({
        error:
          `live broadcast refused: every asset in this contract is paused/blacklisted/non-transferable. ` +
          `Nothing rescuable.`,
      });
    }
    if (req.poe.verdict === "victim_approval_rescue") {
      // Per-victim consent enforcement: the drain plan in this PoE only
      // includes consented victims (rescue-prove gates this with
      // RESCUE_APPROVAL_CONSENT_VICTIMS). We still double-check here that
      // there IS at least one consented victim — otherwise the drain plan
      // is empty and we'd be broadcasting nothing.
      const consentedCount = (req.poe.approvalVictims ?? []).filter((v) => v.consented).length;
      if (consentedCount === 0) {
        logRescueAction({
          findingId: req.poe.findingId,
          attemptId: req.poe.attemptId,
          kind: "rescue-failed",
          detail: { reason: "no-victim-consent" },
        });
        return baseResult({
          error:
            `live broadcast refused: PoE verdict='victim_approval_rescue' but zero victims have ` +
            `consented (RESCUE_APPROVAL_CONSENT_VICTIMS is empty or doesn't list any of the ` +
            `${(req.poe.approvalVictims ?? []).length} at-risk victim addresses). ` +
            `Get off-chain consent from each victim before listing their address.`,
        });
      }
    }
  }

  // (v5: owner-executor guard removed — rescue is always sent from the
  // rescuer EOA. Owner-only findings are rejected upstream by rescue-prove
  // before any drain plan is built.)

  // ---- mode dispatch ----
  if (req.mode === "dry-run-fork") {
    return await dryRunOnFork(req.poe, escrow, baseResult);
  }
  if (req.mode === "dry-run-sign") {
    return await dryRunSign(req.poe, escrow, account!, baseResult);
  }
  // v4: when PoE is requires_flashloan_helper AND we have a receiver
  // address for the chain, route the drain plan through the deployed
  // receiver's executeRescue(...). Otherwise fall through to standard
  // multi-tx broadcast.
  if (req.poe.verdict === "requires_flashloan_helper") {
    const receiver = flashloanReceiverFor(req.poe.chainId);
    if (receiver) {
      return await liveFlashloanBroadcast(req.poe, escrow, account!, receiver, baseResult);
    }
  }
  return await liveBroadcast(req.poe, escrow, account!, baseResult);
}

// ---- live flash-loan-receiver broadcast ----------------------------------
//
// Encodes a single call to the deployed receiver's executeRescue(asset,
// amount, targets[], calldatas[], values[], escrow). The receiver borrows
// from Aave v3, runs the drain plan inside its callback, repays + sweeps
// surplus to escrow. From our broadcaster's perspective this is exactly
// ONE tx (with potentially large calldata).

async function liveFlashloanBroadcast(
  poe: PoeArtifact,
  escrow: string,
  account: ReturnType<typeof privateKeyToAccount>,
  receiver: string,
  base: (o?: Partial<RescueBroadcastResult>) => RescueBroadcastResult,
): Promise<RescueBroadcastResult> {
  const { client, viemChain } = liveClientsFor(poe.chainId);
  if (!client) return base({ error: "no rpc configured for chain " + poe.chainId });
  const wallet = createWalletClient({ account, chain: viemChain, transport: http(client.transport.url) });
  const fl = poe.flashloanRequirement;
  if (!fl) {
    return base({ error: "PoE.flashloanRequirement missing — can't build executeRescue call" });
  }
  // For v4 the flashloanRequirement.asset is the native symbol; assume the
  // canonical wrapped-native of the chain. Operators with a different
  // borrow asset in mind can wire a more specific encoder later.
  const targets = poe.drainPlan.map((s) => s.to);
  const calldatas = poe.drainPlan.map((s) => s.data);
  const values = poe.drainPlan.map((s) => BigInt(s.value));
  // executeRescue selector + abi-encoded args
  const args: ArgValue[] = [
    // For v4, asset/amount are pulled from flashloanRequirement; in v5
    // we'll resolve this via per-chain WETH lookup. For now we leave it
    // to the operator's pre-deployed receiver to default to WETH.
    { kind: "address", value: "0x0000000000000000000000000000000000000000" },
    { kind: "uint", value: BigInt(fl.amount) },
    { kind: "address[]", value: targets },
    { kind: "bytes[]", value: calldatas },
    { kind: "uint[]", value: values.map((v) => v) },
    { kind: "address", value: escrow },
  ];
  // selector = keccak256("executeRescue(address,uint256,address[],bytes[],uint256[],address)")[:4]
  // Computed once via viem.toFunctionSelector and pinned here so the broadcaster
  // doesn't need a runtime hash dep. If the Solidity contract signature
  // ever changes, update this AND contracts/rescue/FlashLoanRescue.sol.
  const EXECUTE_RESCUE_SELECTOR = "0xfe5d0181";
  const data = buildAbiCalldata(EXECUTE_RESCUE_SELECTOR, args);
  logRescueAction({
    findingId: poe.findingId,
    attemptId: poe.attemptId,
    kind: "rescue-requested",
    actor: account.address,
    detail: {
      mode: "live-flashloan",
      receiver,
      flashloanAmount: fl.amount,
      steps: poe.drainPlan.length,
    },
  });
  try {
    const nonce = await client.getTransactionCount({ address: account.address, blockTag: "pending" });
    const fees = await suggestFees(client);
    const txHash = await (wallet as any).sendTransaction({
      to: receiver as Hex,
      data: data as Hex,
      value: 0n,
      nonce,
      ...fees,
    } as any);
    const receipt = await client
      .waitForTransactionReceipt({ hash: txHash as Hex, timeout: 180_000 })
      .catch(() => null);
    const ok = receipt?.status === "success";
    logRescueAction({
      findingId: poe.findingId,
      attemptId: poe.attemptId,
      kind: ok ? "rescue-mined" : "rescue-failed",
      actor: account.address,
      detail: { txHash, mode: "live-flashloan", status: receipt?.status ?? "unknown" },
    });
    return base({
      ok,
      results: [
        {
          index: 0,
          asset: `flash-loan-routed drain (${poe.drainPlan.length} steps)`,
          txHash,
          receipt: receipt
            ? { status: receipt.status, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber }
            : null,
          error: ok ? null : "executeRescue tx reverted or timed out",
        },
      ],
    });
  } catch (err: any) {
    const msg = String(err?.message ?? err).slice(0, 400);
    logRescueAction({
      findingId: poe.findingId,
      attemptId: poe.attemptId,
      kind: "rescue-failed",
      actor: account.address,
      detail: { mode: "live-flashloan", error: msg },
    });
    return base({
      ok: false,
      error: `liveFlashloanBroadcast error: ${msg}`,
      results: [],
    });
  }
}

// ---- dry-run-fork ---------------------------------------------------------

async function dryRunOnFork(
  poe: PoeArtifact,
  escrow: string,
  base: (o?: Partial<RescueBroadcastResult>) => RescueBroadcastResult,
): Promise<RescueBroadcastResult> {
  const anv = await anvilPool.acquire(poe.chainId);
  if (!anv) {
    return base({
      error: "anvil not available for this chain; cannot dry-run on fork",
    });
  }
  const url = anv.url; // local anvil endpoint (anv.rpcUrl is the fork SOURCE)
  const results: RescueBroadcastResult["results"] = [];
  let allOk = true;
  for (const step of poe.drainPlan) {
    try {
      // Re-target escrow at the calldata level. The PoE's drainPlan calldata
      // already embeds the PoE-time escrow; if the caller wants to redirect
      // we don't touch it (escrowOverride is a no-op for fork replay because
      // the original calldata is the proof — substituting would invalidate
      // the PoE).
      const valueHex = step.value === "0" ? "0x0" : "0x" + BigInt(step.value).toString(16);
      const { txHash, receipt } = await sendFromAttacker(url, step.to, step.data, {
        value: valueHex,
      });
      const ok = receipt?.status === "0x1";
      if (!ok) allOk = false;
      results.push({
        index: step.index,
        asset: step.asset,
        txHash,
        receipt: receipt
          ? {
              status: receipt.status === "0x1" ? "success" : ("reverted" as any),
              gasUsed: BigInt(receipt.gasUsed ?? "0x0"),
              blockNumber: BigInt(receipt.blockNumber ?? "0x0"),
            }
          : null,
        error: ok ? null : "tx reverted on fork",
      });
    } catch (err: any) {
      allOk = false;
      results.push({
        index: step.index,
        asset: step.asset,
        error: String(err?.message ?? err),
      });
    }
  }
  logRescueAction({
    findingId: poe.findingId,
    attemptId: poe.attemptId,
    kind: "rescue-dry-run",
    detail: { mode: "fork", allOk, steps: results.length },
  });
  return base({ ok: allOk, results });
}

// ---- dry-run-sign ---------------------------------------------------------

async function dryRunSign(
  poe: PoeArtifact,
  escrow: string,
  account: ReturnType<typeof privateKeyToAccount>,
  base: (o?: Partial<RescueBroadcastResult>) => RescueBroadcastResult,
): Promise<RescueBroadcastResult> {
  const { client, viemChain } = liveClientsFor(poe.chainId);
  if (!client) return base({ error: "no rpc configured for chain " + poe.chainId });
  const wallet = createWalletClient({ account, chain: viemChain, transport: http(client.transport.url) });
  const results: RescueBroadcastResult["results"] = [];
  let nonce = await client.getTransactionCount({ address: account.address, blockTag: "pending" });
  const fees = await suggestFees(client);
  for (const step of poe.drainPlan) {
    try {
      const valueWei = step.value === "0" ? 0n : BigInt(step.value);
      const req = await wallet.prepareTransactionRequest({
        to: step.to as Hex,
        data: step.data as Hex,
        value: valueWei,
        nonce,
        ...fees,
      } as any);
      const signed = await account.signTransaction(req as any);
      results.push({ index: step.index, asset: step.asset, signedRaw: signed, txHash: null });
      nonce++;
    } catch (err: any) {
      results.push({
        index: step.index,
        asset: step.asset,
        error: String(err?.message ?? err),
      });
    }
  }
  logRescueAction({
    findingId: poe.findingId,
    attemptId: poe.attemptId,
    kind: "rescue-dry-run",
    detail: { mode: "sign", steps: results.length },
  });
  return base({ ok: results.every((r) => !r.error), results });
}

// ---- live broadcast -------------------------------------------------------

async function liveBroadcast(
  poe: PoeArtifact,
  escrow: string,
  account: ReturnType<typeof privateKeyToAccount>,
  base: (o?: Partial<RescueBroadcastResult>) => RescueBroadcastResult,
): Promise<RescueBroadcastResult> {
  const { client, viemChain } = liveClientsFor(poe.chainId);
  if (!client) return base({ error: "no rpc configured for chain " + poe.chainId });

  // v5: single-wallet broadcast. Every drain step is sent from the rescuer
  // EOA, which is the same account that simulates the drain on-fork.
  const wallet = createWalletClient({ account, chain: viemChain, transport: http(client.transport.url) });

  let nonce = await client.getTransactionCount({ address: account.address, blockTag: "pending" });
  const fees = await suggestFees(client);
  const results: RescueBroadcastResult["results"] = [];
  let allOk = true;
  logRescueAction({
    findingId: poe.findingId,
    attemptId: poe.attemptId,
    kind: "rescue-requested",
    actor: account.address,
    detail: {
      steps: poe.drainPlan.length,
      escrow,
      mode: "live",
    },
  });
  for (const step of poe.drainPlan) {
    try {
      const valueWei = step.value === "0" ? 0n : BigInt(step.value);
      const txHash = await (wallet as any).sendTransaction({
        to: step.to as Hex,
        data: step.data as Hex,
        value: valueWei,
        nonce,
        ...fees,
      } as any);
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: "rescue-broadcasted",
        actor: account.address,
        detail: { txHash, step: step.index, asset: step.asset },
      });
      const receipt = await client
        .waitForTransactionReceipt({ hash: txHash as Hex, timeout: 120_000 })
        .catch(() => null);
      const ok = receipt?.status === "success";
      if (!ok) allOk = false;
      results.push({
        index: step.index,
        asset: step.asset,
        txHash,
        receipt: receipt
          ? { status: receipt.status, gasUsed: receipt.gasUsed, blockNumber: receipt.blockNumber }
          : null,
        error: ok ? null : "tx reverted on chain",
      });
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: ok ? "rescue-mined" : "rescue-failed",
        actor: account.address,
        detail: { txHash, status: receipt?.status ?? "unknown" },
      });
      nonce++;
    } catch (err: any) {
      allOk = false;
      const msg = String(err?.message ?? err).slice(0, 400);
      results.push({ index: step.index, asset: step.asset, error: msg });
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: "rescue-failed",
        actor: account.address,
        detail: { step: step.index, error: msg },
      });
    }
  }
  return base({ ok: allOk, results });
}

// ---- helpers --------------------------------------------------------------

function liveClientsFor(chainId: number): {
  client: any;
  viemChain: any;
} {
  const meta = chainMetaByChainId(chainId);
  if (!meta) return { client: null, viemChain: undefined };
  const entry = readChainsRaw().find((c) => c.slug === meta.slug);
  if (!entry?.rpcHttpUrl) return { client: null, viemChain: undefined };
  const viemChain = {
    id: chainId,
    name: meta.slug,
    nativeCurrency: {
      name: meta.nativeSymbol,
      symbol: meta.nativeSymbol,
      decimals: meta.nativeDecimals,
    },
    rpcUrls: { default: { http: [entry.rpcHttpUrl] }, public: { http: [entry.rpcHttpUrl] } },
  };
  const client = createPublicClient({ chain: viemChain as any, transport: http(entry.rpcHttpUrl) });
  return { client, viemChain };
}

async function suggestFees(client: any): Promise<
  | {
      maxFeePerGas: bigint;
      maxPriorityFeePerGas: bigint;
    }
  | { gasPrice: bigint }
> {
  try {
    // Try EIP-1559 path
    const fh = await client.estimateFeesPerGas().catch(() => null);
    if (fh?.maxFeePerGas && fh?.maxPriorityFeePerGas) {
      return {
        maxFeePerGas: fh.maxFeePerGas,
        maxPriorityFeePerGas: fh.maxPriorityFeePerGas,
      };
    }
  } catch {}
  try {
    const gp = await client.getGasPrice();
    return { gasPrice: (gp * 11n) / 10n };
  } catch {
    return { gasPrice: parseGwei("10") };
  }
}
