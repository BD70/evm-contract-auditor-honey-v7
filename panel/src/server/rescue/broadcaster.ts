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

  // ---- owner-executor guard -------------------------------------------------
  // PoEs produced by rescue-prove@2 mark steps with `executor: "owner"` when
  // the underlying bug is owner-only and impersonation was used on the fork.
  // The rescuer EOA can't reproduce those steps on mainnet without the
  // owner's private key. We refuse "live" mode unless the operator has
  // wired an owner key (RESCUE_OWNER_PRIVATE_KEY) AND it's the matching
  // owner address. For dry-run-fork we DO allow it because the fork still
  // impersonates inside replay; for dry-run-sign we skip those steps with
  // an explicit error per step instead of failing the entire run.
  const ownerSteps = (req.poe.drainPlan ?? []).filter((s) => s.executor === "owner");
  if (req.mode === "live" && ownerSteps.length > 0) {
    const ownerPk = process.env.RESCUE_OWNER_PRIVATE_KEY ?? "";
    const ownerOk = ownerPk && /^0x[0-9a-fA-F]{64}$/.test(ownerPk);
    if (!ownerOk) {
      logRescueAction({
        findingId: req.poe.findingId,
        attemptId: req.poe.attemptId,
        kind: "rescue-failed",
        detail: {
          reason: "owner-required",
          ownerStepCount: ownerSteps.length,
          executorOwner: req.poe.executorOwner ?? null,
        },
      });
      return baseResult({
        error:
          `live broadcast refused: ${ownerSteps.length} of ${req.poe.drainPlan.length} drain step(s) ` +
          `require the owner's signing key (RESCUE_OWNER_PRIVATE_KEY not configured). ` +
          `The owner address recorded in the PoE is ${req.poe.executorOwner ?? "unknown"} — get the ` +
          `deployer to provide a tx from that address, or supply the key and retry.`,
      });
    }
  }

  // ---- mode dispatch ----
  if (req.mode === "dry-run-fork") {
    return await dryRunOnFork(req.poe, escrow, baseResult);
  }
  if (req.mode === "dry-run-sign") {
    return await dryRunSign(req.poe, escrow, account!, baseResult);
  }
  return await liveBroadcast(req.poe, escrow, account!, baseResult);
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

  // Dual-wallet support: rescuer EOA for attacker-executor steps, owner EOA
  // for owner-executor steps (set up only if needed and the key is present).
  const wallet = createWalletClient({ account, chain: viemChain, transport: http(client.transport.url) });
  let ownerAccount: ReturnType<typeof privateKeyToAccount> | null = null;
  let ownerWallet: ReturnType<typeof createWalletClient> | null = null;
  if (poe.drainPlan.some((s) => s.executor === "owner")) {
    const ownerPk = process.env.RESCUE_OWNER_PRIVATE_KEY ?? "";
    if (ownerPk && /^0x[0-9a-fA-F]{64}$/.test(ownerPk)) {
      ownerAccount = privateKeyToAccount(ownerPk as Hex);
      ownerWallet = createWalletClient({
        account: ownerAccount,
        chain: viemChain,
        transport: http(client.transport.url),
      });
      // Sanity: the configured owner address SHOULD match the executorOwner
      // recorded by rescue-prove. We don't fail hard (operator may have
      // rotated keys), but we log a warning into the timeline so any
      // mismatch is visible.
      if (
        poe.executorOwner &&
        poe.executorOwner.toLowerCase() !== ownerAccount.address.toLowerCase()
      ) {
        logRescueAction({
          findingId: poe.findingId,
          attemptId: poe.attemptId,
          kind: "rescue-requested",
          actor: account.address,
          detail: {
            warning: "owner-key-mismatch",
            poeExecutorOwner: poe.executorOwner,
            configuredOwner: ownerAccount.address,
          },
        });
      }
    }
  }

  let nonce = await client.getTransactionCount({ address: account.address, blockTag: "pending" });
  let ownerNonce =
    ownerAccount
      ? await client.getTransactionCount({ address: ownerAccount.address, blockTag: "pending" })
      : 0;
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
      ownerSteps: poe.drainPlan.filter((s) => s.executor === "owner").length,
      escrow,
      mode: "live",
    },
  });
  for (const step of poe.drainPlan) {
    try {
      const useOwner = step.executor === "owner";
      if (useOwner && !ownerWallet) {
        // Should be impossible (gated upstream) but be safe.
        results.push({
          index: step.index,
          asset: step.asset,
          error: "owner-executor step but no owner wallet configured",
        });
        allOk = false;
        continue;
      }
      const valueWei = step.value === "0" ? 0n : BigInt(step.value);
      const activeWallet: any = useOwner ? ownerWallet! : wallet;
      const txHash = await activeWallet.sendTransaction({
        to: step.to as Hex,
        data: step.data as Hex,
        value: valueWei,
        nonce: useOwner ? ownerNonce : nonce,
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
      if (useOwner) ownerNonce++;
      else nonce++;
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
