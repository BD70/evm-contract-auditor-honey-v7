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

// Canonical wrapped-native ERC20 per chain. Used by liveFlashloanBroadcast
// to pick the borrow asset for Aave v3 flashLoanSimple — passing address(0)
// reverts immediately. Mirrors WRAPPED_NATIVE_BY_CHAIN in rescue-prove.ts;
// kept duplicated to avoid a circular import (rescue-prove imports nothing
// from broadcaster and we want to keep it that way).
const WRAPPED_NATIVE_BY_CHAIN_BROADCASTER: Record<number, string> = {
  1: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",       // WETH
  10: "0x4200000000000000000000000000000000000006",      // WETH (OP)
  56: "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",      // WBNB
  100: "0xe91d153e0b41518a2ce8dd3d7944fa863463a97d",     // WXDAI (Gnosis)
  137: "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",     // WMATIC
  1088: "0x75cb093e4d61d2a2e65d8e0bbb01de8d89b53481",    // WMETIS (Metis)
  8453: "0x4200000000000000000000000000000000000006",    // WETH (Base)
  42161: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",   // WETH (Arb)
  43114: "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",   // WAVAX
  534352: "0x5300000000000000000000000000000000000004",  // WETH (Scroll)
};

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
  /** v8+: bypass safe-verdict gate (set by the API caller when the
   *  operator explicitly wants to broadcast on a verdict like
   *  no_rescue_possible — typical for unpriced tokens / precondition-gap
   *  surfaces). */
  force?: boolean;
  /** v8+: restrict the drain plan to these step indices. When null/omitted,
   *  every step in the PoE drainPlan is broadcast (existing behaviour). */
  selectedSteps?: number[] | null;
  /** v8+: alternative to selectedSteps — keep any step whose `asset` string
   *  contains one of these substrings (lowercased). Useful from the UI
   *  when the operator wants "all USDC steps" or "the token at 0x123…". */
  selectedAssets?: string[] | null;
}

export async function broadcastRescue(req: RescueRequest): Promise<RescueBroadcastResult> {
  const escrow = req.escrowOverride ?? req.poe.escrowAddress;
  const rescuerPk = process.env.RESCUER_PRIVATE_KEY ?? "";
  const account =
    rescuerPk && /^0x[0-9a-fA-F]{64}$/.test(rescuerPk)
      ? privateKeyToAccount(rescuerPk as Hex)
      : null;

  // v8+: filter the drain plan to only the steps the caller selected. We
  // produce a SHALLOW CLONE of the PoE with a filtered drainPlan so the
  // existing per-mode dispatch (dryRunOnFork / liveBroadcast /
  // liveFlashloanBroadcast) operates on the filtered subset without ever
  // mutating the stored PoE artifact.
  const filteredPoe = filterPoeDrainPlan(req.poe, req.selectedSteps, req.selectedAssets);

  const baseResult = (override: Partial<RescueBroadcastResult> = {}): RescueBroadcastResult => ({
    mode: req.mode,
    ok: false,
    results: [],
    rescuerAddress: account?.address ?? "0x0000000000000000000000000000000000000000",
    escrowAddress: escrow,
    error: null,
    ...override,
  });

  // After filtering: if the caller picked steps but nothing matched, fail
  // fast with a clear message. (Empty plans for verdicts the heuristic
  // already produced as no-op are caught at the API layer.)
  if (
    (req.selectedSteps !== null && req.selectedSteps !== undefined) ||
    (req.selectedAssets !== null && req.selectedAssets !== undefined)
  ) {
    if (filteredPoe.drainPlan.length === 0) {
      return baseResult({
        error:
          `selection filtered out every drain step. Original plan had ` +
          `${req.poe.drainPlan.length} step(s); none matched ` +
          `selectedSteps=${JSON.stringify(req.selectedSteps ?? null)} / ` +
          `selectedAssets=${JSON.stringify(req.selectedAssets ?? null)}.`,
      });
    }
  }

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

  // ---- empty-plan guard (applies to every mode) ---------------------------
  // The most common source of "rescue ran but did nothing" confusion is a
  // PoE with an empty drainPlan. Catch it here once for every mode and
  // explain WHY there's nothing to broadcast.
  if (filteredPoe.drainPlan.length === 0) {
    const isFlash = filteredPoe.verdict === "requires_flashloan_helper";
    return baseResult({
      error:
        `nothing to ${req.mode === "live" ? "broadcast" : "simulate"}: drainPlan is empty for this PoE. ` +
        (isFlash
          ? `Verdict is 'requires_flashloan_helper' but the verifier couldn't synthesize per-step ` +
            `drain shapes for the Aave receiver to execute. Borrowing, repaying, and sweeping nothing ` +
            `would just pay the pool fee for no benefit. This rule family (${filteredPoe.findingId.startsWith("sidecar-econ-") ? "economic.unguarded_amm_action" : filteredPoe.contractAddress}) ` +
            `requires a contract-specific drain plan: usually a multi-step swap + manipulate + drain sequence ` +
            `that needs to be hand-crafted from the contract's bytecode. The PoE pre-state shows what's ` +
            `at risk; you'll need an off-chain bot or hand-coded receiver to capture it. `
          : `The verifier didn't find any callable surface for this rule family on the contract. ` +
            `Most commonly this means the contract genuinely doesn't expose a forwarder that a ` +
            `generic EOA can drive — the risk may be real but contract-specific exploitation is ` +
            `needed. Inspect simulation_evidence_json for the selectors the verifier tried. `),
    });
  }

  // ---- mode dispatch ----
  // v8+: dispatch on the FILTERED PoE so caller-selected steps are
  // honoured across every mode.
  if (req.mode === "dry-run-fork") {
    return await dryRunOnFork(filteredPoe, escrow, baseResult);
  }
  if (req.mode === "dry-run-sign") {
    return await dryRunSign(filteredPoe, escrow, account!, baseResult);
  }
  // v4: when PoE is requires_flashloan_helper AND we have a receiver
  // address for the chain, route the drain plan through the deployed
  // receiver's executeRescue(...). Otherwise fall through to standard
  // multi-tx broadcast.
  if (filteredPoe.verdict === "requires_flashloan_helper") {
    const receiver = flashloanReceiverFor(filteredPoe.chainId);
    if (receiver) {
      return await liveFlashloanBroadcast(filteredPoe, escrow, account!, receiver, baseResult);
    }
  }
  return await liveBroadcast(filteredPoe, escrow, account!, baseResult);
}

// ---- drain-plan filter helper -------------------------------------------

function filterPoeDrainPlan(
  poe: PoeArtifact,
  selectedSteps: number[] | null | undefined,
  selectedAssets: string[] | null | undefined,
): PoeArtifact {
  // No filter -> return as-is.
  if (
    (selectedSteps == null || selectedSteps.length === 0) &&
    (selectedAssets == null || selectedAssets.length === 0)
  ) {
    return poe;
  }
  const idxSet = selectedSteps && selectedSteps.length > 0 ? new Set(selectedSteps) : null;
  const assetSubs =
    selectedAssets && selectedAssets.length > 0
      ? selectedAssets.map((s) => s.toLowerCase())
      : null;
  const kept = poe.drainPlan.filter((s) => {
    if (idxSet && !idxSet.has(s.index)) return false;
    if (assetSubs) {
      const asset = (s.asset ?? "").toLowerCase();
      if (!assetSubs.some((sub) => asset.includes(sub))) return false;
    }
    return true;
  });
  // Renumber to 0..N-1 so downstream indices are consecutive (operators
  // expect "step 0 of 3" not "step 7 of 3").
  const reindexed = kept.map((s, i) => ({ ...s, index: i }));
  return { ...poe, drainPlan: reindexed };
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
  // v8.1: resolve the actual borrow asset. Aave v3 reverts immediately on
  // address(0), so we look up the canonical wrapped-native for this
  // chain. If the chain isn't in our table we refuse rather than send a
  // tx that will burn gas hashing address(0).
  const borrowAsset = WRAPPED_NATIVE_BY_CHAIN_BROADCASTER[poe.chainId];
  if (!borrowAsset) {
    return base({
      error:
        `live flash-loan broadcast refused: no canonical wrapped-native asset configured for ` +
        `chain ${poe.chainId}. Add it to WRAPPED_NATIVE_BY_CHAIN_BROADCASTER in broadcaster.ts ` +
        `and rebuild.`,
    });
  }
  // executeRescue selector + abi-encoded args
  const args: ArgValue[] = [
    { kind: "address", value: borrowAsset },
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

  // v8.1: envelope-aware pre-flight. The receiver IS deployed on the
  // chain we'll fork, so we can eth_call the FULL executeRescue tx on a
  // fork and see whether the flash-loan + drain + repay envelope
  // succeeds end-to-end. Bare per-step fork calls (the v8 attempt) are
  // meaningless here: those steps need the pair imbalance the
  // flash-loan creates, so they'd revert solo even when the envelope
  // works on-chain.
  if (LIVE_PREFLIGHT_ENABLED) {
    const anv = await anvilPool.acquire(poe.chainId);
    if (!anv) {
      return base({
        error:
          "live flash-loan broadcast refused: anvil unavailable for envelope pre-flight on chain " +
          poe.chainId +
          ". Set RESCUE_LIVE_PREFLIGHT=false to bypass (not recommended).",
      });
    }
    try {
      // Ensure the rescuer EOA has gas on the fork.
      await rpcRequest(anv.url, "anvil_setBalance", [
        account.address,
        "0x" + (10n ** 18n).toString(16),
      ]).catch(() => null);
      const callResult = await rpcRequest<string>(anv.url, "eth_call", [
        {
          from: account.address,
          to: receiver,
          data,
          value: "0x0",
        },
        "latest",
      ]).catch((err: any) => {
        return { __error: String(err?.message ?? err) } as any;
      });
      const errMsg =
        callResult && typeof callResult === "object" && (callResult as any).__error
          ? String((callResult as any).__error)
          : null;
      if (errMsg) {
        logRescueAction({
          findingId: poe.findingId,
          attemptId: poe.attemptId,
          kind: "rescue-failed",
          actor: account.address,
          detail: {
            reason: "flashloan-envelope-preflight-reverted",
            mode: "live-flashloan",
            error: errMsg.slice(0, 240),
          },
        });
        return base({
          ok: false,
          error:
            `live flash-loan broadcast refused: envelope pre-flight on fresh fork reverted. ` +
            `The receiver's flashLoanSimple→drain→repay envelope didn't succeed; sending live ` +
            `would burn gas. Reason: ${errMsg.slice(0, 220)}. ` +
            `Nothing was sent on-chain — you paid zero gas. ` +
            `Most likely root cause: the drain steps don't actually move enough value out of ` +
            `the target to cover the loan premium. Consider narrowing selectedSteps to ones ` +
            `with the highest expected return, or wait for a richer pair state.`,
        });
      }
      // success: callResult is the returned bytes (may be empty for void return)
    } catch (err: any) {
      // Pre-flight infrastructure error — fall through to live send rather
      // than fail-closed, but log it loudly.
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: "rescue-failed",
        actor: account.address,
        detail: {
          reason: "flashloan-envelope-preflight-infra-error",
          mode: "live-flashloan",
          error: String(err?.message ?? err).slice(0, 240),
        },
      });
    }
  }

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
            ? ({
                status: receipt.status,
                gasUsed: String(receipt.gasUsed),
                blockNumber: String(receipt.blockNumber),
              } as any)
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
        // Receipts are surfaced via NextResponse.json which can't serialize
        // BigInt; cast to string-safe types here (consistent with the
        // wire shape the UI parses).
        receipt: receipt
          ? ({
              status: receipt.status === "0x1" ? "success" : ("reverted" as any),
              gasUsed: String(BigInt(receipt.gasUsed ?? "0x0")),
              blockNumber: String(BigInt(receipt.blockNumber ?? "0x0")),
            } as any)
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
//
// v8+: pre-flight every drain step on a fresh fork BEFORE submitting to
// mainnet. Steps that revert on fork are NEVER sent (saves gas + saves
// the operator from paying for sure-revert txs). If 0 steps pass the
// pre-flight, the broadcast is refused outright with a per-step report
// of revert reasons so the operator understands WHY.
//
// Gate via env: RESCUE_LIVE_PREFLIGHT=false to bypass (not recommended).

const LIVE_PREFLIGHT_ENABLED =
  String(process.env.RESCUE_LIVE_PREFLIGHT ?? "true").toLowerCase() !== "false";

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

  // ---- pre-flight on fork --------------------------------------------------
  // Run every step on a fresh anvil fork first. Only forward steps that
  // succeed on-fork to the actual broadcast loop. If none succeed, refuse
  // the whole broadcast.
  let preflightSteps = poe.drainPlan;
  let preflightSkipped: Array<{ index: number; asset: string; revertReason: string }> = [];
  if (LIVE_PREFLIGHT_ENABLED) {
    const anv = await anvilPool.acquire(poe.chainId);
    if (!anv) {
      return base({
        error:
          "live broadcast refused: anvil unavailable for fork pre-flight on chain " +
          poe.chainId +
          ". Set RESCUE_LIVE_PREFLIGHT=false to bypass (not recommended).",
      });
    }
    const passing: typeof poe.drainPlan = [];
    for (const step of poe.drainPlan) {
      try {
        const valueHex = step.value === "0" ? "0x0" : "0x" + BigInt(step.value).toString(16);
        const { receipt } = await sendFromAttacker(anv.url, step.to, step.data, {
          value: valueHex,
        });
        if (receipt?.status === "0x1") {
          passing.push(step);
        } else {
          preflightSkipped.push({
            index: step.index,
            asset: step.asset,
            revertReason: "fork-revert: tx mined with status=0x0",
          });
        }
      } catch (err: any) {
        preflightSkipped.push({
          index: step.index,
          asset: step.asset,
          revertReason: `fork-revert: ${String(err?.message ?? err).slice(0, 160)}`,
        });
      }
    }
    if (passing.length === 0) {
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: "rescue-failed",
        actor: account.address,
        detail: {
          reason: "preflight-all-reverted",
          mode: "live",
          totalSteps: poe.drainPlan.length,
          skipped: preflightSkipped.slice(0, 4),
        },
      });
      // Surface each pre-flighted step as a non-broadcast result so the
      // UI can show WHY nothing went out.
      return base({
        ok: false,
        results: preflightSkipped.map((s) => ({
          index: s.index,
          asset: s.asset,
          txHash: null,
          receipt: null,
          error: s.revertReason,
        })),
        error:
          `live broadcast refused: pre-flight on fresh fork reverted ALL ${poe.drainPlan.length} step(s). ` +
          `Nothing was sent on-chain — you paid zero gas. Common causes for this contract: ` +
          `(a) target contract requires preconditions you can't satisfy (deposits, approvals, ` +
          `permits, msg.sender checks); (b) tokens are paused/blacklisted/non-transferable; ` +
          `(c) the routing surface validates msg.sender against an allowlist. Inspect each ` +
          `step's revertReason above. To bypass pre-flight (not recommended): RESCUE_LIVE_PREFLIGHT=false.`,
      });
    }
    preflightSteps = passing;
  }

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
      steps: preflightSteps.length,
      totalSteps: poe.drainPlan.length,
      skippedByPreflight: preflightSkipped.length,
      escrow,
      mode: "live",
    },
  });
  // Surface the skipped steps as non-broadcast results too, so the UI
  // shows the full picture (passing + skipped).
  for (const s of preflightSkipped) {
    results.push({
      index: s.index,
      asset: s.asset,
      txHash: null,
      receipt: null,
      error: `skipped (${s.revertReason})`,
    });
  }
  for (const step of preflightSteps) {
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
          ? ({
              status: receipt.status,
              gasUsed: String(receipt.gasUsed),
              blockNumber: String(receipt.blockNumber),
            } as any)
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
