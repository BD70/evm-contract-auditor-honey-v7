/*
 * State-diff witness helper.
 *
 * Used by verifiers as an ORTHOGONAL second source of evidence. Trace-based
 * verdicts ("the call reached an attacker-controlled probe") are necessary but
 * not always sufficient — a contract can have a probe-reachable code path that
 * happens to do nothing dangerous (think: silent fallback handler, gated
 * delegatecall that does a no-op). A state-diff witness proves the exploit
 * actually MOVED VALUE in the attacker's favour, which is the only thing a
 * real-world rescue or audit cares about.
 *
 * Workflow:
 *
 *   const before = await captureState(rpcUrl, ATTACKER_ADDRESS, victim, opts);
 *   // ... send the candidate exploit tx (real, not traceCall) ...
 *   const after  = await captureState(rpcUrl, ATTACKER_ADDRESS, victim, opts);
 *   const diff   = computeStateDiff(before, after);
 *   if (isFavourableToAttacker(diff)) { ... witness! ... }
 *
 * Verifiers wrap the whole thing in `snapshot()` so the state changes are
 * reverted before the next case on the same anvil fork.
 *
 * Token list is chain-aware and small on purpose: tracking every ERC-20 is
 * pointless and slow. We track the highest-TVL stablecoins + bluechips per
 * chain, which is what 95% of exploits drain.
 */

import { rpcRequest } from "./anvil-pool";
import { ZERO32_HEX } from "./evm";

const FEATURE_ENABLED = String(process.env.SIM_FEATURE_STATEDIFF ?? "false").toLowerCase() === "true";

/** Are state-diff witnesses enabled at all? Verifiers should short-circuit
 *  when this is false to avoid the extra RPC roundtrips. Default OFF until we
 *  flip the rollout. */
export function stateDiffEnabled(): boolean {
  return FEATURE_ENABLED;
}

// Per-chain high-value ERC-20s we track for drain detection. ~5 per chain
// keeps the RPC cost low (~50ms for 5 eth_calls in parallel). Anything else
// can be added later via SIM_STATEDIFF_EXTRA_TOKENS env override.
const TOKENS_BY_CHAIN: Record<number, string[]> = {
  1: [
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", // WBTC
  ],
  10: [
    "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", // USDT (Optimism)
    "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", // USDC (Optimism)
    "0x4200000000000000000000000000000000000006", // WETH (Optimism)
  ],
  56: [
    "0x55d398326f99059fF775485246999027B3197955", // USDT (BSC)
    "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", // USDC (BSC)
    "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c", // WBNB
  ],
  137: [
    "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", // USDT (Polygon)
    "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", // USDC (Polygon)
    "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", // WMATIC
  ],
  42161: [
    "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", // USDT (Arbitrum)
    "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // USDC (Arbitrum)
    "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", // WETH (Arbitrum)
  ],
  8453: [
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC (Base)
    "0x4200000000000000000000000000000000000006", // WETH (Base)
  ],
};

function tokensForChain(chainId: number): string[] {
  const base = TOKENS_BY_CHAIN[chainId] ?? [];
  const extraRaw = process.env.SIM_STATEDIFF_EXTRA_TOKENS;
  if (!extraRaw) return base;
  const extras = extraRaw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^0x[0-9a-fA-F]{40}$/.test(s));
  return [...base, ...extras];
}

export interface CaptureOpts {
  /** Override the default token list for this chain. */
  tokens?: string[];
  /** Additional storage slots to snapshot (e.g. owner slot, paused slot). */
  storageSlots?: Array<{ address: string; slot: string; label?: string }>;
  /** Extra addresses to treat as "attacker-aligned" recipients. The probe
   *  contract is attacker-controlled in our verifier model — any value that
   *  ends up at the probe is value the attacker has effectively gained.
   *  Verifiers should pass `[probeAddress]` (and re-entry probe, etc.). */
  extraAttackerHolders?: string[];
}

export interface StateSnapshot {
  attacker: string;
  victim: string;
  attackerEth: string;   // hex 0x-prefixed
  victimEth: string;
  // token address (lower) → balance hex
  attackerTokens: Record<string, string>;
  victimTokens: Record<string, string>;
  // For each extra holder: address (lower) → { eth, tokens (token addr → bal) }
  extraHolders: Record<string, { eth: string; tokens: Record<string, string> }>;
  // "addr:slot" → 32-byte hex
  storage: Record<string, string>;
}

export interface BalanceChange {
  token: string | null; // null = native ETH
  attackerGained: bigint;
  victimLost: bigint;
}

export interface StorageChange {
  address: string;
  slot: string;
  label?: string;
  before: string;
  after: string;
}

export interface StateDiff {
  attackerEthDelta: bigint;
  victimEthDelta: bigint;
  tokenChanges: BalanceChange[];
  storageChanges: StorageChange[];
  /** Sum across native + tokens of value that moved out of victim into
   *  attacker. We don't do USD here — that's the caller's job using its own
   *  price oracle. */
  attackerNetGain: bigint;
}

// ----------------------------------------------------------------------------
// ABI snippets for balanceOf. Hand-encoded to avoid pulling viem into helpers.
// ----------------------------------------------------------------------------

function encodeBalanceOf(addr: string): string {
  const padded = addr.replace(/^0x/, "").toLowerCase().padStart(64, "0");
  return "0x70a08231" + padded;
}

function hexToBig(h: string | null | undefined): bigint {
  if (!h || h === "0x" || h === ZERO32_HEX) return 0n;
  try {
    return BigInt(h);
  } catch {
    return 0n;
  }
}

async function readBalance(url: string, token: string, holder: string): Promise<string> {
  try {
    const out = await rpcRequest<string>(url, "eth_call", [
      { to: token, data: encodeBalanceOf(holder) },
      "latest",
    ]);
    return out && out !== "0x" ? out : "0x0";
  } catch {
    return "0x0";
  }
}

async function readEth(url: string, addr: string): Promise<string> {
  try {
    return await rpcRequest<string>(url, "eth_getBalance", [addr, "latest"]);
  } catch {
    return "0x0";
  }
}

async function readStorage(url: string, address: string, slot: string): Promise<string> {
  try {
    return await rpcRequest<string>(url, "eth_getStorageAt", [address, slot, "latest"]);
  } catch {
    return ZERO32_HEX;
  }
}

// ----------------------------------------------------------------------------
// public API
// ----------------------------------------------------------------------------

export async function captureState(
  url: string,
  chainId: number,
  attacker: string,
  victim: string,
  opts: CaptureOpts = {},
): Promise<StateSnapshot> {
  const tokens = (opts.tokens ?? tokensForChain(chainId)).map((t) => t.toLowerCase());
  const extras = (opts.extraAttackerHolders ?? []).map((a) => a.toLowerCase());

  const ethPromises = Promise.all([
    readEth(url, attacker),
    readEth(url, victim),
    ...extras.map((a) => readEth(url, a)),
  ]);
  const tokenPromises = Promise.all(
    tokens.flatMap((t) => [
      readBalance(url, t, attacker),
      readBalance(url, t, victim),
      ...extras.map((a) => readBalance(url, t, a)),
    ]),
  );
  const storagePromises = Promise.all(
    (opts.storageSlots ?? []).map((s) => readStorage(url, s.address, s.slot)),
  );

  const [eths, tokenBals, storageVals] = await Promise.all([ethPromises, tokenPromises, storagePromises]);
  const attackerEth = eths[0];
  const victimEth = eths[1];
  const extraEths = eths.slice(2);

  const attackerTokens: Record<string, string> = {};
  const victimTokens: Record<string, string> = {};
  const extraHolders: Record<string, { eth: string; tokens: Record<string, string> }> = {};
  for (const a of extras) extraHolders[a] = { eth: "0x0", tokens: {} };
  extras.forEach((a, i) => {
    extraHolders[a].eth = extraEths[i];
  });
  const stride = 2 + extras.length;
  for (let i = 0; i < tokens.length; i++) {
    const base = i * stride;
    attackerTokens[tokens[i]] = tokenBals[base];
    victimTokens[tokens[i]] = tokenBals[base + 1];
    for (let j = 0; j < extras.length; j++) {
      extraHolders[extras[j]].tokens[tokens[i]] = tokenBals[base + 2 + j];
    }
  }
  const storage: Record<string, string> = {};
  (opts.storageSlots ?? []).forEach((s, i) => {
    storage[`${s.address.toLowerCase()}:${s.slot.toLowerCase()}`] = storageVals[i];
  });

  return {
    attacker: attacker.toLowerCase(),
    victim: victim.toLowerCase(),
    attackerEth,
    victimEth,
    attackerTokens,
    victimTokens,
    extraHolders,
    storage,
  };
}

export function computeStateDiff(before: StateSnapshot, after: StateSnapshot): StateDiff {
  // Attacker-aligned ETH delta = main attacker + any extra holders (probes).
  let attackerEthDelta = hexToBig(after.attackerEth) - hexToBig(before.attackerEth);
  for (const a of Object.keys(before.extraHolders)) {
    const bAfter = after.extraHolders[a]?.eth ?? before.extraHolders[a].eth;
    attackerEthDelta += hexToBig(bAfter) - hexToBig(before.extraHolders[a].eth);
  }
  const victimEthDelta = hexToBig(after.victimEth) - hexToBig(before.victimEth);

  const tokenChanges: BalanceChange[] = [];
  for (const token of Object.keys(before.attackerTokens)) {
    let attackerGained = hexToBig(after.attackerTokens[token]) - hexToBig(before.attackerTokens[token]);
    for (const a of Object.keys(before.extraHolders)) {
      const beforeBal = hexToBig(before.extraHolders[a].tokens[token] ?? "0x0");
      const afterBal = hexToBig(after.extraHolders[a]?.tokens[token] ?? "0x0");
      attackerGained += afterBal - beforeBal;
    }
    const victimLost = hexToBig(before.victimTokens[token] ?? "0x0") - hexToBig(after.victimTokens[token] ?? "0x0");
    if (attackerGained === 0n && victimLost === 0n) continue;
    tokenChanges.push({ token, attackerGained, victimLost });
  }

  const storageChanges: StorageChange[] = [];
  for (const k of Object.keys(before.storage)) {
    const b = before.storage[k];
    const a = after.storage[k];
    if (b !== a) {
      const [address, slot] = k.split(":");
      storageChanges.push({ address, slot, before: b, after: a });
    }
  }

  let attackerNetGain = attackerEthDelta;
  for (const t of tokenChanges) {
    if (t.attackerGained > 0n) attackerNetGain += t.attackerGained;
  }

  return { attackerEthDelta, victimEthDelta, tokenChanges, storageChanges, attackerNetGain };
}

/** Did the attacker gain *anything* of value (native, token, or critical
 *  storage write)? Pure heuristic — a single token-gain or storage change is
 *  enough. We deliberately do NOT require the attacker's ETH to go up because
 *  gas costs would mask small exploits. */
export function isFavourableToAttacker(d: StateDiff): boolean {
  if (d.attackerNetGain > 0n) return true;
  if (d.tokenChanges.some((c) => c.attackerGained > 0n)) return true;
  // Storage writes by themselves don't prove value movement, but any storage
  // change in a slot we explicitly chose to track (e.g. owner slot) is itself
  // an exploit witness — the caller decides what to track.
  if (d.storageChanges.length > 0) return true;
  return false;
}

/** Compact summary suitable for embedding in `evidence.stateDiff`. */
export function summariseDiff(d: StateDiff): {
  attackerEthGained?: string;
  victimEthLost?: string;
  tokens: Array<{ token: string; attackerGained: string; victimLost: string }>;
  storage: StorageChange[];
} {
  const out: ReturnType<typeof summariseDiff> = { tokens: [], storage: d.storageChanges };
  if (d.attackerEthDelta !== 0n) out.attackerEthGained = d.attackerEthDelta.toString();
  if (d.victimEthDelta !== 0n) out.victimEthLost = (-d.victimEthDelta).toString();
  for (const c of d.tokenChanges) {
    out.tokens.push({
      token: c.token!,
      attackerGained: c.attackerGained.toString(),
      victimLost: c.victimLost.toString(),
    });
  }
  return out;
}
