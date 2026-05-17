/*
 * AMM/DEX interaction detector.
 *
 * Walks a debug_traceCall result and returns every call to a known
 * router/pair-direct swap selector. The economic-attack verifier uses this
 * to decide whether an unguarded function triggers a price-impacting swap
 * (the GPC/MSC pattern on BSC, Curve-on-Vyper drains, BurgerSwap-style etc.).
 *
 * Selector catalog focuses on:
 *   - UniV2-family routers (Uniswap, Pancake, SushiSwap, QuickSwap, ...) —
 *     same ABI, same selectors, used on every major EVM chain
 *   - UniV3 routers (SwapRouter, SwapRouter02, UniversalRouter)
 *   - Curve exchange / exchange_underlying (int128 and uint256 variants)
 *   - Balancer V2 batchSwap
 *   - Direct UniV2 pair swap() (sometimes called directly without a router)
 *
 * The catalog can be extended without code changes via the
 * SIM_AMM_EXTRA_SELECTORS env (comma-separated 0x-prefixed 4-byte selectors).
 */

import type { CallNode } from "./trace";

export interface AmmHit {
  /** The contract that received the swap call (router or pair). */
  target: string;
  /** The 4-byte function selector that was invoked. */
  selector: string;
  /** Human-readable name for the swap family. */
  name: string;
  /** Which DEX family this selector belongs to. */
  family: "univ2-router" | "univ3-router" | "curve" | "balancer" | "univ2-pair" | "extra";
  /** Depth in the call tree (0 = top-level call, >0 = nested). */
  depth: number;
  /** Was the call successful? Failed swaps still count as "the contract
   *  TRIED to swap" — the rule fires either way. */
  succeeded: boolean;
  /** First 64 bytes of the inner calldata, for diagnostic display. */
  inputPreview: string;
}

interface SelectorMeta {
  selector: string;
  name: string;
  family: AmmHit["family"];
}

// UniV2-family routers (same selectors across all forks).
const UNIV2_ROUTER_SELECTORS: SelectorMeta[] = [
  { selector: "0x38ed1739", name: "swapExactTokensForTokens", family: "univ2-router" },
  { selector: "0x8803dbee", name: "swapTokensForExactTokens", family: "univ2-router" },
  { selector: "0x7ff36ab5", name: "swapExactETHForTokens", family: "univ2-router" },
  { selector: "0x4a25d94a", name: "swapTokensForExactETH", family: "univ2-router" },
  { selector: "0x18cbafe5", name: "swapExactTokensForETH", family: "univ2-router" },
  { selector: "0xfb3bdb41", name: "swapETHForExactTokens", family: "univ2-router" },
  { selector: "0x791ac947", name: "swapExactTokensForETHSupportingFeeOnTransferTokens", family: "univ2-router" },
  { selector: "0xb6f9de95", name: "swapExactETHForTokensSupportingFeeOnTransferTokens", family: "univ2-router" },
  { selector: "0x5c11d795", name: "swapExactTokensForTokensSupportingFeeOnTransferTokens", family: "univ2-router" },
];

// UniV3 SwapRouter / SwapRouter02 / UniversalRouter selectors.
const UNIV3_ROUTER_SELECTORS: SelectorMeta[] = [
  { selector: "0x414bf389", name: "exactInputSingle", family: "univ3-router" },
  { selector: "0xc04b8d59", name: "exactInput", family: "univ3-router" },
  { selector: "0xdb3e2198", name: "exactOutputSingle", family: "univ3-router" },
  { selector: "0xf28c0498", name: "exactOutput", family: "univ3-router" },
  { selector: "0x04e45aaf", name: "exactInputSingle (V2 router)", family: "univ3-router" },
  { selector: "0xb858183f", name: "exactInput (V2 router)", family: "univ3-router" },
  { selector: "0x3593564c", name: "execute (UniversalRouter)", family: "univ3-router" },
];

// Curve exchange selectors (int128 and uint256 variants, with/without receiver).
const CURVE_SELECTORS: SelectorMeta[] = [
  { selector: "0x3df02124", name: "exchange(int128,int128,uint256,uint256)", family: "curve" },
  { selector: "0x5b41b908", name: "exchange(uint256,uint256,uint256,uint256)", family: "curve" },
  { selector: "0xa6417ed6", name: "exchange_underlying(int128,int128,uint256,uint256)", family: "curve" },
  { selector: "0x65b2489b", name: "exchange_underlying(uint256,uint256,uint256,uint256)", family: "curve" },
  { selector: "0xddc1f59d", name: "exchange (registry)", family: "curve" },
];

// Balancer V2 (Vault) and Velodrome/Aerodrome (Solidly fork) selectors.
const BALANCER_SELECTORS: SelectorMeta[] = [
  { selector: "0x52bbbe29", name: "swap (Balancer V2)", family: "balancer" },
  { selector: "0x945bcec9", name: "batchSwap (Balancer V2)", family: "balancer" },
  { selector: "0xcac88ea9", name: "swapExactTokensForTokens (Solidly)", family: "balancer" },
];

// UniV2-Pair-direct primitives. These are pair-manipulation calls that are
// not part of the normal swap-via-router flow:
//   * sync()        - re-aligns pair reserves to its current balanceOf token0/1
//   * skim(addr)    - sends any excess (balance > reserves) to addr
//   * burn(addr)    - burns LP tokens held by msg.sender, sends underlying to addr
//   * mint(addr)    - mints LP for whoever transferred tokens to the pair
//   * swap(...)     - low-level pair swap (router builds on top of this)
//
// Calls to these from a non-pair contract are HIGHLY unusual. Legitimate
// integrators (Uniswap router, Curve, MEV bots, some yield contracts) DO
// touch them, but inside a TOKEN contract or a "reward distribution" contract
// the only realistic reason is intentional pair reserve manipulation — which
// is the root primitive behind the Movie Token / Pizza-Bot / KP3R style
// deflationary-burn exploits where an attacker forces the victim to call
// sync() / skim() after pre-loading the pair balance via a flash swap.
const PAIR_SELECTORS: SelectorMeta[] = [
  { selector: "0x022c0d9f", name: "swap (UniV2 Pair direct)", family: "univ2-pair" },
  { selector: "0xfff6cae9", name: "sync (UniV2 Pair reserve resync)", family: "univ2-pair" },
  { selector: "0xbc25cf77", name: "skim (UniV2 Pair excess drain)", family: "univ2-pair" },
  { selector: "0x89afcb44", name: "burn (UniV2 Pair LP redeem)", family: "univ2-pair" },
  { selector: "0x6a627842", name: "mint (UniV2 Pair LP issue)", family: "univ2-pair" },
];

function buildCatalog(): Map<string, SelectorMeta> {
  const m = new Map<string, SelectorMeta>();
  for (const s of [
    ...UNIV2_ROUTER_SELECTORS,
    ...UNIV3_ROUTER_SELECTORS,
    ...CURVE_SELECTORS,
    ...BALANCER_SELECTORS,
    ...PAIR_SELECTORS,
  ]) {
    m.set(s.selector.toLowerCase(), s);
  }
  // Env-injected extras allow operators to extend without redeploying.
  const extra = process.env.SIM_AMM_EXTRA_SELECTORS;
  if (extra) {
    for (const raw of extra.split(",").map((s) => s.trim())) {
      if (/^0x[0-9a-fA-F]{8}$/.test(raw)) {
        m.set(raw.toLowerCase(), { selector: raw.toLowerCase(), name: `custom:${raw}`, family: "extra" });
      }
    }
  }
  return m;
}

const CATALOG = buildCatalog();

/** Returns true if the 4-byte prefix of `input` matches any catalog entry. */
export function isAmmSelector(input: string | undefined | null): SelectorMeta | null {
  if (!input || input.length < 10) return null;
  const sel = input.slice(0, 10).toLowerCase();
  return CATALOG.get(sel) ?? null;
}

/** Walks the call tree and collects every AMM hit. Top-level call itself is
 *  considered depth=0; nested calls increase depth. Includes failed sub-calls
 *  because "victim attempted a swap" is the witness we care about. */
export function findAmmHits(root: CallNode | null): AmmHit[] {
  if (!root) return [];
  const out: AmmHit[] = [];
  const stack: Array<{ node: CallNode; depth: number }> = [{ node: root, depth: 0 }];
  while (stack.length) {
    const { node, depth } = stack.pop()!;
    const meta = isAmmSelector(node.input);
    if (meta && node.to) {
      out.push({
        target: node.to.toLowerCase(),
        selector: meta.selector,
        name: meta.name,
        family: meta.family,
        depth,
        succeeded: !node.error,
        inputPreview: (node.input ?? "").slice(0, 138),
      });
    }
    if (Array.isArray(node.calls)) {
      for (const c of node.calls) stack.push({ node: c, depth: depth + 1 });
    }
  }
  return out;
}

/** Convenience: was a known AMM swap reached anywhere in the trace? */
export function reachedAnyAmm(root: CallNode | null): boolean {
  return findAmmHits(root).length > 0;
}

/** Pre-computed catalog summary for diagnostic dumps. */
export function catalogSummary() {
  return {
    total: CATALOG.size,
    univ2: UNIV2_ROUTER_SELECTORS.length,
    univ3: UNIV3_ROUTER_SELECTORS.length,
    curve: CURVE_SELECTORS.length,
    balancer: BALANCER_SELECTORS.length,
    pair: PAIR_SELECTORS.length,
  };
}
