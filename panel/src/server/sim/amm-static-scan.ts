// Static-analysis fallback for the economic-attack verifier.
//
// Scans raw runtime bytecode for hardcoded AMM signatures (router/pair
// addresses pushed via PUSH20, and swap function selectors pushed via PUSH4).
// When both are present AND the contract has at least one permissionless
// non-admin function, we have strong static evidence that the contract
// exposes a permissionless AMM-triggering function — even when the dynamic
// path can't fire because the contract has been drained (no token balance
// left to swap, no msg.value precondition satisfiable, etc.).
//
// The post-drain case is critical: every confirmed real-world exploit we
// want to audit ALREADY HAPPENED, meaning the victim contract has zero
// tokens / zero ETH at HEAD. The dynamic verifier returns not_exploitable
// for these because no AMM call physically fires — but the bytecode is the
// same and the bug is the same. Static signature lookup recovers them.
//
// What we do NOT do here:
//   - We do not infer WHICH function calls the router (that requires CFG
//     analysis we don't have). The verifier compensates by requiring a
//     non-admin candidate function to exist.
//   - We do not estimate severity. That's the verifier's job, based on the
//     combination of static + dynamic evidence.

export interface AmmStaticFinding {
  /** Hardcoded router addresses found in the bytecode (PUSH20). */
  routers: Array<{ address: string; name: string }>;
  /** Hardcoded swap selectors found in the bytecode (as PUSH4 or raw). */
  swapSelectors: Array<{ selector: string; name: string; pushCount: number; rawCount: number }>;
  /** Pair-direct manipulation selectors (sync/skim/burn/mint). PRESENCE
   *  ALONE is enough to fire — see comment on PAIR_DIRECT_SELECTORS. */
  pairDirectSelectors: Array<{ selector: string; name: string; pushCount: number; rawCount: number }>;
  /** Other tokens / pair addresses found (informational). */
  tokens: Array<{ address: string; name: string }>;
  /** True iff EITHER:
   *    (a) a hardcoded router address + a PUSHed swap selector are both
   *        present (the GPC/MSC / "permissionless swap" pattern), OR
   *    (b) a PUSHed pair-direct manipulation selector is present (the MT /
   *        deflationary-burn / "permissionless sync" pattern).
   *  The verifier uses this single boolean as the firing condition. */
  signatureConfirmed: boolean;
  /** Which signature path fired — useful for the verdict text and UI. */
  signatureKind: "router+swap" | "pair-direct" | "both" | "none";
}

// Well-known router addresses across major chains. Each entry is keyed by
// lowercased 0x-address. Adding new entries here is the right way to expand
// coverage — we deliberately don't try to dynamically resolve unknown
// addresses (would need an indexer or per-chain factory walk).
const KNOWN_ROUTERS: Record<string, string> = {
  // --- Ethereum mainnet ---
  "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap V2 Router",
  "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap V3 SwapRouter",
  "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap V3 SwapRouter02",
  "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap UniversalRouter (current)",
  "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap UniversalRouter (legacy)",
  "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f": "SushiSwap Router",
  "0xba12222222228d8ba445958a75a0704d566bf2c8": "Balancer V2 Vault",
  "0x99a58482bd75cbab83b27ec03ca68ff489b5788f": "Curve Registry Exchange",
  // --- BSC ---
  "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap V2 Router",
  "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap V3 SmartRouter",
  "0x05ff2b0db69458a0750badebc4f9e13add608c7f": "PancakeSwap V1 Router",
  "0x3a6d8ca21d1cf76f653a67577fa0d27453350dd8": "Apeswap BSC Router",
  "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506": "SushiSwap BSC Router",
  // --- Polygon ---
  "0xa5e0829caced8ffdd4de3c43696c57f7d7a678ff": "QuickSwap Router",
  "0x1b02da8cb0d097eb8d57a175b88c7d8b47997506x": "SushiSwap Polygon Router",
  // --- Arbitrum ---
  "0x1b81d678ffb9c0263b24a97847620c99d213eb14": "SushiSwap Arb Router",
  // --- Avalanche ---
  "0x60ae616a2155ee3d9a68541ba4544862310933d4": "Trader Joe Router",
  "0xe54ca86531e17ef3616d22ca28b0d458b6c89106": "Pangolin Router",
  // --- Optimism ---
  "0xa132dab612db5cb9fc9ac426a0cc215a3423f9c9": "Velodrome Router",
};

// Known token addresses we surface for diagnostic context. Hitting these in
// the bytecode doesn't fire the witness by itself — only routers do.
const KNOWN_TOKENS: Record<string, string> = {
  // ETH
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "WETH",
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "USDC",
  "0xdac17f958d2ee523a2206206994597c13d831ec7": "USDT",
  "0x6b175474e89094c44da98b954eedeac495271d0f": "DAI",
  // BSC
  "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "WBNB",
  "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
  "0x55d398326f99059ff775485246999027b3197955": "USDT (BSC)",
  "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC (BSC)",
  // Polygon
  "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270": "WMATIC",
  "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": "USDC (Polygon)",
  // Arbitrum / Optimism
  "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": "WETH (Arb)",
  "0x4200000000000000000000000000000000000006": "WETH (OP)",
};

// AMM swap selectors. SAME ABI across UniV2 forks (Pancake, Sushi, Quick,
// Trader Joe, etc.). UniV3 and Curve get separate entries.
const SWAP_SELECTORS: Record<string, string> = {
  "0x38ed1739": "swapExactTokensForTokens",
  "0x8803dbee": "swapTokensForExactTokens",
  "0x7ff36ab5": "swapExactETHForTokens",
  "0x4a25d94a": "swapTokensForExactETH",
  "0x18cbafe5": "swapExactTokensForETH",
  "0xfb3bdb41": "swapETHForExactTokens",
  "0x791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens",
  "0xb6f9de95": "swapExactETHForTokensSupportingFeeOnTransferTokens",
  "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
  "0x414bf389": "exactInputSingle (UniV3)",
  "0xc04b8d59": "exactInput (UniV3)",
  "0xdb3e2198": "exactOutputSingle (UniV3)",
  "0x04e45aaf": "exactInputSingle (V3 router02)",
  "0xb858183f": "exactInput (V3 router02)",
  "0x3df02124": "exchange (Curve int128)",
  "0x5b41b908": "exchange (Curve uint256)",
  "0x52bbbe29": "swap (Balancer V2)",
  "0x945bcec9": "batchSwap (Balancer V2)",
  "0x022c0d9f": "swap (UniV2 pair direct)",
};

// UniV2-Pair-direct manipulation selectors. These deserve a SEPARATE category
// because their presence alone (without a router address) is enough to fire
// the witness — a token / reward / mining contract that calls sync() or
// skim() on a pair has only one reason to do so: it wants to drive the
// pair's reserves up or down. That's the root primitive behind the
// "deflationary-token + LP-burn + flash-swap" exploit class (Movie Token /
// MT, PizzaBot, KP3R / Slope, Numen Cyber's COVER post-mortem set).
//
// Legitimate contracts that call these:
//   * Uniswap V2 Router itself (we don't audit it)
//   * Genuine sync-aware tax tokens (rare; risky by design)
//   * MEV bots (auditing irrelevant — they're attackers, not victims)
// So firing on their bare presence is high-precision; false-positive cost
// is low and the bug class is severe (six-figure exploits routinely).
const PAIR_DIRECT_SELECTORS: Record<string, string> = {
  "0xfff6cae9": "sync (UniV2 Pair reserve resync)",
  "0xbc25cf77": "skim (UniV2 Pair excess drain)",
  "0x89afcb44": "burn (UniV2 Pair LP redeem)",
  "0x6a627842": "mint (UniV2 Pair LP issue)",
};

/** Walks the bytecode hex looking for PUSH20 (opcode 0x73) followed by 20
 *  bytes that match a known router OR token. Returns deduplicated hits. */
export function scanForHardcodedAddresses(bytecodeHex: string): {
  routers: AmmStaticFinding["routers"];
  tokens: AmmStaticFinding["tokens"];
} {
  const code = bytecodeHex.replace(/^0x/, "").toLowerCase();
  const routers = new Set<string>();
  const tokens = new Set<string>();
  // Walk byte by byte; on PUSH20 (0x73) extract the next 20 bytes.
  for (let i = 0; i + 42 <= code.length; i += 2) {
    if (code.slice(i, i + 2) !== "73") continue;
    const addrHex = code.slice(i + 2, i + 42);
    if (!/^[0-9a-f]{40}$/.test(addrHex)) continue;
    const addr = "0x" + addrHex;
    if (KNOWN_ROUTERS[addr]) routers.add(addr);
    else if (KNOWN_TOKENS[addr]) tokens.add(addr);
  }
  return {
    routers: Array.from(routers).map((a) => ({ address: a, name: KNOWN_ROUTERS[a] })),
    tokens: Array.from(tokens).map((a) => ({ address: a, name: KNOWN_TOKENS[a] })),
  };
}

/** Helper: count PUSH4 (opcode 0x63) and raw occurrences for a given map of
 *  selectors. */
function scanSelectorMap(
  bytecodeHex: string,
  map: Record<string, string>,
): Array<{ selector: string; name: string; pushCount: number; rawCount: number }> {
  const code = bytecodeHex.replace(/^0x/, "").toLowerCase();
  const out: Array<{ selector: string; name: string; pushCount: number; rawCount: number }> = [];
  for (const [sel, name] of Object.entries(map)) {
    const needle = sel.slice(2);
    const push4 = "63" + needle;
    let pushCount = 0;
    let rawCount = 0;
    let idx = 0;
    while ((idx = code.indexOf(push4, idx)) !== -1) {
      pushCount++;
      idx += push4.length;
    }
    idx = 0;
    while ((idx = code.indexOf(needle, idx)) !== -1) {
      rawCount++;
      idx += needle.length;
    }
    if (pushCount > 0 || rawCount > 0) {
      out.push({ selector: sel, name, pushCount, rawCount });
    }
  }
  return out;
}

/** Looks for AMM swap selectors in the bytecode. We count both PUSH4 forms
 *  (opcode 0x63 + selector) and raw occurrences — the raw count is
 *  diagnostic only (the selector might appear inside a hash/seed). The
 *  PUSH4 count is what actually proves the selector is going to be used
 *  as a call target. */
export function scanForSwapSelectors(bytecodeHex: string): AmmStaticFinding["swapSelectors"] {
  return scanSelectorMap(bytecodeHex, SWAP_SELECTORS);
}

/** Looks for pair-direct manipulation selectors (sync/skim/burn/mint) — the
 *  primitives behind the deflationary-token + LP-burn exploit class. */
export function scanForPairDirectSelectors(
  bytecodeHex: string,
): AmmStaticFinding["pairDirectSelectors"] {
  return scanSelectorMap(bytecodeHex, PAIR_DIRECT_SELECTORS);
}

export function ammStaticScan(bytecodeHex: string): AmmStaticFinding {
  if (!bytecodeHex || bytecodeHex === "0x" || bytecodeHex === "0x0") {
    return {
      routers: [],
      swapSelectors: [],
      pairDirectSelectors: [],
      tokens: [],
      signatureConfirmed: false,
      signatureKind: "none",
    };
  }
  const { routers, tokens } = scanForHardcodedAddresses(bytecodeHex);
  const swapSelectors = scanForSwapSelectors(bytecodeHex);
  const pairDirectSelectors = scanForPairDirectSelectors(bytecodeHex);

  // Path A: router-style swap. Requires BOTH a hardcoded router address AND
  // a PUSHed swap selector. High precision; rules out tokens that just embed
  // a router-like bytecode pattern and selectors that appear only as hash
  // collisions.
  const hasPushedSwapSelector = swapSelectors.some((s) => s.pushCount > 0);
  const routerSwapMatch = routers.length > 0 && hasPushedSwapSelector;

  // Path B: pair-direct manipulation. PUSHed sync/skim/burn/mint selector is
  // sufficient. These selectors are NOT in any "normal" contract surface — a
  // token or reward contract that PUSHes 0xfff6cae9 (sync()) is, in practice,
  // always doing pair reserve manipulation. The MT (Movie Token) drain is
  // the canonical example.
  const hasPushedPairDirect = pairDirectSelectors.some((s) => s.pushCount > 0);

  let signatureKind: AmmStaticFinding["signatureKind"] = "none";
  if (routerSwapMatch && hasPushedPairDirect) signatureKind = "both";
  else if (routerSwapMatch) signatureKind = "router+swap";
  else if (hasPushedPairDirect) signatureKind = "pair-direct";

  return {
    routers,
    swapSelectors,
    pairDirectSelectors,
    tokens,
    signatureConfirmed: signatureKind !== "none",
    signatureKind,
  };
}
