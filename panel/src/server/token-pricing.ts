// USD pricing for ERC-20 tokens with strict request budget.
//
// Strategy:
//   1. Hardcoded fallbacks for stablecoins ($1.00) and wrapped natives.
//      → covers 60-80% of all token holdings we ever look up, ZERO requests.
//   2. Coingecko /simple/token_price/{platform} batched per chain.
//      → at most ONE request per chain per 60 min, regardless of how many
//        tokens we're pricing. Cached in token_price_usd table.
//   3. Tokens Coingecko doesn't know about (long-tail meme/shitcoins) get
//      price=null and surface as "unpriced" in the UI rather than $0,
//      because $0 would understate the at-risk surface for the user.
//
// Native token pricing is ALWAYS via the fallback list (Coingecko returns
// platform-keyed prices, native ETH/BNB/MATIC aren't per-platform tokens).
// We use CoinGecko's separate `/simple/price?ids=...&vs_currencies=usd`
// endpoint for natives via a single boot-time fetch with 30-min TTL.

import { rawDb } from "@/src/db/client";

const PRICE_TTL_MS = Number(process.env.EXPOSURE_PRICE_TTL_MS ?? 60 * 60_000);
const NATIVE_PRICE_TTL_MS = Number(process.env.EXPOSURE_NATIVE_PRICE_TTL_MS ?? 30 * 60_000);
const CG_TIMEOUT_MS = Number(process.env.EXPOSURE_COINGECKO_TIMEOUT_MS ?? 6_000);
const CG_BASE = process.env.COINGECKO_BASE_URL ?? "https://api.coingecko.com/api/v3";
const CG_API_KEY = process.env.COINGECKO_API_KEY ?? ""; // optional, demo key works without one

// Coingecko platform slugs we support. Keep in sync with chain-meta.ts.
// chainId → coingecko platform slug
const CG_PLATFORM: Record<number, string> = {
  1: "ethereum",
  56: "binance-smart-chain",
  137: "polygon-pos",
  10: "optimistic-ethereum",
  8453: "base",
  42161: "arbitrum-one",
  43114: "avalanche",
  81457: "blast",
  42220: "celo",
  324: "zksync",
  146: "sonic",
  59144: "linea",
  100: "xdai",
};

// chainId → coingecko id for the NATIVE asset.
const CG_NATIVE: Record<number, string> = {
  1: "ethereum",
  56: "binancecoin",
  137: "matic-network",
  10: "ethereum",
  8453: "ethereum",
  42161: "ethereum",
  43114: "avalanche-2",
  81457: "ethereum",
  42220: "celo",
  324: "ethereum",
  146: "sonic-3",
  59144: "ethereum",
  100: "xdai",
};

// Hardcoded fallbacks per (chainId, address) → usd/token. Covers all
// stablecoins and the wrapped-native — these never need a network call.
const FALLBACK_PRICES: Record<string, number> = Object.fromEntries(
  Object.entries<Record<string, number>>({
    // Ethereum mainnet
    "1": {
      "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 1.0, // USDC
      "0xdac17f958d2ee523a2206206994597c13d831ec7": 1.0, // USDT
      "0x6b175474e89094c44da98b954eedeac495271d0f": 1.0, // DAI
      "0x4fabb145d64652a948d72533023f6e7a623c7c53": 1.0, // BUSD
      "0x853d955acef822db058eb8505911ed77f175b99e": 1.0, // FRAX
      "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": -1,  // WETH — use native price
      "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599": -2,  // WBTC — pegged to BTC
    },
    // BSC
    "56": {
      "0x55d398326f99059ff775485246999027b3197955": 1.0, // USDT
      "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": 1.0, // USDC
      "0xe9e7cea3dedca5984780bafc599bd69add087d56": 1.0, // BUSD
      "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": -1,  // WBNB
    },
    // Polygon
    "137": {
      "0x3c499c542cef5e3811e1192ce70d8cc03d5c3359": 1.0, // USDC (native)
      "0x2791bca1f2de4661ed88a30c99a7a9449aa84174": 1.0, // USDC.e (bridged)
      "0xc2132d05d31c914a87c6611c10748aeb04b58e8f": 1.0, // USDT
      "0x8f3cf7ad23cd3cadbd9735aff958023239c6a063": 1.0, // DAI
      "0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270": -1,  // WMATIC
    },
    // Arbitrum
    "42161": {
      "0xaf88d065e77c8cc2239327c5edb3a432268e5831": 1.0, // USDC
      "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": 1.0, // USDC.e
      "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": 1.0, // USDT
      "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": 1.0, // DAI
      "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": -1,  // WETH
    },
    // Optimism
    "10": {
      "0x0b2c639c533813f4aa9d7837caf62653d097ff85": 1.0, // USDC
      "0x7f5c764cbc14f9669b88837ca1490cca17c31607": 1.0, // USDC.e
      "0x94b008aa00579c1307b0ef2c499ad98a8ce58e58": 1.0, // USDT
      "0x4200000000000000000000000000000000000006": -1,  // WETH
    },
    // Base
    "8453": {
      "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913": 1.0, // USDC
      "0x50c5725949a6f0c72e6c4a641f24049a917db0cb": 1.0, // DAI
      "0x4200000000000000000000000000000000000006": -1,  // WETH
    },
    // Avalanche
    "43114": {
      "0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e": 1.0, // USDC
      "0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7": 1.0, // USDT
      "0xd586e7f844cea2f87f50152665bcbc2c279d8d70": 1.0, // DAI.e
      "0xb31f66aa3c1e785363f0875a1b74e27b85fd66c7": -1,  // WAVAX
    },
  }).flatMap(([chainId, m]) =>
    Object.entries(m).map(([addr, price]) => [`${chainId}:${addr.toLowerCase()}`, price]),
  ),
);

interface PriceRow {
  usd_per_token: number | null;
  source: string;
  fetched_at: number;
}

let nativeCache: Map<number, { usd: number; at: number }> = new Map();

/** Per-chain native price (ETH / BNB / MATIC / ...). Single Coingecko call
 * shared across all chains, 30-min TTL. Fallback to 0 (= unpriced) if the
 * call fails — the UI will surface as "n/a". */
export async function getNativePriceUsd(chainId: number): Promise<number> {
  const now = Date.now();
  const c = nativeCache.get(chainId);
  if (c && now - c.at < NATIVE_PRICE_TTL_MS) return c.usd;

  const ids = Array.from(new Set(Object.values(CG_NATIVE))).join(",");
  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (CG_API_KEY) headers["x-cg-demo-api-key"] = CG_API_KEY;
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), CG_TIMEOUT_MS);
    const r = await fetch(`${CG_BASE}/simple/price?ids=${ids}&vs_currencies=usd`, { headers, signal: ac.signal });
    clearTimeout(t);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    for (const [cId, cgId] of Object.entries(CG_NATIVE)) {
      const usd = Number(j?.[cgId]?.usd ?? 0);
      if (usd > 0) nativeCache.set(Number(cId), { usd, at: now });
    }
    return nativeCache.get(chainId)?.usd ?? 0;
  } catch {
    return c?.usd ?? 0; // stale-while-error
  }
}

function selectCache(chainId: number, addresses: string[]): Map<string, PriceRow> {
  if (addresses.length === 0) return new Map();
  const placeholders = addresses.map(() => "?").join(",");
  const rows = rawDb
    .prepare(
      `SELECT token_address, usd_per_token, source, fetched_at
       FROM token_price_usd
       WHERE chain_id = ? AND token_address IN (${placeholders})`,
    )
    .all(chainId, ...addresses) as Array<{ token_address: string } & PriceRow>;
  const out = new Map<string, PriceRow>();
  const now = Date.now();
  for (const r of rows) {
    if (now - r.fetched_at < PRICE_TTL_MS) {
      out.set(r.token_address.toLowerCase(), {
        usd_per_token: r.usd_per_token,
        source: r.source,
        fetched_at: r.fetched_at,
      });
    }
  }
  return out;
}

function upsertPrice(chainId: number, addr: string, usd: number | null, source: string) {
  rawDb
    .prepare(
      `INSERT OR REPLACE INTO token_price_usd (chain_id, token_address, usd_per_token, source, fetched_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .run(chainId, addr.toLowerCase(), usd, source, Date.now());
}

// Resolve fallback price including the special sentinels:
//   -1 = wrapped-native (uses native USD price)
//   -2 = WBTC (uses bitcoin USD price — fetched lazily, cached)
let btcPriceCache: { usd: number; at: number } | null = null;
async function getBtcPrice(): Promise<number> {
  const now = Date.now();
  if (btcPriceCache && now - btcPriceCache.at < NATIVE_PRICE_TTL_MS) return btcPriceCache.usd;
  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (CG_API_KEY) headers["x-cg-demo-api-key"] = CG_API_KEY;
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), CG_TIMEOUT_MS);
    const r = await fetch(`${CG_BASE}/simple/price?ids=bitcoin&vs_currencies=usd`, { headers, signal: ac.signal });
    clearTimeout(t);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    const usd = Number(j?.bitcoin?.usd ?? 0);
    if (usd > 0) {
      btcPriceCache = { usd, at: now };
      return usd;
    }
  } catch {}
  return btcPriceCache?.usd ?? 0;
}

async function resolveFallback(chainId: number, addr: string): Promise<number | null> {
  const raw = FALLBACK_PRICES[`${chainId}:${addr.toLowerCase()}`];
  if (raw == null) return null;
  if (raw === -1) return await getNativePriceUsd(chainId);
  if (raw === -2) return await getBtcPrice();
  return raw;
}

/**
 * Get USD spot price per token unit (NOT per base-unit; multiply by
 * balance / 10^decimals to get USD value).
 *
 * - Hardcoded fallbacks (stablecoins, wrapped natives) → no network.
 * - Cached entries from token_price_usd (60-min TTL) → no network.
 * - Misses are pooled into ONE Coingecko call per chain.
 *
 * Returns a map keyed by lowercase address. Entries with `null` mean
 * "unpriced" (Coingecko doesn't know the token); the UI surfaces those
 * as "—" rather than $0 to avoid understating risk.
 */
export async function getTokenPricesUsd(
  chainId: number,
  addresses: string[],
): Promise<Map<string, number | null>> {
  const out = new Map<string, number | null>();
  const lower = Array.from(new Set(addresses.map((a) => a.toLowerCase())));
  if (lower.length === 0) return out;

  // 1. Fallback hits.
  const remaining: string[] = [];
  for (const a of lower) {
    const fb = await resolveFallback(chainId, a);
    if (fb != null && fb > 0) out.set(a, fb);
    else remaining.push(a);
  }
  if (remaining.length === 0) return out;

  // 2. SQLite cache hits.
  const cached = selectCache(chainId, remaining);
  for (const [a, p] of cached) out.set(a, p.usd_per_token);

  const misses = remaining.filter((a) => !cached.has(a));
  if (misses.length === 0) return out;

  // 3. ONE Coingecko call per chain. If we don't have a platform mapping,
  // mark misses as unpriced (no spam).
  const platform = CG_PLATFORM[chainId];
  if (!platform) {
    for (const a of misses) {
      out.set(a, null);
      upsertPrice(chainId, a, null, "unsupported-chain");
    }
    return out;
  }

  try {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (CG_API_KEY) headers["x-cg-demo-api-key"] = CG_API_KEY;
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), CG_TIMEOUT_MS);
    const url = `${CG_BASE}/simple/token_price/${platform}?contract_addresses=${misses.join(",")}&vs_currencies=usd`;
    const r = await fetch(url, { headers, signal: ac.signal });
    clearTimeout(t);
    if (!r.ok) {
      // Mark all as unpriced and cache (short-lived: 60min TTL respected via fetched_at)
      for (const a of misses) {
        out.set(a, null);
        upsertPrice(chainId, a, null, `cg-error-${r.status}`);
      }
      return out;
    }
    const j: any = await r.json();
    for (const a of misses) {
      const v = j?.[a]?.usd;
      const usd = typeof v === "number" && v > 0 ? v : null;
      out.set(a, usd);
      upsertPrice(chainId, a, usd, "coingecko");
    }
    return out;
  } catch {
    for (const a of misses) {
      out.set(a, null);
      upsertPrice(chainId, a, null, "cg-fetch-failed");
    }
    return out;
  }
}
