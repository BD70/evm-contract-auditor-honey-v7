// Per-contract exposure lookup. For each (chainId, address) we query
// QuickNode's `qn_getWalletTokenBalance` (Token & NFT API v2) to get native +
// ERC-20 balances in a single RPC. If the add-on is not enabled on a chain's
// endpoint we transparently fall back to bare `eth_getBalance`.
//
// Results are memoised in-memory with a short TTL so the panel doesn't hammer
// QuickNode every time a user refreshes the findings page.

import { readChainsRaw } from "./chains-store";
import { chainMetaByChainId, type ChainMeta } from "@/src/lib/chain-meta";
import { discoverHoldings, invalidateHoldings } from "./token-discovery";
import { getNativePriceUsd, getTokenPricesUsd } from "./token-pricing";

const TTL_MS = Number(process.env.EXPOSURE_CACHE_TTL_MS ?? 5 * 60_000);
const RPC_TIMEOUT_MS = Number(process.env.EXPOSURE_RPC_TIMEOUT_MS ?? 8_000);
const PER_CHAIN_CONCURRENCY = Number(process.env.EXPOSURE_PER_CHAIN_CONCURRENCY ?? 3);
const MAX_TOKENS_RETURNED = Number(process.env.EXPOSURE_MAX_TOKENS ?? 25);
const DUST_USD_THRESHOLD = Number(process.env.EXPOSURE_DUST_USD ?? 1.0);

export interface TokenBalance {
  address: string;
  symbol: string;
  name: string;
  decimals: number;
  /** raw amount in token base units, decimal string */
  balance: string;
  /** USD spot price per token unit (NOT per base-unit). null = unpriced. */
  usdPerToken?: number | null;
  /** USD value of `balance` (= balance/10^decimals * usdPerToken). null = unpriced. */
  usdValue?: number | null;
}

export interface Exposure {
  chainId: number;
  address: string;
  /** native amount in wei, decimal string */
  nativeWei: string;
  nativeSymbol: string;
  nativeDecimals: number;
  tokens: TokenBalance[];
  /** truthy if the chain endpoint doesn't support qn_getWalletTokenBalance */
  tokenScanUnsupported?: boolean;
  fetchedAt: number;
  /** present when the lookup itself failed (rpc down, address invalid, ...) */
  error?: string;
  // ── USD pricing (v3) ───────────────────────────────────────────────────────
  /** USD spot price of the chain's native asset (ETH/BNB/MATIC/…). null = unpriced. */
  nativeUsdPerToken?: number | null;
  /** USD value of nativeWei. */
  nativeUsdValue?: number | null;
  /** Sum of USD values across all priced tokens (dust included). */
  tokensUsdValue?: number | null;
  /** Sum of native + tokens. */
  totalUsdValue?: number | null;
  /** Coarse data-source label for the token list, for UI tooltips. */
  tokenSource?: "qn-add-on" | "log-scan" | "log-scan-cache" | "none";
  /** Number of tokens dropped because their per-token USD value is below the dust threshold. */
  dustTokensFiltered?: number;
}

type Globals = { __exposureCache?: Map<string, Exposure>; __unsupportedHosts?: Set<string> };
const g = globalThis as unknown as Globals;
if (!g.__exposureCache) g.__exposureCache = new Map();
if (!g.__unsupportedHosts) g.__unsupportedHosts = new Set();
const cache = g.__exposureCache!;
const unsupportedHosts = g.__unsupportedHosts!;

function cacheKey(chainId: number, address: string): string {
  return `${chainId}:${address.toLowerCase()}`;
}

function rpcUrlForChain(chainId: number): { url: string; meta: ChainMeta } | null {
  const meta = chainMetaByChainId(chainId);
  if (!meta) return null;
  const entry = readChainsRaw().find((c) => c.slug === meta.slug);
  if (!entry?.rpcHttpUrl) return null;
  return { url: entry.rpcHttpUrl, meta };
}

async function rpcCall<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), RPC_TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    if (j.error) {
      const err = new Error(j.error.message ?? "rpc error");
      (err as any).code = j.error.code;
      throw err;
    }
    return j.result as T;
  } finally {
    clearTimeout(t);
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

async function fetchExposureOne(chainId: number, address: string): Promise<Exposure> {
  const resolved = rpcUrlForChain(chainId);
  if (!resolved) {
    const meta = chainMetaByChainId(chainId);
    return {
      chainId,
      address,
      nativeWei: "0",
      nativeSymbol: meta?.nativeSymbol ?? "?",
      nativeDecimals: meta?.nativeDecimals ?? 18,
      tokens: [],
      fetchedAt: Date.now(),
      error: "no rpc configured for chain",
    };
  }
  const { url, meta } = resolved;
  const host = hostOf(url);

  // Fast path: skip qn_* on hosts where we know the add-on isn't enabled.
  const tryTokens = !unsupportedHosts.has(host);

  if (tryTokens) {
    try {
      const res = await rpcCall<{
        nativeTokenBalance?: string;
        result?: Array<{
          address: string;
          name: string;
          symbol: string;
          decimals: string;
          totalBalance: string;
        }>;
      }>(url, "qn_getWalletTokenBalance", [
        { wallet: address, page: 1, perPage: MAX_TOKENS_RETURNED },
      ]);
      // QuickNode returns nativeTokenBalance as a *human-readable decimal string*
      // (e.g. "33.111612880018143614") which we need to convert back to wei to
      // stay consistent with our internal units.
      const nativeWei = humanToBaseUnits(res?.nativeTokenBalance ?? "0", meta.nativeDecimals);
      const tokens: TokenBalance[] = (res?.result ?? [])
        .map((t) => ({
          address: t.address,
          name: t.name,
          symbol: t.symbol,
          decimals: Number(t.decimals) || 0,
          balance: t.totalBalance ?? "0",
        }))
        .filter((t) => t.balance && t.balance !== "0");
      return await enrichWithUsd({
        chainId,
        address,
        nativeWei,
        nativeSymbol: meta.nativeSymbol,
        nativeDecimals: meta.nativeDecimals,
        tokens,
        tokenSource: "qn-add-on",
        fetchedAt: Date.now(),
      });
    } catch (err: any) {
      // Known "QN add-on absent" signals:
      //   -32601 method not found  (RPC standard)
      //   -32004 method unavailable
      //   -32609 QuickNode-specific: "token api is not enabled - enable the
      //          Token and NFT API add-on at marketplace.quicknode.com"
      // We also pattern-match the message so we catch future variants without
      // a code (e.g. plain 4xx replies wrapped as a generic error).
      const msg = String(err?.message ?? err);
      if (
        err?.code === -32601 ||
        err?.code === -32004 ||
        err?.code === -32609 ||
        /method not (found|allowed)/i.test(msg) ||
        /is not enabled/i.test(msg) ||
        /not (?:available|supported)/i.test(msg) ||
        /add[- ]on/i.test(msg)
      ) {
        unsupportedHosts.add(host);
      }
      // fall through to eth_getBalance
    }
  }

  // Fallback ladder for tokens when QN add-on is unavailable:
  //   1. log-discovery via eth_getLogs + balanceOf (works on any RPC,
  //      heavily cached so the rate cost is bounded — see token-discovery.ts).
  //   2. bare native balance only (final fallback if log-scan also fails).
  let nativeWei = "0";
  try {
    const hex = await rpcCall<string>(url, "eth_getBalance", [address, "latest"]);
    nativeWei = BigInt(hex).toString();
  } catch (err: any) {
    return {
      chainId,
      address,
      nativeWei: "0",
      nativeSymbol: meta.nativeSymbol,
      nativeDecimals: meta.nativeDecimals,
      tokens: [],
      tokenScanUnsupported: true,
      fetchedAt: Date.now(),
      error: String(err?.message ?? err),
    };
  }

  // Log-scan discovery (rate-conservative; see token-discovery.ts header).
  let tokens: TokenBalance[] = [];
  let tokenSource: Exposure["tokenSource"] = "none";
  try {
    const disc = await discoverHoldings(url, chainId, address);
    tokenSource = disc.source === "cache" ? "log-scan-cache" : disc.source === "log-scan" ? "log-scan" : "none";
    tokens = disc.holdings.map((h) => ({
      address: h.tokenAddress,
      symbol: h.metadata.symbol,
      name: h.metadata.name,
      decimals: h.metadata.decimals,
      balance: h.balance,
    }));
  } catch {
    // discoverHoldings is best-effort; failures degrade to "no tokens"
    tokens = [];
    tokenSource = "none";
  }

  return await enrichWithUsd({
    chainId,
    address,
    nativeWei,
    nativeSymbol: meta.nativeSymbol,
    nativeDecimals: meta.nativeDecimals,
    tokens,
    tokenSource,
    tokenScanUnsupported: tokenSource === "none",
    fetchedAt: Date.now(),
  });
}

/** Compute USD value per token + totals, and filter dust below threshold.
 * This is the only place where exposure objects get their `usd*` fields. */
async function enrichWithUsd(exp: Exposure): Promise<Exposure> {
  // Native price (1 Coingecko call shared across chains, 30-min cached).
  let nativeUsdPerToken: number | null = null;
  try {
    nativeUsdPerToken = await getNativePriceUsd(exp.chainId);
    if (!nativeUsdPerToken || nativeUsdPerToken <= 0) nativeUsdPerToken = null;
  } catch {
    nativeUsdPerToken = null;
  }
  const nativeFloat = Number(exp.nativeWei) / Math.pow(10, exp.nativeDecimals);
  const nativeUsdValue = nativeUsdPerToken != null ? nativeFloat * nativeUsdPerToken : null;

  // Token prices (1 Coingecko call per chain, 60-min cached).
  let priced: Map<string, number | null> = new Map();
  if (exp.tokens.length > 0) {
    try {
      priced = await getTokenPricesUsd(exp.chainId, exp.tokens.map((t) => t.address));
    } catch {
      priced = new Map();
    }
  }

  let tokensUsdValue = 0;
  let pricedSeen = 0;
  let dustFiltered = 0;
  const enriched: TokenBalance[] = [];
  for (const t of exp.tokens) {
    const usdPer = priced.get(t.address.toLowerCase()) ?? null;
    const human = Number(BigInt(t.balance)) / Math.pow(10, t.decimals);
    const usdVal = usdPer != null ? human * usdPer : null;
    if (usdVal != null) {
      pricedSeen++;
      if (usdVal < DUST_USD_THRESHOLD) {
        dustFiltered++;
        continue; // drop priced dust
      }
      tokensUsdValue += usdVal;
    }
    enriched.push({ ...t, usdPerToken: usdPer, usdValue: usdVal });
  }
  // Sort by USD value desc (unpriced go last)
  enriched.sort((a, b) => {
    const av = a.usdValue ?? -1;
    const bv = b.usdValue ?? -1;
    return bv - av;
  });

  const totalUsdValue =
    (nativeUsdValue ?? 0) + (pricedSeen > 0 ? tokensUsdValue : 0);

  return {
    ...exp,
    tokens: enriched.slice(0, MAX_TOKENS_RETURNED),
    nativeUsdPerToken,
    nativeUsdValue,
    tokensUsdValue: pricedSeen > 0 ? tokensUsdValue : null,
    totalUsdValue: nativeUsdValue != null || pricedSeen > 0 ? totalUsdValue : null,
    dustTokensFiltered: dustFiltered,
  };
}

/** Public helper for on-demand exposure refresh (used by the UI re-check button). */
export function invalidateExposureCache(chainId: number, address: string): void {
  cache.delete(cacheKey(chainId, address));
  invalidateHoldings(chainId, address);
}

function humanToBaseUnits(amount: string, decimals: number): string {
  if (!amount) return "0";
  const s = String(amount).trim();
  if (!/^-?\d+(\.\d+)?$/.test(s)) return "0";
  const neg = s.startsWith("-");
  const abs = neg ? s.slice(1) : s;
  const [whole, frac = ""] = abs.split(".");
  const fracPadded = (frac + "0".repeat(decimals)).slice(0, decimals);
  // BigInt has no notion of leading zeros, so concat is safe.
  const combined = (whole + fracPadded).replace(/^0+/, "") || "0";
  return (neg ? "-" : "") + combined;
}

async function withConcurrency<T>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let i = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (i < items.length) {
      const idx = i++;
      try {
        await fn(items[idx]);
      } catch {
        // swallow; per-item errors are captured into the Exposure object
      }
    }
  });
  await Promise.all(workers);
}

export interface ExposureRequest {
  chainId: number;
  address: string;
}

/**
 * Batched exposure fetch. Returns a map keyed by `${chainId}:${addressLower}`.
 * Hits the cache when fresh and only fans out RPC calls for stale entries,
 * with bounded per-chain concurrency.
 */
export async function batchExposure(reqs: ExposureRequest[]): Promise<Record<string, Exposure>> {
  const now = Date.now();
  const out: Record<string, Exposure> = {};
  const stale: ExposureRequest[] = [];
  const seenKeys = new Set<string>();

  for (const r of reqs) {
    if (!r || typeof r.chainId !== "number" || typeof r.address !== "string") continue;
    if (!/^0x[a-fA-F0-9]{40}$/.test(r.address)) continue;
    const k = cacheKey(r.chainId, r.address);
    if (seenKeys.has(k)) continue;
    seenKeys.add(k);
    const cached = cache.get(k);
    if (cached && now - cached.fetchedAt < TTL_MS) {
      out[k] = cached;
    } else {
      stale.push({ chainId: r.chainId, address: r.address });
    }
  }

  if (stale.length === 0) return out;

  // Group by chainId so we can run one bounded worker pool per chain (and not
  // overload any single QuickNode endpoint).
  const byChain = new Map<number, ExposureRequest[]>();
  for (const s of stale) {
    const arr = byChain.get(s.chainId) ?? [];
    arr.push(s);
    byChain.set(s.chainId, arr);
  }

  await Promise.all(
    Array.from(byChain.entries()).map(([, group]) =>
      withConcurrency(group, PER_CHAIN_CONCURRENCY, async (item) => {
        const exp = await fetchExposureOne(item.chainId, item.address);
        const k = cacheKey(item.chainId, item.address);
        cache.set(k, exp);
        out[k] = exp;
      }),
    ),
  );

  return out;
}
