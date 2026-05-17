// Server-side cached proxy for https://chainlist.org/rpcs.json.
//
// We hit chainlist on a background schedule (12h TTL by default) and serve
// a slimmed-down payload to the panel UI: just the bits a "quick pick an
// RPC" feature needs (chainId, name, native symbol, list of open public
// HTTP RPCs, list of WSS endpoints). This keeps the response under ~250 KB
// even with 2700+ chains and lets the UI cache it client-side.

import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CHAINLIST_URL = process.env.CHAINLIST_URL ?? "https://chainlist.org/rpcs.json";
const TTL_MS = Number(process.env.CHAINLIST_CACHE_TTL_MS ?? 12 * 60 * 60_000);
const FETCH_TIMEOUT_MS = Number(process.env.CHAINLIST_FETCH_TIMEOUT_MS ?? 15_000);

interface SlimChain {
  chainId: number;
  name: string;
  shortName: string;
  nativeSymbol: string;
  nativeDecimals: number;
  isTestnet: boolean;
  httpRpcs: string[];
  wssRpcs: string[];
  explorers: string[];
  tvl?: number;
}

type Globals = {
  __chainlistCache?: { fetchedAt: number; chains: SlimChain[]; chainsByChainId: Record<number, SlimChain> };
  __chainlistInflight?: Promise<SlimChain[]>;
};
const g = globalThis as unknown as Globals;

function isProbablyOpenRpc(url: string): boolean {
  // Filter out placeholder URLs that require an API key (e.g.
  // `https://eth-mainnet.alchemyapi.io/v2/YOUR-API-KEY`) and any RPC that
  // expects a per-user identifier inside the URL. Heuristic: refuse URLs
  // containing the words API_KEY / YOUR_ / {{...}} / ${...}, or with no
  // path segment after the hostname for known managed providers.
  const lower = url.toLowerCase();
  if (lower.includes("api_key") || lower.includes("your-")) return false;
  if (lower.includes("${") || lower.includes("{{") || lower.includes("}}")) return false;
  if (lower.includes("apikey=") || lower.includes("?key=")) return false;
  return true;
}

function pickRpcs(raw: any[]): { http: string[]; wss: string[] } {
  const http: string[] = [];
  const wss: string[] = [];
  for (const e of raw ?? []) {
    const url: string | undefined = typeof e === "string" ? e : e?.url;
    if (!url || typeof url !== "string") continue;
    if (!isProbablyOpenRpc(url)) continue;
    if (url.startsWith("wss://") || url.startsWith("ws://")) wss.push(url);
    else if (url.startsWith("https://") || url.startsWith("http://")) http.push(url);
  }
  // Dedupe (some chains list the same host twice).
  return { http: dedupe(http).slice(0, 8), wss: dedupe(wss).slice(0, 4) };
}

function dedupe(xs: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const x of xs) {
    if (seen.has(x)) continue;
    seen.add(x);
    out.push(x);
  }
  return out;
}

async function fetchChainlist(): Promise<SlimChain[]> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  try {
    const r = await fetch(CHAINLIST_URL, { signal: ac.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const raw = (await r.json()) as any[];
    const chains: SlimChain[] = [];
    for (const c of raw) {
      if (typeof c?.chainId !== "number") continue;
      const { http, wss } = pickRpcs(c.rpc);
      if (http.length === 0 && wss.length === 0) continue;
      chains.push({
        chainId: c.chainId,
        name: typeof c.name === "string" ? c.name : `chain ${c.chainId}`,
        shortName: typeof c.shortName === "string" ? c.shortName : "",
        nativeSymbol: c?.nativeCurrency?.symbol ?? "ETH",
        nativeDecimals: c?.nativeCurrency?.decimals ?? 18,
        isTestnet: Boolean(c?.isTestnet),
        httpRpcs: http,
        wssRpcs: wss,
        explorers: Array.isArray(c?.explorers)
          ? c.explorers.map((e: any) => e?.url).filter(Boolean).slice(0, 3)
          : [],
        tvl: typeof c.tvl === "number" ? c.tvl : undefined,
      });
    }
    return chains;
  } finally {
    clearTimeout(t);
  }
}

async function getCached(force = false): Promise<SlimChain[]> {
  const now = Date.now();
  if (!force && g.__chainlistCache && now - g.__chainlistCache.fetchedAt < TTL_MS) {
    return g.__chainlistCache.chains;
  }
  if (g.__chainlistInflight) return g.__chainlistInflight;
  const p = fetchChainlist()
    .then((chains) => {
      const byId: Record<number, SlimChain> = {};
      for (const c of chains) byId[c.chainId] = c;
      g.__chainlistCache = { fetchedAt: Date.now(), chains, chainsByChainId: byId };
      return chains;
    })
    .finally(() => {
      g.__chainlistInflight = undefined;
    });
  g.__chainlistInflight = p;
  return p;
}

export async function GET(req: Request) {
  const url = new URL(req.url);
  const force = url.searchParams.get("refresh") === "1";
  const chainIdParam = url.searchParams.get("chainId");
  try {
    const chains = await getCached(force);
    if (chainIdParam) {
      const id = Number(chainIdParam);
      const one = chains.find((c) => c.chainId === id) ?? null;
      return NextResponse.json({
        fetchedAt: g.__chainlistCache?.fetchedAt ?? Date.now(),
        chain: one,
      });
    }
    return NextResponse.json({
      fetchedAt: g.__chainlistCache?.fetchedAt ?? Date.now(),
      count: chains.length,
      chains,
    });
  } catch (err: any) {
    // Serve stale cache on fetch errors when possible.
    if (g.__chainlistCache) {
      return NextResponse.json(
        {
          fetchedAt: g.__chainlistCache.fetchedAt,
          count: g.__chainlistCache.chains.length,
          chains: g.__chainlistCache.chains,
          stale: true,
          error: String(err?.message ?? err),
        },
        { status: 200 },
      );
    }
    return NextResponse.json({ error: String(err?.message ?? err) }, { status: 502 });
  }
}
