// POST /api/scan/uninitialized-proxies
//
// The #1 historically profitable vulnerability class for rescue bots:
// UUPS/Transparent proxy implementations that were never initialized.
// Anyone can call initialize() and take ownership, then upgrade or drain.
//
// Strategy:
//   1. Query recent proxy deployment events (EIP-1967 Upgraded logs)
//   2. For each proxy, resolve the implementation address
//   3. Call initialize() variants on the IMPLEMENTATION (not the proxy)
//   4. If it doesn't revert → the implementation is uninitialized → exploitable
//
// This is how the Wormhole bridge ($326M) was nearly drained and how
// multiple smaller protocols have been exploited.

import { NextResponse } from "next/server";
import { rawDb } from "@/src/db/client";
import { bootOnce } from "@/src/server/boot";
import { readChainsRaw } from "@/src/server/chains-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 600;

const EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const UPGRADED_TOPIC = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b";

// Common initialize selectors
const INIT_SELECTORS = [
  { sel: "0x8129fc1c", name: "initialize()" },
  { sel: "0xc4d66de8", name: "initialize(address)" },
  { sel: "0xf8c8765e", name: "initialize(address,address,address,address)" },
  { sel: "0x485cc955", name: "initialize(address,address)" },
  { sel: "0x1459457a", name: "initialize(address,address,address,address,address)" },
  { sel: "0xfe4b84df", name: "initialize(uint256)" },
];

interface ProxyTarget {
  proxyAddress: string;
  implAddress: string;
  chainId: number;
  rpcUrl: string;
}

export async function POST(req: Request) {
  bootOnce();
  let body: any = {};
  try { body = await req.json(); } catch {}
  const chainIds: number[] = body?.chainIds ?? [1, 56, 137, 42161, 10, 8453];
  const lookbackBlocks = body?.lookbackBlocks ?? 50_000;
  const limit = Math.min(body?.limit ?? 50, 200);

  const chains = readChainsRaw();
  const results: Array<{
    proxy: string;
    impl: string;
    chainId: number;
    initialized: boolean;
    vulnerable: boolean;
    initSelector?: string;
    error?: string;
  }> = [];

  for (const chainId of chainIds) {
    const chain = chains.find((c: any) => c.chainId === chainId || c.slug === chainSlugForId(chainId));
    const rpcUrl = (chain as any)?.rpcHttpUrl;
    if (!rpcUrl) continue;

    try {
      const proxies = await findRecentProxies(rpcUrl, chainId, lookbackBlocks, limit);

      for (const p of proxies) {
        try {
          const check = await checkInitialization(p);
          results.push({
            proxy: p.proxyAddress,
            impl: p.implAddress,
            chainId,
            initialized: !check.vulnerable,
            vulnerable: check.vulnerable,
            initSelector: check.selector,
          });

          if (check.vulnerable) {
            void notifyUninitializedProxy(p, check.selector!);
          }
        } catch (e: any) {
          results.push({
            proxy: p.proxyAddress,
            impl: p.implAddress,
            chainId,
            initialized: true,
            vulnerable: false,
            error: String(e?.message ?? e).slice(0, 200),
          });
        }
      }
    } catch (e: any) {
      results.push({
        proxy: "scan-failed",
        impl: "",
        chainId,
        initialized: false,
        vulnerable: false,
        error: String(e?.message ?? e).slice(0, 200),
      });
    }
  }

  const vulnerable = results.filter((r) => r.vulnerable);
  return NextResponse.json({
    ok: true,
    scanned: results.length,
    vulnerable: vulnerable.length,
    results,
  });
}

async function findRecentProxies(
  rpcUrl: string,
  chainId: number,
  lookback: number,
  limit: number,
): Promise<ProxyTarget[]> {
  const latestHex = await rpcCall<string>(rpcUrl, "eth_blockNumber", []);
  const latest = BigInt(latestHex);
  const from = latest > BigInt(lookback) ? latest - BigInt(lookback) : 0n;

  const proxies: ProxyTarget[] = [];
  const seen = new Set<string>();
  const BATCH = 2000n;

  for (let cursor = from; cursor < latest && proxies.length < limit; cursor += BATCH) {
    const end = cursor + BATCH > latest ? latest : cursor + BATCH;
    let logs: any[];
    try {
      logs = await rpcCall<any[]>(rpcUrl, "eth_getLogs", [
        {
          fromBlock: "0x" + cursor.toString(16),
          toBlock: "0x" + end.toString(16),
          topics: [UPGRADED_TOPIC],
        },
      ]);
    } catch {
      continue;
    }

    for (const log of logs) {
      const proxyAddr = log.address?.toLowerCase();
      if (!proxyAddr || seen.has(proxyAddr)) continue;
      seen.add(proxyAddr);

      try {
        const implSlot = await rpcCall<string>(rpcUrl, "eth_getStorageAt", [
          proxyAddr,
          EIP1967_IMPL_SLOT,
          "latest",
        ]);
        if (!implSlot || implSlot === "0x" + "0".repeat(64)) continue;
        const implAddr = "0x" + implSlot.slice(-40).toLowerCase();
        if (implAddr === "0x" + "0".repeat(40)) continue;

        proxies.push({ proxyAddress: proxyAddr, implAddress: implAddr, chainId, rpcUrl });
        if (proxies.length >= limit) break;
      } catch {
        continue;
      }
    }
  }

  return proxies;
}

async function checkInitialization(
  target: ProxyTarget,
): Promise<{ vulnerable: boolean; selector?: string }> {
  // Try calling initialize() on the IMPLEMENTATION contract directly
  // If it doesn't revert, the implementation is uninitialized
  for (const init of INIT_SELECTORS) {
    const attackerAddr = "0x00FFB41480e264Df6629A2b0A0BCA5Dc1f4D00Ff";
    let data = init.sel;
    // Pad with attacker address for selectors that take address args
    const argCount = (init.name.match(/address/g) || []).length;
    for (let i = 0; i < argCount; i++) {
      data += attackerAddr.slice(2).toLowerCase().padStart(64, "0");
    }
    const uintCount = (init.name.match(/uint256/g) || []).length;
    for (let i = 0; i < uintCount; i++) {
      data += "0".repeat(63) + "1";
    }

    try {
      // eth_call (read-only) to see if it reverts
      await rpcCall<string>(target.rpcUrl, "eth_call", [
        { to: target.implAddress, data, from: attackerAddr },
        "latest",
      ]);
      // Didn't revert — this implementation is uninitialized!
      return { vulnerable: true, selector: init.name };
    } catch {
      // Reverted — this selector is either not present or already initialized
      continue;
    }
  }

  return { vulnerable: false };
}

async function rpcCall<T>(url: string, method: string, params: unknown[]): Promise<T> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 15_000);
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    if (j.error) throw new Error(j.error.message ?? JSON.stringify(j.error));
    return j.result;
  } finally {
    clearTimeout(t);
  }
}

function chainSlugForId(chainId: number): string {
  const map: Record<number, string> = {
    1: "eth-mainnet", 56: "bsc-mainnet", 137: "polygon-mainnet",
    43114: "avalanche-mainnet", 42161: "arbitrum-mainnet", 10: "optimism-mainnet",
    8453: "base-mainnet", 100: "gnosis-mainnet",
  };
  return map[chainId] ?? `chain-${chainId}`;
}

async function notifyUninitializedProxy(target: ProxyTarget, selector: string): Promise<void> {
  try {
    const { tgBotEnabled } = await import("@/src/server/rescue/tg-bot");
    if (!tgBotEnabled()) return;
    const TG_API_BASE = "https://api.telegram.org/bot";
    const token = process.env.TG_BOT_TOKEN ?? "";
    const chatId = process.env.TG_CHAT_ID ?? "";
    if (!token || !chatId) return;
    const text = [
      `*UNINITIALIZED PROXY FOUND*`,
      `chain: \`${target.chainId}\``,
      `proxy: \`${target.proxyAddress}\``,
      `impl:  \`${target.implAddress}\``,
      `vulnerable selector: \`${selector}\``,
      ``,
      `This implementation can be taken over by calling ${selector} directly.`,
      `Check proxy TVL and act fast.`,
    ].join("\n");
    await fetch(`${TG_API_BASE}${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: "Markdown", disable_web_page_preview: true }),
    });
  } catch {}
}
