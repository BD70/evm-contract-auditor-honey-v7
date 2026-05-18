// POST /api/scan/historical
//
// Deep-scan existing high-value contracts for vulnerabilities that others
// missed. Unlike the runner (which watches new deployments), this endpoint
// audits contracts that have been live for months/years.
//
// Body:
//   {
//     addresses?: Array<{ address: string; chainId: number }>,
//     fetchTopTvl?: boolean,       // pull top DeFi contracts from DeFi Llama
//     tvlMinUsd?: number,          // min TVL filter (default $50k)
//     limit?: number,              // max contracts to scan (default 20)
//     skipExisting?: boolean,      // skip addresses already in findings DB
//     runPoE?: boolean,            // also run rescue-prove on any findings
//   }

import { NextResponse } from "next/server";
import { rawDb } from "@/src/db/client";
import { bootOnce } from "@/src/server/boot";
import { startAudit } from "@/src/server/audit-service";
import { rescueProve } from "@/src/server/sim/rescue-prove";
import { readChainsRaw } from "@/src/server/chains-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 600;

interface Target {
  address: string;
  chainId: number;
  name?: string;
  tvl?: number;
}

export async function POST(req: Request) {
  bootOnce();
  let body: any = {};
  try { body = await req.json(); } catch {}
  const limit = Math.min(body?.limit ?? 20, 100);
  const skipExisting = body?.skipExisting !== false;
  const runPoE = body?.runPoE !== false;
  const tvlMinUsd = body?.tvlMinUsd ?? 50_000;
  const fetchTopTvl = !!body?.fetchTopTvl;

  let targets: Target[] = [];

  if (Array.isArray(body?.addresses)) {
    for (const a of body.addresses) {
      if (a?.address && a?.chainId) {
        targets.push({ address: a.address.toLowerCase(), chainId: a.chainId, name: a.name });
      }
    }
  }

  if (fetchTopTvl) {
    try {
      const defiTargets = await fetchDefiLlamaTargets(tvlMinUsd, limit * 3);
      targets.push(...defiTargets);
    } catch (e: any) {
      return NextResponse.json({ error: `DeFi Llama fetch failed: ${e?.message}` }, { status: 502 });
    }
  }

  if (targets.length === 0) {
    return NextResponse.json(
      { error: "provide addresses[] or set fetchTopTvl=true" },
      { status: 400 },
    );
  }

  // Deduplicate
  const seen = new Set<string>();
  targets = targets.filter((t) => {
    const key = `${t.chainId}:${t.address.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Skip addresses already scanned
  if (skipExisting) {
    const existing = new Set<string>();
    const rows = rawDb
      .prepare("SELECT LOWER(contract_address) || ':' || chain_id AS k FROM findings WHERE contract_address IS NOT NULL")
      .all() as any[];
    for (const r of rows) existing.add(r.k);
    targets = targets.filter((t) => !existing.has(`${t.address.toLowerCase()}:${t.chainId}`));
  }

  targets = targets.slice(0, limit);
  if (targets.length === 0) {
    return NextResponse.json({ ok: true, scanned: 0, message: "all targets already scanned" });
  }

  const chains = readChainsRaw();

  const results: Array<{
    address: string;
    chainId: number;
    name?: string;
    tvl?: number;
    auditOk: boolean;
    findingCount: number;
    findings: string[];
    poeVerdict?: string;
    poeRescuedUsd?: number | null;
    error?: string;
    durationMs: number;
  }> = [];

  for (const target of targets) {
    const t0 = Date.now();
    try {
      const chain = chains.find((c: any) =>
        (c.chainId === target.chainId) ||
        (c.slug === chainSlugForId(target.chainId))
      );
      const rpcUrl = (chain as any)?.rpcHttpUrl;
      if (!rpcUrl) {
        results.push({
          address: target.address,
          chainId: target.chainId,
          name: target.name,
          tvl: target.tvl,
          auditOk: false,
          findingCount: 0,
          findings: [],
          error: `no RPC configured for chainId ${target.chainId}`,
          durationMs: Date.now() - t0,
        });
        continue;
      }

      const code = await rpcGetCode(rpcUrl, target.address);
      if (!code || code === "0x" || code === "0x0") {
        results.push({
          address: target.address,
          chainId: target.chainId,
          name: target.name,
          tvl: target.tvl,
          auditOk: false,
          findingCount: 0,
          findings: [],
          error: "no code at address (EOA or self-destructed)",
          durationMs: Date.now() - t0,
        });
        continue;
      }

      const hex = code.startsWith("0x") ? code.slice(2) : code;
      const { runId } = await startAudit({
        kind: "manual_address",
        bytecode: hex,
        address: target.address,
        chainId: target.chainId,
        rpcUrl,
        inputSummary: `historical-scan: ${target.name ?? target.address}`,
      });

      // Wait for audit to complete (poll DB)
      const auditResult = await waitForAuditRun(runId, 120_000);

      const findingRows = rawDb
        .prepare(
          "SELECT id, rule_id, simulation_status FROM findings WHERE run_id = ? AND contract_address = ?",
        )
        .all(runId, target.address) as any[];

      const findingIds = findingRows.map((r: any) => r.id);

      let poeVerdict: string | undefined;
      let poeRescuedUsd: number | null | undefined;

      // Run PoE on findings if requested
      if (runPoE && findingRows.length > 0) {
        for (const f of findingRows) {
          try {
            const poe = await rescueProve({
              findingId: f.id,
              chainId: target.chainId,
              contractAddress: target.address,
              ruleId: f.rule_id,
            });
            if (
              poe.verdict === "true_positive_drained" ||
              poe.verdict === "true_positive_partial" ||
              poe.verdict === "victim_approval_rescue"
            ) {
              poeVerdict = poe.verdict;
              poeRescuedUsd = poe.totalRescuedUsd;
              // Notify TG about the hit
              void notifyHistoricalHit(target, poe);
              break;
            }
            if (!poeVerdict) {
              poeVerdict = poe.verdict;
              poeRescuedUsd = poe.totalRescuedUsd;
            }
          } catch {}
        }
      }

      results.push({
        address: target.address,
        chainId: target.chainId,
        name: target.name,
        tvl: target.tvl,
        auditOk: auditResult.ok,
        findingCount: findingRows.length,
        findings: findingRows.map((r: any) => `${r.rule_id} (${r.simulation_status ?? "pending"})`),
        poeVerdict,
        poeRescuedUsd,
        durationMs: Date.now() - t0,
      });
    } catch (e: any) {
      results.push({
        address: target.address,
        chainId: target.chainId,
        name: target.name,
        tvl: target.tvl,
        auditOk: false,
        findingCount: 0,
        findings: [],
        error: String(e?.message ?? e).slice(0, 300),
        durationMs: Date.now() - t0,
      });
    }
  }

  const hits = results.filter(
    (r) =>
      r.poeVerdict === "true_positive_drained" ||
      r.poeVerdict === "true_positive_partial" ||
      r.poeVerdict === "victim_approval_rescue",
  );

  return NextResponse.json({
    ok: true,
    scanned: results.length,
    totalFindings: results.reduce((a, r) => a + r.findingCount, 0),
    hits: hits.length,
    results,
  });
}

// ── helpers ──────────────────────────────────────────────────────────────

async function fetchDefiLlamaTargets(minTvl: number, limit: number): Promise<Target[]> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 30_000);
  try {
    const r = await fetch("https://api.llama.fi/protocols", { signal: ac.signal });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const protocols: any[] = await r.json();

    const targets: Target[] = [];
    const chainIdMap: Record<string, number> = {
      ethereum: 1, bsc: 56, polygon: 137, avalanche: 43114,
      arbitrum: 42161, optimism: 10, base: 8453, gnosis: 100,
    };

    for (const p of protocols) {
      if ((p.tvl ?? 0) < minTvl) continue;
      if (!p.address || typeof p.address !== "string") continue;

      const chain = String(p.chain ?? "").toLowerCase();
      const chainId = chainIdMap[chain];
      if (!chainId) continue;

      targets.push({
        address: p.address.toLowerCase(),
        chainId,
        name: p.name ?? p.slug,
        tvl: p.tvl,
      });

      if (targets.length >= limit) break;
    }
    return targets;
  } finally {
    clearTimeout(t);
  }
}

function chainSlugForId(chainId: number): string {
  const map: Record<number, string> = {
    1: "eth-mainnet", 56: "bsc-mainnet", 137: "polygon-mainnet",
    43114: "avalanche-mainnet", 42161: "arbitrum-mainnet", 10: "optimism-mainnet",
    8453: "base-mainnet", 100: "gnosis-mainnet", 59144: "linea-mainnet",
    324: "zksync-mainnet", 81457: "blast-mainnet",
  };
  return map[chainId] ?? `chain-${chainId}`;
}

async function rpcGetCode(rpcUrl: string, address: string): Promise<string> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 15_000);
  try {
    const r = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_getCode", params: [address, "latest"] }),
      signal: ac.signal,
    });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const j: any = await r.json();
    if (j.error) throw new Error(j.error.message ?? JSON.stringify(j.error));
    return j.result;
  } finally {
    clearTimeout(timer);
  }
}

async function waitForAuditRun(runId: string, timeoutMs: number): Promise<{ ok: boolean }> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const row = rawDb
      .prepare("SELECT status FROM audit_runs WHERE id = ?")
      .get(runId) as any;
    if (row?.status === "completed" || row?.status === "ingested") return { ok: true };
    if (row?.status === "failed" || row?.status === "error") return { ok: false };
    await new Promise((r) => setTimeout(r, 2_000));
  }
  return { ok: false };
}

async function notifyHistoricalHit(target: Target, poe: any): Promise<void> {
  try {
    const { notifyPoe } = await import("@/src/server/rescue/tg-bot");
    await notifyPoe({
      findingId: poe.findingId,
      chainId: target.chainId,
      contractAddress: target.address,
      verdict: `HISTORICAL HIT: ${poe.verdict}`,
      totalRescuedUsd: poe.totalRescuedUsd,
      rescuedCount: poe.rescuedAssets?.length ?? 0,
      escrow: poe.escrowAddress ?? "0x00ff…00ff",
      blockNumber: poe.blockNumber,
    });
  } catch {}
}
