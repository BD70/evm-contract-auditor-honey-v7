import { NextResponse } from "next/server";
import { bootOnce } from "@/src/server/boot";
import { simWorker, runEconomicSidecar } from "@/src/server/sim/worker";
import { anvilPool } from "@/src/server/sim/anvil-pool";
import {
  verifyFinding,
  canVerifyRule,
  engineForRule,
  SUPPORTED_RULES,
  VERIFIERS,
} from "@/src/server/sim/exploits";
import { rawDb } from "@/src/db/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  bootOnce();
  const anvilOk = await anvilPool.isAvailable();
  const breakdown = rawDb
    .prepare(
      `SELECT COALESCE(simulation_status, 'unverified') as status, COUNT(*) as n
       FROM findings GROUP BY 1 ORDER BY 2 DESC`,
    )
    .all() as { status: string; n: number }[];
  const cacheSize = (rawDb.prepare(`SELECT COUNT(*) as n FROM simulation_cache`).get() as { n: number }).n;
  return NextResponse.json({
    verifiers: VERIFIERS.map((v) => ({ id: v.id, version: v.version, rules: v.rules })),
    supportedRules: SUPPORTED_RULES,
    anvilAvailable: anvilOk,
    worker: simWorker.getStats(),
    findingsByStatus: breakdown,
    cacheRows: cacheSize,
  });
}

/** POST { findingId } -> run verification immediately and return verdict. */
export async function POST(req: Request) {
  bootOnce();
  let body: any;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid JSON" }, { status: 400 });
  }
  const findingId = String(body?.findingId ?? "");
  if (!findingId) return NextResponse.json({ error: "findingId required" }, { status: 400 });
  const row = rawDb
    .prepare(
      `SELECT id, rule_id as ruleId, contract_address as contractAddress, chain_id as chainId, bytecode_hash as bytecodeHash
       FROM findings WHERE id = ?`,
    )
    .get(findingId) as
    | { id: string; ruleId: string; contractAddress: string | null; chainId: number | null; bytecodeHash: string | null }
    | undefined;
  if (!row) return NextResponse.json({ error: "finding not found" }, { status: 404 });
  if (!canVerifyRule(row.ruleId)) {
    return NextResponse.json({ status: "skipped", reason: "rule not supported by verifier" });
  }
  if (!row.contractAddress || row.chainId == null) {
    return NextResponse.json({ status: "skipped", reason: "missing contract address / chainId" });
  }
  // Load raw finding JSON for witness selector extraction
  let evidence: unknown;
  try {
    const raw = rawDb.prepare("SELECT raw_json FROM findings WHERE id = ?").get(findingId) as { raw_json?: string } | undefined;
    if (raw?.raw_json) evidence = JSON.parse(raw.raw_json);
  } catch {}
  const result = await verifyFinding({
    chainId: row.chainId,
    contractAddress: row.contractAddress,
    ruleId: row.ruleId,
    evidence,
  });
  const engineInfo = engineForRule(row.ruleId) ?? { engine: result.engine, version: result.engineVersion };
  rawDb
    .prepare(
      `UPDATE findings
       SET simulation_status = ?,
           simulation_verdict = ?,
           simulation_evidence_json = ?,
           simulation_engine = ?,
           simulated_at = ?
       WHERE id = ?`,
    )
    .run(
      result.status,
      result.verdict ?? null,
      JSON.stringify(result.evidence),
      `${engineInfo.engine}@${engineInfo.version}`,
      Date.now(),
      findingId,
    );
  if (row.bytecodeHash) {
    try {
      rawDb
        .prepare(
          `INSERT OR REPLACE INTO simulation_cache
             (bytecode_hash, rule_id, engine, engine_version, status, verdict, evidence_json, simulated_at, duration_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          row.bytecodeHash,
          row.ruleId,
          engineInfo.engine,
          engineInfo.version,
          result.status,
          result.verdict ?? null,
          JSON.stringify(result.evidence),
          Date.now(),
          result.durationMs,
        );
    } catch {}
  }

  // Sidecar pass: also run the economic-attack verifier (different bug class
  // that often co-exists with the primary rule's surface). Skip if the primary
  // verifier IS the economic-attack one to avoid recursion. Errors here are
  // silent — the on-demand verdict was already computed; sidecar is bonus.
  let sidecar: { ran: boolean; status?: string; findingId?: string; cached?: boolean } | null = null;
  if (engineInfo.engine !== "anvil-fork-economic") {
    try {
      sidecar = await runEconomicSidecar({
        chainId: row.chainId!,
        contractAddress: row.contractAddress!,
        bytecodeHash: row.bytecodeHash,
        sourceFindingId: row.id,
      });
    } catch (err) {
      console.warn("[api/simulation] sidecar failed", err);
    }
  }

  // Rescue-prove pass: when the primary verifier said "verified" and the
  // rule family is one we know how to drain (arbitrary-call / selfdestruct),
  // run the rescue-prove module synchronously so the API response carries
  // the PoE summary. Best-effort — never fails the simulation result.
  let poe: { verdict: string; rescuedAssets: number; totalRescuedUsd: number | null; attemptId: string } | null = null;
  const rescueEligible =
    result.status === "verified" &&
    (row.ruleId.startsWith("call.") ||
      row.ruleId.startsWith("control.unguarded_selfdestruct") ||
      row.ruleId.startsWith("init.") ||
      row.ruleId.startsWith("economic.") ||
      row.ruleId.startsWith("proxy.") ||
      row.ruleId.startsWith("bridge.") ||
      row.ruleId.startsWith("oracle.") ||
      row.ruleId.startsWith("logic.") ||
      row.ruleId.startsWith("access.") ||
      row.ruleId === "defi.erc4626.withdraw.missing_caller_authorization") &&
    String(process.env.RESCUE_PROVE_ENABLED ?? "true").toLowerCase() !== "false";
  if (rescueEligible) {
    try {
      const { rescueProve } = await import("@/src/server/sim/rescue-prove");
      const artifact = await rescueProve({
        findingId: findingId,
        chainId: row.chainId!,
        contractAddress: row.contractAddress!,
        ruleId: row.ruleId,
        evidence: result.evidence,
      });
      poe = {
        verdict: artifact.verdict,
        rescuedAssets: artifact.rescuedAssets.length,
        totalRescuedUsd: artifact.totalRescuedUsd,
        attemptId: artifact.attemptId,
      };
    } catch (err) {
      console.warn("[api/simulation] rescue-prove failed", err);
    }
  }

  return NextResponse.json({ ...result, sidecar, poe });
}
