import { NextResponse } from "next/server";
import { getAuditRun } from "@/src/server/audit-service";
import { rawDb } from "@/src/db/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type FindingRow = {
  id: string;
  ruleId: string;
  severity: string;
  title: string | null;
  source: string | null;
  simulationStatus: string | null;
  simulationVerdict: string | null;
  simulationEngine: string | null;
  simulationEvidenceJson: string | null;
};

export async function GET(_req: Request, { params }: { params: Promise<{ runId: string }> }) {
  const { runId } = await params;
  const row = getAuditRun(runId);
  if (!row) return NextResponse.json({ error: "not found" }, { status: 404 });

  // (1) Findings attached to THIS run_id — the canonical, static-analyzer
  //     output for this manual audit plus any sidecar finding the worker
  //     materialised under this run.
  const rawFindings = rawDb
    .prepare(
      `SELECT id, rule_id as ruleId, severity, title, source,
              simulation_status as simulationStatus,
              simulation_verdict as simulationVerdict,
              simulation_engine as simulationEngine,
              simulation_evidence_json as simulationEvidenceJson
       FROM findings WHERE run_id = ? ORDER BY discovered_at DESC`,
    )
    .all(runId) as FindingRow[];

  // (2) Bytecode-keyed sidecar findings. The economic-attack sidecar is
  //     materialised ONCE per (chain,address,rule); subsequent re-uploads
  //     of the same bytecode hit the idempotency check and skip insertion.
  //     Without this query, those re-uploads would render a confusing
  //     "no sidecar finding" view even though the system DID detect the
  //     bug on a previous run. So we also surface sidecar findings whose
  //     bytecode_hash or contract_address matches this run's target,
  //     deduplicated against (1) above.
  const haveIds = new Set(rawFindings.map((f) => f.id));
  let extras: FindingRow[] = [];
  const auditRow = rawDb
    .prepare(`SELECT bytecode_hash AS bh, contract_address AS addr, chain_id AS cid FROM audit_runs WHERE id = ?`)
    .get(runId) as { bh: string | null; addr: string | null; cid: number | null } | undefined;
  if (auditRow && (auditRow.bh || auditRow.addr)) {
    const clauses: string[] = [];
    const params2: any[] = [];
    if (auditRow.bh) {
      clauses.push("bytecode_hash = ?");
      params2.push(auditRow.bh);
    }
    if (auditRow.addr && auditRow.cid != null) {
      clauses.push("(lower(contract_address) = lower(?) AND chain_id = ?)");
      params2.push(auditRow.addr, auditRow.cid);
    }
    const where = clauses.join(" OR ");
    extras = rawDb
      .prepare(
        `SELECT id, rule_id as ruleId, severity, title, source,
                simulation_status as simulationStatus,
                simulation_verdict as simulationVerdict,
                simulation_engine as simulationEngine,
                simulation_evidence_json as simulationEvidenceJson
         FROM findings
         WHERE source LIKE 'sidecar-%' AND (${where})
         ORDER BY discovered_at DESC`,
      )
      .all(...params2) as FindingRow[];
    extras = extras.filter((f) => !haveIds.has(f.id));
  }

  const all = [...rawFindings, ...extras];
  const findings = all.map((f) => {
    let attackerKind: "any" | "owner" | null = null;
    if (f.simulationEvidenceJson) {
      try {
        const ev = JSON.parse(f.simulationEvidenceJson);
        if (ev?.attackerKind === "any" || ev?.attackerKind === "owner") attackerKind = ev.attackerKind;
      } catch {
        /* ignore */
      }
    }
    const { simulationEvidenceJson: _unused, ...rest } = f;
    void _unused;
    return { ...rest, simulationAttackerKind: attackerKind };
  });

  return NextResponse.json({
    ...row,
    findings,
    sidecarExtrasCount: extras.length,
  });
}
