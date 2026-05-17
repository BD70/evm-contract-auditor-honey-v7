
import crypto from "node:crypto";
import { rawDb } from "@/src/db/client";
import { eventBus, type FindingEvent } from "./event-bus";
import { exposureSurfaceForRule } from "./sim/rule-surface";

type Source = "runner" | "manual";

export interface IngestContext {
  source: Source;
  runId?: string | null;
  chainId?: number | null;
  blockNumber?: number | null;
  txHash?: string | null;
  contractAddress?: string | null;
  bytecodeHash?: string | null;
  discoveredAt?: number;
}

function findingId(rawFinding: any, ctx: IngestContext): string {
  const ruleId = rawFinding?.rule_id ?? "unknown";
  const selectors = Array.isArray(rawFinding?.affected_functions)
    ? rawFinding.affected_functions.map((f: any) => f.selector ?? f.id ?? "").join(",")
    : "";
  const fnSelector = rawFinding?.function?.selector ?? "";
  const key = [
    ctx.source,
    ctx.bytecodeHash ?? "",
    ctx.contractAddress ?? "",
    ctx.txHash ?? "",
    ruleId,
    fnSelector,
    selectors,
    ctx.runId ?? "",
  ].join("|");
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 32);
}

export function ingestApiJson(apiJson: any, ctx: IngestContext): { ids: string[] } {
  const findings = Array.isArray(apiJson?.findings) ? apiJson.findings : [];
  const ids: string[] = [];
  const now = ctx.discoveredAt ?? Date.now();
  const insert = rawDb.prepare(`
    INSERT OR REPLACE INTO findings (
      id, run_id, rule_id, internal_name, severity, status, confidence, title, category,
      bytecode_hash, contract_address, chain_id, block_number, tx_hash, discovered_at, source,
      judged_by, judge_verdict, judge_rationale, judge_confidence, affected_functions_json, raw_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const f of findings) {
    const id = findingId(f, ctx);
    const affected = f.affected_functions ?? (f.function ? [f.function] : []);
    insert.run(
      id,
      ctx.runId ?? null,
      f.rule_id ?? "unknown",
      f.internal_name ?? null,
      f.severity ?? "unknown",
      f.status ?? null,
      f.confidence ?? null,
      f.title ?? f.reporting?.user_summary ?? null,
      f.category ?? null,
      ctx.bytecodeHash ?? f.bytecode_hash ?? null,
      ctx.contractAddress ?? null,
      ctx.chainId ?? null,
      ctx.blockNumber ?? null,
      ctx.txHash ?? null,
      now,
      ctx.source,
      f.judged_by ?? null,
      f.judge_verdict ?? null,
      f.judge_rationale ?? null,
      f.judge_confidence != null ? String(f.judge_confidence) : null,
      JSON.stringify(affected),
      JSON.stringify(f),
    );
    ids.push(id);
    const evt: FindingEvent = {
      id,
      ruleId: f.rule_id ?? "unknown",
      severity: f.severity ?? "unknown",
      title: f.title ?? f.reporting?.user_summary ?? null,
      source: ctx.source,
      discoveredAt: now,
    };
    eventBus.emit("findings:new", evt);
  }
  return { ids };
}

export interface DeploymentInput {
  chainId?: number | null;
  blockNumber?: number | null;
  contractAddress?: string | null;
  txHash: string;
  deployer?: string | null;
  bytecodeHash?: string | null;
  proxyKind?: string | null;
  proxyTarget?: string | null;
  detectedAt?: number;
  auditStatus: "pending" | "ok" | "failed" | "cached";
  runnerEventId?: string | null;
  rawJson?: any;
}

export function upsertDeployment(d: DeploymentInput) {
  const id = `${d.chainId ?? 0}:${d.txHash}:${d.contractAddress ?? ""}`;
  rawDb
    .prepare(
      `INSERT OR REPLACE INTO deployments (
        id, chain_id, block_number, contract_address, tx_hash, deployer, bytecode_hash,
        proxy_kind, proxy_target, detected_at, audit_status, runner_event_id, raw_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      id,
      d.chainId ?? null,
      d.blockNumber ?? null,
      d.contractAddress ?? null,
      d.txHash,
      d.deployer ?? null,
      d.bytecodeHash ?? null,
      d.proxyKind ?? null,
      d.proxyTarget ?? null,
      d.detectedAt ?? Date.now(),
      d.auditStatus,
      d.runnerEventId ?? null,
      d.rawJson ? JSON.stringify(d.rawJson) : null,
    );
}

export interface FindingsQuery {
  limit?: number;
  offset?: number;
  severity?: string[];
  source?: Source;
  ruleId?: string;
  search?: string;
  chainId?: number;
  status?: string;
  since?: number;
  /** filter by simulation_status; pass "unverified" to match NULL/pending */
  simStatus?: string[];
}

export function queryFindings(q: FindingsQuery) {
  const where: string[] = [];
  const params: any[] = [];
  if (q.severity?.length) {
    where.push(`f.severity IN (${q.severity.map(() => "?").join(",")})`);
    params.push(...q.severity);
  }
  if (q.source) {
    where.push("f.source = ?");
    params.push(q.source);
  }
  if (q.ruleId) {
    where.push("f.rule_id = ?");
    params.push(q.ruleId);
  }
  if (q.chainId != null) {
    where.push("f.chain_id = ?");
    params.push(q.chainId);
  }
  if (q.status) {
    where.push("f.status = ?");
    params.push(q.status);
  }
  if (q.since != null) {
    where.push("f.discovered_at >= ?");
    params.push(q.since);
  }
  if (q.search) {
    where.push("(f.title LIKE ? OR f.rule_id LIKE ? OR f.contract_address LIKE ? OR f.bytecode_hash LIKE ?)");
    const s = `%${q.search}%`;
    params.push(s, s, s, s);
  }
  if (q.simStatus?.length) {
    const wantsUnverified = q.simStatus.includes("unverified") || q.simStatus.includes("pending");
    const concrete = q.simStatus.filter((s) => s !== "unverified" && s !== "pending");
    const clauses: string[] = [];
    if (wantsUnverified) clauses.push("f.simulation_status IS NULL");
    if (concrete.length) {
      clauses.push(`f.simulation_status IN (${concrete.map(() => "?").join(",")})`);
      params.push(...concrete);
    }
    if (clauses.length) where.push(`(${clauses.join(" OR ")})`);
  }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const limit = Math.max(1, Math.min(500, q.limit ?? 50));
  const offset = Math.max(0, q.offset ?? 0);
  const rows = rawDb
    .prepare(
      `SELECT f.id, f.run_id as runId, f.rule_id as ruleId, f.severity, f.status, f.confidence, f.title, f.category,
              f.bytecode_hash as bytecodeHash, f.contract_address as contractAddress, f.chain_id as chainId,
              f.block_number as blockNumber, f.tx_hash as txHash, f.discovered_at as discoveredAt, f.source,
              f.judged_by as judgedBy, f.judge_verdict as judgeVerdict,
              f.simulation_status as simulationStatus, f.simulation_verdict as simulationVerdict,
              f.simulation_engine as simulationEngine, f.simulated_at as simulatedAt,
              f.simulation_evidence_json as simulationEvidenceJson,
              poe.verdict as poeVerdict,
              poe.rescued_usd as poeRescuedUsd,
              poe.attacker_kind as poeAttackerKind
       FROM findings f
       LEFT JOIN (
         SELECT finding_id, verdict, rescued_usd, attacker_kind,
                ROW_NUMBER() OVER (PARTITION BY finding_id ORDER BY created_at DESC) as rn
         FROM proofs_of_exploit
       ) poe ON poe.finding_id = f.id AND poe.rn = 1
       ${clause}
       ORDER BY f.discovered_at DESC LIMIT ? OFFSET ?`,
    )
    .all(...params, limit, offset) as Array<Record<string, unknown>>;

  // Derive lightweight UI-friendly fields from the evidence JSON so the
  // frontend doesn't re-parse for every row. Fields:
  //   simulationAttackerKind : "any" | "owner" | null
  //   ruleExposureSurface    : "native" | "token" | "both" | "none"
  for (const r of rows) {
    const raw = r.simulationEvidenceJson as string | null;
    let attackerKind: "any" | "owner" | null = null;
    let centralizationRisk = false;
    if (raw) {
      try {
        const ev = JSON.parse(raw);
        if (ev && (ev.attackerKind === "any" || ev.attackerKind === "owner")) {
          attackerKind = ev.attackerKind;
        }
        if (ev?.centralizationRisk === true) centralizationRisk = true;
      } catch {
        /* ignore — evidence JSON malformed */
      }
    }
    r.simulationAttackerKind = attackerKind;
    r.simulationCentralizationRisk = centralizationRisk;
    r.ruleExposureSurface = exposureSurfaceForRule(String(r.ruleId ?? ""));
    // Don't ship the entire evidence blob in the listing; it can be huge.
    delete r.simulationEvidenceJson;
  }

  const totalRow = rawDb.prepare(`SELECT COUNT(*) as n FROM findings f ${clause}`).get(...params) as { n: number };
  return { rows, total: totalRow.n, limit, offset };
}

export function getFinding(id: string): any | null {
  const row = rawDb.prepare(`SELECT * FROM findings WHERE id = ?`).get(id) as any;
  if (!row) return null;
  const poe = rawDb
    .prepare(
      `SELECT verdict, rescued_usd, attacker_kind FROM proofs_of_exploit
       WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1`,
    )
    .get(id) as { verdict: string; rescued_usd: number | null; attacker_kind: string } | undefined;
  return {
    ...row,
    raw: row.raw_json ? JSON.parse(row.raw_json) : null,
    affectedFunctions: row.affected_functions_json ? JSON.parse(row.affected_functions_json) : [],
    poe_verdict: poe?.verdict ?? null,
    poe_rescued_usd: poe?.rescued_usd ?? null,
    poe_attacker_kind: poe?.attacker_kind ?? null,
  };
}

export function severityCounts(sinceMs: number): Record<string, number> {
  const rows = rawDb
    .prepare(`SELECT severity, COUNT(*) as n FROM findings WHERE discovered_at >= ? GROUP BY severity`)
    .all(sinceMs) as { severity: string; n: number }[];
  return Object.fromEntries(rows.map((r) => [r.severity, r.n]));
}

export function recentFindings(limit = 10) {
  return rawDb
    .prepare(
      `SELECT id, rule_id as ruleId, severity, title, source, discovered_at as discoveredAt, contract_address as contractAddress
       FROM findings ORDER BY discovered_at DESC LIMIT ?`,
    )
    .all(limit);
}

export function listAuditRuns(limit = 50) {
  return rawDb
    .prepare(
      `SELECT id, kind, input_summary as inputSummary, bytecode_hash as bytecodeHash, contract_address as contractAddress,
              chain_id as chainId, started_at as startedAt, finished_at as finishedAt, duration_ms as durationMs,
              status, finding_count as findingCount, error
       FROM audit_runs ORDER BY started_at DESC LIMIT ?`,
    )
    .all(limit);
}
