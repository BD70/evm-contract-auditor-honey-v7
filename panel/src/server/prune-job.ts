
import { rawDb } from "@/src/db/client";

interface RetentionDays {
  findings: number;
  auditRuns: number;
  lifecycle: number;
  webhooks: number;
}

const DEFAULTS: RetentionDays = {
  findings: Number(process.env.PANEL_RETENTION_FINDINGS_DAYS ?? 30),
  auditRuns: Number(process.env.PANEL_RETENTION_RUNS_DAYS ?? 14),
  lifecycle: Number(process.env.PANEL_RETENTION_LIFECYCLE_DAYS ?? 7),
  webhooks: Number(process.env.PANEL_RETENTION_WEBHOOKS_DAYS ?? 14),
};

// Pending deployments retention is separate (and aggressive) because the
// runners firehose `deployment.json` events into the DB at thousands per
// hour, each with ~7 KB of raw_json. Without an active deployments->audit
// consumer (none today; manual audits only) the table grows by ~500 MB/day.
// We apply TWO bounds and keep the tighter one:
//   - age: drop rows older than this window (default 1h)
//   - count: keep at most this many rows total (oldest-first eviction)
// The count cap is the safety net for sustained high ingest rates where
// age-only pruning can't keep up.
const PENDING_DEPLOYMENTS_MAX_AGE_MS =
  Number(process.env.PANEL_RETENTION_PENDING_DEPLOYMENTS_HOURS ?? 1) * 60 * 60 * 1000;
const PENDING_DEPLOYMENTS_MAX_ROWS =
  Number(process.env.PANEL_RETENTION_PENDING_DEPLOYMENTS_MAX ?? 5_000);

export interface PruneResult {
  findings: number;
  auditRuns: number;
  lifecycle: number;
  webhooks: number;
  deployments: number;
  pendingDeployments: number;
  vacuumed: boolean;
  ts: number;
}

function ms(days: number): number {
  return Math.max(1, days) * 24 * 60 * 60 * 1000;
}

export function runPrune(retention: Partial<RetentionDays> = {}, opts: { vacuum?: boolean } = {}): PruneResult {
  const r = { ...DEFAULTS, ...retention };
  const now = Date.now();
  const result: PruneResult = {
    findings: 0,
    auditRuns: 0,
    lifecycle: 0,
    webhooks: 0,
    deployments: 0,
    pendingDeployments: 0,
    vacuumed: false,
    ts: now,
  };

  // Findings: drop runner-source rows older than retention; keep manual runs longer
  // (operators usually want to retrieve their own test history).
  const findingsCutoff = now - ms(r.findings);
  result.findings = (rawDb
    .prepare(`DELETE FROM findings WHERE source = 'runner' AND discovered_at < ?`)
    .run(findingsCutoff).changes) as number;

  // Audit runs: drop completed manual + runner rows older than cutoff. Never
  // delete a row that is still 'running' (would orphan the SSE stream).
  const runsCutoff = now - ms(r.auditRuns);
  result.auditRuns = (rawDb
    .prepare(`DELETE FROM audit_runs WHERE status != 'running' AND started_at < ?`)
    .run(runsCutoff).changes) as number;

  // Lifecycle: keep last 7d of start/stop/crash events. Pure observability.
  const lifeCutoff = now - ms(r.lifecycle);
  result.lifecycle = (rawDb
    .prepare(`DELETE FROM runner_lifecycle WHERE at < ?`)
    .run(lifeCutoff).changes) as number;

  // Webhook events: drop delivered rows; keep pending/failed so the operator
  // can still see stuck deliveries.
  const whCutoff = now - ms(r.webhooks);
  result.webhooks = (rawDb
    .prepare(`DELETE FROM webhook_events WHERE status = 'delivered' AND updated_at < ?`)
    .run(whCutoff).changes) as number;

  // Deployments: drop rows whose findings no longer exist (orphans).
  result.deployments = (rawDb
    .prepare(
      `DELETE FROM deployments WHERE bytecode_hash IS NOT NULL
       AND bytecode_hash NOT IN (SELECT bytecode_hash FROM findings WHERE bytecode_hash IS NOT NULL)
       AND detected_at < ?`,
    )
    .run(now - ms(r.auditRuns)).changes) as number;

  // Pending deployments: drop rows that have been sitting unaudited for too
  // long, AND cap total count. The runner ingests thousands/hour; without
  // this the table grew unbounded (496 MB / 77K rows on 2026-05-18) and
  // `SELECT * FROM deployments` calls would materialise hundreds of MB into
  // JS heap and OOM the panel.
  const ageDeleted = (rawDb
    .prepare(
      `DELETE FROM deployments
        WHERE audit_status = 'pending'
          AND detected_at < ?`,
    )
    .run(now - PENDING_DEPLOYMENTS_MAX_AGE_MS).changes) as number;

  // Size cap (after age prune so we count what's left). Oldest-first eviction
  // via subquery so we never accidentally drop a freshly-ingested row.
  const remaining = (rawDb
    .prepare(`SELECT COUNT(*) AS n FROM deployments WHERE audit_status = 'pending'`)
    .get() as { n: number } | undefined)?.n ?? 0;
  let sizeDeleted = 0;
  if (remaining > PENDING_DEPLOYMENTS_MAX_ROWS) {
    const overflow = remaining - PENDING_DEPLOYMENTS_MAX_ROWS;
    sizeDeleted = (rawDb
      .prepare(
        `DELETE FROM deployments
          WHERE id IN (
            SELECT id FROM deployments
              WHERE audit_status = 'pending'
              ORDER BY detected_at ASC
              LIMIT ?
          )`,
      )
      .run(overflow).changes) as number;
  }
  result.pendingDeployments = ageDeleted + sizeDeleted;

  if (opts.vacuum) {
    rawDb.exec("VACUUM");
    result.vacuumed = true;
  }
  return result;
}

type Globals = { __panelPruneTimer?: NodeJS.Timeout };
const g = globalThis as unknown as Globals;

export function ensurePruneSchedule() {
  if (g.__panelPruneTimer) return;
  // Run once on boot (lazily, after a 30s grace so the DB has settled).
  setTimeout(() => {
    try {
      runPrune();
    } catch (err) {
      console.warn("[panel] prune-on-boot failed", err);
    }
  }, 30_000).unref();
  // Then hourly.
  g.__panelPruneTimer = setInterval(() => {
    try {
      runPrune();
    } catch (err) {
      console.warn("[panel] prune scheduled run failed", err);
    }
  }, 60 * 60 * 1000);
  g.__panelPruneTimer.unref();
}
