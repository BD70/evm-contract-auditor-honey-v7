
import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import * as schema from "./schema";
import path from "node:path";
import fs from "node:fs";
import { panelPaths } from "@/src/server/paths";

type DrizzleDB = ReturnType<typeof drizzle<typeof schema>>;

const g = globalThis as unknown as { __panelDb?: { raw: Database.Database; db: DrizzleDB } };

function ensureDir(p: string) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
}

function columnExists(raw: Database.Database, table: string, column: string): boolean {
  const rows = raw.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  return rows.some((r) => r.name === column);
}

function addColumnIfMissing(raw: Database.Database, table: string, column: string, decl: string) {
  if (!columnExists(raw, table, column)) {
    raw.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
  }
}

function applyMigrations(raw: Database.Database) {
  raw.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      run_id TEXT,
      rule_id TEXT NOT NULL,
      internal_name TEXT,
      severity TEXT NOT NULL,
      status TEXT,
      confidence TEXT,
      title TEXT,
      category TEXT,
      bytecode_hash TEXT,
      contract_address TEXT,
      chain_id INTEGER,
      block_number INTEGER,
      tx_hash TEXT,
      discovered_at INTEGER NOT NULL,
      source TEXT NOT NULL,
      judged_by TEXT,
      judge_verdict TEXT,
      judge_rationale TEXT,
      judge_confidence TEXT,
      affected_functions_json TEXT,
      raw_json TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_findings_sev_time ON findings(severity, discovered_at);
    CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
    CREATE INDEX IF NOT EXISTS idx_findings_bytecode ON findings(bytecode_hash);
    CREATE INDEX IF NOT EXISTS idx_findings_chain_block ON findings(chain_id, block_number);
    CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

    CREATE TABLE IF NOT EXISTS deployments (
      id TEXT PRIMARY KEY,
      chain_id INTEGER,
      block_number INTEGER,
      contract_address TEXT,
      tx_hash TEXT NOT NULL,
      deployer TEXT,
      bytecode_hash TEXT,
      proxy_kind TEXT,
      proxy_target TEXT,
      detected_at INTEGER NOT NULL,
      audit_status TEXT NOT NULL,
      runner_event_id TEXT,
      raw_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_deployments_chain_block ON deployments(chain_id, block_number);
    CREATE INDEX IF NOT EXISTS idx_deployments_bytecode ON deployments(bytecode_hash);

    CREATE TABLE IF NOT EXISTS audit_runs (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      input_summary TEXT,
      bytecode_hash TEXT,
      contract_address TEXT,
      chain_id INTEGER,
      rules_fingerprint TEXT,
      started_at INTEGER NOT NULL,
      finished_at INTEGER,
      duration_ms INTEGER,
      status TEXT NOT NULL,
      stderr_tail TEXT,
      finding_count INTEGER DEFAULT 0,
      raw_json TEXT,
      error TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_runs_kind ON audit_runs(kind);
    CREATE INDEX IF NOT EXISTS idx_runs_started ON audit_runs(started_at);

    CREATE TABLE IF NOT EXISTS webhook_events (
      event_id TEXT PRIMARY KEY,
      event_type TEXT,
      status TEXT NOT NULL,
      attempts INTEGER DEFAULT 0,
      last_error TEXT,
      payload_json TEXT,
      updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_webhooks_status ON webhook_events(status);
    CREATE INDEX IF NOT EXISTS idx_webhooks_updated ON webhook_events(updated_at);

    CREATE TABLE IF NOT EXISTS runner_lifecycle (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT NOT NULL,
      pid INTEGER,
      at INTEGER NOT NULL,
      exit_code INTEGER,
      reason TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_lifecycle_at ON runner_lifecycle(at);
  `);

  // Simulation columns (fork-based exploit verification). Added as a follow-up
  // migration so existing databases pick them up on next boot without losing
  // data. simulation_status: pending | running | verified | refuted |
  // inconclusive | skipped | error. simulation_verdict is a finer-grained
  // outcome, e.g. "exploitable" | "not_exploitable" | "decon_failed".
  addColumnIfMissing(raw, "findings", "simulation_status", "TEXT");
  addColumnIfMissing(raw, "findings", "simulation_verdict", "TEXT");
  addColumnIfMissing(raw, "findings", "simulation_evidence_json", "TEXT");
  addColumnIfMissing(raw, "findings", "simulation_engine", "TEXT");
  addColumnIfMissing(raw, "findings", "simulated_at", "INTEGER");
  raw.exec(
    `CREATE INDEX IF NOT EXISTS idx_findings_sim_status ON findings(simulation_status, severity, discovered_at)`,
  );

  // Per-(bytecode_hash, rule_id) simulation cache. Results are deterministic
  // for a given (bytecode, rule, simulation engine version) tuple so we only
  // simulate each contract once and reuse the verdict across all findings
  // sharing the same bytecode (which is overwhelmingly the case: most flagged
  // proxy contracts share an implementation).
  raw.exec(`
    CREATE TABLE IF NOT EXISTS simulation_cache (
      bytecode_hash TEXT NOT NULL,
      rule_id TEXT NOT NULL,
      engine TEXT NOT NULL,
      engine_version TEXT NOT NULL,
      status TEXT NOT NULL,
      verdict TEXT,
      evidence_json TEXT,
      simulated_at INTEGER NOT NULL,
      duration_ms INTEGER,
      PRIMARY KEY (bytecode_hash, rule_id, engine, engine_version)
    );
    CREATE INDEX IF NOT EXISTS idx_simcache_at ON simulation_cache(simulated_at);
  `);
}

function init() {
  const dbPath = process.env.PANEL_DB_PATH ?? path.join(panelPaths.panelRoot, "data", "findings.db");
  ensureDir(dbPath);
  const raw = new Database(dbPath);
  raw.pragma("journal_mode = WAL");
  raw.pragma("foreign_keys = ON");
  applyMigrations(raw);
  const db = drizzle(raw, { schema });
  return { raw, db };
}

if (!g.__panelDb) g.__panelDb = init();

export const db = g.__panelDb.db;
export const rawDb = g.__panelDb.raw;
export * as panelSchema from "./schema";
