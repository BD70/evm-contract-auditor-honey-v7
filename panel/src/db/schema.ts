import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core";

export const findings = sqliteTable(
  "findings",
  {
    id: text("id").primaryKey(),
    runId: text("run_id"),
    ruleId: text("rule_id").notNull(),
    internalName: text("internal_name"),
    severity: text("severity").notNull(),
    status: text("status"),
    confidence: text("confidence"),
    title: text("title"),
    category: text("category"),
    bytecodeHash: text("bytecode_hash"),
    contractAddress: text("contract_address"),
    chainId: integer("chain_id"),
    blockNumber: integer("block_number"),
    txHash: text("tx_hash"),
    discoveredAt: integer("discovered_at").notNull(),
    source: text("source").notNull(), // 'runner' | 'manual'
    judgedBy: text("judged_by"),
    judgeVerdict: text("judge_verdict"),
    judgeRationale: text("judge_rationale"),
    judgeConfidence: text("judge_confidence"),
    affectedFunctionsJson: text("affected_functions_json"),
    rawJson: text("raw_json").notNull(),
  },
  (t) => ({
    sevTimeIdx: index("idx_findings_sev_time").on(t.severity, t.discoveredAt),
    ruleIdx: index("idx_findings_rule").on(t.ruleId),
    bytecodeIdx: index("idx_findings_bytecode").on(t.bytecodeHash),
    chainBlockIdx: index("idx_findings_chain_block").on(t.chainId, t.blockNumber),
    runIdx: index("idx_findings_run").on(t.runId),
  }),
);

export const deployments = sqliteTable(
  "deployments",
  {
    id: text("id").primaryKey(), // chainId:txHash:contractAddress
    chainId: integer("chain_id"),
    blockNumber: integer("block_number"),
    contractAddress: text("contract_address"),
    txHash: text("tx_hash").notNull(),
    deployer: text("deployer"),
    bytecodeHash: text("bytecode_hash"),
    proxyKind: text("proxy_kind"),
    proxyTarget: text("proxy_target"),
    detectedAt: integer("detected_at").notNull(),
    auditStatus: text("audit_status").notNull(), // pending | ok | failed | cached
    runnerEventId: text("runner_event_id"),
    rawJson: text("raw_json"),
  },
  (t) => ({
    chainBlockIdx: index("idx_deployments_chain_block").on(t.chainId, t.blockNumber),
    bytecodeIdx: index("idx_deployments_bytecode").on(t.bytecodeHash),
  }),
);

export const auditRuns = sqliteTable(
  "audit_runs",
  {
    id: text("id").primaryKey(),
    kind: text("kind").notNull(), // runner | manual_hex | manual_file | manual_address | reaudit
    inputSummary: text("input_summary"),
    bytecodeHash: text("bytecode_hash"),
    contractAddress: text("contract_address"),
    chainId: integer("chain_id"),
    rulesFingerprint: text("rules_fingerprint"),
    startedAt: integer("started_at").notNull(),
    finishedAt: integer("finished_at"),
    durationMs: integer("duration_ms"),
    status: text("status").notNull(), // running | ok | failed
    stderrTail: text("stderr_tail"),
    findingCount: integer("finding_count").default(0),
    rawJson: text("raw_json"),
    error: text("error"),
  },
  (t) => ({
    kindIdx: index("idx_runs_kind").on(t.kind),
    startedIdx: index("idx_runs_started").on(t.startedAt),
  }),
);

export const webhookEvents = sqliteTable(
  "webhook_events",
  {
    eventId: text("event_id").primaryKey(),
    eventType: text("event_type"),
    status: text("status").notNull(), // delivered | pending | failed
    attempts: integer("attempts").default(0),
    lastError: text("last_error"),
    payloadJson: text("payload_json"),
    updatedAt: integer("updated_at").notNull(),
  },
  (t) => ({
    statusIdx: index("idx_webhooks_status").on(t.status),
    updatedIdx: index("idx_webhooks_updated").on(t.updatedAt),
  }),
);

export const runnerLifecycle = sqliteTable(
  "runner_lifecycle",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    event: text("event").notNull(), // started | stopped | crashed
    pid: integer("pid"),
    at: integer("at").notNull(),
    exitCode: integer("exit_code"),
    reason: text("reason"),
  },
  (t) => ({
    atIdx: index("idx_lifecycle_at").on(t.at),
  }),
);

export type Finding = typeof findings.$inferSelect;
export type NewFinding = typeof findings.$inferInsert;
export type Deployment = typeof deployments.$inferSelect;
export type NewDeployment = typeof deployments.$inferInsert;
export type AuditRun = typeof auditRuns.$inferSelect;
export type NewAuditRun = typeof auditRuns.$inferInsert;
export type WebhookEvent = typeof webhookEvents.$inferSelect;
export type NewWebhookEvent = typeof webhookEvents.$inferInsert;
export type RunnerLifecycleEvent = typeof runnerLifecycle.$inferSelect;
