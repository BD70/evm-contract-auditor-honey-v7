export const AUDIT_API_SCHEMA = "evm-audit.api.v2";

export type TargetKind = "runtime" | "proxy_shell" | "implementation" | "beacon";

export type ProxyType = "eip1167" | "erc1967" | "beacon" | "delegatecall_generic";

export type ProxyResolutionStatus = "resolved" | "unresolved_safe" | "unresolved_rpc_error" | "empty_code" | "ambiguous";

export type WebhookEventType =
  | "contract_detected"
  | "audit_completed"
  | "findings_detected"
  | "audit_failed"
  | "proxy_resolution_failed"
  | "runner_started";

export interface AuditApiAffectedFunction {
  selector?: string;
  name?: string;
}

export interface AuditApiFinding {
  rule_id: string;
  internal_name?: string;
  title?: string;
  status?: string;
  severity?: string;
  confidence?: number;
  proof_level?: string;
  scope?: string;
  match_count?: number;
  summary?: string;
  user_summary?: string;
  technical_summary?: string;
  exploit_narrative?: string;
  affected_functions?: AuditApiAffectedFunction[];
  raw_matches?: Array<Record<string, unknown>>;
  witness?: Record<string, unknown>;
}

export interface AuditApiAnalysis {
  matched: boolean;
  finding_count: number;
  raw_match_count: number;
  highest_severity?: string | null;
  highest_confidence?: number;
}

export interface AuditApiJson {
  ok: boolean;
  schema: typeof AUDIT_API_SCHEMA;
  schema_version: string;
  input: { kind: string; value: string };
  bytecode_identity?: Record<string, unknown>;
  analysis: AuditApiAnalysis;
  coverage?: Record<string, unknown>;
  exposure_estimate?: Record<string, unknown>;
  findings: AuditApiFinding[];
  warnings?: string[];
  chain_context?: Record<string, unknown>;
}

export interface RunnerConfig {
  rpcHttpUrl: string;
  rpcWsUrl?: string;
  confirmations: number;
  startBlock: number;
  rulesPath: string;
  auditorBin: string;
  ruleBin: string;
  maxBlockFetchConcurrency: number;
  maxAuditWorkers: number;
  maxWebhookConcurrency: number;
  analysisTimeoutMs: number;
  maxAuditorOutputBytes: number;
  webhookUrl?: string;
  webhookAuthHeader?: string;
  stateDir: string;
  logLevel: "debug" | "info" | "warn" | "error";
  pollIntervalMs: number;
  maxReorgDepth: number;
  maxHistory: number;
  maxArtifactInlineBytes: number;
  maxPersistedArtifactBytes: number;
  webhookMaxAttempts: number;
  rpcMaxAttempts: number;
  retryBaseDelayMs: number;
  maxResultCacheEntries: number;
  maxDeliveredEventEntries: number;
  maxPendingWebhookEntries: number;
  uiMode: "auto" | "tui" | "plain" | "json";
  healthPort: number;
  stepBudgetMs: number;
  healthStrict: boolean;
  // Per-probe enable/disable (all default true except probeTraceApi)
  probeRpc: boolean;
  probeTraceApi: boolean;
  probeAuditor: boolean;
  probeRulesDir: boolean;
  probeStateDir: boolean;
}

export interface RunnerRuntime {
  runnerVersion: string;
  rulesFingerprint: string;
  auditorSchema: typeof AUDIT_API_SCHEMA;
}

export interface CliOptions {
  envFile?: string;
  startBlock?: number;
  once: boolean;
  replayBlock?: number;
  replayRange?: { from: number; to: number };
  maxReplayRangeBlocks?: number;
  dryRunWebhook: boolean;
  noWebhook: boolean;
  rulesPath?: string;
  chain?: string;
}

export interface RpcTransaction {
  hash: string;
  from: string;
  to: string | null;
  input?: string;
  data?: string;
}

export type RpcBlockTransaction = RpcTransaction | string;

export interface RpcBlock {
  number: string;
  hash: string;
  parentHash: string;
  timestamp: string;
  transactions: RpcBlockTransaction[];
}

export interface RpcReceipt {
  transactionHash: string;
  blockNumber: string;
  contractAddress: string | null;
  gasUsed?: string;
  status?: string;
}

export interface DetectedDeployment {
  chainId: number;
  blockNumber: number;
  blockHash: string;
  parentHash: string;
  blockTimestamp: number;
  txHash: string;
  deployer: string;
  contractAddress: string;
  gasUsed?: string;
  creationBytecode: string;
  creationBytecodeHash: string;
  correlationId: string;
  detectionSource: "top_level_create" | "trace_create" | "trace_create2";
  parentTxTo?: string | null;
}

export interface ProxyHints {
  source: "runner-rpc";
  delegatecallOpcodePresent?: boolean;
  eip1167Detected?: boolean;
}

export interface ProxyResolution {
  detected: boolean;
  status: ProxyResolutionStatus;
  proxyType?: ProxyType;
  implementationAddress?: string;
  adminAddress?: string;
  beaconAddress?: string;
  fixedCloneTarget?: string;
  implementationResolved: boolean;
  unresolvedReason?: string;
  hints?: ProxyHints;
}

export interface AuditTarget {
  chainId: number;
  correlationId: string;
  blockNumber: number;
  blockHash: string;
  blockTimestamp?: number;
  txHash: string;
  contractAddress: string;
  deployer: string;
  gasUsed?: string;
  creationBytecodeHash: string;
  creationBytecode?: string;
  runtimeBytecode: string;
  runtimeBytecodeHash: string;
  targetKind: TargetKind;
  targetAddress: string;
  proxy: ProxyResolution;
}

export interface AuditJob {
  cacheKey: string;
  target: AuditTarget;
  eofFormat?: boolean;
  proxyShell?: boolean;
}

export interface AuditArtifact {
  runnerVersion: string;
  rulesFingerprint: string;
  auditorSchema: typeof AUDIT_API_SCHEMA;
  subprocessMode: "hex_arg" | "temp_file";
  targetAddress: string;
  blockTag: number;
  proxy: ProxyResolution;
  stdout?: string;
  stderr?: string;
}

export interface AuditResult {
  ok: boolean;
  cached: boolean;
  cacheKey: string;
  target: AuditTarget;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  auditorExitCode?: number | null;
  stdout?: string;
  stderr?: string;
  failureReason?: string;
  artifactPath?: string;
  apiJson?: AuditApiJson;
  artifact?: AuditArtifact;
}

export interface BlockHistoryEntry {
  number: number;
  hash: string;
  parentHash: string;
  processedAt: string;
}

export interface CachedAuditRecord {
  createdAt: string;
  artifactPath?: string;
  apiJson?: AuditApiJson;
  targetAddress: string;
  targetKind: TargetKind;
  rulesFingerprint: string;
  runnerVersion: string;
  auditorSchema: typeof AUDIT_API_SCHEMA;
}

export interface DeliveredEventRecord {
  deliveredAt: string;
  type: WebhookEventType;
}

export interface PendingWebhookRecord {
  event: WebhookEvent;
  firstFailedAt: string;
  lastFailedAt: string;
  failureReason: string;
  attempts: number;
}

export interface RunnerCheckpoint {
  checkpointVersion: "2";
  chainId: number;
  lastProcessedBlock: number;
  updatedAt: string;
  history: BlockHistoryEntry[];
  resultCache: Record<string, CachedAuditRecord>;
  deliveredEvents: Record<string, DeliveredEventRecord>;
  pendingWebhookEvents: Record<string, PendingWebhookRecord>;
}

export interface AuditSummary {
  matched: boolean;
  findingCount: number;
  highestSeverity?: string | null;
  highestConfidence?: number;
  ruleIds: string[];
}

export interface WebhookEvent {
  id: string;
  type: WebhookEventType;
  timestamp: string;
  chainId: number;
  blockNumber: number;
  txHash: string;
  contractAddress: string;
  deployer: string;
  correlationId: string;
  targetKind?: TargetKind;
  bytecodeHashes: {
    creation: string;
    runtime?: string;
  };
  proxy?: ProxyResolution;
  auditSummary?: AuditSummary;
  artifactPath?: string;
  rawApiJson?: AuditApiJson;
  failureReason?: string;
  auditorExitCode?: number | null;
  auditorStderrTail?: string;
  detectionSource?: DetectedDeployment["detectionSource"];
  healthReport?: import("./health.js").HealthReport;
}

export interface RunSummary {
  scannedBlocks: number;
  deployments: number;
  topLevelCreateDeployments: number;
  internalCreateDeployments: number;
  auditTargets: number;
  cacheHits: number;
  findings: number;
  proxyUnresolved: number;
  auditFailures: number;
  webhookFailures: number;
}

export interface DeploymentScanResult {
  deployments: DetectedDeployment[];
  txCount: number;
  topLevelCreateTxCount: number;
  internalCreateCount: number;
  traceMode: "top_level_only" | "debug_traceBlockByNumber" | "trace_block";
  traceAvailable: boolean;
}

export interface TraceCreateDeployment {
  txHash: string;
  from: string;
  to?: string | null;
  createdAddress: string;
  initCode: string;
  kind: "create" | "create2";
}
