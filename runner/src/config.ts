import { readFile } from "node:fs/promises";
import path from "node:path";
import { type ChainEntry, loadChainsFile, selectChain } from "./chains.js";
import { parseEnvFileDocument } from "./schemas.js";
import type { CliOptions, RunnerConfig } from "./types.js";
import { clampPositiveInteger, parseInteger, parseLogLevel, requireNonNegativeInteger } from "./utils.js";

export async function loadConfig(cwd: string, options: CliOptions): Promise<RunnerConfig> {
  const envFile = options.envFile ?? path.join(cwd, ".env");
  let fileEnv: Record<string, string> = {};
  try {
    fileEnv = parseEnvFileDocument(await readFile(envFile, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
      fileEnv = {};
    } else {
      throw error;
    }
  }
  const env = { ...fileEnv, ...process.env } as Record<string, string | undefined>;

  const repoRoot = path.dirname(path.resolve(cwd, envFile));
  const chain = await resolveChain(repoRoot, options.chain);

  const rulesPath = chain?.rulesPath ?? options.rulesPath ?? env.RULES_PATH ?? "rules/core";
  const baseStateDir = path.resolve(cwd, env.STATE_DIR ?? "runner-state");

  const config: RunnerConfig = {
    rpcHttpUrl: chain?.rpcHttpUrl ?? env.RPC_HTTP_URL ?? "http://127.0.0.1:8545",
    rpcWsUrl: chain?.rpcWsUrl ?? env.RPC_WS_URL,
    confirmations: chain?.confirmations ?? parseInteger(env.CONFIRMATIONS, 2),
    startBlock: options.startBlock ?? chain?.startBlock ?? parseInteger(env.START_BLOCK, 0),
    rulesPath,
    auditorBin: env.AUDITOR_BIN ?? "evm-audit",
    ruleBin: env.RULE_BIN ?? "evm-rule",
    maxBlockFetchConcurrency: parseInteger(env.MAX_BLOCK_FETCH_CONCURRENCY, 2),
    maxAuditWorkers: parseInteger(env.MAX_AUDIT_WORKERS, 4),
    maxWebhookConcurrency: parseInteger(env.MAX_WEBHOOK_CONCURRENCY, 4),
    analysisTimeoutMs: parseInteger(env.ANALYSIS_TIMEOUT_MS, 60_000),
    maxAuditorOutputBytes: parseInteger(env.MAX_AUDITOR_OUTPUT_BYTES, 5_000_000),
    webhookUrl: chain?.webhookUrl ?? env.WEBHOOK_URL,
    webhookAuthHeader: chain?.webhookAuthHeader ?? env.WEBHOOK_AUTH_HEADER,
    stateDir: chain ? path.join(baseStateDir, chain.slug) : baseStateDir,
    logLevel: parseLogLevel(env.LOG_LEVEL),
    pollIntervalMs: parseInteger(env.POLL_INTERVAL_MS, 3_000),
    maxReorgDepth: parseInteger(env.MAX_REORG_DEPTH, 32),
    maxHistory: parseInteger(env.MAX_HISTORY, 128),
    maxArtifactInlineBytes: parseInteger(env.MAX_ARTIFACT_INLINE_BYTES, 32_768),
    maxPersistedArtifactBytes: parseInteger(env.MAX_PERSISTED_ARTIFACT_BYTES, 2_000_000),
    webhookMaxAttempts: parseInteger(env.WEBHOOK_MAX_ATTEMPTS, 3),
    rpcMaxAttempts: parseInteger(env.RPC_MAX_ATTEMPTS, 3),
    retryBaseDelayMs: parseInteger(env.RETRY_BASE_DELAY_MS, 250),
    maxResultCacheEntries: parseInteger(env.MAX_RESULT_CACHE_ENTRIES, 5_000),
    maxDeliveredEventEntries: parseInteger(env.MAX_DELIVERED_EVENT_ENTRIES, 20_000),
    maxPendingWebhookEntries: parseInteger(env.MAX_PENDING_WEBHOOK_ENTRIES, 1_000),
    uiMode: parseUiMode(env.UI_MODE),
    healthPort: parseInteger(env.HEALTH_PORT, 9090),
    stepBudgetMs: parseInteger(env.STEP_BUDGET_MS, 120_000),
    healthStrict: (env.HEALTH_STRICT ?? "true").toLowerCase() !== "false",
    // Individual probe switches — trace API off by default (most providers lack it)
    probeRpc: (env.HEALTH_PROBE_RPC ?? "true").toLowerCase() !== "false",
    probeTraceApi: (env.HEALTH_PROBE_TRACE_API ?? env.TRACE_API_OPTIONAL ?? "false").toLowerCase() === "true",
    probeAuditor: (env.HEALTH_PROBE_AUDITOR ?? "true").toLowerCase() !== "false",
    probeRulesDir: (env.HEALTH_PROBE_RULES_DIR ?? "true").toLowerCase() !== "false",
    probeStateDir: (env.HEALTH_PROBE_STATE_DIR ?? "true").toLowerCase() !== "false",
  };
  validateConfig(config);
  return config;
}

export function validateConfig(config: RunnerConfig): void {
  if (!config.rpcHttpUrl) {
    throw new Error("RPC_HTTP_URL is required");
  }
  if (!/^https?:\/\//.test(config.rpcHttpUrl)) {
    throw new Error("RPC_HTTP_URL must start with http:// or https://");
  }
  if (config.rpcWsUrl && !/^wss?:\/\//.test(config.rpcWsUrl)) {
    throw new Error("RPC_WS_URL must start with ws:// or wss://");
  }
  if (!path.isAbsolute(config.stateDir)) {
    throw new Error("STATE_DIR must resolve to an absolute path");
  }
  requireNonNegativeInteger("CONFIRMATIONS", config.confirmations);
  requireNonNegativeInteger("START_BLOCK", config.startBlock);
  clampPositiveInteger("MAX_BLOCK_FETCH_CONCURRENCY", config.maxBlockFetchConcurrency);
  clampPositiveInteger("MAX_AUDIT_WORKERS", config.maxAuditWorkers);
  clampPositiveInteger("MAX_WEBHOOK_CONCURRENCY", config.maxWebhookConcurrency);
  clampPositiveInteger("ANALYSIS_TIMEOUT_MS", config.analysisTimeoutMs);
  clampPositiveInteger("MAX_AUDITOR_OUTPUT_BYTES", config.maxAuditorOutputBytes, 1024);
  clampPositiveInteger("POLL_INTERVAL_MS", config.pollIntervalMs);
  clampPositiveInteger("MAX_REORG_DEPTH", config.maxReorgDepth);
  clampPositiveInteger("MAX_HISTORY", config.maxHistory);
  clampPositiveInteger("MAX_ARTIFACT_INLINE_BYTES", config.maxArtifactInlineBytes);
  clampPositiveInteger("MAX_PERSISTED_ARTIFACT_BYTES", config.maxPersistedArtifactBytes, 1024);
  clampPositiveInteger("WEBHOOK_MAX_ATTEMPTS", config.webhookMaxAttempts);
  clampPositiveInteger("RPC_MAX_ATTEMPTS", config.rpcMaxAttempts);
  clampPositiveInteger("RETRY_BASE_DELAY_MS", config.retryBaseDelayMs);
  clampPositiveInteger("MAX_RESULT_CACHE_ENTRIES", config.maxResultCacheEntries);
  clampPositiveInteger("MAX_DELIVERED_EVENT_ENTRIES", config.maxDeliveredEventEntries);
  clampPositiveInteger("MAX_PENDING_WEBHOOK_ENTRIES", config.maxPendingWebhookEntries);
}

async function resolveChain(repoRoot: string, requested: string | undefined): Promise<ChainEntry | null> {
  const entries = await loadChainsFile(repoRoot);
  if (!entries) {
    return null;
  }
  if (requested) {
    return selectChain(entries, requested);
  }
  const enabled = entries.filter((c) => c.enabled);
  if (enabled.length === 0) {
    return null;
  }
  if (enabled.length === 1) {
    return enabled[0];
  }
  throw new Error(
    `chains.json defines multiple enabled chains; pass --chain <slug> (one of: ${enabled.map((c) => c.slug).join(", ")})`,
  );
}

function parseUiMode(value: string | undefined): RunnerConfig["uiMode"] {
  switch ((value ?? "auto").toLowerCase()) {
    case "auto":
    case "tui":
    case "plain":
    case "json":
      return (value ?? "auto").toLowerCase() as RunnerConfig["uiMode"];
    default:
      return "auto";
  }
}
