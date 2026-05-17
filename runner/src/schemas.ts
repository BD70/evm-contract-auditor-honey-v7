import type { AuditApiJson, RunnerCheckpoint } from "./types.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function parseAuditApiJsonDocument(stdout: string): AuditApiJson {
  const parsed = JSON.parse(stdout) as Record<string, unknown>;
  if (parsed.schema !== "evm-audit.api.v2") {
    throw new Error("invalid_auditor_schema");
  }
  if (typeof parsed.schema_version !== "string") {
    throw new Error("invalid_auditor_schema_version");
  }
  if (!isRecord(parsed.input) || typeof parsed.input.kind !== "string" || typeof parsed.input.value !== "string") {
    throw new Error("invalid_auditor_input");
  }
  if (!isRecord(parsed.analysis)) {
    throw new Error("invalid_auditor_analysis");
  }
  if (typeof parsed.analysis.matched !== "boolean") {
    throw new Error("invalid_auditor_analysis");
  }
  if (typeof parsed.analysis.finding_count !== "number" || typeof parsed.analysis.raw_match_count !== "number") {
    throw new Error("invalid_auditor_analysis");
  }
  if (!Array.isArray(parsed.findings)) {
    throw new Error("invalid_auditor_findings");
  }
  if (!isRecord(parsed.diagnostics)) {
    throw new Error("invalid_auditor_diagnostics");
  }
  return parsed as unknown as AuditApiJson;
}

export function validateCheckpointDocument(value: unknown): RunnerCheckpoint {
  if (!isRecord(value)) {
    throw new Error("invalid_checkpoint");
  }
  if (value.checkpointVersion !== "2") {
    throw new Error("invalid_checkpoint_version");
  }
  if (typeof value.chainId !== "number" || typeof value.lastProcessedBlock !== "number") {
    throw new Error("invalid_checkpoint_header");
  }
  if (!Array.isArray(value.history) || !isRecord(value.resultCache) || !isRecord(value.deliveredEvents) || !isRecord(value.pendingWebhookEvents)) {
    throw new Error("invalid_checkpoint_shape");
  }
  return value as RunnerCheckpoint;
}

export function parseEnvFileDocument(content: string): Record<string, string> {
  const parsed: Record<string, string> = {};
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) {
      continue;
    }
    const idx = line.indexOf("=");
    if (idx === -1) {
      throw new Error(`invalid_env_line:${line}`);
    }
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (!key) {
      throw new Error(`invalid_env_key:${line}`);
    }
    parsed[key] = value.replace(/^"(.*)"$/, "$1");
  }
  return parsed;
}
