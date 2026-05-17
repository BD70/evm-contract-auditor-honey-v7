import { z } from "zod";

type FieldKind = "string" | "url" | "int" | "bool" | "secret" | "enum";

export interface EnvField {
  key: string;
  kind: FieldKind;
  group: string;
  default?: string | number | boolean;
  description: string;
  required?: boolean;
  secret?: boolean;
  options?: string[];
}

export const ENV_FIELDS: EnvField[] = [
  // RPC
  { key: "RPC_HTTP_URL", kind: "url", group: "RPC", description: "Primary JSON-RPC endpoint (required for runner).", required: true, default: "http://127.0.0.1:8545" },
  { key: "RPC_WS_URL", kind: "url", group: "RPC", description: "Optional WebSocket endpoint for head subscription." },
  { key: "POLL_INTERVAL_MS", kind: "int", group: "RPC", default: 3000, description: "Poll interval in ms when WS not available." },
  { key: "RPC_MAX_ATTEMPTS", kind: "int", group: "RPC", default: 3, description: "Max RPC retry attempts." },
  { key: "CONFIRMATIONS", kind: "int", group: "RPC", default: 2, description: "Block confirmations before audit." },
  { key: "START_BLOCK", kind: "int", group: "RPC", default: 0, description: "Fallback start block when no checkpoint exists." },
  { key: "MAX_REORG_DEPTH", kind: "int", group: "RPC", default: 32, description: "Maximum reorg depth tolerated." },
  { key: "MAX_BLOCK_FETCH_CONCURRENCY", kind: "int", group: "RPC", default: 2, description: "Concurrent block fetch limit." },

  // Audit
  { key: "RULES_PATH", kind: "string", group: "Audit", default: "rules/core", description: "Path to rules dir or file." },
  { key: "AUDITOR_BIN", kind: "string", group: "Audit", default: "evm-audit", description: "Path to the Go evm-audit binary. Defaults to PATH lookup." },
  { key: "RULE_BIN", kind: "string", group: "Audit", default: "evm-rule", description: "Path to the Go evm-rule binary (workbench)." },
  { key: "PYTHON_BIN", kind: "string", group: "Audit", default: "python3", description: "Deprecated: legacy Python interpreter. Set AUDITOR_BIN instead." },
  { key: "AUDITOR_CMD", kind: "string", group: "Audit", default: "", description: "Deprecated: legacy Python module spec." },
  { key: "MAX_AUDIT_WORKERS", kind: "int", group: "Audit", default: 4, description: "Concurrent audit subprocesses." },
  { key: "ANALYSIS_TIMEOUT_MS", kind: "int", group: "Audit", default: 60000, description: "Hard timeout per audit (ms)." },
  { key: "STEP_BUDGET_MS", kind: "int", group: "Audit", default: 120000, description: "Per-step wall-clock budget passed to audit (ms)." },
  { key: "MAX_AUDITOR_OUTPUT_BYTES", kind: "int", group: "Audit", default: 5000000, description: "Cap on subprocess stdout bytes." },

  // Webhook
  { key: "WEBHOOK_URL", kind: "url", group: "Webhook", description: "Outbound webhook target (optional)." },
  { key: "WEBHOOK_AUTH_HEADER", kind: "secret", group: "Webhook", secret: true, description: "Header value sent on webhook posts." },
  { key: "WEBHOOK_MAX_ATTEMPTS", kind: "int", group: "Webhook", default: 3, description: "Max retry attempts per event." },
  { key: "MAX_WEBHOOK_CONCURRENCY", kind: "int", group: "Webhook", default: 4, description: "Concurrent in-flight retries." },
  { key: "RETRY_BASE_DELAY_MS", kind: "int", group: "Webhook", default: 250, description: "Exponential backoff base (ms)." },

  // State
  { key: "STATE_DIR", kind: "string", group: "State", default: "runner-state", description: "Checkpoint + artifact root dir." },
  { key: "MAX_HISTORY", kind: "int", group: "State", default: 128, description: "Block hash history window." },
  { key: "MAX_RESULT_CACHE_ENTRIES", kind: "int", group: "State", default: 5000, description: "Audit result cache cap." },
  { key: "MAX_DELIVERED_EVENT_ENTRIES", kind: "int", group: "State", default: 20000, description: "Delivered webhook event memo cap." },
  { key: "MAX_PENDING_WEBHOOK_ENTRIES", kind: "int", group: "State", default: 1000, description: "Pending webhook retry cap." },
  { key: "MAX_ARTIFACT_INLINE_BYTES", kind: "int", group: "State", default: 32768, description: "Inline artifact size threshold." },
  { key: "MAX_PERSISTED_ARTIFACT_BYTES", kind: "int", group: "State", default: 2000000, description: "Per-artifact persistence cap." },

  // Health
  { key: "HEALTH_STRICT", kind: "bool", group: "Health", default: true, description: "Fail startup if any probe fails." },
  { key: "HEALTH_PORT", kind: "int", group: "Health", default: 9090, description: "Port for /health, /ready, /metrics." },
  { key: "HEALTH_PROBE_RPC", kind: "bool", group: "Health", default: true, description: "Probe RPC reachability." },
  { key: "HEALTH_PROBE_TRACE_API", kind: "bool", group: "Health", default: false, description: "Probe debug_traceBlockByNumber." },
  { key: "HEALTH_PROBE_AUDITOR", kind: "bool", group: "Health", default: true, description: "Probe evm-audit binary --version succeeds." },
  { key: "HEALTH_PROBE_PYTHON", kind: "bool", group: "Health", default: false, description: "Deprecated: probe Python evm_audit module." },
  { key: "HEALTH_PROBE_RULES_DIR", kind: "bool", group: "Health", default: true, description: "Probe rules directory readable." },
  { key: "HEALTH_PROBE_STATE_DIR", kind: "bool", group: "Health", default: true, description: "Probe state directory writable." },

  // LLM Judge
  { key: "EVM_LLM_BASE_URL", kind: "url", group: "LLM Judge", default: "http://localhost:11434/v1", description: "OpenAI-compatible LLM endpoint." },
  { key: "EVM_LLM_MODEL", kind: "string", group: "LLM Judge", default: "qwen2.5-coder:14b", description: "Model name passed to the judge." },
  { key: "EVM_LLM_API_KEY", kind: "secret", group: "LLM Judge", secret: true, default: "local", description: "API key sent to the LLM." },
  { key: "EVM_LLM_TIMEOUT", kind: "int", group: "LLM Judge", default: 30, description: "Judge request timeout (seconds)." },

  // Other
  { key: "UI_MODE", kind: "enum", group: "Other", options: ["auto", "tui", "plain", "json"], default: "auto", description: "Runner output mode. Forced to 'json' while panel-managed." },
  { key: "LOG_LEVEL", kind: "enum", group: "Other", options: ["debug", "info", "warn", "error"], default: "info", description: "Runner log verbosity." },
];

export const ENV_FIELD_BY_KEY: Record<string, EnvField> = Object.fromEntries(
  ENV_FIELDS.map((f) => [f.key, f]),
);

export const ENV_GROUPS = Array.from(new Set(ENV_FIELDS.map((f) => f.group)));

const fieldToZod = (f: EnvField) => {
  switch (f.kind) {
    case "int":
      return z.preprocess(
        (v) => (v === "" || v == null ? undefined : typeof v === "number" ? v : Number(v)),
        z.number().int().optional(),
      );
    case "bool":
      return z.preprocess(
        (v) => (v == null ? undefined : typeof v === "boolean" ? v : String(v).toLowerCase() === "true"),
        z.boolean().optional(),
      );
    case "url":
      return z.string().url().optional().or(z.literal(""));
    case "enum":
      return z.enum((f.options ?? []) as [string, ...string[]]).optional();
    default:
      return z.string().optional();
  }
};

export const envPatchSchema = z.object(
  Object.fromEntries(ENV_FIELDS.map((f) => [f.key, fieldToZod(f)])),
);

export type EnvPatch = z.infer<typeof envPatchSchema>;
