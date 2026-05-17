import { existsSync, mkdirSync, writeFileSync, unlinkSync } from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { RunnerConfig } from "./types.js";

const execFileAsync = promisify(execFile);

export interface ProbeResult {
  ok: boolean;
  detail: string;
  latencyMs: number;
  skipped?: boolean;
}

export interface HealthReport {
  timestamp: number;
  probes: {
    archiveNode: ProbeResult;
    traceApi: ProbeResult;
    auditorRuntime: ProbeResult;
    rulesDir: ProbeResult;
    stateDir: ProbeResult;
  };
  allOk: boolean;
}

function skipped(reason: string): ProbeResult {
  return { ok: true, detail: `skipped:${reason}`, latencyMs: 0, skipped: true };
}

async function probeArchiveNode(rpcHttpUrl: string): Promise<ProbeResult> {
  const t0 = Date.now();
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5_000);
    try {
      const res = await fetch(rpcHttpUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }),
        signal: ctrl.signal,
      });
      const json = await res.json() as { result?: string; error?: unknown };
      if (json.result) {
        return { ok: true, detail: `block=${json.result}`, latencyMs: Date.now() - t0 };
      }
      return { ok: false, detail: `rpc_error:${JSON.stringify(json.error)}`, latencyMs: Date.now() - t0 };
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    return { ok: false, detail: `fetch_failed:${(err as Error).message}`, latencyMs: Date.now() - t0 };
  }
}

async function probeTraceApi(rpcHttpUrl: string): Promise<ProbeResult> {
  const t0 = Date.now();
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10_000);
    try {
      const res = await fetch(rpcHttpUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "debug_traceBlockByNumber",
          params: ["latest", { tracer: "callTracer", timeout: "5s" }],
        }),
        signal: ctrl.signal,
      });
      const json = await res.json() as { result?: unknown; error?: { message?: string } };
      if (json.result !== undefined) {
        return { ok: true, detail: "trace_api_ok", latencyMs: Date.now() - t0 };
      }
      const msg = json.error?.message ?? "unknown";
      return { ok: false, detail: `trace_api_error:${msg}`, latencyMs: Date.now() - t0 };
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    return { ok: false, detail: `fetch_failed:${(err as Error).message}`, latencyMs: Date.now() - t0 };
  }
}

async function probeAuditorRuntime(auditorBin: string): Promise<ProbeResult> {
  const t0 = Date.now();
  try {
    const { stdout } = await execFileAsync(auditorBin, ["--version"], { timeout: 5_000 });
    return { ok: true, detail: stdout.trim() || "ok", latencyMs: Date.now() - t0 };
  } catch (err) {
    return { ok: false, detail: `auditor_failed:${(err as Error).message}`, latencyMs: Date.now() - t0 };
  }
}

function probeRulesDir(rulesPath: string): ProbeResult {
  const t0 = Date.now();
  try {
    if (!existsSync(rulesPath)) {
      return { ok: false, detail: `rules_dir_missing:${rulesPath}`, latencyMs: Date.now() - t0 };
    }
    const { readdirSync } = require("node:fs") as typeof import("node:fs");
    const files = readdirSync(rulesPath).filter((f: string) => f.endsWith(".json"));
    if (files.length === 0) {
      return { ok: false, detail: "rules_dir_empty_no_json", latencyMs: Date.now() - t0 };
    }
    return { ok: true, detail: `${files.length}_rules`, latencyMs: Date.now() - t0 };
  } catch (err) {
    return { ok: false, detail: `rules_dir_error:${(err as Error).message}`, latencyMs: Date.now() - t0 };
  }
}

function probeStateDir(stateDir: string): ProbeResult {
  const t0 = Date.now();
  const probe = path.join(stateDir, `.health_probe_${Date.now()}`);
  try {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(probe, "ok");
    unlinkSync(probe);
    return { ok: true, detail: "state_dir_writable", latencyMs: Date.now() - t0 };
  } catch (err) {
    return { ok: false, detail: `state_dir_error:${(err as Error).message}`, latencyMs: Date.now() - t0 };
  }
}

export async function runStartupHealthCheck(config: RunnerConfig): Promise<HealthReport> {
  const [archiveNode, traceApi, auditorRuntime] = await Promise.all([
    config.probeRpc ? probeArchiveNode(config.rpcHttpUrl) : Promise.resolve(skipped("HEALTH_PROBE_RPC=false")),
    config.probeTraceApi ? probeTraceApi(config.rpcHttpUrl) : Promise.resolve(skipped("HEALTH_PROBE_TRACE_API=false")),
    config.probeAuditor ? probeAuditorRuntime(config.auditorBin) : Promise.resolve(skipped("HEALTH_PROBE_AUDITOR=false")),
  ]);
  const rulesDir = config.probeRulesDir ? probeRulesDir(config.rulesPath) : skipped("HEALTH_PROBE_RULES_DIR=false");
  const stateDir = config.probeStateDir ? probeStateDir(config.stateDir) : skipped("HEALTH_PROBE_STATE_DIR=false");

  const probes = { archiveNode, traceApi, auditorRuntime, rulesDir, stateDir };
  const allOk = Object.values(probes).every((p) => p.ok);

  return { timestamp: Date.now(), probes, allOk };
}
