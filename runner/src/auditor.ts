import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { AuditApiJson, AuditJob, AuditResult, RunnerConfig, RunnerRuntime } from "./types.js";
import { AUDIT_API_SCHEMA } from "./types.js";
import { NodeProcessRunner } from "./process_runner.js";
import { parseAuditApiJsonDocument } from "./schemas.js";
import { nowIso } from "./utils.js";

const MAX_INLINE_HEX_ARG = 100_000;

export async function runAuditJob(config: RunnerConfig, runtime: RunnerRuntime, job: AuditJob): Promise<AuditResult> {
  const startedAt = nowIso();
  const started = Date.now();
  const { target } = job;
  const baseResult: AuditResult = {
    ok: false,
    cached: false,
    cacheKey: job.cacheKey,
    target,
    startedAt,
    completedAt: startedAt,
    durationMs: 0,
  };

  let tempDir = "";
  let subprocessMode: "hex_arg" | "temp_file" = "hex_arg";
  const chainContext = JSON.stringify({
    chainId: target.chainId,
    blockNumber: target.blockNumber,
    blockTimestamp: target.blockTimestamp,
    txHash: target.txHash,
    deployer: target.deployer,
    contractAddress: target.contractAddress,
  });
  let args = [
    "--rules", config.rulesPath,
    "--format", "api-json",
    "--no-resolve",
    "--chain-context", chainContext,
    "--step-budget-ms", String(config.stepBudgetMs ?? 120_000),
    ...(job.eofFormat ? ["--eof"] : []),
    ...(job.proxyShell ? ["--proxy-shell"] : []),
  ];
  const processRunner = new NodeProcessRunner();
  if (target.runtimeBytecode.length > MAX_INLINE_HEX_ARG) {
    subprocessMode = "temp_file";
    tempDir = await mkdtemp(path.join(os.tmpdir(), "evm-audit-runner-"));
    const hexPath = path.join(tempDir, "runtime.hex");
    await writeFile(hexPath, `${target.runtimeBytecode}\n`, "utf8");
    args = [...args, "--file", hexPath];
  } else {
    args = [...args, "--hex", target.runtimeBytecode];
  }

  try {
    const { code, timedOut, outputLimitExceeded, stdout, stderr } = await processRunner.run(
      config.auditorBin,
      args,
      config.analysisTimeoutMs,
      config.maxAuditorOutputBytes,
    );
    const completedAt = nowIso();
    const durationMs = Date.now() - started;

    if (timedOut) {
      return buildFailure(baseResult, runtime, subprocessMode, completedAt, durationMs, stdout, stderr, null, "analysis_timeout");
    }
    if (outputLimitExceeded) {
      return buildFailure(baseResult, runtime, subprocessMode, completedAt, durationMs, stdout, stderr, null, "auditor_output_limit_exceeded");
    }

    if (code !== 0) {
      return buildFailure(baseResult, runtime, subprocessMode, completedAt, durationMs, stdout, stderr, code, "auditor_exit_nonzero");
    }

    let apiJson: AuditApiJson;
    try {
      apiJson = parseAuditApiJson(stdout);
    } catch (error) {
      return buildFailure(
        baseResult,
        runtime,
        subprocessMode,
        completedAt,
        durationMs,
        stdout,
        stderr,
        code,
        error instanceof Error ? error.message : "invalid_auditor_json",
      );
    }

    return {
      ...baseResult,
      ok: true,
      completedAt,
      durationMs,
      stdout,
      stderr,
      auditorExitCode: code,
      apiJson,
      artifact: {
        runnerVersion: runtime.runnerVersion,
        rulesFingerprint: runtime.rulesFingerprint,
        auditorSchema: runtime.auditorSchema,
        subprocessMode,
        targetAddress: target.targetAddress,
        blockTag: target.blockNumber,
        proxy: target.proxy,
        stdout,
        stderr,
      },
    };
  } finally {
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true });
    }
  }
}

function buildFailure(
  baseResult: AuditResult,
  runtime: RunnerRuntime,
  subprocessMode: "hex_arg" | "temp_file",
  completedAt: string,
  durationMs: number,
  stdout: string,
  stderr: string,
  auditorExitCode: number | null,
  failureReason: string,
): AuditResult {
  return {
    ...baseResult,
    completedAt,
    durationMs,
    stdout,
    stderr,
    auditorExitCode,
    failureReason,
    artifact: {
      runnerVersion: runtime.runnerVersion,
      rulesFingerprint: runtime.rulesFingerprint,
      auditorSchema: runtime.auditorSchema,
      subprocessMode,
      targetAddress: baseResult.target.targetAddress,
      blockTag: baseResult.target.blockNumber,
      proxy: baseResult.target.proxy,
      stdout,
      stderr,
    },
  };
}

export function parseAuditApiJson(stdout: string): AuditApiJson {
  const parsed = parseAuditApiJsonDocument(stdout);
  if (parsed.schema !== AUDIT_API_SCHEMA) {
    throw new Error("invalid_auditor_schema");
  }
  for (const finding of parsed.findings) {
    if (typeof finding.rule_id !== "string") {
      throw new Error("invalid_auditor_findings");
    }
  }
  return parsed;
}
