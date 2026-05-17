import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseAuditApiJson, runAuditJob } from "../src/auditor.js";
import type { AuditJob, RunnerConfig, RunnerRuntime } from "../src/types.js";

let tempRoot = "";

afterEach(async () => {
  if (tempRoot) {
    await rm(tempRoot, { recursive: true, force: true });
    tempRoot = "";
  }
});

const runtime: RunnerRuntime = {
  runnerVersion: "1.0.0",
  rulesFingerprint: "rules-fingerprint",
  auditorSchema: "evm-audit.api.v2",
};

function baseConfig(scriptPath: string): RunnerConfig {
  return {
    rpcHttpUrl: "http://127.0.0.1:8545",
    confirmations: 2,
    startBlock: 0,
    rulesPath: "rules/core",
    pythonBin: process.execPath,
    auditorCmd: scriptPath,
    maxBlockFetchConcurrency: 1,
    maxAuditWorkers: 1,
    maxWebhookConcurrency: 1,
    analysisTimeoutMs: 100,
    maxAuditorOutputBytes: 1_000_000,
    stateDir: "runner-state",
    logLevel: "info",
    pollIntervalMs: 1000,
    maxReorgDepth: 16,
    maxHistory: 32,
    maxArtifactInlineBytes: 4096,
    maxPersistedArtifactBytes: 1_000_000,
    webhookMaxAttempts: 3,
    rpcMaxAttempts: 3,
    retryBaseDelayMs: 10,
    maxResultCacheEntries: 100,
    maxDeliveredEventEntries: 100,
    maxPendingWebhookEntries: 100,
    uiMode: "json",
  };
}

function baseJob(): AuditJob {
  return {
    cacheKey: "cache-key",
    target: {
      chainId: 1,
      correlationId: "corr",
      blockNumber: 1,
      blockHash: "0x1",
      txHash: "0xtx",
      contractAddress: "0xcontract",
      deployer: "0xdeployer",
      creationBytecodeHash: "abc",
      creationBytecode: "0x6000",
      runtimeBytecode: "0x6000",
      runtimeBytecodeHash: "def",
      targetKind: "runtime",
      targetAddress: "0xcontract",
      proxy: { detected: false, status: "unresolved_safe", implementationResolved: false },
    },
  };
}

describe("auditor subprocess", () => {
  test("parses stdout api-json", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-test-"));
    const script = path.join(tempRoot, "ok.mjs");
    await writeFile(
      script,
      `process.stdout.write(JSON.stringify({ok:true,schema:"evm-audit.api.v2",schema_version:"2.0.0",input:{kind:"hex_string",value:"x"},analysis_context:{analysis_id:"a",created_at:"2026-01-01T00:00:00Z",input_kind:"hex_string",resolver_enabled:false,profiles_enabled:true},analysis:{matched:true,finding_count:1,raw_match_count:1,highest_severity:"high",highest_confidence:0.9},diagnostics:{analysis_warnings:[],deconstruction:{},checker_trace_count:1},artifacts:{behavior_schema:"evm-audit.behavior.v2",state_model_schema:"evm-audit.state_model.v2"},exposure_estimate:{kind:"demo"},findings:[{rule_id:"demo"}],warnings:[]}));`,
      "utf8",
    );
    const result = await runAuditJob(baseConfig(script), runtime, baseJob());
    expect(result.ok).toBe(true);
    expect(result.apiJson?.analysis.matched).toBe(true);
    expect(result.artifact?.rulesFingerprint).toBe("rules-fingerprint");
  });

  test("rejects wrong schema", () => {
    expect(() =>
      parseAuditApiJson(
        JSON.stringify({
          ok: true,
          schema: "wrong",
          schema_version: "2.0.0",
          input: { kind: "hex_string", value: "x" },
          analysis: { matched: true, finding_count: 1, raw_match_count: 1 },
          diagnostics: {},
          findings: [],
        }),
      ),
    ).toThrow("invalid_auditor_schema");
  });

  test("times out hung subprocess", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-test-"));
    const script = path.join(tempRoot, "hang.mjs");
    await writeFile(script, `setTimeout(() => {}, 10_000);`, "utf8");
    const result = await runAuditJob(baseConfig(script), runtime, baseJob());
    expect(result.ok).toBe(false);
    expect(result.failureReason).toBe("analysis_timeout");
  });

  test("fails when subprocess output exceeds configured limit", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-test-"));
    const script = path.join(tempRoot, "big-output.mjs");
    await writeFile(script, `process.stdout.write("x".repeat(5000));`, "utf8");
    const config = baseConfig(script);
    config.maxAuditorOutputBytes = 1024;
    const result = await runAuditJob(config, runtime, baseJob());
    expect(result.ok).toBe(false);
    expect(result.failureReason).toBe("auditor_output_limit_exceeded");
  });
});
