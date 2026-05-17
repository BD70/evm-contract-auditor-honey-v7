import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { runRunner } from "../src/runner.js";
import type { RunnerConfig } from "../src/types.js";

let tempRoot = "";
let originalFetch: typeof fetch;

beforeEach(() => {
  originalFetch = globalThis.fetch;
});

afterEach(async () => {
  globalThis.fetch = originalFetch;
  mock.restore();
  if (tempRoot) {
    await rm(tempRoot, { recursive: true, force: true });
    tempRoot = "";
  }
});

describe("runner integration", () => {
  test("persists delivered webhook ids and avoids duplicate replay delivery", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-it-"));
    const script = path.join(tempRoot, "auditor.mjs");
    await writeFile(
      script,
      `process.stdout.write(JSON.stringify({ok:true,schema:"evm-audit.api.v2",schema_version:"2.0.0",input:{kind:"hex_string",value:"x"},analysis_context:{analysis_id:"a",created_at:"2026-01-01T00:00:00Z",input_kind:"hex_string",resolver_enabled:false,profiles_enabled:true},analysis:{matched:true,finding_count:1,raw_match_count:1,highest_severity:"high",highest_confidence:0.9},diagnostics:{analysis_warnings:["demo-warning"],deconstruction:{},checker_trace_count:1},artifacts:{behavior_schema:"evm-audit.behavior.v2",state_model_schema:"evm-audit.state_model.v2"},findings:[{rule_id:"demo"}],warnings:["demo-warning"]}));`,
      "utf8",
    );

    let webhookCalls = 0;
    const rpcCalls: string[] = [];
    globalThis.fetch = mock(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === "http://webhook.local") {
        webhookCalls += 1;
        return new Response("ok", { status: 200 });
      }
      const payload = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      rpcCalls.push(payload.method);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: rpcResult(payload.method, payload.params),
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const config: RunnerConfig = {
      rpcHttpUrl: "http://rpc.local",
      rpcWsUrl: undefined,
      confirmations: 0,
      startBlock: 0,
      rulesPath: "rules/core",
      pythonBin: process.execPath,
      auditorCmd: script,
      maxBlockFetchConcurrency: 2,
      maxAuditWorkers: 1,
      maxWebhookConcurrency: 2,
      analysisTimeoutMs: 1000,
      webhookUrl: "http://webhook.local",
      webhookAuthHeader: undefined,
      stateDir: path.join(tempRoot, "state"),
      logLevel: "error",
      pollIntervalMs: 5,
      maxReorgDepth: 8,
      maxHistory: 16,
      maxArtifactInlineBytes: 4096,
      maxPersistedArtifactBytes: 1_000_000,
      webhookMaxAttempts: 1,
      rpcMaxAttempts: 1,
      retryBaseDelayMs: 1,
      maxResultCacheEntries: 100,
      maxDeliveredEventEntries: 100,
      maxPendingWebhookEntries: 100,
      uiMode: "json",
    };

    await runRunner(config, { once: true, dryRunWebhook: false, noWebhook: false });
    expect(webhookCalls).toBe(3);

    await runRunner(config, { once: true, dryRunWebhook: false, noWebhook: false, replayBlock: 1 });
    expect(webhookCalls).toBe(3);

    const checkpointPath = path.join(config.stateDir, "checkpoint.json");
    const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8")) as {
      deliveredEvents: Record<string, unknown>;
    };
    expect(Object.keys(checkpoint.deliveredEvents)).toHaveLength(3);
    expect(rpcCalls.includes("eth_getCode")).toBe(true);
  });

  test("detects factory deployments from debug trace data", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-it-"));
    const script = path.join(tempRoot, "auditor.mjs");
    await writeFile(
      script,
      `process.stdout.write(JSON.stringify({ok:true,schema:"evm-audit.api.v2",schema_version:"2.0.0",input:{kind:"hex_string",value:"x"},analysis_context:{analysis_id:"a",created_at:"2026-01-01T00:00:00Z",input_kind:"hex_string",resolver_enabled:false,profiles_enabled:true},analysis:{matched:false,finding_count:0,raw_match_count:0,highest_severity:null,highest_confidence:0},diagnostics:{analysis_warnings:[],deconstruction:{},checker_trace_count:0},artifacts:{behavior_schema:"evm-audit.behavior.v2",state_model_schema:"evm-audit.state_model.v2"},findings:[],warnings:[]}));`,
      "utf8",
    );

    const rpcCalls: string[] = [];
    globalThis.fetch = mock(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const payload = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      rpcCalls.push(payload.method);
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: factoryRpcResult(payload.method, payload.params),
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const config: RunnerConfig = {
      rpcHttpUrl: "http://rpc.local",
      rpcWsUrl: undefined,
      confirmations: 0,
      startBlock: 0,
      rulesPath: "rules/core",
      pythonBin: process.execPath,
      auditorCmd: script,
      maxBlockFetchConcurrency: 2,
      maxAuditWorkers: 1,
      maxWebhookConcurrency: 2,
      analysisTimeoutMs: 1000,
      webhookUrl: undefined,
      webhookAuthHeader: undefined,
      stateDir: path.join(tempRoot, "state"),
      logLevel: "error",
      pollIntervalMs: 5,
      maxReorgDepth: 8,
      maxHistory: 16,
      maxArtifactInlineBytes: 4096,
      maxPersistedArtifactBytes: 1_000_000,
      webhookMaxAttempts: 1,
      rpcMaxAttempts: 1,
      retryBaseDelayMs: 1,
      maxResultCacheEntries: 100,
      maxDeliveredEventEntries: 100,
      maxPendingWebhookEntries: 100,
      uiMode: "json",
    };

    await runRunner(config, { once: true, dryRunWebhook: false, noWebhook: true });

    const checkpointPath = path.join(config.stateDir, "checkpoint.json");
    const checkpoint = JSON.parse(await readFile(checkpointPath, "utf8")) as {
      resultCache: Record<string, unknown>;
    };
    expect(Object.keys(checkpoint.resultCache)).toHaveLength(1);
    expect(rpcCalls.includes("debug_traceBlockByNumber")).toBe(true);

    const artifactPath = path.join(config.stateDir, "artifacts", "1", "1", "0xfactorytx", "deployment.json");
    const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as { detectionSource: string; parentTxTo: string };
    expect(artifact.detectionSource).toBe("trace_create");
    expect(artifact.parentTxTo).toBe("0xfactory");
  });

  test("truncates oversized persisted audit artifacts", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-it-"));
    const script = path.join(tempRoot, "auditor-big.mjs");
    await writeFile(
      script,
      `process.stdout.write(JSON.stringify({ok:true,schema:"evm-audit.api.v2",schema_version:"2.0.0",input:{kind:"hex_string",value:"x"},analysis_context:{analysis_id:"a",created_at:"2026-01-01T00:00:00Z",input_kind:"hex_string",resolver_enabled:false,profiles_enabled:true},analysis:{matched:true,finding_count:1,raw_match_count:1,highest_severity:"high",highest_confidence:0.9},diagnostics:{analysis_warnings:[],deconstruction:{},checker_trace_count:1},artifacts:{behavior_schema:"evm-audit.behavior.v2",state_model_schema:"evm-audit.state_model.v2"},findings:[{rule_id:"demo",summary:"${"x".repeat(2000)}"}],warnings:[]}));`,
      "utf8",
    );

    globalThis.fetch = mock(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const payload = JSON.parse(String(init?.body)) as { method: string; params: unknown[] };
      return new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: rpcResult(payload.method, payload.params),
        }),
        { status: 200 },
      );
    }) as unknown as typeof fetch;

    const config: RunnerConfig = {
      rpcHttpUrl: "http://rpc.local",
      rpcWsUrl: undefined,
      confirmations: 0,
      startBlock: 0,
      rulesPath: "rules/core",
      pythonBin: process.execPath,
      auditorCmd: script,
      maxBlockFetchConcurrency: 2,
      maxAuditWorkers: 1,
      maxWebhookConcurrency: 2,
      analysisTimeoutMs: 1000,
      maxAuditorOutputBytes: 1_000_000,
      webhookUrl: undefined,
      webhookAuthHeader: undefined,
      stateDir: path.join(tempRoot, "state"),
      logLevel: "error",
      pollIntervalMs: 5,
      maxReorgDepth: 8,
      maxHistory: 16,
      maxArtifactInlineBytes: 4096,
      maxPersistedArtifactBytes: 1200,
      webhookMaxAttempts: 1,
      rpcMaxAttempts: 1,
      retryBaseDelayMs: 1,
      maxResultCacheEntries: 100,
      maxDeliveredEventEntries: 100,
      maxPendingWebhookEntries: 100,
      uiMode: "json",
    };

    await runRunner(config, { once: true, dryRunWebhook: false, noWebhook: true });

    const artifactPath = path.join(config.stateDir, "artifacts", "1", "1", "0xtx1", "runtime.json");
    const artifact = JSON.parse(await readFile(artifactPath, "utf8")) as {
      apiJson?: unknown;
      stdout?: string;
      stderr?: string;
      failureReason?: string;
    };
    expect(artifact.apiJson).toBeUndefined();
    expect(artifact.stdout).toBeUndefined();
    expect(artifact.stderr).toBeUndefined();
    expect(artifact.failureReason).toBe("artifact_payload_truncated");
  });
});

function rpcResult(method: string, params: unknown[]): unknown {
  switch (method) {
    case "eth_chainId":
      return "0x1";
    case "eth_blockNumber":
      return "0x1";
    case "eth_getBlockByNumber":
      return {
        number: "0x1",
        hash: "0xblock1",
        parentHash: "0xblock0",
        timestamp: "0x10",
        transactions: [
          {
            hash: "0xtx1",
            from: "0xdeployer",
            to: null,
            input: "0x6000",
          },
        ],
      };
    case "eth_getTransactionReceipt":
      return {
        transactionHash: "0xtx1",
        blockNumber: "0x1",
        contractAddress: "0xcontract1",
        gasUsed: "0x5208",
      };
    case "eth_getCode":
      return params[0] === "0xcontract1" ? "0x60006000" : "0x";
    case "eth_getStorageAt":
      return `0x${"0".repeat(64)}`;
    default:
      throw new Error(`unexpected rpc method ${method}`);
  }
}

function factoryRpcResult(method: string, params: unknown[]): unknown {
  switch (method) {
    case "eth_chainId":
      return "0x1";
    case "eth_blockNumber":
      return "0x1";
    case "eth_getBlockByNumber":
      return {
        number: "0x1",
        hash: "0xblock1",
        parentHash: "0xblock0",
        timestamp: "0x10",
        transactions: [
          {
            hash: "0xfactorytx",
            from: "0xdeployer",
            to: "0xfactory",
            input: "0xabcdef",
          },
        ],
      };
    case "debug_traceBlockByNumber":
      return [
        {
          txHash: "0xfactorytx",
          result: {
            type: "CALL",
            from: "0xdeployer",
            to: "0xfactory",
            input: "0xabcdef",
            calls: [
              {
                type: "CREATE",
                from: "0xfactory",
                to: "0xchild",
                input: "0x60006000",
              },
            ],
          },
        },
      ];
    case "eth_getCode":
      return params[0] === "0xchild" ? "0x60006000" : "0x";
    case "eth_getStorageAt":
      return `0x${"0".repeat(64)}`;
    default:
      throw new Error(`unexpected rpc method ${method}`);
  }
}
