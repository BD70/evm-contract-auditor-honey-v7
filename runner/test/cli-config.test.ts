import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseCli } from "../src/cli.js";
import { loadConfig } from "../src/config.js";

let tempRoot = "";
let originalMaxAuditWorkers: string | undefined;
let originalRpcHttpUrl: string | undefined;

afterEach(async () => {
  if (originalMaxAuditWorkers === undefined) {
    delete process.env.MAX_AUDIT_WORKERS;
  } else {
    process.env.MAX_AUDIT_WORKERS = originalMaxAuditWorkers;
  }
  originalMaxAuditWorkers = undefined;
  if (originalRpcHttpUrl === undefined) {
    delete process.env.RPC_HTTP_URL;
  } else {
    process.env.RPC_HTTP_URL = originalRpcHttpUrl;
  }
  originalRpcHttpUrl = undefined;
  if (tempRoot) {
    await rm(tempRoot, { recursive: true, force: true });
    tempRoot = "";
  }
});

describe("cli parsing and config", () => {
  test("rejects malformed replay range", () => {
    expect(() => parseCli(["--replay-range", "10"])).toThrow("--replay-range must be <from>:<to>");
  });

  test("rejects oversized replay range span", () => {
    expect(() => parseCli(["--replay-range", "1:10001"])).toThrow("--replay-range exceeds max span");
  });

  test("rejects replay block combined with replay range", () => {
    expect(() => parseCli(["--replay-block", "10", "--replay-range", "1:5"])).toThrow(
      "--replay-block and --replay-range are mutually exclusive",
    );
  });

  test("rejects negative start block", () => {
    expect(() => parseCli(["--start-block", "-1"])).toThrow("--start-block must be >= 0");
  });

  test("loads config defaults and validates concurrency", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-config-"));
    const envFile = path.join(tempRoot, ".env");
    await writeFile(envFile, "MAX_AUDIT_WORKERS=3\n", "utf8");
    originalMaxAuditWorkers = process.env.MAX_AUDIT_WORKERS;
    delete process.env.MAX_AUDIT_WORKERS;
    const config = await loadConfig(tempRoot, { once: true, dryRunWebhook: false, noWebhook: false, envFile });
    expect(config.maxAuditWorkers).toBe(3);
    expect(config.webhookMaxAttempts).toBe(3);
    expect(config.maxAuditorOutputBytes).toBe(5_000_000);
    expect(config.maxPersistedArtifactBytes).toBe(2_000_000);
  });

  test("rejects invalid RPC URL shape", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-config-"));
    const envFile = path.join(tempRoot, ".env");
    await writeFile(envFile, "RPC_HTTP_URL=127.0.0.1:8545\n", "utf8");
    originalRpcHttpUrl = process.env.RPC_HTTP_URL;
    delete process.env.RPC_HTTP_URL;
    await expect(loadConfig(tempRoot, { once: true, dryRunWebhook: false, noWebhook: false, envFile })).rejects.toThrow(
      "RPC_HTTP_URL must start with http:// or https://",
    );
  });
});
