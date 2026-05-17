import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { StateDirectoryLease } from "../src/lease.js";
import { StateStore, markEventDelivered, recordPendingWebhook, rewindCheckpoint, updateHistory } from "../src/state.js";
import type { RunnerCheckpoint } from "../src/types.js";

let tempRoot = "";

afterEach(async () => {
  if (tempRoot) {
    await rm(tempRoot, { recursive: true, force: true });
    tempRoot = "";
  }
});

function baseCheckpoint(): RunnerCheckpoint {
  return {
    checkpointVersion: "2",
    chainId: 1,
    lastProcessedBlock: 9,
    updatedAt: "2026-01-01T00:00:00.000Z",
    history: [
      { number: 8, hash: "0x8", parentHash: "0x7", processedAt: "2026-01-01T00:00:00.000Z" },
      { number: 9, hash: "0x9", parentHash: "0x8", processedAt: "2026-01-01T00:00:00.000Z" },
    ],
    resultCache: {},
    deliveredEvents: {},
    pendingWebhookEvents: {},
  };
}

describe("checkpoint state", () => {
  test("updates block history and processed height", () => {
    const next = updateHistory(baseCheckpoint(), { number: 10, hash: "0xa", parentHash: "0x9" }, 8);
    expect(next.lastProcessedBlock).toBe(10);
    expect(next.history.at(-1)?.hash).toBe("0xa");
  });

  test("rewinds checkpoint on reorg", () => {
    const rewound = rewindCheckpoint(baseCheckpoint(), 8);
    expect(rewound.lastProcessedBlock).toBe(8);
    expect(rewound.history).toHaveLength(1);
  });

  test("tracks delivered and pending webhook ledger", () => {
    const checkpoint = baseCheckpoint();
    const event = {
      id: "event-1",
      type: "audit_completed" as const,
      timestamp: "2026-01-01T00:00:00.000Z",
      chainId: 1,
      blockNumber: 10,
      txHash: "0xtx",
      contractAddress: "0xcontract",
      deployer: "0xdeployer",
      correlationId: "corr",
      bytecodeHashes: { creation: "c", runtime: "r" },
    };
    recordPendingWebhook(checkpoint, event, "webhook http 500");
    expect(checkpoint.pendingWebhookEvents[event.id]?.attempts).toBe(1);
    markEventDelivered(checkpoint, event);
    expect(checkpoint.deliveredEvents[event.id]?.type).toBe("audit_completed");
    expect(checkpoint.pendingWebhookEvents[event.id]).toBeUndefined();
  });

  test("prunes large checkpoint maps on save", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-state-"));
    const store = new StateStore(tempRoot, {
      maxHistory: 8,
      maxResultCacheEntries: 2,
      maxDeliveredEventEntries: 2,
      maxPendingWebhookEntries: 1,
      maxPersistedArtifactBytes: 1024 * 1024,
    });
    const checkpoint = baseCheckpoint();
    checkpoint.resultCache = {
      a: { createdAt: "2026-01-01T00:00:00.000Z", targetAddress: "0x1", targetKind: "runtime", rulesFingerprint: "r", runnerVersion: "1", auditorSchema: "evm-audit.api.v2" },
      b: { createdAt: "2026-01-02T00:00:00.000Z", targetAddress: "0x2", targetKind: "runtime", rulesFingerprint: "r", runnerVersion: "1", auditorSchema: "evm-audit.api.v2" },
      c: { createdAt: "2026-01-03T00:00:00.000Z", targetAddress: "0x3", targetKind: "runtime", rulesFingerprint: "r", runnerVersion: "1", auditorSchema: "evm-audit.api.v2" },
    };
    checkpoint.deliveredEvents = {
      a: { deliveredAt: "2026-01-01T00:00:00.000Z", type: "audit_completed" },
      b: { deliveredAt: "2026-01-02T00:00:00.000Z", type: "audit_completed" },
      c: { deliveredAt: "2026-01-03T00:00:00.000Z", type: "audit_completed" },
    };
    checkpoint.pendingWebhookEvents = {
      a: { event: { id: "a", type: "audit_failed", timestamp: "2026-01-01T00:00:00.000Z", chainId: 1, blockNumber: 1, txHash: "0x1", contractAddress: "0x1", deployer: "0x1", correlationId: "a", bytecodeHashes: { creation: "a" } }, firstFailedAt: "2026-01-01T00:00:00.000Z", lastFailedAt: "2026-01-01T00:00:00.000Z", failureReason: "x", attempts: 1 },
      b: { event: { id: "b", type: "audit_failed", timestamp: "2026-01-02T00:00:00.000Z", chainId: 1, blockNumber: 1, txHash: "0x2", contractAddress: "0x2", deployer: "0x2", correlationId: "b", bytecodeHashes: { creation: "b" } }, firstFailedAt: "2026-01-02T00:00:00.000Z", lastFailedAt: "2026-01-02T00:00:00.000Z", failureReason: "x", attempts: 1 },
    };
    await store.save(checkpoint);
    const saved = JSON.parse(await readFile(path.join(tempRoot, "checkpoint.json"), "utf8")) as RunnerCheckpoint;
    expect(Object.keys(saved.resultCache)).toEqual(["b", "c"]);
    expect(Object.keys(saved.deliveredEvents)).toEqual(["b", "c"]);
    expect(Object.keys(saved.pendingWebhookEvents)).toEqual(["b"]);
  });
});

describe("state directory lease", () => {
  test("prevents concurrent runner ownership of the same state directory", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-lock-"));
    const first = await StateDirectoryLease.acquire(tempRoot);
    await expect(StateDirectoryLease.acquire(tempRoot)).rejects.toThrow("state directory is already in use");
    await first.release();
    const second = await StateDirectoryLease.acquire(tempRoot);
    await second.release();
  });

  test("includes lock owner details in contention error when lock owner is alive", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-lock-"));
    const first = await StateDirectoryLease.acquire(tempRoot);
    await expect(StateDirectoryLease.acquire(tempRoot)).rejects.toThrow(`pid=${process.pid}`);
    await first.release();
  });

  test("acquires lock even if stale lock file exists", async () => {
    tempRoot = await mkdtemp(path.join(os.tmpdir(), "runner-lock-"));
    const lockPath = path.join(tempRoot, ".runner.lock");
    // Use a PID that is extremely unlikely to exist
    await writeFile(lockPath, JSON.stringify({ pid: 99999, acquiredAt: "2026-01-01T00:00:00.000Z" }), "utf8");
    const lease = await StateDirectoryLease.acquire(tempRoot);
    await lease.release();
  });
});
