import path from "node:path";
import { readFile } from "node:fs/promises";
import { validateCheckpointDocument } from "./schemas.js";
import type { AuditResult, CachedAuditRecord, PendingWebhookRecord, RunnerCheckpoint, WebhookEvent } from "./types.js";
import { compactJsonSize, ensureDir, nowIso, writeJsonFile } from "./utils.js";

export class StateStore {
  private readonly checkpointPath: string;
  private readonly artifactsDir: string;
  // Serialize all checkpoint writes through a single promise chain. Parallel
  // audit + webhook handlers used to call save() concurrently, which raced on
  // tmp-file creation/rename and produced ENOENT crashes. With this queue,
  // each save runs to completion before the next starts; the file always
  // reflects the latest in-memory checkpoint after the chain drains.
  private saveChain: Promise<void> = Promise.resolve();

  constructor(
    private readonly stateDir: string,
    private readonly limits: {
      maxHistory: number;
      maxResultCacheEntries: number;
      maxDeliveredEventEntries: number;
      maxPendingWebhookEntries: number;
      maxPersistedArtifactBytes: number;
    },
  ) {
    this.checkpointPath = path.join(stateDir, "checkpoint.json");
    this.artifactsDir = path.join(stateDir, "artifacts");
  }

  async load(chainId: number, startBlock: number): Promise<RunnerCheckpoint> {
    await ensureDir(this.stateDir);
    await ensureDir(this.artifactsDir);
    const fallback = createEmptyCheckpoint(chainId, startBlock);
    const checkpoint = await this.readCheckpointOrFallback(fallback);
    if (checkpoint.chainId !== chainId) {
      return fallback;
    }
    checkpoint.resultCache ??= {};
    checkpoint.history ??= [];
    checkpoint.deliveredEvents ??= {};
    checkpoint.pendingWebhookEvents ??= {};
    return checkpoint;
  }

  private async readCheckpointOrFallback(fallback: RunnerCheckpoint): Promise<RunnerCheckpoint> {
    try {
      const content = await readFile(this.checkpointPath, "utf8");
      return validateCheckpointDocument(JSON.parse(content));
    } catch (error) {
      if ((error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
        return fallback;
      }
      throw error;
    }
  }

  async save(checkpoint: RunnerCheckpoint): Promise<void> {
    const next = this.saveChain.then(() => this.saveNow(checkpoint));
    // Swallow chain errors so a single failure doesn't poison subsequent saves.
    this.saveChain = next.catch(() => undefined);
    return next;
  }

  private async saveNow(checkpoint: RunnerCheckpoint): Promise<void> {
    checkpoint.updatedAt = nowIso();
    checkpoint.history = checkpoint.history.slice(-this.limits.maxHistory);
    checkpoint.resultCache = pruneRecordMap(checkpoint.resultCache, this.limits.maxResultCacheEntries, (entry) => entry.createdAt);
    checkpoint.deliveredEvents = pruneRecordMap(
      checkpoint.deliveredEvents,
      this.limits.maxDeliveredEventEntries,
      (entry) => entry.deliveredAt,
    );
    checkpoint.pendingWebhookEvents = pruneRecordMap(
      checkpoint.pendingWebhookEvents,
      this.limits.maxPendingWebhookEntries,
      (entry) => entry.lastFailedAt,
    );
    await writeJsonFile(this.checkpointPath, checkpoint);
  }

  async writeAuditArtifact(result: AuditResult): Promise<string> {
    const filePath = path.join(
      this.artifactsDir,
      String(result.target.chainId),
      String(result.target.blockNumber),
      result.target.txHash,
      `${result.target.targetKind}.json`,
    );
    await writeJsonFile(filePath, sanitizeAuditResultForPersistence(result, this.limits.maxPersistedArtifactBytes));
    return filePath;
  }

  async writeDeploymentArtifact(
    deployment: {
      chainId: number;
      blockNumber: number;
      txHash: string;
      creationBytecodeHash: string;
      creationBytecode: string;
    },
    payload: unknown,
  ): Promise<string> {
    const filePath = path.join(
      this.artifactsDir,
      String(deployment.chainId),
      String(deployment.blockNumber),
      deployment.txHash,
      "deployment.json",
    );
    await writeJsonFile(filePath, {
      creationBytecodeHash: deployment.creationBytecodeHash,
      creationBytecode: deployment.creationBytecode,
      ...((payload as Record<string, unknown>) ?? {}),
    });
    return filePath;
  }
}

export function createEmptyCheckpoint(chainId: number, startBlock: number): RunnerCheckpoint {
  return {
    checkpointVersion: "2",
    chainId,
    lastProcessedBlock: Math.max(startBlock - 1, -1),
    updatedAt: nowIso(),
    history: [],
    resultCache: {},
    deliveredEvents: {},
    pendingWebhookEvents: {},
  };
}

export function updateHistory(
  checkpoint: RunnerCheckpoint,
  block: { number: number; hash: string; parentHash: string },
  maxHistory: number,
): RunnerCheckpoint {
  const history = checkpoint.history
    .filter((entry) => entry.number !== block.number)
    .concat([{ number: block.number, hash: block.hash, parentHash: block.parentHash, processedAt: nowIso() }])
    .slice(-maxHistory);
  return { ...checkpoint, lastProcessedBlock: block.number, updatedAt: nowIso(), history };
}

export function rewindCheckpoint(checkpoint: RunnerCheckpoint, toBlock: number): RunnerCheckpoint {
  return {
    ...checkpoint,
    lastProcessedBlock: toBlock,
    updatedAt: nowIso(),
    history: checkpoint.history.filter((entry) => entry.number <= toBlock),
  };
}

export function markEventDelivered(checkpoint: RunnerCheckpoint, event: WebhookEvent): void {
  checkpoint.deliveredEvents[event.id] = {
    deliveredAt: nowIso(),
    type: event.type,
  };
  delete checkpoint.pendingWebhookEvents[event.id];
}

export function recordPendingWebhook(
  checkpoint: RunnerCheckpoint,
  event: WebhookEvent,
  failureReason: string,
): PendingWebhookRecord {
  const previous = checkpoint.pendingWebhookEvents[event.id];
  const next: PendingWebhookRecord = {
    event,
    firstFailedAt: previous?.firstFailedAt ?? nowIso(),
    lastFailedAt: nowIso(),
    failureReason,
    attempts: (previous?.attempts ?? 0) + 1,
  };
  checkpoint.pendingWebhookEvents[event.id] = next;
  return next;
}

export function getCachedRecord(checkpoint: RunnerCheckpoint, cacheKey: string): CachedAuditRecord | undefined {
  return checkpoint.resultCache[cacheKey];
}

function pruneRecordMap<T extends Record<string, any>>(
  records: T,
  maxEntries: number,
  getTimestamp: (entry: T[string]) => string | undefined,
): T {
  const entries = Object.entries(records);
  if (entries.length <= maxEntries) {
    return records;
  }
  const kept = entries
    .sort((a, b) => compareTimestamp(getTimestamp(a[1]), getTimestamp(b[1])))
    .slice(entries.length - maxEntries);
  return Object.fromEntries(kept) as T;
}

function compareTimestamp(left: string | undefined, right: string | undefined): number {
  const leftTs = Date.parse(left ?? "") || 0;
  const rightTs = Date.parse(right ?? "") || 0;
  return leftTs - rightTs;
}

function sanitizeAuditResultForPersistence(result: AuditResult, maxBytes: number): AuditResult {
  const sanitized: AuditResult = {
    ...result,
    apiJson: result.apiJson,
    artifact: result.artifact ? { ...result.artifact } : undefined,
  };
  if (compactJsonSize(sanitized) <= maxBytes) {
    return sanitized;
  }

  if (sanitized.artifact) {
    delete sanitized.artifact.stdout;
    delete sanitized.artifact.stderr;
  }
  delete sanitized.stdout;
  delete sanitized.stderr;
  if (compactJsonSize(sanitized) <= maxBytes) {
    return sanitized;
  }

  delete sanitized.apiJson;
  sanitized.failureReason = sanitized.failureReason ?? "artifact_payload_truncated";
  return sanitized;
}
