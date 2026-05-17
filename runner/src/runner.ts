import path from "node:path";
import type {
  AuditJob,
  AuditResult,
  AuditSummary,
  AuditTarget,
  CliOptions,
  DetectedDeployment,
  DeploymentScanResult,
  RpcBlock,
  RpcReceipt,
  RunSummary,
  RunnerCheckpoint,
  RunnerConfig,
  RunnerRuntime,
  WebhookEvent,
} from "./types.js";
import { AUDIT_API_SCHEMA } from "./types.js";
import { StateDirectoryLease } from "./lease.js";
import { Logger } from "./logger.js";
import { JsonRpcClient } from "./rpc.js";
import { StateStore, getCachedRecord, markEventDelivered, recordPendingWebhook, rewindCheckpoint, updateHistory } from "./state.js";
import { buildAdditionalAuditTargets, resolveProxy } from "./proxy.js";
import { runAuditJob } from "./auditor.js";
import { postWebhook } from "./webhook.js";
import { compactJsonSize, ensureDir, eventId, hashPath, hexToNumber, normalizeHex, nowIso, sha256Hex, sleep } from "./utils.js";
import { validateBytecode } from "./bytecode_validation.js";
import { runStartupHealthCheck } from "./health.js";
import { startHealthServer, metrics, setLastHealthReport } from "./http_health.js";

const RUNNER_VERSION = "1.0.0";
type FullRpcTransaction = { hash: string; from: string; to: string | null; input?: string; data?: string };

export async function runRunner(config: RunnerConfig, options: CliOptions): Promise<void> {
  await ensureDir(config.stateDir);
  const lease = await StateDirectoryLease.acquire(config.stateDir);
  // Sync fail-safe: even if SIGKILL bypasses the async finally below, this hook
  // runs on every process exit and best-effort removes the lock so the next
  // runner doesn't have to wait for stale-lock detection.
  const path_ = require("node:path") as typeof import("node:path");
  const fs_ = require("node:fs") as typeof import("node:fs");
  const lockPath = path_.join(config.stateDir, ".runner.lock");
  const releaseSync = () => {
    try {
      fs_.rmSync(lockPath, { force: true });
    } catch {}
  };
  process.on("exit", releaseSync);
  let logger: Logger | undefined;
  let onSignal: ((signal: string) => void) | undefined;

  try {
    logger = new Logger(config.logLevel, config.uiMode);
    // ... (rest of the setup)
    const rpc = new JsonRpcClient(
      config.rpcHttpUrl,
      config.rpcWsUrl,
      config.pollIntervalMs,
      config.rpcMaxAttempts,
      config.retryBaseDelayMs,
    );
    const chainId = await rpc.getChainId();
    const state = new StateStore(config.stateDir, {
      maxHistory: config.maxHistory,
      maxResultCacheEntries: config.maxResultCacheEntries,
      maxDeliveredEventEntries: config.maxDeliveredEventEntries,
      maxPendingWebhookEntries: config.maxPendingWebhookEntries,
      maxPersistedArtifactBytes: config.maxPersistedArtifactBytes,
    });
    const checkpoint = await state.load(chainId, config.startBlock);
    const runtime: RunnerRuntime = {
      runnerVersion: RUNNER_VERSION,
      rulesFingerprint: await hashPath(path.resolve(process.cwd(), config.rulesPath)),
      auditorSchema: AUDIT_API_SCHEMA,
    };
    const summary = createSummary();

    await replayPendingWebhookEvents(config, logger, state, checkpoint, options, summary);

    if (options.replayBlock !== undefined) {
      await processRange(config, runtime, logger, rpc, state, checkpoint, options, options.replayBlock, options.replayBlock, summary);
      emitSummary(logger, summary, "runner_replay_complete");
      return;
    }
    if (options.replayRange) {
      await processRange(config, runtime, logger, rpc, state, checkpoint, options, options.replayRange.from, options.replayRange.to, summary);
      emitSummary(logger, summary, "runner_replay_complete");
      return;
    }

    // Startup health check
    const healthReport = await runStartupHealthCheck(config);
    setLastHealthReport(healthReport);
    logger.info("startup_health_check", { ...healthReport });
    if (!healthReport.allOk && config.healthStrict) {
      const failedProbes = Object.entries(healthReport.probes)
        .filter(([, p]) => !p.ok)
        .map(([name, p]) => `${name}: ${p.detail}`)
        .join("; ");
      throw new Error(`Startup health check failed (set HEALTH_STRICT=false to bypass): ${failedProbes}`);
    }

    // HTTP health / metrics server
    startHealthServer(config.healthPort, () => runStartupHealthCheck(config));
    logger.info("http_health_server_started", { port: config.healthPort });

    // Emit runner_started webhook with health report
    await postWebhook(
      config,
      {
        id: eventId([runtime.rulesFingerprint, "runner_started"]),
        type: "runner_started",
        timestamp: nowIso(),
        chainId,
        blockNumber: checkpoint.lastProcessedBlock,
        txHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
        contractAddress: "0x0000000000000000000000000000000000000000",
        deployer: "0x0000000000000000000000000000000000000000",
        correlationId: "runner_started",
        bytecodeHashes: { creation: "0x" },
        healthReport,
      },
      options.dryRunWebhook,
    );

    logger.info("runner_started", {
      chainId,
      startBlock: checkpoint.lastProcessedBlock + 1,
      confirmations: config.confirmations,
      rulesPath: config.rulesPath,
      rulesFingerprint: runtime.rulesFingerprint,
    });

    let stopping = false;
    onSignal = (signal: string) => {
      if (!stopping) {
        stopping = true;
        logger?.info("runner_stopping", { signal });
      }
    };
    process.on("SIGINT", onSignal);
    process.on("SIGTERM", onSignal);

    let latest = await rpc.getLatestBlockNumber();
    for (;;) {
      if (stopping) {
        break;
      }
      const safeBlock = latest - config.confirmations;
      if (safeBlock > checkpoint.lastProcessedBlock) {
        await processRange(
          config,
          runtime,
          logger,
          rpc,
          state,
          checkpoint,
          options,
          checkpoint.lastProcessedBlock + 1,
          safeBlock,
          summary,
        );
      }
      if (options.once || stopping) {
        if (options.once) {
          emitSummary(logger, summary, "runner_once_complete");
        }
        break;
      }
      latest = await rpc.waitForNextLatestBlock(latest);
      await sleep(50);
    }
  } finally {
    if (onSignal) {
      process.off("SIGINT", onSignal);
      process.off("SIGTERM", onSignal);
    }
    await lease.release();
    process.off("exit", releaseSync);
    logger?.close();
  }
}

async function processRange(
  config: RunnerConfig,
  runtime: RunnerRuntime,
  logger: Logger,
  rpc: JsonRpcClient,
  state: StateStore,
  checkpoint: RunnerCheckpoint,
  options: CliOptions,
  fromBlock: number,
  toBlock: number,
  summary: RunSummary,
): Promise<void> {
  for (let blockNumber = fromBlock; blockNumber <= toBlock; blockNumber += 1) {
    const block = await rpc.getBlockByNumber(blockNumber, true);
    await ensureReorgSafeCheckpoint(config, logger, rpc, state, checkpoint, block);
    const scan = await detectDeployments(rpc, block, checkpoint.chainId, config.maxBlockFetchConcurrency);
    summary.scannedBlocks += 1;
    summary.deployments += scan.deployments.length;
    summary.topLevelCreateDeployments += scan.topLevelCreateTxCount;
    summary.internalCreateDeployments += scan.internalCreateCount;
    logger.info("block_scanned", {
      blockNumber,
      txCount: scan.txCount,
      topLevelCreateTxCount: scan.topLevelCreateTxCount,
      internalCreateCount: scan.internalCreateCount,
      deploymentCount: scan.deployments.length,
      traceAvailable: scan.traceAvailable,
      traceMode: scan.traceMode,
    });

    for (const deployment of scan.deployments) {
      await processDeployment(config, runtime, logger, rpc, state, checkpoint, options, deployment, summary);
    }

    const next = updateHistory(
      checkpoint,
      { number: blockNumber, hash: block.hash, parentHash: block.parentHash },
      config.maxHistory,
    );
    Object.assign(checkpoint, next);
    await state.save(checkpoint);
  }
}

async function replayPendingWebhookEvents(
  config: RunnerConfig,
  logger: Logger,
  state: StateStore,
  checkpoint: RunnerCheckpoint,
  options: CliOptions,
  summary: RunSummary,
): Promise<void> {
  const pending = Object.values(checkpoint.pendingWebhookEvents);
  await runBounded(pending, config.maxWebhookConcurrency, async (record) => {
    await emitEvent(config, logger, state, checkpoint, options, record.event, summary);
  });
}

async function ensureReorgSafeCheckpoint(
  config: RunnerConfig,
  logger: Logger,
  rpc: JsonRpcClient,
  state: StateStore,
  checkpoint: RunnerCheckpoint,
  block: RpcBlock,
): Promise<void> {
  const blockNumber = hexToNumber(block.number);
  const previous = checkpoint.history.find((entry) => entry.number === blockNumber - 1);
  if (!previous || previous.hash === block.parentHash) {
    return;
  }
  logger.warn("reorg_detected", {
    atBlock: blockNumber,
    expectedParent: previous.hash,
    actualParent: block.parentHash,
  });
  const history = [...checkpoint.history].sort((a, b) => b.number - a.number);
  let rewindTo = Math.max(config.startBlock - 1, -1);
  for (const entry of history) {
    if (blockNumber - entry.number > config.maxReorgDepth) {
      break;
    }
    const chainBlock = await rpc.getBlockByNumber(entry.number, false);
    if (chainBlock.hash === entry.hash) {
      rewindTo = entry.number;
      break;
    }
  }
  Object.assign(checkpoint, rewindCheckpoint(checkpoint, rewindTo));
  await state.save(checkpoint);
}

async function detectDeployments(
  rpc: JsonRpcClient,
  block: RpcBlock,
  chainId: number,
  concurrency: number,
): Promise<DeploymentScanResult> {
  const blockNumber = hexToNumber(block.number);
  const blockTimestamp = hexToNumber(block.timestamp);
  const fullTransactions = (
    await Promise.all(
      block.transactions.map(async (transaction) => {
        if (typeof transaction !== "string") {
          return transaction;
        }
        return rpc.getTransactionByHash(transaction);
      }),
    )
  ).filter((tx): tx is FullRpcTransaction => tx !== null && tx !== undefined);
  const creations = fullTransactions.filter((tx) => tx.to === null);
  const receipts = new Map<string, RpcReceipt | null>();
  await runBounded(creations, concurrency, async (tx) => {
    receipts.set(tx.hash, await rpc.getTransactionReceipt(tx.hash));
  });
  const topLevelDeployments = creations.flatMap((tx) => {
    const receipt = receipts.get(tx.hash);
    if (!receipt?.contractAddress) {
      return [];
    }
    return [toDetectedDeployment(chainId, block, blockNumber, blockTimestamp, tx, receipt, "top_level_create")];
  });
  const seen = new Set(topLevelDeployments.map((deployment) => deployment.correlationId));

  const traced = await rpc.getInternalDeployments(blockNumber);
  const txIndex = new Map(fullTransactions.map((tx) => [tx.hash, tx]));
  const internalDeployments: DetectedDeployment[] = [];
  if (traced) {
    for (const traceDeployment of traced.deployments) {
      const tx = txIndex.get(traceDeployment.txHash);
      const correlationId = eventId([chainId, blockNumber, traceDeployment.txHash, traceDeployment.createdAddress]);
      if (seen.has(correlationId)) {
        continue;
      }
      seen.add(correlationId);
      internalDeployments.push({
        chainId,
        blockNumber,
        blockHash: block.hash,
        parentHash: block.parentHash,
        blockTimestamp,
        txHash: traceDeployment.txHash,
        deployer: traceDeployment.from || tx?.from || "0x",
        contractAddress: traceDeployment.createdAddress,
        gasUsed: undefined,
        creationBytecode: normalizeHex(traceDeployment.initCode || tx?.input || tx?.data || "0x"),
        creationBytecodeHash: sha256Hex(normalizeHex(traceDeployment.initCode || tx?.input || tx?.data || "0x")),
        correlationId,
        detectionSource: traceDeployment.kind === "create2" ? "trace_create2" : "trace_create",
        parentTxTo: tx?.to ?? traceDeployment.to ?? null,
      });
    }
  }
  return {
    deployments: [...topLevelDeployments, ...internalDeployments],
    txCount: fullTransactions.length,
    topLevelCreateTxCount: topLevelDeployments.length,
    internalCreateCount: internalDeployments.length,
    traceMode: traced?.mode ?? "top_level_only",
    traceAvailable: Boolean(traced),
  };
}

function toDetectedDeployment(
  chainId: number,
  block: RpcBlock,
  blockNumber: number,
  blockTimestamp: number,
  tx: FullRpcTransaction,
  receipt: RpcReceipt,
  detectionSource: DetectedDeployment["detectionSource"],
): DetectedDeployment {
  const creationBytecode = normalizeHex(tx.input ?? tx.data ?? "0x");
  const contractAddress = receipt.contractAddress!;
  return {
    chainId,
    blockNumber,
    blockHash: block.hash,
    parentHash: block.parentHash,
    blockTimestamp,
    txHash: tx.hash,
    deployer: tx.from,
    contractAddress,
    gasUsed: receipt.gasUsed,
    creationBytecode,
    creationBytecodeHash: sha256Hex(creationBytecode),
    correlationId: eventId([chainId, blockNumber, tx.hash, contractAddress]),
    detectionSource,
    parentTxTo: tx.to,
  };
}

async function processDeployment(
  config: RunnerConfig,
  runtime: RunnerRuntime,
  logger: Logger,
  rpc: JsonRpcClient,
  state: StateStore,
  checkpoint: RunnerCheckpoint,
  options: CliOptions,
  deployment: DetectedDeployment,
  summary: RunSummary,
): Promise<void> {
  const runtimeBytecode = normalizeHex(await rpc.getCode(deployment.contractAddress, deployment.blockNumber));
  const proxy = await resolveProxy(rpc, deployment.contractAddress, runtimeBytecode, deployment.blockNumber);
  const runtimeHash = sha256Hex(runtimeBytecode);
  const baseTarget: AuditTarget = {
    chainId: deployment.chainId,
    correlationId: deployment.correlationId,
    blockNumber: deployment.blockNumber,
    blockHash: deployment.blockHash,
    blockTimestamp: deployment.blockTimestamp,
    txHash: deployment.txHash,
    contractAddress: deployment.contractAddress,
    deployer: deployment.deployer,
    gasUsed: deployment.gasUsed,
    creationBytecodeHash: deployment.creationBytecodeHash,
    creationBytecode: deployment.creationBytecode,
    runtimeBytecode,
    runtimeBytecodeHash: runtimeHash,
    targetKind: proxy.detected ? "proxy_shell" : "runtime",
    targetAddress: deployment.contractAddress,
    proxy,
  };

  await state.writeDeploymentArtifact(deployment, {
    correlationId: deployment.correlationId,
    contractAddress: deployment.contractAddress,
    deployer: deployment.deployer,
    gasUsed: deployment.gasUsed,
    detectionSource: deployment.detectionSource,
    parentTxTo: deployment.parentTxTo,
    proxy,
    runtimeBytecodeHash: runtimeHash,
  });

  await emitEvent(
    config,
    logger,
    state,
    checkpoint,
    options,
    {
      id: eventId([deployment.correlationId, "contract_detected"]),
      type: "contract_detected",
      timestamp: nowIso(),
      chainId: deployment.chainId,
      blockNumber: deployment.blockNumber,
      txHash: deployment.txHash,
      contractAddress: deployment.contractAddress,
      deployer: deployment.deployer,
      correlationId: deployment.correlationId,
      targetKind: baseTarget.targetKind,
      bytecodeHashes: {
        creation: deployment.creationBytecodeHash,
        runtime: runtimeHash,
      },
      proxy,
      detectionSource: deployment.detectionSource,
    },
    summary,
  );

  const bytecodeValidation = validateBytecode(runtimeBytecode);
  if (!bytecodeValidation.shouldAudit) {
    summary.auditFailures += 1;
    logger.info("skipping bytecode pre-validation", {
      kind: bytecodeValidation.kind,
      reason: bytecodeValidation.reason,
      address: deployment.contractAddress,
    });
    await emitEvent(
      config,
      logger,
      state,
      checkpoint,
      options,
      {
        id: eventId([deployment.correlationId, "audit_failed", bytecodeValidation.kind]),
        type: "audit_failed",
        timestamp: nowIso(),
        chainId: deployment.chainId,
        blockNumber: deployment.blockNumber,
        txHash: deployment.txHash,
        contractAddress: deployment.contractAddress,
        deployer: deployment.deployer,
        correlationId: deployment.correlationId,
        targetKind: baseTarget.targetKind,
        bytecodeHashes: { creation: deployment.creationBytecodeHash, runtime: runtimeHash },
        proxy,
        failureReason: bytecodeValidation.reason,
      },
      summary,
    );
    return;
  }

  const targets = [baseTarget, ...(await buildAdditionalAuditTargets(rpc, baseTarget))].map((target) => ({
    ...target,
    runtimeBytecodeHash: target.runtimeBytecodeHash || sha256Hex(target.runtimeBytecode),
  }));
  summary.auditTargets += targets.length;

  if (proxy.detected && !proxy.implementationResolved) {
    summary.proxyUnresolved += 1;
    await emitEvent(
      config,
      logger,
      state,
      checkpoint,
      options,
      {
        id: eventId([deployment.correlationId, "proxy_resolution_failed"]),
        type: "proxy_resolution_failed",
        timestamp: nowIso(),
        chainId: deployment.chainId,
        blockNumber: deployment.blockNumber,
        txHash: deployment.txHash,
        contractAddress: deployment.contractAddress,
        deployer: deployment.deployer,
        correlationId: deployment.correlationId,
        targetKind: baseTarget.targetKind,
        bytecodeHashes: { creation: deployment.creationBytecodeHash, runtime: runtimeHash },
        proxy,
        failureReason: proxy.unresolvedReason,
      },
      summary,
    );
  }

  await runBounded(targets, config.maxAuditWorkers, async (target) => {
    const cacheKey = buildCacheKey(runtime, target);
    const cached = getCachedRecord(checkpoint, cacheKey);
    let result: AuditResult;
    if (cached?.apiJson || cached?.artifactPath) {
      summary.cacheHits += 1;
      result = {
        ok: true,
        cached: true,
        cacheKey,
        target,
        startedAt: nowIso(),
        completedAt: nowIso(),
        durationMs: 0,
        apiJson: cached.apiJson,
        artifactPath: cached.artifactPath,
      };
    } else {
      metrics.queueDepth += 1;
      const job: AuditJob = {
        cacheKey,
        target,
        eofFormat: bytecodeValidation.kind === "eof",
        proxyShell: bytecodeValidation.kind === "skip_proxy_shell",
      };
      result = await runAuditJob(config, runtime, job);
      metrics.queueDepth -= 1;
      result.artifactPath = await state.writeAuditArtifact(result);
      if (result.ok && result.apiJson) {
        checkpoint.resultCache[cacheKey] = {
          createdAt: nowIso(),
          apiJson: result.apiJson,
          artifactPath: result.artifactPath,
          targetAddress: target.targetAddress,
          targetKind: target.targetKind,
          rulesFingerprint: runtime.rulesFingerprint,
          runnerVersion: runtime.runnerVersion,
          auditorSchema: runtime.auditorSchema,
        };
      }
      await state.save(checkpoint);
    }
    if (!result.ok) {
      summary.auditFailures += 1;
      metrics.auditErrorsTotal += 1;
    } else {
      metrics.auditsTotal += 1;
    }
    if (result.apiJson?.analysis.matched) {
      summary.findings += result.apiJson.analysis.finding_count;
    }
    await emitAuditEvents(config, logger, state, checkpoint, options, result, summary);
  });
}

function buildCacheKey(runtime: RunnerRuntime, target: AuditTarget): string {
  return sha256Hex(
    [
      String(target.chainId),
      target.runtimeBytecodeHash,
      target.targetKind,
      runtime.rulesFingerprint,
      runtime.auditorSchema,
      runtime.runnerVersion,
    ].join(":"),
  );
}

async function emitAuditEvents(
  config: RunnerConfig,
  logger: Logger,
  state: StateStore,
  checkpoint: RunnerCheckpoint,
  options: CliOptions,
  result: AuditResult,
  summary: RunSummary,
): Promise<void> {
  const auditSummary = toAuditSummary(result.apiJson);
  const shouldInline = result.apiJson && compactJsonSize(result.apiJson) <= config.maxArtifactInlineBytes;
  const baseEvent: WebhookEvent = {
    id: eventId([result.target.correlationId, "audit_completed", result.target.targetKind]),
    type: result.ok ? "audit_completed" : "audit_failed",
    timestamp: nowIso(),
    chainId: result.target.chainId,
    blockNumber: result.target.blockNumber,
    txHash: result.target.txHash,
    contractAddress: result.target.contractAddress,
    deployer: result.target.deployer,
    correlationId: result.target.correlationId,
    targetKind: result.target.targetKind,
    bytecodeHashes: {
      creation: result.target.creationBytecodeHash,
      runtime: result.target.runtimeBytecodeHash,
    },
    proxy: result.target.proxy,
    auditSummary,
    artifactPath: result.artifactPath,
    rawApiJson: shouldInline ? result.apiJson : undefined,
    failureReason: result.failureReason,
    auditorExitCode: result.ok ? undefined : result.auditorExitCode ?? null,
    auditorStderrTail: result.ok ? undefined : tailString(result.stderr, 480),
  };
  await emitEvent(config, logger, state, checkpoint, options, baseEvent, summary);
  if (result.ok && result.apiJson?.analysis.matched) {
    await emitEvent(
      config,
      logger,
      state,
      checkpoint,
      options,
      {
        ...baseEvent,
        id: eventId([result.target.correlationId, "findings_detected", result.target.targetKind]),
        type: "findings_detected",
      },
      summary,
    );
  }
}

function toAuditSummary(apiJson?: AuditResult["apiJson"]): AuditSummary | undefined {
  if (!apiJson) {
    return undefined;
  }
  return {
    matched: apiJson.analysis.matched,
    findingCount: apiJson.analysis.finding_count,
    highestSeverity: apiJson.analysis.highest_severity,
    highestConfidence: apiJson.analysis.highest_confidence,
    ruleIds: apiJson.findings.map((finding) => finding.rule_id),
  };
}

async function emitEvent(
  config: RunnerConfig,
  logger: Logger,
  state: StateStore,
  checkpoint: RunnerCheckpoint,
  options: CliOptions,
  event: WebhookEvent,
  summary: RunSummary,
): Promise<void> {
  if (checkpoint.deliveredEvents[event.id]) {
    logger.debug("event_skipped_duplicate", {
      eventId: event.id,
      type: event.type,
    });
    return;
  }

  logger.info(event.type, {
    eventId: event.id,
    correlationId: event.correlationId,
    blockNumber: event.blockNumber,
    txHash: event.txHash,
    contractAddress: event.contractAddress,
    targetKind: event.targetKind,
    proxyStatus: event.proxy?.status,
    failureReason: event.failureReason,
    auditorExitCode: event.auditorExitCode,
    auditorStderrTail: event.auditorStderrTail,
    detectionSource: event.detectionSource,
    auditSummary: event.auditSummary,
  });

  if (options.noWebhook) {
    return;
  }
  try {
    await postWebhook(config, event, options.dryRunWebhook);
    if (!options.dryRunWebhook) {
      markEventDelivered(checkpoint, event);
      await state.save(checkpoint);
    }
  } catch (error) {
    summary.webhookFailures += 1;
    const failureReason = error instanceof Error ? error.message : String(error);
    recordPendingWebhook(checkpoint, event, failureReason);
    await state.save(checkpoint);
    logger.error("webhook_failed", {
      eventId: event.id,
      error: failureReason,
    });
  }
}

function tailString(value: string | undefined, max: number): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  // Keep the LAST `max` chars — that's where the Python traceback ends up.
  return trimmed.length > max ? `…${trimmed.slice(-max)}` : trimmed;
}

function createSummary(): RunSummary {
  return {
    scannedBlocks: 0,
    deployments: 0,
    topLevelCreateDeployments: 0,
    internalCreateDeployments: 0,
    auditTargets: 0,
    cacheHits: 0,
    findings: 0,
    proxyUnresolved: 0,
    auditFailures: 0,
    webhookFailures: 0,
  };
}

function emitSummary(logger: Logger, summary: RunSummary, message: string): void {
  logger.info(message, { ...summary });
}

async function runBounded<T>(items: T[], concurrency: number, worker: (item: T) => Promise<void>): Promise<void> {
  const limit = Math.max(1, concurrency);
  let index = 0;
  const runners = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (index < items.length) {
      const current = items[index];
      index += 1;
      await worker(current);
    }
  });
  await Promise.all(runners);
}
