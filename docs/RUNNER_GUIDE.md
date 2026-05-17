# Runner Guide

## Purpose

`runner/` is the production harness for `evm_audit`.

It watches a JSON-RPC node for finalized contract deployments, extracts runtime bytecode, audits it through the Python `api-json` interface, resolves common proxy layouts with live RPC reads, writes local artifacts, and emits structured webhook events.

The Python auditor remains authoritative. The runner does not embed or reimplement detector logic.

## Supported Boundary

The only supported machine boundary between the runner and the Python stack is:

```bash
python3 -m evm_audit --format api-json --no-resolve
```

The runner validates that subprocess output matches `evm-audit.api.v2` before treating an audit as successful.

For deployment discovery it uses:

- top-level contract creation transactions from block data
- internal `CREATE`/`CREATE2` deployments from trace APIs when the node exposes them

## Setup

1. Copy `.env.example` to `.env`
2. Set `RPC_HTTP_URL`
3. Set `RULES_PATH`
4. Optionally set `RPC_WS_URL` and `WEBHOOK_URL`
5. Install Node-side dependencies with `bun install`

## Commands

Continuous mode:

```bash
bun run runner --env-file .env
```

Run one finalized pass and exit:

```bash
bun run runner --env-file .env --once
```

Replay a specific block:

```bash
bun run runner --env-file .env --replay-block 12345
```

Replay a range:

```bash
bun run runner --env-file .env --replay-range 12345:12360
```

Override the rules path:

```bash
bun run runner --env-file .env --rules rules/core
```

Disable outbound webhooks:

```bash
bun run runner --env-file .env --no-webhook
```

`--config` is still accepted as a compatibility alias for `--env-file`.

## Config Reference

- `RPC_HTTP_URL`: required primary JSON-RPC endpoint
- `RPC_WS_URL`: optional websocket endpoint for head notifications
- `CONFIRMATIONS`: finalized depth before a block is processed
- `START_BLOCK`: fallback start block when no checkpoint exists
- `RULES_PATH`: rule file or directory passed to `evm_audit`
- `PYTHON_BIN`: Python executable used for subprocess audits
- `AUDITOR_CMD`: Python-side command fragment, default `-m evm_audit`
- `MAX_BLOCK_FETCH_CONCURRENCY`: bounded receipt-fetch concurrency
- `MAX_AUDIT_WORKERS`: bounded subprocess audit concurrency
- `MAX_WEBHOOK_CONCURRENCY`: bounded retry/replay webhook concurrency
- `ANALYSIS_TIMEOUT_MS`: hard timeout for one audit subprocess
- `WEBHOOK_URL`: optional webhook target
- `WEBHOOK_AUTH_HEADER`: optional header in `name:value` or bearer-token form
- `STATE_DIR`: checkpoint, event ledger, and artifact root
- `LOG_LEVEL`: `debug | info | warn | error`
- `POLL_INTERVAL_MS`: HTTP polling interval and websocket liveness fallback basis
- `MAX_REORG_DEPTH`: how far the runner will search backward for a stable ancestor
- `MAX_HISTORY`: rolling processed-block history length
- `MAX_ARTIFACT_INLINE_BYTES`: inline `rawApiJson` cutoff in webhook payloads
- `WEBHOOK_MAX_ATTEMPTS`: per-event retry attempts before durable pending state
- `RPC_MAX_ATTEMPTS`: per-request RPC retry attempts
- `RETRY_BASE_DELAY_MS`: base backoff multiplier for RPC and webhook retries
- `MAX_RESULT_CACHE_ENTRIES`: hard cap for cached audit results stored in `checkpoint.json`
- `MAX_DELIVERED_EVENT_ENTRIES`: hard cap for delivered webhook ids stored in `checkpoint.json`
- `MAX_PENDING_WEBHOOK_ENTRIES`: hard cap for pending webhook retries stored in `checkpoint.json`
- `UI_MODE`: `auto | tui | plain | json`

### Startup Health Check

The runner probes its dependencies before entering the block-watch loop. Each probe can be individually disabled.

| Variable | Default | What it checks |
|---|---|---|
| `HEALTH_STRICT` | `true` | If `false`, failed probes log a warning but the runner still starts. Set `false` in dev. |
| `HEALTH_PORT` | `9090` | Port for `/health`, `/ready`, `/metrics` HTTP endpoints. |
| `HEALTH_PROBE_RPC` | `true` | Calls `eth_blockNumber` to verify the RPC endpoint is reachable. |
| `HEALTH_PROBE_TRACE_API` | `false` | Calls `debug_traceBlockByNumber`. Enable only when your node supports trace APIs (archive node / premium plan). Without this the runner works in top-level-only mode. |
| `HEALTH_PROBE_PYTHON` | `true` | Runs `python3 -m evm_audit --version` to verify the Python stack is installed. |
| `HEALTH_PROBE_RULES_DIR` | `true` | Checks that `RULES_PATH` exists and contains at least one `.json` rule file. |
| `HEALTH_PROBE_STATE_DIR` | `true` | Creates `STATE_DIR` if missing and verifies write access. |

**Common dev setup** (no archive node, no trace API):
```env
HEALTH_PROBE_TRACE_API=false
HEALTH_STRICT=true
```

**Production setup** (archive node with trace APIs):
```env
HEALTH_PROBE_TRACE_API=true
HEALTH_STRICT=true
```

Probes that are disabled report `skipped` in the health report and do not count as failures.

### Pipeline Step Budget

| Variable | Default | Purpose |
|---|---|---|
| `STEP_BUDGET_MS` | `120000` | Soft wall-clock budget per audit in ms. Pipeline degrades gracefully (skips slow steps) instead of hard-timing-out. |

## State Layout

`STATE_DIR/checkpoint.json` persists:

- finalized checkpoint height
- rolling processed block hashes
- audit result cache
- delivered webhook event ids
- pending webhook retries

The checkpoint is bounded. Large maps are pruned on save so long-running processes do not grow `checkpoint.json` without limit.

Artifacts are written under:

```text
STATE_DIR/artifacts/<chainId>/<blockNumber>/<txHash>/
```

The runner writes:

- `deployment.json` for deployment provenance
- `<targetKind>.json` for each audit target

## Cache Semantics

Audit cache keys include:

- runtime bytecode hash
- target kind
- rules fingerprint
- auditor schema id
- runner version

That means changing rules, schema, or runner cache semantics invalidates old cached results automatically.

## Replay and Idempotency

- The runner processes only finalized blocks in continuous mode.
- Replay modes can re-run past blocks without changing the Python boundary.
- Webhook event ids are deterministic and are also persisted after successful delivery.
- Successful deliveries are skipped on replay and restart.
- Failed deliveries are stored in `pendingWebhookEvents` and retried on the next run.

Webhook delivery is best-effort. It is idempotent at the runner layer, not exactly-once transport.

## Deployment Discovery

The runner prefers a union of:

- top-level `tx.to == null` deployments
- internal factory deployments from `debug_traceBlockByNumber`
- fallback internal factory deployments from `trace_block`

If trace APIs are unavailable, the runner degrades to `top_level_only` mode and still processes direct deployments correctly. Logs expose:

- `txCount`
- `topLevelCreateTxCount`
- `internalCreateCount`
- `traceAvailable`
- `traceMode`

## Proxy Resolution

The runner always audits the deployed runtime bytecode.

Additional behavior:

- EIP-1167 clone shells trigger a second audit on the fixed implementation runtime when code exists.
- ERC-1967 implementation/admin/beacon slots are read at the deployment block tag.
- Beacon proxies attempt `implementation()` resolution at the deployment block tag.
- Beacon and implementation findings remain separate from shell findings and share the same deployment correlation id.

The runner does not guess generic delegatecall implementations. Unresolved delegatecall shells are surfaced explicitly.

Proxy resolution status is reported as one of:

- `resolved`
- `unresolved_safe`
- `unresolved_rpc_error`
- `empty_code`
- `ambiguous`

## Webhook Events

The runner emits these event types:

- `contract_detected`
- `audit_completed`
- `findings_detected`
- `audit_failed`
- `proxy_resolution_failed`

Each payload includes deterministic ids, deployment metadata, bytecode hashes, proxy metadata, and an audit summary. `rawApiJson` is only inlined when it fits under `MAX_ARTIFACT_INLINE_BYTES`; otherwise the payload carries an artifact path.

## Logs and Operator Output

Logs are JSON lines by default.

When `UI_MODE=auto` and stdout is an interactive TTY, the runner switches to a live in-place dashboard instead of printing one line per event. Use `UI_MODE=json` if you want machine logs, or `UI_MODE=plain` to disable the dashboard.

Important fields:

- `correlationId`
- `eventId`
- `targetKind`
- `proxyStatus`
- `failureReason`
- `auditSummary`

`--once` and replay modes also emit an end-of-run summary with blocks scanned, deployments, cache hits, findings, proxy unresolved count, audit failures, and webhook failures.

## Known Failure Modes

- Empty runtime bytecode produces `audit_failed` with `empty_runtime_bytecode`
- Invalid subprocess JSON or schema mismatch produces an audit failure artifact
- Webhook transient failures are retried and then persisted as pending
- WebSocket subscription failure falls back to HTTP polling
- Ambiguous or unresolved proxy layouts remain explicit instead of guessed

## Troubleshooting

If you see repeated `proxy_resolution_failed` events:

- verify the deployment block is still accessible on the node
- check whether the proxy uses a non-standard slot layout
- inspect the stored deployment and target artifacts under `STATE_DIR/artifacts`

If you see `audit_failed` with invalid JSON or nonzero exit:

- run the logged Python command manually against the stored runtime
- verify the current rules path exists and is readable
- confirm the environment still supports `python3 -m evm_audit --format api-json --no-resolve`

If webhook events are missing:

- inspect `pendingWebhookEvents` in `checkpoint.json`
- verify `WEBHOOK_URL` and `WEBHOOK_AUTH_HEADER`
- replay the block or restart the runner after fixing the endpoint
