# EVM Auditor — Admin Panel

Next.js (App Router) + Chakra UI v3 admin console for the EVM Contract Auditor.
Wraps the runner and the Python CLIs (`evm_audit`, `evm_rule`) behind a single web UI.

## Features

- **Runner control** — spawn/stop/restart the production runner as a managed child process
  (`bun runner/src/cli.ts`). UI mode is forced to `json` so every log line is parsed.
- **Live logs (SSE)** — `/api/runner/stream` streams parsed log lines + runner state.
- **Findings explorer** — every audit result lands in a local SQLite DB. Filter by severity,
  source, rule, chain, free-text search; click into a finding for a 6-tab detail view
  (Summary, Evidence, Counter-evidence, Witness, Judge, Raw JSON).
- **Manual audits** — three input modes: paste runtime hex, drag-drop file (raw or Solidity
  artifact JSON), or fetch by address via configured/custom RPC. Live progress stream.
- **Detector workbench** — list every rule in `rules/core/`. Inspect the JSON, run
  `evm_rule explain` against arbitrary audit JSON, run corpus tests.
- **Chains** — `/chains` manages a `chains.json` (CRUD) defining multiple EVM chains.
  Each enabled chain is orchestrated as its own runner child with an isolated
  state dir (`STATE_DIR/<slug>`), lock, checkpoint and health port; start/stop/
  restart per chain. With no `chains.json` the panel falls back to the single
  `.env`-driven runner.
- **Config editor** — schema-driven form over the runner `.env`. Preview diff, save,
  optionally restart runner.
- **LLM judge** — toggle and re-judge from finding detail; secrets redacted in the UI.
- **Auth** — HTTP Basic Auth via `PANEL_USER` / `PANEL_PASS`.

## Quick start

```bash
cd panel
bun install
cp .env.example .env
# edit PANEL_USER / PANEL_PASS
bun run db:migrate
PANEL_USER=admin PANEL_PASS=changeme bun dev
```

Open <http://localhost:3000>, accept the basic-auth prompt.

## Architecture

- The panel does not embed any audit logic. It spawns:
  - `bun runner/src/cli.ts` for live monitoring.
  - `python3 -m evm_audit --format api-json` for ad-hoc audits.
  - `python3 -m evm_rule explain|test` for the detector workbench.
- All state is in `panel/data/findings.db` (SQLite via Drizzle). The runner's
  `STATE_DIR/artifacts/**` is watched with chokidar and ingested into the DB.
- Live updates use SSE everywhere (`/api/runner/stream`, `/api/findings/stream`,
  `/api/audits/stream/[runId]`). No WS, no Redis.

## Environment

| Var | Purpose |
|---|---|
| `PANEL_USER` / `PANEL_PASS` | HTTP Basic Auth credentials (required). |
| `REPO_ROOT` | Override autodetected repo root (default: parent of `panel/`). |
| `RUNNER_ENV_FILE` | Path to the runner's `.env` (default: `<REPO_ROOT>/.env`). |
| `STATE_DIR_OVERRIDE` | Override autodetected runner `STATE_DIR`. |
| `PANEL_DB_PATH` | Override SQLite path (default: `panel/data/findings.db`). |
| `HEALTH_PORT` | Runner health port to poll (default: `9090`). |

## Scripts

- `bun dev` — Next dev server.
- `bun build` / `bun start` — production build.
- `bun run db:migrate` — apply DB schema (idempotent).
- `bun run type-check` — TypeScript-only check.

## Notes

- Single-runner assumption: the panel manages exactly one runner child at a time.
  If `STATE_DIR/.runner.lock` is held by an external process, Start returns 409.
- Secret env values (`WEBHOOK_AUTH_HEADER`, `EVM_LLM_API_KEY`, etc.) are returned
  masked from `/api/config`; the panel preserves the existing value unless you
  explicitly type a new one.
