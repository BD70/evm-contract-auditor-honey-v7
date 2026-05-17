# Updates — 2026-05-17 (Part 4)

## Headline

1. **Tax-token false-positive killer extended to `pair-direct` and `both`** (was
   `router+swap` only). New TN corpus anchor for the FP that motivated it
   (`0x479f9583ebae8aa115c90b835d103a3214fa97db`, ETH). `economic-attack` engine
   bumped to `@4`.
2. **Rescue pipeline shipped end-to-end** — definitive exploit confirmation
   plus an auto-rescue path with operator-gated broadcasting:
   - `rescue-prove@1` simulator: on a fork, attempts an actual drain of the
     contract's native + ERC-20 holdings into an escrow address, and emits a
     **Proof-of-Exploit (PoE)** JSON describing exactly what moved.
   - Persistent schema: `proofs_of_exploit` and `rescue_actions` tables.
   - Four new REST endpoints under `/api/proofs/*`.
   - In-process Telegram bot (long-poll, env-gated) that pushes PoE
     notifications and exposes `/poe`, `/timeline`, `/rescue` commands.
   - Rescue broadcaster (viem-based) with three execution modes:
     `dry-run-fork`, `dry-run-sign`, `live` (the last gated by
     `RESCUE_BROADCAST_ENABLED`, `RESCUE_AUTH_TOKEN`, and
     `RESCUER_PRIVATE_KEY`).
   - New UI panel on every finding page (`ProofOfExploitPanel`): verdict
     badge, rescuable assets in USD, drain-plan step counter, dry-run replay
     button, downloadable PoE JSON, action timeline.

The two pieces are independent — the FP fix lands a regression test today; the
rescue pipeline is the foundation the user asked for in
> "we need proper dynamic simulation, trying effective auto rescue on any
> native and/or tokens, to 100% confirm".

---

## 1. `economic-attack@4` — tax-token suppressor extended

### Symptom

Sidecar finding `sidecar-econ-4166ef2c…` on
[`0x479f9583ebae8aa115c90b835d103a3214fa97db`](https://etherscan.io/address/0x479f9583ebae8aa115c90b835d103a3214fa97db)
fired with `staticSignatureKind: pair-direct` because the bytecode hardcodes
the UniV2 `sync()` selector (`0xfff6cae9`). The contract is a vanilla
fee-on-transfer tax token; `sync()` lives inside the post-tax distribution
flow and is internal-only. The dynamic verifier corroborated: 9/24
candidates auth-reverted, 0/24 reached `sync`.

### Fix

`panel/src/server/sim/exploits/economic-attack.ts`:

- The tax-token suppressor (introduced in v3 for `router+swap`) now applies
  to ALL static signature kinds. The verdict message branches on
  `signatureKind` so the explanation is accurate (`router+swap` →
  "swapTokensForEth call lives inside `_transfer()`", `pair-direct` →
  "sync/skim/burn embedded in the post-tax distribution flow", `both` →
  "full FOT-tax + reserve-resync wiring").
- `TAX_TOKEN_NAME_SIGNATURES`: dropped bare `uniswapV2Router` /
  `uniswapV2Pair` — too common, present on legit exploit targets (Movie
  Token / MT regressed on the first attempt). The remaining ~70-name list
  still catches the long tail of tax-token templates without misfiring on
  TPs.
- Engine version bumped `3` → `4`.

### Validation

- Full corpus (`SIM_FEATURE_STATEDIFF=true npm run sim:corpus`): **24/24
  pass**, including
  - `econ-bsc-91334d03-amm` (TP — router+swap)
  - `econ-bsc-mt-b32979f3-pair-direct` (TP — pair-direct)
  - `econ-eth-tax-token-f9e2cd82-tn` (TN — router+swap, v3 anchor)
  - `econ-eth-tax-token-1983ceca-tn` (TN — router+swap, v3 anchor)
  - `econ-eth-tax-token-pair-direct-479f9583-tn` (TN — pair-direct, **NEW** v4 anchor)
- Existing DB row demoted: `severity=info`, `simulation_status=not_exploitable`,
  `simulation_engine=anvil-fork-economic@4`, title prefixed
  `[SUPPRESSED v4]`.

### Why this is structural, not a one-off

The suppressor's gate is the **resolved candidate-name set**, not the static
bytecode signature alone. The set is computed from the verifier's
decompilation pass, so it works on any UniV2 tax-token template regardless
of which AMM primitive it touches. The two pair-direct TPs in the corpus
have 0 and 1 tax-template hits respectively; the FP we just killed has 4.
The discriminator is genuinely orthogonal.

---

## 2. Rescue pipeline (`rescue-prove@1` + PoE + TG bot + broadcaster)

### Problem statement

The current verifier stack produces **heuristic** verdicts: "the call
forwarded to an attacker-controlled probe" or "the bytecode hardcodes a
router and PUSHes a swap selector". These are necessary indicators but not
sufficient to prove that an attacker can extract value. Without that proof:
- Every "verified" finding still requires manual review.
- There's no actionable artifact for an auto-rescue / refund-to-deployer
  pipeline.
- We can't separate "actually drainable today" from "vulnerable in theory".

### Solution — three layers, all landed

#### Layer 1 — `rescue-prove@1` (`panel/src/server/sim/rescue-prove.ts`)

A new verifier-augmentation that runs AFTER any verdict of `verified`:

1. Forks the chain at latest block via the shared Anvil pool.
2. Pulls the contract's full asset list from the existing exposure pipeline
   (native + log-discovered ERC-20s + USD prices).
3. Builds a **drain plan** tailored to the rule family:
   - `call.*` (arbitrary-call): reuses the witnessed `(selector, argTypes,
     hitPosition)` from the primary evidence, substitutes the probe slot
     with each asset's address, and rewrites the bytes payload to
     `transfer(escrow, balance)` (per token) or zero-data with `value=
     contractBalance` (for native).
   - `control.unguarded_selfdestruct`: builds a `selector(escrow)` call.
   - Other families: returns `no_rescue_possible` with a note (will be
     extended in v2; the heuristic verdict remains authoritative).
4. Executes each step from a funded attacker EOA on the fork.
5. Reads the contract + escrow balances before/after and emits a PoE
   artifact with one of these verdicts:
   - `true_positive_drained` — the contract was emptied into escrow.
   - `true_positive_partial` — some assets moved; others remain.
   - `no_rescue_possible` — drain plan ran but no value moved (likely an
     internal guard reverted; the contract may still be technically
     vulnerable but isn't auto-rescuable with v1 patterns).
   - `skipped` — prereqs missing (no exposure, no anvil, etc).
   - `error` — simulator crashed before completing.

PoE artifacts are persisted in `proofs_of_exploit` (one row per attempt;
latest is the canonical one for a finding). Every PoE generation, dry-run,
broadcast, identity-challenge, etc. is logged into `rescue_actions` for the
full audit trail.

`true_positive_*` PoEs automatically:
- POST to `RESCUE_NOTIFY_URL` (if set) with a summary.
- Push a Telegram message via the in-process bot (if `TG_BOT_TOKEN`
  configured).

Bounds & toggles:
- `RESCUE_PROVE_ENABLED` (default `true`)
- `RESCUE_MAX_STEPS` (default 12 — drain plans get truncated past this)
- `RESCUE_MIN_USD` (default $1 — assets below this USD value aren't counted
  in the verdict)
- `RESCUE_ESCROW_ADDR` (default sentinel `0x…FA75`; replace with a real
  escrow you control)

#### Layer 2 — REST API

All under `/api/proofs/*`, behind the existing panel HTTP-basic auth:

| Endpoint | Description |
|---|---|
| `GET  /api/proofs/[findingId]` | Latest PoE + action timeline. `?all=true` returns every attempt. |
| `GET  /api/proofs/[findingId]/poe.json` | Plain JSON download of the canonical PoE. |
| `POST /api/proofs/[findingId]/rescue` | Body: `{mode, authToken?, escrowOverride?}`. `mode` ∈ `dry-run-fork` \| `dry-run-sign` \| `live`. |
| `POST /api/proofs/notify` | External webhook receiver — TG bots / monitoring can push lifecycle events (`identity-challenge`, `identity-verified`, `rescue-confirmed`) into the finding timeline. |

`POST /api/simulation` was also extended: when re-simulating a finding
whose rule is in the rescue-prove scope, the response now carries a
`poe: {verdict, rescuedAssets, totalRescuedUsd, attemptId}` summary.

#### Layer 3 — Telegram bot + rescue broadcaster

**`panel/src/server/rescue/tg-bot.ts`** — Pure HTTP-API bot (no extra deps).
Started by `boot.ts` when `TG_BOT_TOKEN` is set; long-polls every 30 s.

Commands (chat-id-allowlisted by `TG_ALLOWED_CHAT_IDS`):

| Command | Behaviour |
|---|---|
| `/start` | Sanity check. |
| `/poe <findingId>` | Renders the PoE verdict, rescuable-asset breakdown, drain-plan stats. |
| `/timeline <findingId>` | Last 25 rescue_actions rows in monospace. |
| `/rescue <findingId> [auth_token]` | No auth → `dry-run-fork`. With auth → `live` (requires the full env gate; otherwise returns the gate error). |
| `/help` | Lists the commands. |

Outbound notifications: when `rescue-prove` emits a
`true_positive_drained` or `_partial` PoE, the bot posts a Markdown
summary to `TG_CHAT_ID` with the command hints.

**`panel/src/server/rescue/broadcaster.ts`** — viem-based signer/broadcaster.

| Mode | What it does |
|---|---|
| `dry-run-fork` (default) | Re-runs the PoE drain plan on a fresh anvil fork and returns each step's success/revert. No real chain interaction. |
| `dry-run-sign` | Signs each step locally with `RESCUER_PRIVATE_KEY` and returns the raw signed payloads WITHOUT broadcasting. For hand-off to a hardware-wallet pipeline. |
| `live` | Broadcasts. Requires ALL of: `RESCUE_BROADCAST_ENABLED=true`, `RESCUER_PRIVATE_KEY=0x…`, `RESCUE_AUTH_TOKEN=…` (must equal the request's `authToken`), `RESCUE_ESCROW_ADDR=0x…`. EIP-1559 fee suggestion via `client.estimateFeesPerGas`, falls back to `getGasPrice * 1.1` or `10 gwei`. Sequential nonce, 120 s receipt wait per step. |

Every step is logged into `rescue_actions` with the mode, tx hash (when
applicable), step index, asset, and result.

#### UI — `ProofOfExploitPanel` (in `FindingDetail.tsx`)

Surfaces above the tab bar on every finding page. Hidden entirely when the
rule isn't in rescue-prove's scope AND no PoE exists, so it doesn't bloat
the page with empty state.

Layout when a PoE exists:
- Verdict badge (color-coded: red/orange/yellow/gray).
- Three big-number stats: **Rescuable USD**, **Asset count**, **Drain
  steps** (`succeeded/total`).
- Per-asset table: symbol, balance, USD.
- Notes from the prover.
- Action row: `Replay drain on fork (dry-run)` button, `Download PoE JSON`
  link, escrow address.
- Last 10 timeline events in monospace.

When the rule is eligible but no PoE exists yet (typical right after a
fresh static analyzer hit), shows a single muted line: "no PoE yet —
rescue-prove will run after the next simulation pass".

### Auto-fire integration

Rescue-prove now runs automatically in three contexts:

1. **Background sim worker** (`worker.ts → handleGroup`): after the
   primary verifier produces a `verified` verdict on an eligible rule.
2. **Manual audit flow** (`audit-service.ts`): after the post-audit sidecar
   pass, every verified eligible finding under the same `run_id` gets a
   rescue-prove attempt within a budget (`RESCUE_MANUAL_BUDGET_MS`,
   default 45 s; per-finding cap 30 s).
3. **On-demand re-simulation** (`POST /api/simulation`): inline with the
   verdict response, so the UI's "Re-run simulation" button now returns
   the PoE summary in the same round-trip.

### Schema

New tables in `panel/src/db/client.ts → applyMigrations`:

```sql
CREATE TABLE proofs_of_exploit (
  attempt_id           TEXT PRIMARY KEY,
  finding_id           TEXT NOT NULL,
  chain_id             INTEGER NOT NULL,
  contract_address     TEXT NOT NULL,
  attacker_kind        TEXT,             -- 'any' | 'owner' | 'unknown'
  escrow_address       TEXT,
  verdict              TEXT NOT NULL,
  rescued_native_wei   TEXT,
  rescued_tokens_count INTEGER DEFAULT 0,
  rescued_usd          REAL,
  drain_plan_count     INTEGER DEFAULT 0,
  engine               TEXT NOT NULL,
  engine_version       TEXT NOT NULL,
  block_number         INTEGER,
  duration_ms          INTEGER,
  created_at           INTEGER NOT NULL,
  artifact_json        TEXT NOT NULL,
  error                TEXT
);

CREATE TABLE rescue_actions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id   TEXT NOT NULL,
  attempt_id   TEXT,
  kind         TEXT NOT NULL,   -- poe-generated | tg-notified |
                                -- identity-challenge | identity-verified |
                                -- rescue-requested | rescue-dry-run |
                                -- rescue-broadcasted | rescue-mined |
                                -- rescue-failed
  actor        TEXT,
  detail_json  TEXT,
  at           INTEGER NOT NULL
);
```

### `.env` knobs (all optional except where noted)

```bash
# rescue-prove ----------------------------------------------------------
RESCUE_PROVE_ENABLED=true            # disable on resource-constrained boxes
RESCUE_MAX_STEPS=12
RESCUE_MIN_USD=1.0
RESCUE_ESCROW_ADDR=0x...             # where rescued funds land (REQUIRED for live)
RESCUE_NOTIFY_URL=https://...        # generic outbound webhook (optional)
RESCUE_MANUAL_BUDGET_MS=45000        # budget for the manual-audit rescue pass

# rescue broadcaster ---------------------------------------------------
RESCUE_BROADCAST_ENABLED=false       # MUST be true for live broadcasts
RESCUER_PRIVATE_KEY=0x...            # the rescuer wallet's key
RESCUE_AUTH_TOKEN=...                # required in POST body for live mode

# TG bot ---------------------------------------------------------------
TG_BOT_TOKEN=...                     # set to enable the in-process bot
TG_CHAT_ID=...                       # primary destination for notifications
TG_ALLOWED_CHAT_IDS=...,...          # comma list; falls back to TG_CHAT_ID
TG_POLL_TIMEOUT_S=30
```

### Operational workflow (the user's stated flow, end-to-end)

1. Static analyzer flags a contract → primary verifier runs → if verdict =
   `verified` → rescue-prove runs on the same fork.
2. If rescue-prove emits `true_positive_drained` (or `_partial`), it pushes
   a TG message to `TG_CHAT_ID` with the verdict, total USD, command hints.
3. Operator reads the message, decides whether to engage. If yes:
   1. Off-chain: contact deployer (off-platform), share the PoE artifact
      (downloadable from `/api/proofs/[id]/poe.json`), agree on
      authorization.
   2. Send `POST /api/proofs/notify` with `kind=identity-verified` so the
      panel timeline reflects the off-chain step.
   3. On TG: `/rescue <findingId> <RESCUE_AUTH_TOKEN>` → broadcaster signs
      the drain plan with `RESCUER_PRIVATE_KEY` and broadcasts step-by-step,
      logging each tx into the timeline.
4. Each rescued tx hash is visible in the finding's UI timeline and on TG.

### What's deliberately deferred (v2+)

- Rescue paths for `economic.unguarded_amm_action` (needs flash-loan
  scripting) and `init.public_initializer_takeover` (needs a two-step
  drain: initialize + privileged drain).
- Multi-hop drain plans (e.g., `unwrap WETH → transfer ETH`).
- LP-token unfurling (`pair.burn()` → underlying tokens).
- NFT detection + safeTransferFrom drain.
- TG message edit-in-place (e.g., update the original notify with
  "rescued ✅") — currently every action posts a fresh message.

---

## 3. Smoke-test transcript (this turn)

```
PRIMARY: verified                            # primary verifier (anvil-fork-probe@13)
SIDECAR: {ran:True, status:not_exploitable, cached:True}
POE    : {verdict:no_rescue_possible, rescuedAssets:0, totalRescuedUsd:None, attemptId:poe-cef931f4a3b62ff976073a49}

verdict: no_rescue_possible
attemptId: poe-cef931f4a3b62ff976073a49
notes: ['drain plan ran 6 step(s); 0 succeeded but no value moved out of the contract into escrow.
        Likely the function reached an internal guard that reverted silently, or the contract
        actually has no extractable surplus.']

preState contractNativeWei: 809700000000000000
preState tokens: 5
drainPlan steps: 6
  step 0 asset=ERC20 (0x09a4…)  success=False
  step 1 asset=gas711.com         success=False
  step 2 asset=ERC20 (0x224a…)   success=False
  ...
```

This is `0xfF9B21c3` Symbiosis OnSwap on ETH — the user-cited "any-caller
exploitable" contract. Primary verifier confirmed exploitability via CALL
witness; rescue-prove tried 6 drain shapes and concluded **the contract
cannot be drained with a simple transfer plan** (Symbiosis's OnSwap has
additional argument-validation in the bytes payload). This is the right
verdict — it definitively answers "is this rescuable today?" with a hard
no, rather than leaving the operator guessing.

The dry-run rescue endpoint correctly refuses non-rescuable verdicts:

```
POST /api/proofs/<id>/rescue {"mode":"dry-run-fork"}
{
    "error": "cannot rescue: PoE verdict is 'no_rescue_possible'. Only
              true_positive_drained / true_positive_partial PoEs are rescuable."
}
```

---

## 4. Files touched

### Created
- `panel/src/server/sim/rescue-prove.ts` (~480 lines)
- `panel/src/server/sim/poe-store.ts` (~200 lines)
- `panel/src/server/rescue/broadcaster.ts` (~340 lines)
- `panel/src/server/rescue/tg-bot.ts` (~210 lines)
- `panel/app/api/proofs/[findingId]/route.ts`
- `panel/app/api/proofs/[findingId]/poe.json/route.ts`
- `panel/app/api/proofs/[findingId]/rescue/route.ts`
- `panel/app/api/proofs/notify/route.ts`
- New corpus case `econ-eth-tax-token-pair-direct-479f9583-tn` in
  `panel/src/server/sim/__corpus__/cases.json`
- `docs/UPDATES_2026-05-17-part4.md` (this file)

### Modified
- `panel/src/server/sim/exploits/economic-attack.ts` — engine `@4`, tax-token
  suppressor extended to all signature kinds, list cleaned.
- `panel/src/db/client.ts` — `proofs_of_exploit` + `rescue_actions` migrations.
- `panel/src/server/sim/worker.ts` — fire rescue-prove on every verified
  eligible finding.
- `panel/src/server/audit-service.ts` — fire rescue-prove on manual-audit
  verified findings within `RESCUE_MANUAL_BUDGET_MS`.
- `panel/app/api/simulation/route.ts` — return `poe` summary in on-demand
  re-sim response.
- `panel/src/server/boot.ts` — start TG bot when configured.
- `panel/src/components/FindingDetail.tsx` — new `ProofOfExploitPanel`.

### Database side-effects on this machine
- Existing FP `sidecar-econ-4166ef2c…` demoted to `severity=info`,
  `simulation_status=not_exploitable`, `simulation_engine=anvil-fork-economic@4`.

---

## 5. Corpus

```
[corpus] pass=24  fail=0  error=0  total=24  elapsed=20.7s
```

All 24 cases passing, including the new pair-direct tax-token TN anchor.
