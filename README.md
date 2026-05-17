# EVM Contract Auditor

This project is a bytecode-first smart-contract audit engine.

The strict product contract is:

`bytecode -> behavior facts -> state model -> deterministic detector spec -> optional witness backends -> findings`

The repo is split into four runtime surfaces:

1. `evm_decon`: deconstruct runtime bytecode into `evm-audit.behavior`.
2. `evm_check`: run deterministic detectors against behavior JSON.
3. `evm_rule`: scaffold, validate, explain, test, and doctor detectors.
4. `evm_diff`: compare source-truth fixtures against bytecode-derived behavior for regression testing only.

Internal service entrypoint:

- `evm_decon.pipeline`: reusable in-process deconstruction service used by CLI and `evm_audit`

## Mental Model

- `behavior JSON` is the machine contract emitted from bytecode analysis.
- `state model` is a normalized index derived from behavior JSON for cross-function reasoning.
- `detectors` express vulnerability logic only.
- `profiles` add contract-family hints and semantic anchors only.
- `corpus` files are test fixtures only.
- `witness backends` are optional corroboration layers, not mandatory dependencies.

If those concepts blur together, detector quality collapses into shallow pattern matching. This repo now keeps them separate on purpose.

## Supported Entrypoint: the Go port

**The Go implementation under `go/` is the supported, actively developed
auditor.** It is a fully native, in-process pipeline (no Python subprocess) and
ships all five tools as standalone binaries:

```bash
cd go && go build -o bin/evm-audit ./cmd/evm-audit \
  && go build -o bin/evm-check ./cmd/evm-check \
  && go build -o bin/evm-decon ./cmd/evm-decon \
  && go build -o bin/evm-diff ./cmd/evm-diff \
  && go build -o bin/evm-rule ./cmd/evm-rule

go/bin/evm-audit --hex "0x6080..." --rules rules/core --format api-json
```

The Python packages (`evm_audit`, `evm_check`, `evm_decon`, `evm_diff`,
`evm_rule`) are **soft-deprecated and frozen**: they are retained only as the
byte-exact parity oracle and receive no new detectors or decon improvements.
Each Python CLI prints a one-line deprecation notice to **stderr** (stdout is
unchanged; silence with `EVM_AUDITOR_SILENCE_DEPRECATION=1`). New rules — such
as `call.arbitrary_external_call_unvalidated_target` — are validated against the
Go engine.

## Public Commands (legacy Python — frozen oracle)

Human-readable behavior summary:

```bash
python3 -m evm_decon --file contract.hex --format semantic
```

Machine behavior JSON:

```bash
python3 -m evm_decon --file contract.hex --format json --output contract.audit.json
```

Run detectors:

```bash
python3 -m evm_check --facts contract.audit.json --rules rules/core
python3 -m evm_check --facts contract.audit.json --rules rules/core --format sarif
```

Run end-to-end:

```bash
python3 -m evm_audit --file contract.hex --rules rules/core --format json
python3 -m evm_audit --file contract.hex --rules rules/core --format sarif
python3 -m evm_audit --file contract.hex --rules rules/core --format api-json
python3 -m evm_audit --hex "0x6080..." --rules rules/core --format api-json
```

Detector workbench:

```bash
python3 -m evm_rule init access.example.detector
python3 -m evm_rule validate rules/core/access.public_privileged_slot_poisoning.json
python3 -m evm_rule doctor rules/core/access.public_privileged_slot_poisoning.json
python3 -m evm_rule test rules/core/access.public_privileged_slot_poisoning.json corpus/access_slot_poisoning
python3 -m evm_rule explain rules/core/defi.rounding.assumed_actual_balance_mismatch.json corpus/rounding/positive_balancer_like.audit.json
```

Source-truth differential checks:

```bash
python3 -m evm_diff --source-truth corpus/diff/transfer.truth.json --audit-json contract.audit.json
```

Production runner for live deployment monitoring:

```bash
bun install
bun run runner --env-file .env
```

Multi-chain: drop a `chains.json` (see `chains.example.json`) next to `.env`.
Each entry overrides the env-derived RPC/webhook/rules fields and runs in an
isolated `STATE_DIR/<slug>` (own checkpoint, lock, artifacts). Select one with
`--chain <slug>`; with a single enabled chain it auto-selects. Without
`chains.json` the runner stays single-chain and env-driven (unchanged).

```bash
bun run runner --env-file .env --chain eth-mainnet
```

See [docs/RUNNER_GUIDE.md](docs/RUNNER_GUIDE.md) for the block watcher, top-level plus factory deployment detection, state layout, cache semantics, webhook idempotency, proxy handling, and replay modes.

Admin panel (web UI for runner control, findings explorer, ad-hoc audits, detector workbench, live config editor):

```bash
cd panel
bun install
cp .env.example .env   # set PANEL_USER / PANEL_PASS
PANEL_USER=admin PANEL_PASS=changeme bun dev
```

See [panel/README.md](panel/README.md) for the full panel feature list.

Programmatic composition:

```python
from evm_decon.pipeline import PipelineOptions, analyze_bytecode, build_behavior_audit

artifacts = analyze_bytecode(bytecode_hex, PipelineOptions(no_resolve=True))
audit = build_behavior_audit(artifacts)
```

## Behavior JSON

`evm_decon --format json` emits `evm-audit.behavior.v2` `2.0.0`.

Top-level fields:

```json
{
  "schema": "evm-audit.behavior.v2",
  "schema_version": "2.0.0",
  "engine_version": "1.0.0",
  "ruleset_version": "1.0.0",
  "bytecode_identity": {},
  "bytecode": {},
  "contract": {},
  "functions": [],
  "storage": {},
  "memory": {},
  "arithmetic": {},
  "calls": [],
  "events": [],
  "flows": [],
  "invariants": [],
  "assumptions": [],
  "analysis_warnings": [],
  "coverage": {},
  "state_model": {},
  "checker_findings": []
}
```

`checker_findings` stays empty in plain `evm_decon` output. Real vulnerability matches appear only after `evm_check` or `evm_audit` runs detectors.

Important rule-authoring principle:

- names and selectors are labels only;
- behavior facts, state joins, path facts, and effect facts are primary evidence.
- profile hints may add context, but profile-only semantics are not primary detector proof.

## State Model

`state_model` is a normalized index for robust detectors. It includes:

- `storage_entities`
- `slot_index`
- `path_index`
- `guard_catalog`
- `call_index`
- `economic_index`
- `proxy_index`
- `initializer_index`
- `evidence_index`
- `library_fingerprints` — detected OpenZeppelin and proxy library patterns, each with an `id` counter-evidence token

This is where multi-step detectors bind the same slot across writes, reads, guards, and effects.

Library fingerprint tokens from `library_fingerprints[*].id` are automatically merged into the counter-evidence evaluation for all detectors. See [docs/COUNTER_EVIDENCE.md](docs/COUNTER_EVIDENCE.md) for the full token catalog.

## Detector Spec

Every production detector uses `evm-audit.detector.v1` and must declare:

- `rule`
- `intent`
- `requires`
- `counter_evidence`
- `proof`
- `analysis_requirements`
- `fixture_requirements`
- `reporting`

Production detectors should set `analysis_requirements.require_usable_primary_evidence=true`.
That prevents a rule from firing only because a profile guessed function semantics or storage roles.

Important detector metadata:

- `rule.id`: stable public detector id
- `rule.internal_name`: stable internal tracking name in the form `reference_<family>_<vuln>_v1`
- `reporting.user_summary`: short user-facing explanation
- `reporting.technical_summary`: precise technical explanation of what matched
- `reporting.exploit_narrative`: short exploit story for API or UI use

The matcher supports:

- explicit variable binding across steps
- same-slot joins
- same-guard joins
- same-delegate-target joins
- sensitive-effect constraints
- trust constraints on callers and write origins
- confidence gates on inferred state roles and paths

## Built-In Example Detectors (26 total)

These are reference detector classes, not first-party contract-family logic.
All detectors use schema `evm-audit.detector.v1` `1.1.0` and include `witness_goal` blocks.

Counter-evidence and coverage gates are mandatory contracts — see [`evm_check/findings.py:103-144`](evm_check/findings.py) and [`evm_check/policy.py:65-93`](evm_check/policy.py).

**Initialization / Access Control**
- `init.public_initializer_takeover`
- `access.public_privileged_slot_poisoning`
- `access.hardcoded_admin_address`
- `auth.authorization_predicate_poisoning`
- `control.tx_origin_authentication`
- `control.unguarded_selfdestruct`

**Proxy / Delegatecall**
- `proxy.unprotected_implementation_upgrade`
- `delegatecall.storage_controlled_target`

**Reentrancy**
- `reentrancy.classic_mutex_absent`
- `reentrancy.state_after_external_call`
- `reentrancy.read_only_exposure`

**Call Safety**
- `call.unchecked_return_value`
- `call.unvalidated_calldataload_target_injection`
- `call.user_controlled_external_target`

**Arithmetic / Rounding**
- `overflow.unchecked_arithmetic`
- `defi.rounding.assumed_actual_balance_mismatch`

**Token Security**
- `token.transfer.sender_debit_credit_mismatch`
- `token.erc20_approve_race`
- `token.unsafe_erc20_assumption`

**DeFi Logic**
- `defi.erc4626.withdraw.missing_caller_authorization`
- `defi.erc4626.first_depositor_inflation`
- `defi.swap.missing_slippage_or_deadline`

**Oracle / Randomness**
- `oracle.chainlink_staleness_unchecked`
- `randomness.timestamp_or_blockhash_value_gating`

**Auth / Signatures**
- `auth.signature_replay_missing_nonce`
- `auth.eip712_domain_separator_missing`

## API Output

`evm_audit --format api-json` emits `evm-audit.api.v2`.

Use this as the preferred machine interface for external scripts and services.
It is also the only supported subprocess boundary for the production runner.

It contains:

- `analysis.matched`
- `analysis.finding_count`
- `analysis.raw_match_count`
- `bytecode_identity`
- `coverage`
- `exposure_estimate`
- collapsed issue-level `findings`
- `affected_functions` when the same issue matches multiple functions
- `user_summary`, `technical_summary`, and `exploit_narrative`

Example:

```json
{
  "schema": "evm-audit.api.v2",
  "analysis": {
    "matched": true,
    "finding_count": 1,
    "raw_match_count": 2
  },
  "findings": [
    {
      "rule_id": "token.transfer.sender_debit_credit_mismatch",
      "internal_name": "reference_frost_sender_debit_credit_mismatch_v1",
      "status": "probable_vulnerability",
      "severity": "critical",
      "match_count": 2,
      "affected_functions": [
        {"selector": "0xa9059cbb", "name": "transfer(address,uint256)"},
        {"selector": "0x23b872dd", "name": "transferFrom(address,address,uint256)"}
      ]
    }
  ]
}
```

## Optional LLM Judge

An optional local-LLM judge can downgrade probable false-positive findings.
It uses an OpenAI-compatible API (Ollama, vLLM, LM Studio, llama.cpp, LocalAI).

```bash
# Install the optional extra
pip install evm-contract-auditor[llm]

# Run with judge (falls back silently if server unreachable)
python3 -m evm_audit --file contract.hex --rules rules/core --format api-json --llm-judge

# Invalidate cache and re-judge
python3 -m evm_audit --file contract.hex --rules rules/core --format api-json --llm-judge --llm-judge-refresh
```

Configuration via environment variables:

| Variable | Default |
|---|---|
| `EVM_LLM_BASE_URL` | `http://localhost:11434/v1` |
| `EVM_LLM_MODEL` | `qwen2.5-coder:14b` |
| `EVM_LLM_API_KEY` | `local` |
| `EVM_LLM_TIMEOUT` | `30` (seconds) |

The judge is strictly downgrade-only — it can never increase a finding's severity or
promote `suspicious_behavior` to `probable_vulnerability`. Suppressed findings are
never sent to the model. Results are cached at `~/.cache/evm-auditor/llm-judge/`.

Judge output fields added to each finding: `judged_by`, `judge_verdict`, `judge_rationale`, `judge_confidence`.

## Optional Static Witness Backends

The native engine remains deterministic and repo-owned.

Optional adapters can strengthen or downgrade confidence:

- `slither`
- `mythril`
- `halmos`
- `echidna`

They are never required for the base detector to run.

## Validation

Run the regression suite:

```bash
python3 -m unittest discover -s test -p 'test_*.py'
```

## Documentation Map

- [Architecture Guide](ARCHITECTURE_GUIDE.md)
- [Runner Guide](docs/RUNNER_GUIDE.md)
- [Rule System Overview](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/RULE_SYSTEM_OVERVIEW.md)
- [Behavior Schema](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/BEHAVIOR_SCHEMA.md)
- [State Model](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/STATE_MODEL.md)
- [Detector Spec v1](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/DETECTOR_SPEC_V1.md)
- [Counter Evidence](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/COUNTER_EVIDENCE.md)
- [Corpus Spec](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/CORPUS_SPEC.md)
- [Profile Spec](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/PROFILE_SPEC.md)
- [AI Rule Authoring Playbook](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/AI_RULE_AUTHORING_PLAYBOOK.md)
- [Rule Authoring Examples](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/RULE_AUTHORING_EXAMPLES)
- [Migration v0 to v1](/Users/honeysingh/Projects/misc/evm-contract-auditor/docs/MIGRATION_V0_TO_V1.md)
