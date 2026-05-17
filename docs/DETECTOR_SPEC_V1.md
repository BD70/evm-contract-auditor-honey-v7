# Detector Spec v1.1.0

Detectors express vulnerability logic only.

Schema: `evm-audit.detector.v1` — supported versions `1.0.0` and `1.1.0`.

## Schema v1.1.0 additions (additive, backwards-compatible)

- `witness_goal` block: structured proof claim describing how a human or tool would demonstrate exploitability
- `witness_status` on each finding: one of `confirmed_exploit | probable_vulnerability | suspicious_behavior | analysis_inconclusive | suppressed_by_counter_evidence | not_reproduced | not_attempted`

### witness_goal block

```jsonc
"witness_goal": {
  "goal_type": "multi_tx_exploit | single_tx_exploit | invariant_violation",
  "preconditions": ["attacker is first depositor", "..."],
  "steps": [
    {"actor": "attacker", "action": "...", "expected_state": "..."}
  ],
  "success_condition": "...",
  "environment_requirements": ["..."],
  "budget_hint": {"max_tx": 3, "max_gas": 1000000}
}
```

The field is present on every finding in api-json output. When no executor has run, `witness_status` is `not_attempted`. The field carries structured context for SaaS UI, triage, and downstream tooling — not an executor requirement.


They must not treat the following as primary proof:

- selector names
- function names
- profile-only semantic overrides
- profile-only storage anchors

## Evidence Contract

Every detector must define `analysis_requirements.require_usable_primary_evidence`.

When this is `true`, the checker only allows primary matched evidence whose trust object declares `usable_as_detector_proof=true`.

This applies to:

- arithmetic and accounting facts
- storage-role and slot matches used by stateful rules
- delegatecall target facts

Profiles may still add context, labels, and semantic normalization, but profile hints are not enough on their own to manufacture detector-grade facts.

## Provenance Model

The engine distinguishes:

- `bytecode_inferred`: derived directly from recovered actions, guards, calls, or storage evidence
- `profile_corroborated`: profile interpretation backed by underlying bytecode-derived semantic signal
- `profile_hint`: profile-only interpretation, not usable as detector proof
- `heuristic`: weak inference, generally not usable as detector proof

## Authoring Rule

If a detector would fire only because a profile guessed semantics, the detector is wrong.

A valid detector must still fail safely on unrelated contracts that merely share common selectors.
