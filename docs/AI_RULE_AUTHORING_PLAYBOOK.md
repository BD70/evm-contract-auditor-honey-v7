# AI Rule Authoring Playbook

Use this when asking an AI to author a detector.

## Required Inputs

Give the AI:

- vulnerability thesis
- protected asset or effect
- attack sequence
- exact sensitive effect
- expected counter-evidence
- expected proof strategy
- any proxy/init/accounting semantics that matter

## Required Outputs

The AI should produce:

1. detector JSON in `evm-audit.detector.v1`
2. corpus manifest
3. at least 2 positive, 2 negative, 1 inconclusive fixture plans
4. short rationale for proof level
5. short rationale for counter-evidence handling
6. `internal_name` in the form `reference_<family>_<vuln>_v1`
7. `summary`, `user_summary`, `technical_summary`, and `exploit_narrative`

## Prompt Contract

Tell the AI:

- selectors and names are labels only
- same-slot joins are mandatory for stateful bugs
- sensitive effects are mandatory
- primary matched evidence must have `usable_as_detector_proof=true`
- profile hints may add context but may not be the only reason a detector matches
- corpus fixtures must validate the exact detector id
- benchmark constants belong in fixtures, not generic detectors
- API consumers will use the reporting summaries directly

## Failure Checklist

Reject AI output that:

- matches only on names/selectors
- lacks variable binding
- does not bind the same slot across steps
- does not require a sensitive effect
- does not define counter-evidence
- uses disabled analysis thresholds
- mixes profile hints with detector logic
- relies on profile-only evidence for the matched exploit argument
- has no internal tracking name
- has no user-facing and technical reporting summaries
- lacks proxy-awareness counter-evidence (PROXY_FORWARDING_PATTERN, ERC1967_PROXY, etc.)
- uses coarse STATE_WRITE_AFTER_CALL without preferring VERIFIED version
- has max_unknown_action_expression_count > 50 for high/critical findings
- has max_unresolved_selector_count > 15 for high/critical findings
- has min_path_reachability_confidence < 0.7 for high/critical findings
- does not include ADMIN_GUARD in counter_evidence for access-control rules

## Proxy-Awareness Requirements

Every new rule MUST include proxy-aware counter-evidence unless it is
impossible for the rule to fire on proxy contracts. At minimum:

```json
"counter_evidence": {
  "suppress_if_any": [
    "PROXY_FORWARDING_PATTERN",
    "ERC1967_PROXY",
    "KNOWN_SAFE_PROXY_PATTERN",
    "proxy_safe_delegatecall"
  ],
  "downgrade_if_any": [
    "TRANSPARENT_PROXY",
    "UUPS_PROXY",
    "BEACON_PROXY",
    "ADMIN_GUARD",
    "admin_guarded_function"
  ]
}
```

## Guard-Awareness Requirements

Access-control rules must include:
- ADMIN_GUARD, admin_guarded_function, STRONG_AUTH_GUARD in suppress or downgrade
- AUTH_GUARDED in suppress or downgrade

Reentrancy rules must include:
- REENTRANCY_GUARD, nonReentrant, mutex_lock, reentrancy_guard in suppress

## Analysis Threshold Minimums

For high/critical severity rules:
- min_function_coverage: ≥ 0.6
- min_path_reachability_confidence: ≥ 0.7
- max_unknown_action_expression_count: ≤ 50
- max_unresolved_selector_count: ≤ 15
- max_unresolved_paths: ≤ 10

For medium severity rules:
- min_function_coverage: ≥ 0.5
- min_path_reachability_confidence: ≥ 0.5
- max_unknown_action_expression_count: ≤ 100
- max_unresolved_selector_count: ≤ 30
