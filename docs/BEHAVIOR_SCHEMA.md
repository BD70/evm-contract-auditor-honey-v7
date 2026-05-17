# Behavior Schema

`evm-audit.behavior.v2` `2.0.0` is the machine contract emitted by `evm_decon`.

The state model within the behavior document uses schema `evm-audit.state_model.v2` `2.1.0`.

## Stability Rules

- required fields are versioned
- unknown fields are ignored by downstream consumers
- names and selectors are stable labels, not stable evidence classes

## Key Top-Level Families

- `bytecode_identity`: original/runtime/metadata-stripped identities
- `contract`: family, selectors, protocol roles, pattern hints
- `functions`: local behavior units
- `storage`: recovered layout plus reads/writes
- `arithmetic`: contract-level arithmetic summary
- `flows`: source-to-sink traces
- `invariants`: interpreted protocol/accounting facts
- `coverage`: analysis quality gates
- `state_model`: normalized cross-function index

## Function Facts

Each function may carry:

- identity
- interface hints
- control flow
- ordered actions
- state reads/writes
- external calls
- arithmetic facts
- flows
- guards
- behavior tags
- evidence

## Coverage Fields

Coverage is part of the detector contract, not a UI nicety. Important fields:

- `function_coverage`
- `storage_role_confidence`
- `path_reachability_confidence`
- `unknown_action_expression_count`
- `unresolved_selector_count`
- `unresolved_path_count`
- `has_unmodeled_terminators`

High/critical detectors must gate on these.

## State Model

The `state_model` block (schema `evm-audit.state_model.v2` `2.1.0`) contains:

- `slot_index`: per-slot writers, readers, guards, semantic roles, and role confidence
- `guard_catalog`: detected guard patterns with evidence refs
- `call_index`: outbound call evidence with target origin and reachable effects
- `economic_index`: accounting and value-flow facts
- `proxy_index`: proxy pattern detection with standard and slot kind tokens
- `initializer_index`: initializer slot and modifier patterns
- `evidence_index`: resolved evidence references
- `library_fingerprints`: detected OpenZeppelin and proxy library patterns

### library_fingerprints

Each entry:

```json
{
  "id": "OZ_REENTRANCY_GUARD",
  "kind": "oz_guard | oz_library | proxy",
  "evidence_refs": ["..."],
  "confidence": 0.95
}
```

The `id` field is a counter-evidence token. Any `id` appearing here is automatically unioned into the counter-evidence evaluation for every rule. See [COUNTER_EVIDENCE.md](COUNTER_EVIDENCE.md) for the full token list.
