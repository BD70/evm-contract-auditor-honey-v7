# State Model

`state_model` is the normalized index that powers robust detectors.

## Sections

- `storage_entities`: canonical storage identities
- `slot_index`: per-slot readers, writers, guards, proxy/init metadata
- `path_index`: path-level effect summaries
- `guard_catalog`: typed guard references and strengths
- `call_index`: call/delegatecall target facts
- `economic_index`: arithmetic and invariant evidence
- `proxy_index`: proxy-standard interpretations
- `initializer_index`: initializer semantics
- `evidence_index`: action and slot evidence references

## Slot Index

Each slot entry should make these questions answerable:

- what semantic role does this slot likely hold?
- how confident is that role?
- who writes it?
- who reads it?
- was the write user-controlled?
- was the read part of an authorization guard?
- which effects become reachable after that read?

## Guard Semantics

Guards should be represented as structured references, not raw labels when possible.

Important classes:

- `authorization_guard`
- `initializer_guard`
- `signature_authorization_guard`
- `governance_guard`
- `timelock_guard`

## Call Semantics

Delegate targets must distinguish:

- fixed target
- storage-backed target
- publicly mutable storage target
- calldata-controlled target

That distinction is the difference between expected proxy behavior and critical code-execution risk.
