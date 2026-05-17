# Rule System Overview

This system has five distinct artifacts:

1. `behavior JSON`
2. `state model`
3. `detector`
4. `profile`
5. `corpus`

## Behavior JSON

Behavior JSON is emitted from bytecode analysis. It contains function-local and contract-level facts.

## State Model

The state model is derived from behavior JSON. It is not hand-authored. It normalizes slots, guards, paths, calls, and evidence references so cross-function detectors can match precisely.

## Detector

A detector is vulnerability logic only. It must never contain:

- benchmark-only constants
- contract-family allowlists
- fixture-specific assumptions

A detector must also provide:

- a stable public `rule.id`
- a stable internal `rule.internal_name`
- user-facing and technical reporting summaries
- an explicit detector-grade evidence policy

Detector-grade evidence must come from facts whose trust is usable as proof.
Profile hints can enrich interpretation, but they may not manufacture a match by themselves.

## Profile

A profile can add:

- selector names
- storage anchors
- protocol roles
- semantic overrides

A profile may not add:

- exploit conclusions
- finding severities
- detector suppressions

## Corpus

A corpus is regression data only. It validates:

- detector positives
- detector negatives
- detector inconclusive cases

## Witness Backends

Witness backends are optional corroboration layers. They are not part of the core detector contract.

## API Surface

For external services, prefer `evm_audit --format api-json`.

That output is issue-oriented rather than raw-match-oriented:

- identical matches across multiple functions may collapse into one issue
- the issue keeps `match_count`
- the issue keeps `affected_functions`
