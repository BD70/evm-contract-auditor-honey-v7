# Corpus Spec

Corpora use `evm-audit.corpus.v1`.

## Required Fields

- `schema`
- `schema_version`
- `detector_id`
- `scenario_taxonomy`
- `metrics`
- `cases`

## Case Shape

Each case declares:

- `id`
- `audit_json`
- `expectation.kind`
- `expectation.rule_ids`

Expectation kinds:

- `positive`
- `negative`
- `inconclusive`

## Metrics

Keep unit-fixture metrics separate from benchmark metrics.

Do not present synthetic unit fixtures as product-level detector precision claims.

## Required Detector Coverage

Built-in example detectors in this repo ship with at least:

- 2 positive fixtures
- 2 negative fixtures
- 1 inconclusive fixture
