# Usage Guide

## Generate Behavior JSON

```bash
python3 -m evm_decon --file contract.hex --format json --output contract.audit.json
```

Use this when you want behavior facts and state-model output only.

## Run Detectors Against Existing Behavior JSON

```bash
python3 -m evm_check --facts contract.audit.json --rules rules/core --format json --output check.result.json
```

Use `--format sarif` only for SARIF consumers.

## One-Shot Audit

From a hex file:

```bash
python3 -m evm_audit --file contract.hex --rules rules/core --format json --output audit.result.json
```

From a raw hex string:

```bash
python3 -m evm_audit --hex "0x6080..." --rules rules/core --format json --output audit.result.json
```

## API-Oriented Output

```bash
python3 -m evm_audit --file contract.hex --rules rules/core --format api-json --output audit.result.api.json
```

Use `api-json` for services and scripts because it:

- reports whether anything matched
- collapses duplicate-looking function matches into one issue
- includes `affected_functions`
- includes user-facing and technical summaries

## Detector Workbench

```bash
python3 -m evm_rule init access.example.detector
python3 -m evm_rule validate rules/core
python3 -m evm_rule doctor rules/core/access.public_privileged_slot_poisoning.json
python3 -m evm_rule test rules/core/token.transfer.sender_debit_credit_mismatch.json corpus/frost_transfer_inflation
python3 -m evm_rule explain rules/core/token.transfer.sender_debit_credit_mismatch.json corpus/frost_transfer_inflation/positive_frost_fee.audit.json
```
