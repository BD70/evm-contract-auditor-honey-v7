# Contract Profiles

Put customer-specific or known-contract profile JSON files in this directory.

This is the local contract-profile database. The engine loads every `*.json`
file in this directory recursively by default, so you can create subdirectories
per customer, protocol, chain, or fixture without listing files one by one:

```text
contract_profiles/
  customer_a/
    vault_v1.json
    vault_v2.json
  local_fixtures/
    pancake_pair.json
```

```bash
python3 -m evm_decon --file contract.hex --format json
```

You can also explicitly load any profile directory:

```bash
python3 -m evm_decon --file contract.hex --format json --profiles-dir ./contract_profiles
```

To disable the default `profiles/` and `contract_profiles/` directories and load only a selected directory:

```bash
python3 -m evm_decon --file contract.hex --format json --no-profiles --profiles-dir ./my_profiles
```

Profiles can define selector signatures, pattern matches, storage anchors, function semantic overrides, expected permissionless functions, and generic pattern suppressions.
