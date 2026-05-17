Regenerate the real runtime fixture from the checked-in bytecode artifact:

`python3 -m evm_decon --file test/FROST/deployed_code.hex --format json --no-resolve --no-assembly --profiles-dir contract_profiles > corpus/frost_transfer_inflation/real_frost_runtime.audit.json`

Optional source compile path, if `solc 0.6.12` is available later:

1. compile the FROST deployment target to runtime bytecode
2. replace `test/FROST/deployed_code.hex`
3. rerun the command above
