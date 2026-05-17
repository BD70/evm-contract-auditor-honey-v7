# evm-auditor (Go port) — the supported auditor

This is the **supported, actively developed** implementation. The Python
`evm_*` packages are soft-deprecated and frozen as the byte-exact parity
oracle (each prints a stderr deprecation notice; stdout unchanged). All new
detectors are authored and validated here — e.g.
`call.arbitrary_external_call_unvalidated_target` (caller-controlled external
call target + calldata with no allowlist; the Symbiosis MetaRouter/OnchainSwap
arbitrary-call class), proven on the deployed OnchainSwapV3 runtime via
`test/parity/arbitrary_call_test.go`.

Drop-in CLI replacements:

| Python                       | Go                              | Phase | Status |
|------------------------------|---------------------------------|-------|--------|
| `python3 -m evm_check`       | `evm-check`                     | 1     | shipped, byte-parity vs Python |
| `python3 -m evm_diff`        | `evm-diff`                      | 2     | shipped |
| `python3 -m evm_rule …`      | `evm-rule …` (cobra subcmds)    | 6     | shipped |
| `python3 -m evm_audit`       | `evm-audit`                     | 5     | shipped — native in-process decon, no Python subprocess |
| `python3 -m evm_decon`       | `evm-decon`                     | 3     | shipped — native pipeline (disasm→…→semantic), knownbc fingerprinting, `--format json` + `--format semantic` |

## Build

```bash
cd go
make build      # produces ./bin/{evm-check,evm-diff,evm-rule,evm-audit,evm-decon}
```

Static binaries — no CGO, no runtime deps. `evm-audit`/`evm-decon` run the
deconstruction pipeline natively in Go (no `python3` required). Python is only
needed for the parity harness, which diffs Go output against the reference.

## Layout

```
cmd/                # main packages, one per binary
internal/
  check/            # evm_check port
    loader/         # rule + corpus JSON/YAML loading
    engine/         # detector matcher (function + stateful), findings
    policy/         # status, severity, confidence, coverage
    witness/        # native deterministic witness backends
    sarif/          # SARIF 2.1.0 emitter
    apijson/        # evm-audit.api.v2 emitter
    llmjudge/       # OpenAI-compatible LLM judge HTTP client + cache
  audit/            # evm_audit glue
  diff/             # evm_diff
  rule/             # evm_rule workbench
  decon/            # evm_decon (native Go port)
    disasm/         # opcode table + linear disassembler
    blocks/         # basic block split
    {meta,selector,resolver,stacksim,cfg,slicer,abi,storage,patterns,semantic}/  # pipeline stages
    knownbc/        # known-bytecode fingerprinting (proxies, OZ libs) → library_fingerprints
    pseudocode/     # human-readable --format semantic report
    builder/        # behavior.v2 emitter incl. full state_model index set
    pipeline/       # stage orchestrator (no Python subprocess)
  cli/              # shared CLI helpers (Python-compat JSON encoder, file I/O)
  version/
pkg/
  schema/           # versioned schema constants (behavior.v2, detector.v1, api.v2)
  keccak/           # Keccak-256 + storage-slot helpers
  bytecode/         # hex normalization + sha256 helpers
test/parity/        # golden-file harness vs Python reference
```

## Migration plan

See `../.../master plan` (root). Phase cutover gated by `test/parity/` zero-diff
over the corpus.

## Cutover for panel + runner

Once Phase 5 parity is signed off:

```diff
# panel/.env, runner/.env
- AUDITOR_CMD=-m evm_audit
+ AUDITOR_CMD=evm-audit
- # PYTHON_BIN no longer needed
+ # delete PYTHON_BIN
```

Argv shapes are unchanged (`--file/--hex --rules --format api-json …`); the
panel/runner subprocess code is untouched.

## Testing

```bash
make build
make parity        # diff Go vs Python: evm-check (byte-exact) + decon parity
make parity-decon  # decon-only: finding-set + token-exact over corpus/decon/
go test ./...      # unit tests (knownbc tokens, state_model, keccak, …)
```

`make parity-decon` runs `corpus/decon/` (curated runtime-hex fixtures, see
`corpus/decon/manifest.json`): for each fixture it asserts Python and Go
`evm-audit --format api-json` yield the same finding set, and that
`state_model.library_fingerprints` + `guard_catalog` token ids match exactly.
Known-failing Python reference cases (FROST/pancake) are excluded via the
manifest `parity_include` flag (frozen-oracle policy).

## Versions

- Go ≥ 1.25
- Python ≥ 3.11 (only required for the parity harness; not needed at runtime)
