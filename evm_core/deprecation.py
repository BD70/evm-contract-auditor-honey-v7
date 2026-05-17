"""Soft-deprecation notice for the legacy Python CLIs.

The Go port (`go/`) is now the supported entrypoint for all five tools
(evm-audit, evm-check, evm-decon, evm-diff, evm-rule). The Python packages are
retained only as the frozen parity oracle and for byte-exact regression
testing — they receive no new detectors or decon improvements.

The notice is written to stderr only (never stdout), so machine consumers and
the parity harness, which compare stdout, are unaffected. Silence it with
EVM_AUDITOR_SILENCE_DEPRECATION=1.
"""
from __future__ import annotations

import os
import sys

_EMITTED: set[str] = set()


def emit_soft_deprecation(tool: str) -> None:
    if os.environ.get("EVM_AUDITOR_SILENCE_DEPRECATION") == "1":
        return
    if tool in _EMITTED:
        return
    _EMITTED.add(tool)
    print(
        f"[deprecation] Python `{tool}` is soft-deprecated and frozen as the "
        f"parity oracle. Use the Go binary instead: build with "
        f"`cd go && go build -o bin/{tool.replace('_', '-')} ./cmd/"
        f"{tool.replace('_', '-')}` and run `go/bin/{tool.replace('_', '-')}`. "
        f"Set EVM_AUDITOR_SILENCE_DEPRECATION=1 to silence this notice.",
        file=sys.stderr,
    )
