from __future__ import annotations

import argparse
from typing import Any

from evm_check.engine import check_audit, load_rules
from evm_decon.pipeline import PipelineOptions, analyze_bytecode, build_behavior_audit


def build_behavior_document(bytecode_hex: str, args: argparse.Namespace) -> dict[str, Any]:
    options = PipelineOptions(
        no_resolve=args.no_resolve,
        no_profiles=args.no_profiles,
        profile_dirs=args.profile_dirs or [],
        eof_format=getattr(args, "eof", False),
        proxy_shell=getattr(args, "proxy_shell", False),
        step_budget_ms=getattr(args, "step_budget_ms", None),
    )
    artifacts = analyze_bytecode(
        bytecode_hex,
        options=options,
        input_kind="hex_string" if args.hex is not None else "hex_file",
    )
    return build_behavior_audit(artifacts)


def audit_bytecode(bytecode_hex: str, args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    audit = build_behavior_document(bytecode_hex, args)
    checker = check_audit(audit, load_rules(args.rules))
    return audit, checker
