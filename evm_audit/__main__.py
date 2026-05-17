from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from evm_check.sarif import to_sarif
from evm_decon.pipeline import BytecodeInputError, load_bytecode_from_file

from .api import to_api_json
from .service import audit_bytecode


def main() -> int:
    from evm_core.deprecation import emit_soft_deprecation
    emit_soft_deprecation("evm_audit")
    import sys as _sys
    if "--version" in _sys.argv:
        from evm_core import API_SCHEMA_VERSION
        print(f"evm_audit {API_SCHEMA_VERSION}")
        return 0

    parser = argparse.ArgumentParser(
        prog="evm_audit",
        description="Deconstruct bytecode and run deterministic vulnerability rules.",
    )
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument("--file", help="Path to bytecode hex file")
    source.add_argument("--hex", help="Raw runtime bytecode hex string")
    parser.add_argument("--rules", required=True, help="Rule file or directory")
    parser.add_argument("--format", choices=["json", "sarif", "api-json"], default="json")
    parser.add_argument("--output", "-o", help="Write audit result to file")
    parser.add_argument("--no-resolve", action="store_true", help="Disable external selector API calls")
    parser.add_argument(
        "--profiles-dir",
        "--profile-dir",
        dest="profile_dirs",
        metavar="DIR",
        action="append",
        default=[],
        help="Directory containing contract profile JSON files. Every *.json file is loaded recursively.",
    )
    parser.add_argument("--no-profiles", action="store_true", help="Disable default data profile loading")
    parser.add_argument("--llm-judge", action="store_true", help="Pass findings through a local LLM judge (requires openai package and a reachable server)")
    parser.add_argument("--llm-judge-refresh", action="store_true", help="Ignore cached judge results and re-query the model")
    parser.add_argument(
        "--chain-context",
        type=str,
        default=None,
        help='JSON string with chain metadata: {"chainId", "blockNumber", "blockTimestamp", "txHash", "deployer"}',
    )
    parser.add_argument(
        "--eof",
        action="store_true",
        help="Input bytecode is EIP-3541 EOF format; skip disassembly, emit eof_format warning",
    )
    parser.add_argument(
        "--proxy-shell",
        action="store_true",
        dest="proxy_shell",
        help="Input is a known proxy shell; skip deep pipeline steps",
    )
    parser.add_argument(
        "--step-budget-ms",
        type=int,
        default=None,
        dest="step_budget_ms",
        help="Soft per-step wall-clock budget in ms; pipeline degrades gracefully on overrun",
    )
    args = parser.parse_args()

    if args.hex is None and args.file is None:
        parser.error("one of the arguments --file/--hex is required")

    chain_context: dict | None = None
    if args.chain_context:
        try:
            chain_context = json.loads(args.chain_context)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Error: --chain-context is not valid JSON: {exc}")

    bytecode_path: Path | None = None
    try:
        if args.hex is not None:
            bytecode_path = _write_temp_hex(args.hex)
            bytecode_hex = args.hex
            input_kind = "hex_string"
            input_value = "<inline_hex>"
        else:
            bytecode_path = Path(args.file).resolve()
            bytecode_hex = load_bytecode_from_file(bytecode_path)
            input_kind = "hex_file"
            input_value = str(bytecode_path)

        audit, checker = audit_bytecode(bytecode_hex, args)
        if getattr(args, "llm_judge", False):
            checker = _run_llm_judge(checker, audit, args)
        if args.format == "sarif":
            text = json.dumps(to_sarif(checker), indent=2, sort_keys=True)
        elif args.format == "api-json":
            api_result = to_api_json(
                audit,
                checker,
                input_kind,
                input_value,
                bytecode_hex=bytecode_hex,
                chain_context=chain_context,
            )
            text = json.dumps(api_result, indent=2, sort_keys=True)
        else:
            audit["checker_findings"] = checker["findings"]
            audit["checker_trace"] = checker["trace"]
            text = json.dumps(audit, indent=2, sort_keys=True)
        _emit(text, args.output)
        return 0
    except BytecodeInputError as exc:
        raise SystemExit(f"Error: {exc}")
    finally:
        if args.hex is not None and bytecode_path is not None and bytecode_path.exists():
            bytecode_path.unlink(missing_ok=True)


def _run_llm_judge(checker: dict, audit: dict, args: object) -> dict:
    from evm_check.llm_judge import JudgeConfig, is_available, run_judge_pass
    from evm_check.rule_loader import load_rules

    cfg = JudgeConfig(refresh_cache=getattr(args, "llm_judge_refresh", False))
    if not is_available(cfg):
        import logging
        logging.getLogger(__name__).warning(
            "LLM judge requested but server at %s is unreachable or openai package is missing; skipping",
            cfg.base_url,
        )
        return checker

    rules = load_rules(getattr(args, "rules", "rules/core"))
    rules_by_id = {r["rule"]["id"]: r for r in rules}
    checker = dict(checker)
    checker["findings"] = run_judge_pass(checker["findings"], audit, rules_by_id, cfg)
    checker["llm_judge_model"] = cfg.model
    checker["llm_judge_base_url"] = cfg.base_url
    return checker


def _write_temp_hex(raw_hex: str) -> Path:
    normalized = raw_hex.strip()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    handle = tempfile.NamedTemporaryFile("w", suffix=".hex", delete=False)
    with handle:
        handle.write(normalized)
        handle.write("\n")
    return Path(handle.name)


def _emit(text: str, output: str | None) -> None:
    if output:
        with open(output, "w") as handle:
            handle.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    raise SystemExit(main())
