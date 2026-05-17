from __future__ import annotations

import argparse
import json
import sys

from .engine import check_audit, load_rules
from .sarif import to_sarif


def main() -> int:
    from evm_core.deprecation import emit_soft_deprecation
    emit_soft_deprecation("evm_check")
    parser = argparse.ArgumentParser(
        prog="evm_check",
        description="Run deterministic vulnerability rules against evm-audit behavior JSON.",
    )
    parser.add_argument("--facts", required=True, help="Path to evm-audit behavior JSON")
    parser.add_argument("--rules", required=True, help="Rule file or directory")
    parser.add_argument("--format", choices=["json", "sarif"], default="json")
    parser.add_argument("--output", "-o", help="Write checker result to file")
    parser.add_argument("--llm-judge", action="store_true", help="Pass findings through a local LLM judge (requires openai package and a reachable server)")
    parser.add_argument("--llm-judge-refresh", action="store_true", help="Ignore cached judge results and re-query the model")
    args = parser.parse_args()

    with open(args.facts) as f:
        audit = json.load(f)
    rules = load_rules(args.rules)
    result = check_audit(audit, rules)
    if getattr(args, "llm_judge", False):
        from .llm_judge import JudgeConfig, is_available, run_judge_pass
        cfg = JudgeConfig(refresh_cache=getattr(args, "llm_judge_refresh", False))
        if is_available(cfg):
            rules_by_id = {r["rule"]["id"]: r for r in rules}
            result = dict(result)
            result["findings"] = run_judge_pass(result["findings"], audit, rules_by_id, cfg)
        else:
            import logging
            logging.getLogger(__name__).warning("LLM judge requested but unavailable; skipping")
    if args.format == "sarif":
        result = to_sarif(result)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
