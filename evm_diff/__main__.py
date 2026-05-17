from __future__ import annotations

import argparse
import json
from typing import Any


def main() -> int:
    from evm_core.deprecation import emit_soft_deprecation
    emit_soft_deprecation("evm_diff")
    parser = argparse.ArgumentParser(
        prog="evm_diff",
        description="Compare source-derived test truth against evm-audit behavior JSON.",
    )
    parser.add_argument("--source-truth", required=True, help="Truth fixture JSON")
    parser.add_argument("--audit-json", required=True, help="Audit behavior JSON")
    parser.add_argument("--output", "-o", help="Write diff result to file")
    args = parser.parse_args()

    with open(args.source_truth) as f:
        truth = json.load(f)
    with open(args.audit_json) as f:
        audit = json.load(f)
    result = diff_truth(truth, audit)
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0 if result["ok"] else 1


def diff_truth(truth: dict[str, Any], audit: dict[str, Any]) -> dict[str, Any]:
    failures = []
    functions = {
        fn.get("identity", {}).get("selector"): fn
        for fn in audit.get("functions", [])
    }
    functions.update({
        fn.get("identity", {}).get("name"): fn
        for fn in audit.get("functions", [])
        if fn.get("identity", {}).get("name")
    })
    for expected in truth.get("functions", []):
        key = expected.get("selector") or expected.get("name")
        fn = functions.get(key)
        if not fn:
            failures.append({"function": key, "error": "missing_function"})
            continue
        expected_writes = set(expected.get("writes", []))
        if expected_writes:
            observed = set(fn.get("state", {}).get("semantic_summary", {}).get("writes", []))
            observed.update(str(w.get("slot")) for w in fn.get("state", {}).get("writes", []))
            missing = sorted(w for w in expected_writes if not any(w in o for o in observed))
            if missing:
                failures.append({"function": key, "error": "missing_writes", "missing": missing, "observed": sorted(observed)})
        if expected.get("mutability"):
            observed_mutability = fn.get("interface", {}).get("mutability") or _infer_mutability(fn)
            if observed_mutability != expected["mutability"]:
                failures.append({
                    "function": key,
                    "error": "mutability_mismatch",
                    "expected": expected["mutability"],
                    "observed": observed_mutability,
                })
    return {
        "schema": "evm-audit.diff",
        "ok": not failures,
        "failures": failures,
    }


def _infer_mutability(fn: dict[str, Any]) -> str:
    if fn.get("state", {}).get("writes"):
        return "nonpayable"
    if fn.get("state", {}).get("reads"):
        return "view"
    return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
