from __future__ import annotations

import argparse
import json
from pathlib import Path

from evm_check.engine import check_audit, load_corpus_manifest, load_rules, validate_rules
from evm_check.schema import validate_corpus


TEMPLATE = {
    "schema": "evm-audit.detector.v1",
    "schema_version": "1.0.0",
    "rule": {
        "id": "{rule_id}",
        "internal_name": "reference_{rule_id}",
        "title": "Review required for {rule_id}",
        "category": "custom",
        "severity": "medium",
        "scope": "function",
        "lifecycle_status": "example",
        "default_status": "suspicious_behavior",
        "confidence_policy": {
            "base": 0.6,
            "with_witness": 0.82,
            "inconclusive": 0.35,
        },
        "disallow_primary_evidence": ["function_name", "selector"],
    },
    "intent": {
        "vulnerability_class": "replace_me",
        "attack_thesis": "Replace with a bytecode-observable attack thesis.",
        "protected_asset_or_effect": ["replace_me"],
        "exploit_model": "single_tx_or_multi_tx",
    },
    "requires": {
        "stateful": False,
        "facts_all": ["REVIEW_REQUIRED"],
        "flows_all": [],
        "reachable_effect_any": [],
        "authorized_path_effect_any": [],
        "economic_effect_any": [],
        "sequence": [],
    },
    "counter_evidence": {
        "suppress_if_any": [],
        "downgrade_if_any": [],
        "inconclusive_if_any": [],
        "manual_review_if_any": [],
    },
    "proof": {
        "min_level": "P2",
        "preferred_witness": "reachable_path",
        "acceptable_witnesses": ["reachable_path", "invariant_argument"],
        "witness_generation": {
            "native": "path_match",
            "optional_adapters": [],
        },
    },
    "analysis_requirements": {
        "min_function_coverage": 0.85,
        "min_storage_role_confidence": 0.8,
        "min_path_reachability_confidence": 0.8,
        "max_unknown_action_expression_count": 10,
        "max_unresolved_selector_count": 20,
        "max_unresolved_paths": 10,
        "require_no_unmodeled_terminators": True,
    },
    "fixture_requirements": {
        "corpus": "corpus/{rule_id}",
        "positive_fixtures_min": 2,
        "negative_fixtures_min": 2,
        "inconclusive_fixtures_min": 1,
        "required_scenarios": ["positive", "negative", "inconclusive"],
    },
    "reporting": {
        "title_template": "{rule_id}",
        "summary": "Replace with a one-paragraph detector summary.",
        "user_summary": "Replace with a short user-facing explanation.",
        "technical_summary": "Replace with the precise technical explanation of the matched behavior.",
        "exploit_narrative": "Replace with a short exploit narrative that explains how the behavior becomes exploitable.",
        "exploit_preconditions": [],
        "remediation_hints": [],
        "sarif": {
            "taxa": [],
            "precision": "medium",
        },
    },
}

CORPUS_TEMPLATE = {
    "schema": "evm-audit.corpus.v1",
    "schema_version": "1.0.0",
    "detector_id": "{rule_id}",
    "scenario_taxonomy": ["positive", "negative", "inconclusive"],
    "metrics": {
        "unit_fixture_metrics": {
            "false_positive_count": 0,
            "false_negative_count": 0,
        },
        "benchmark_metrics": {},
    },
    "cases": [
        {
            "id": "replace_me_positive",
            "audit_json": "positive.audit.json",
            "expectation": {
                "kind": "positive",
                "rule_ids": ["{rule_id}"],
            },
        }
    ],
}


def main() -> int:
    from evm_core.deprecation import emit_soft_deprecation
    emit_soft_deprecation("evm_rule")
    parser = argparse.ArgumentParser(prog="evm_rule", description="Detector workbench for deterministic evm-audit checks.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="Create a detector template and paired corpus manifest")
    init.add_argument("rule_id")
    init.add_argument("--output-dir", default="rules")
    init.add_argument("--corpus-dir", default="corpus")

    test = sub.add_parser("test", help="Run a detector against a fixture corpus")
    test.add_argument("rule")
    test.add_argument("corpus")

    explain = sub.add_parser("explain", help="Show why a detector matched or did not match an audit JSON")
    explain.add_argument("rule")
    explain.add_argument("audit_json")

    validate = sub.add_parser("validate", help="Validate detector schema, corpus mapping, and proof policy")
    validate.add_argument("rule")

    doctor = sub.add_parser("doctor", help="Find shallow-detector anti-patterns")
    doctor.add_argument("rule")

    args = parser.parse_args()
    if args.cmd == "init":
        return _init_detector(args.rule_id, Path(args.output_dir), Path(args.corpus_dir))
    if args.cmd == "explain":
        with open(args.audit_json) as f:
            audit = json.load(f)
        rule = load_rules(args.rule)[0]
        result = check_audit(audit, [rule])
        print(json.dumps({"findings": result["findings"], "trace": result["trace"]}, indent=2, sort_keys=True))
        return 0
    if args.cmd == "validate":
        rules = load_rules(args.rule)
        root = _validation_root(Path(args.rule))
        result = validate_rules(rules, root=root)
        if result["ok"]:
            for rule in rules:
                corpus_path = root / rule["fixture_requirements"]["corpus"]
                if corpus_path.exists():
                    corpus = json.loads((corpus_path / "corpus.json").read_text())
                    corpus_result = validate_corpus(corpus, expected_rule_id=rule["rule"]["id"])
                    if not corpus_result["ok"]:
                        result["ok"] = False
                        result.setdefault("errors", []).append({
                            "rule_id": rule["rule"]["id"],
                            "errors": corpus_result["errors"],
                        })
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 1
    if args.cmd == "doctor":
        rule = load_rules(args.rule)[0]
        print(json.dumps(_doctor(rule), indent=2, sort_keys=True))
        return 0
    if args.cmd == "test":
        return _run_corpus(Path(args.rule), Path(args.corpus))
    return 1


def _init_detector(rule_id: str, out_dir: Path, corpus_root: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    corpus_path = corpus_root / rule_id
    corpus_path.mkdir(parents=True, exist_ok=True)
    detector_path = out_dir / f"{rule_id}.json"
    detector_path.write_text(json.dumps(_fill_template(TEMPLATE, rule_id), indent=2) + "\n")
    (corpus_path / "corpus.json").write_text(json.dumps(_fill_template(CORPUS_TEMPLATE, rule_id), indent=2) + "\n")
    print(json.dumps({"detector": str(detector_path), "corpus": str(corpus_path / 'corpus.json')}, indent=2))
    return 0


def _fill_template(template: object, rule_id: str) -> object:
    text = json.dumps(template)
    return json.loads(text.replace("{rule_id}", rule_id))


def _run_corpus(rule_path: Path, corpus_path: Path) -> int:
    rule = load_rules(rule_path)[0]
    corpus = load_corpus_manifest(corpus_path, expected_rule_id=rule["rule"]["id"])
    failures = []
    results = []
    counts = {"positive": 0, "negative": 0, "inconclusive": 0}
    false_positive = 0
    false_negative = 0
    for case in corpus.get("cases", []):
        audit_path = corpus_path / case["audit_json"]
        audit = json.loads(audit_path.read_text())
        result = check_audit(audit, [rule])
        matched_ids = {finding["rule_id"] for finding in result["findings"]}
        expectation = case["expectation"]
        kind = expectation["kind"]
        counts[kind] += 1
        expected = set(expectation.get("rule_ids", []))
        missing = sorted(expected - matched_ids) if kind == "positive" else []
        forbidden = sorted(expected & matched_ids) if kind == "negative" else []
        inconclusive_ok = True
        if kind == "inconclusive":
            inconclusive_ok = any(
                finding["rule_id"] in expected and finding["status"] == "analysis_inconclusive"
                for finding in result["findings"]
            )
        ok = not missing and not forbidden and inconclusive_ok
        if not ok:
            failures.append({
                "case": case["id"],
                "missing": missing,
                "forbidden": forbidden,
                "inconclusive_ok": inconclusive_ok,
            })
        false_positive += len(forbidden)
        false_negative += len(missing)
        results.append({"case": case["id"], "ok": ok, "findings": sorted(matched_ids)})
    fixture_requirements = rule["fixture_requirements"]
    if counts["positive"] < fixture_requirements["positive_fixtures_min"]:
        failures.append({"case": "__fixture_requirements__", "missing_positive": True})
    if counts["negative"] < fixture_requirements["negative_fixtures_min"]:
        failures.append({"case": "__fixture_requirements__", "missing_negative": True})
    if counts["inconclusive"] < fixture_requirements["inconclusive_fixtures_min"]:
        failures.append({"case": "__fixture_requirements__", "missing_inconclusive": True})
    metrics = {
        **corpus.get("metrics", {}),
        "false_positive_count": false_positive,
        "false_negative_count": false_negative,
        "detector_precision": 1.0 if false_positive == 0 else 0.0,
        "detector_recall": 1.0 if false_negative == 0 else 0.0,
    }
    print(json.dumps({"ok": not failures, "metrics": metrics, "results": results, "failures": failures}, indent=2, sort_keys=True))
    return 1 if failures else 0


def _doctor(rule: dict[str, object]) -> dict[str, object]:
    issues = []
    requires = rule.get("requires", {})
    sequence = requires.get("sequence", []) if isinstance(requires, dict) else []
    if isinstance(sequence, list):
        if sequence and not any(step.get("bind") for step in sequence if isinstance(step, dict)):
            issues.append("sequence has no bind variables")
        if sequence and not any(
            isinstance(step.get("match"), dict) and any(
                isinstance(value, dict) and any(key in value for key in ("same_slot_as", "same_guard_as", "same_delegate_target_as"))
                for value in step.get("match", {}).values()
            )
            for step in sequence if isinstance(step, dict)
        ):
            issues.append("sequence has no explicit joins")
    analysis = rule.get("analysis_requirements", {})
    if isinstance(analysis, dict) and analysis.get("max_unknown_action_expression_count", 0) >= 1_000_000:
        issues.append("analysis thresholds are effectively disabled")
    proof = rule.get("proof", {})
    if isinstance(proof, dict) and proof.get("preferred_witness") == "none" and rule.get("rule", {}).get("severity") in {"high", "critical"}:
        issues.append("high-severity detector has no witness strategy")
    return {"rule_id": rule.get("rule", {}).get("id"), "issues": issues}


def _validation_root(rule_path: Path) -> Path:
    if not rule_path.is_file():
        return Path.cwd()
    resolved = rule_path.resolve()
    for parent in resolved.parents:
        if parent.name == "rules":
            return parent.parent
    return resolved.parent


if __name__ == "__main__":
    raise SystemExit(main())
