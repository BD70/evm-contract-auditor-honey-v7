"""SARIF rendering for checker findings."""

from __future__ import annotations

from typing import Any


def to_sarif(check_result: dict[str, Any]) -> dict[str, Any]:
    rules = {}
    results = []
    for finding in check_result.get("findings", []):
        rule_id = finding.get("rule_id", "evm.unknown")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.get("title", rule_id),
            "shortDescription": {"text": finding.get("title", rule_id)},
            "properties": {
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "status": finding.get("status"),
                "proof_level": finding.get("proof_level"),
            },
        })
        func = finding.get("function") or {}
        witness_goal = finding.get("witness_goal") or {}
        success_condition = witness_goal.get("success_condition")
        message_text = finding.get("title", rule_id)
        if success_condition:
            message_text = f"{message_text} — Proof goal: {success_condition}"
        results.append({
            "ruleId": rule_id,
            "level": _level(finding.get("severity")),
            "message": {"text": message_text},
            "locations": _locations_for(finding),
            "properties": {
                "status": finding.get("status"),
                "witness_status": finding.get("witness_status"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "proof_level": finding.get("proof_level"),
                "internal_name": finding.get("internal_name"),
                "selector": func.get("selector"),
                "function": func.get("name"),
                "scope": finding.get("scope"),
                "evidence": finding.get("evidence", {}),
                "witness": (finding.get("proof", {}) or {}).get("witness"),
                "witness_goal": witness_goal or None,
                "counter_evidence": finding.get("counter_evidence", {}),
                "exploit_preconditions": finding.get("exploit_preconditions", []),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "evm-audit",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _level(severity: str | None) -> str:
    sev = (severity or "").lower()
    if sev in {"critical", "high"}:
        return "error"
    if sev in {"medium", "warning"}:
        return "warning"
    if sev in {"low", "info", "informational"}:
        return "note"
    return "none"


def _locations_for(finding: dict[str, Any]) -> list[dict[str, Any]]:
    func = finding.get("function") or {}
    logical = []
    selector = func.get("selector")
    if selector:
        logical.append({"name": f"function:{selector}", "kind": "function"})
    evidence = finding.get("evidence", {})
    slot_refs = []
    for seq in evidence.get("sequences", []):
        slot_refs.extend(seq.get("slot_refs", []))
        for step in seq.get("steps", []):
            if step.get("slot"):
                slot_refs.append(step["slot"])
    if slot_refs:
        logical.extend({"name": f"storage-slot:{slot}", "kind": "object"} for slot in sorted(set(slot_refs)))
    return [{
        "physicalLocation": {
            "artifactLocation": {
                "uri": "bytecode:metadata_stripped_keccak256:unknown",
            },
            "region": {
                "startLine": 1,
                "startColumn": 1,
            },
        },
        "logicalLocations": logical,
    }]
