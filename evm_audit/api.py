from __future__ import annotations

from typing import Any

from evm_core import API_SCHEMA_V2, API_SCHEMA_VERSION, validate_api_document


_ERC20_SELECTORS: dict[str, str] = {
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x70a08231": "balanceOf(address)",
    "0xdd62ed3e": "allowance(address,address)",
    "0x18160ddd": "totalSupply()",
    "0x313ce567": "decimals()",
}

_VALUE_MOVING_SELECTORS = {"0xa9059cbb", "0x23b872dd"}
_APPROVAL_SELECTORS = {"0x095ea7b3"}


def to_api_json(audit: dict[str, Any], checker: dict[str, Any], input_kind: str, input_value: str, *, bytecode_hex: str = "", chain_context: dict[str, Any] | None = None) -> dict[str, Any]:
    raw_findings = checker.get("findings", [])
    findings = _collapse_api_findings(raw_findings)
    positive_statuses = {"probable_vulnerability", "confirmed_vulnerability"}
    matched = any(finding.get("status") in positive_statuses for finding in findings)
    severities = [str(finding.get("severity", "")).lower() for finding in findings]
    ordered = ["critical", "high", "medium", "low", "info", "informational"]
    highest_severity = next((severity for severity in ordered if severity in severities), None)
    highest_confidence = max((float(finding.get("confidence", 0.0)) for finding in findings), default=0.0)
    raw_analysis_warnings = list(audit.get("analysis_warnings", []))
    pipeline_warns = (audit.get("diagnostics", {}) or {}).get("analysis", {}).get("pipeline_warnings", [])
    for pw in pipeline_warns:
        raw_analysis_warnings.append({"id": "pipeline_truncated", "message": pw, "severity": "info"})
    warnings = [w.get("message") for w in raw_analysis_warnings if w.get("message")]
    document = {
        "ok": True,
        "schema": API_SCHEMA_V2,
        "schema_version": API_SCHEMA_VERSION,
        "input": {
            "kind": input_kind,
            "value": input_value,
        },
        "analysis_context": audit.get("analysis_context", {}),
        "bytecode_identity": audit.get("bytecode_identity", {}),
        "analysis": {
            "matched": matched,
            "finding_count": len(findings),
            "raw_match_count": len(raw_findings),
            "highest_severity": highest_severity,
            "highest_confidence": highest_confidence,
        },
        "coverage": audit.get("coverage", {}),
        "diagnostics": {
            "analysis_warnings": warnings,
            "deconstruction": audit.get("diagnostics", {}),
            "checker_trace_count": len(checker.get("trace", [])),
        },
        "artifacts": {
            "behavior_schema": audit.get("schema"),
            "state_model_schema": (audit.get("state_model") or {}).get("schema"),
        },
        "exposure_estimate": _exposure_estimate(audit, findings, bytecode_hex=bytecode_hex),
        "findings": [_api_finding(finding) for finding in findings],
        "warnings": warnings,
        "chain_context": chain_context or {},
    }
    return validate_api_document(document)


def _api_finding(finding: dict[str, Any]) -> dict[str, Any]:
    function = finding.get("function") or {}
    witness = (finding.get("proof") or {}).get("witness")
    return {
        "rule_id": finding.get("rule_id"),
        "internal_name": finding.get("internal_name"),
        "title": finding.get("title"),
        "status": finding.get("status"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "proof_level": finding.get("proof_level"),
        "scope": finding.get("scope"),
        "match_count": finding.get("match_count", 1),
        "function": {
            "selector": function.get("selector"),
            "name": function.get("name"),
            "id": function.get("id") or (f"fn:{function.get('selector')}" if function.get("selector") else None),
        },
        "affected_functions": finding.get("affected_functions", [{
            "selector": function.get("selector"),
            "name": function.get("name"),
        }]),
        "raw_matches": finding.get("raw_matches", [_raw_match(finding)]),
        "summary": finding.get("summary"),
        "user_summary": finding.get("user_summary") or finding.get("summary"),
        "technical_summary": finding.get("technical_summary") or finding.get("summary"),
        "exploit_narrative": finding.get("exploit_narrative"),
        "exploit_preconditions": finding.get("exploit_preconditions", []),
        "evidence_refs": (witness or {}).get("evidence_refs", {}),
        "witness": witness,
        "witness_status": finding.get("witness_status"),
        "witness_goal": finding.get("witness_goal"),
        "judged_by": finding.get("judged_by"),
        "judge_verdict": finding.get("judge_verdict"),
        "judge_rationale": finding.get("judge_rationale"),
        "judge_confidence": finding.get("judge_confidence"),
        "requires_manual_review": finding.get("requires_manual_review"),
    }


def _collapse_api_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        witness = ((finding.get("proof") or {}).get("witness")) or {}
        key = (
            finding.get("rule_id"),
            finding.get("status"),
            finding.get("severity"),
            finding.get("proof_level"),
            finding.get("summary"),
            finding.get("user_summary"),
            finding.get("technical_summary"),
            finding.get("exploit_narrative"),
            witness.get("kind"),
            witness.get("mismatch_amount"),
            witness.get("mismatch_relation"),
        )
        entry = grouped.get(key)
        function = finding.get("function") or {}
        function_ref = {
            "selector": function.get("selector"),
            "name": function.get("name"),
        }
        if entry is None:
            collapsed = dict(finding)
            collapsed["match_count"] = 1
            collapsed["affected_functions"] = [function_ref]
            collapsed["raw_matches"] = [_raw_match(finding)]
            grouped[key] = collapsed
            continue
        entry["match_count"] = int(entry.get("match_count", 1)) + 1
        affected = entry.setdefault("affected_functions", [])
        if function_ref not in affected:
            affected.append(function_ref)
        raw_matches = entry.setdefault("raw_matches", [])
        raw_match = _raw_match(finding)
        if raw_match not in raw_matches:
            raw_matches.append(raw_match)
    return list(grouped.values())


def _raw_match(finding: dict[str, Any]) -> dict[str, Any]:
    function = finding.get("function") or {}
    witness = (finding.get("proof") or {}).get("witness") or {}
    evidence_refs = witness.get("evidence_refs") or {}
    return {
        "function": {
            "selector": function.get("selector"),
            "name": function.get("name"),
            "id": function.get("id") or (f"fn:{function.get('selector')}" if function.get("selector") else None),
        },
        "path_id": witness.get("path_id"),
        "witness_id": witness.get("witness_id"),
        "evidence_refs": evidence_refs,
    }


def _exposure_estimate(audit: dict[str, Any], findings: list[dict[str, Any]], *, bytecode_hex: str = "") -> dict[str, Any]:
    functions = audit.get("functions", [])
    state_model = audit.get("state_model", {})
    call_index = state_model.get("call_index", [])

    token_ops: list[dict[str, Any]] = []
    seen_ops: set[tuple[str, str]] = set()
    for fn in functions:
        selector = fn.get("identity", {}).get("selector", "")
        fn_name = fn.get("identity", {}).get("name")
        guards = [g for g in fn.get("guards", []) if isinstance(g, dict)]
        guard_ids = [g.get("id", "") for g in guards]
        is_guarded = bool(guard_ids)

        for action in fn.get("actions", []):
            if action.get("type") not in ("CALL", "STATICCALL", "DELEGATECALL"):
                continue
            expr = str(action.get("expression", ""))
            for method_sel, method_name in _ERC20_SELECTORS.items():
                if method_sel in expr:
                    key = (selector, method_sel)
                    if key in seen_ops:
                        continue
                    seen_ops.add(key)
                    token_ops.append({
                        "function": selector,
                        "function_name": fn_name,
                        "erc20_method": method_name,
                        "erc20_selector": method_sel,
                        "moves_value": method_sel in _VALUE_MOVING_SELECTORS,
                        "requires_approval": method_sel in _APPROVAL_SELECTORS,
                        "guarded": is_guarded,
                        "guard_refs": guard_ids,
                    })

    for call_entry in call_index:
        target = str(call_entry.get("target", ""))
        fn_sel = call_entry.get("function", "")
        for method_sel, method_name in _ERC20_SELECTORS.items():
            if method_sel in target:
                key = (fn_sel, method_sel)
                if key in seen_ops:
                    continue
                seen_ops.add(key)
                token_ops.append({
                    "function": fn_sel,
                    "function_name": None,
                    "erc20_method": method_name,
                    "erc20_selector": method_sel,
                    "moves_value": method_sel in _VALUE_MOVING_SELECTORS,
                    "requires_approval": method_sel in _APPROVAL_SELECTORS,
                    "guarded": bool(call_entry.get("guard_refs")),
                    "guard_refs": call_entry.get("guard_refs", []),
                })

    bytecode_erc20: list[dict[str, str]] = []
    bc = bytecode_hex.lower().replace("0x", "")
    for method_sel, method_name in _ERC20_SELECTORS.items():
        raw_sel = method_sel[2:]
        if raw_sel in bc:
            bytecode_erc20.append({
                "erc20_selector": method_sel,
                "erc20_method": method_name,
                "source": "bytecode_scan",
            })

    uses_transfer_from = (
        any(op["erc20_selector"] == "0x23b872dd" for op in token_ops)
        or any(e["erc20_selector"] == "0x23b872dd" for e in bytecode_erc20)
    )
    uses_approve = (
        any(op["requires_approval"] for op in token_ops)
        or any(e["erc20_selector"] == "0x095ea7b3" for e in bytecode_erc20)
    )

    exposure_type = "unknown"
    if any(f.get("rule_id") == "control.unguarded_selfdestruct" for f in findings):
        exposure_type = "total_contract_eth_balance"
    elif any(f.get("rule_id") == "delegatecall.storage_controlled_target" for f in findings):
        exposure_type = "full_storage_takeover"
    elif uses_transfer_from:
        exposure_type = "caller_approved_tokens"
    elif any(op["moves_value"] for op in token_ops):
        exposure_type = "per_transaction_amount"
    elif not token_ops:
        exposure_type = "none"

    return {
        "type": exposure_type,
        "token_operations": token_ops,
        "bytecode_selector_hints": bytecode_erc20,
        "uses_transfer_from": uses_transfer_from,
        "uses_approve": uses_approve,
    }
