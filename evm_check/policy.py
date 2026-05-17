"""Shared checker policy decisions for status, severity, and confidence."""

from __future__ import annotations

from typing import Any

STATUS_PROBABLE = "probable_vulnerability"
STATUS_SUSPICIOUS = "suspicious_behavior"
STATUS_SUPPRESSED = "suppressed_by_counter_evidence"
STATUS_INCONCLUSIVE = "analysis_inconclusive"

WITNESS_STATUS_NOT_ATTEMPTED = "not_attempted"
WITNESS_STATUS_SUPPRESSED = "suppressed_by_counter_evidence"
WITNESS_STATUS_INCONCLUSIVE = "analysis_inconclusive"


def status_for(
    coverage_ok: bool,
    counter_results: dict[str, Any],
    witness: dict[str, Any] | None,
    default_status: str,
) -> str:
    if not coverage_ok:
        return STATUS_INCONCLUSIVE
    if counter_results.get("suppressed_by") or counter_results.get("suppress_if_any"):
        return STATUS_SUPPRESSED
    if counter_results.get("inconclusive_if_any") or counter_results.get("inconclusive_by"):
        return STATUS_INCONCLUSIVE
    if counter_results.get("downgraded_by") or counter_results.get("downgrade_if_any"):
        return STATUS_SUSPICIOUS
    if counter_results.get("manual_review_if_any"):
        return STATUS_SUSPICIOUS
    if witness or default_status in {STATUS_PROBABLE, "confirmed_vulnerability"}:
        return default_status
    return STATUS_SUSPICIOUS


def confidence_for(
    meta: dict[str, Any],
    coverage_checks: dict[str, Any],
    witness: dict[str, Any] | None,
    coverage_ok: bool,
) -> float:
    policy = meta.get("confidence_policy", {})
    base = float(policy.get("base", 0.6))
    if not coverage_ok:
        confidence = float(policy.get("inconclusive", max(0.2, base - 0.25)))
    elif witness:
        confidence = float(policy.get("with_witness", min(0.99, base + 0.2)))
    else:
        confidence = base
    cap = confidence_cap(meta, coverage_checks)
    return min(confidence, cap) if cap is not None else confidence


def confidence_cap(meta: dict[str, Any], coverage_checks: dict[str, Any]) -> float | None:
    if meta.get("confidence_cap_policy") != "min_required_input":
        return None
    inputs = meta.get("required_confidence_inputs", [])
    if not inputs:
        return None
    actual = coverage_checks.get("actual", {})
    values = [float(actual[name]) for name in inputs if name in actual]
    if not values:
        return None
    return min(values)


def coverage_checks(audit: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    coverage = audit.get("coverage", {})
    analysis = rule.get("analysis_requirements", {})
    actual = {
        "function_coverage": float(coverage.get("function_coverage", 0.0)),
        "unknown_action_expression_count": int(coverage.get("unknown_action_expression_count", 0)),
        "unresolved_selector_count": int(coverage.get("unresolved_selector_count", 0)),
        "unresolved_path_count": int(coverage.get("unresolved_path_count", 0)),
        "storage_role_confidence": float(coverage.get("storage_role_confidence", 1.0)),
        "path_reachability_confidence": float(coverage.get("path_reachability_confidence", 1.0)),
        "external_call_resolution_confidence": float(coverage.get("external_call_resolution_confidence", 1.0)),
        "has_unmodeled_terminators": bool(coverage.get("has_unmodeled_terminators", False)),
    }
    failures = []
    if actual["function_coverage"] < float(analysis.get("min_function_coverage", 0.0)):
        failures.append("function_coverage")
    if actual["storage_role_confidence"] < float(analysis.get("min_storage_role_confidence", 0.0)):
        failures.append("storage_role_confidence")
    if actual["path_reachability_confidence"] < float(analysis.get("min_path_reachability_confidence", 0.0)):
        failures.append("path_reachability_confidence")
    if actual["unknown_action_expression_count"] > int(analysis.get("max_unknown_action_expression_count", 0)):
        failures.append("unknown_action_expression_count")
    if actual["unresolved_selector_count"] > int(analysis.get("max_unresolved_selector_count", 0)):
        failures.append("unresolved_selector_count")
    if actual["unresolved_path_count"] > int(analysis.get("max_unresolved_paths", 0)):
        failures.append("unresolved_path_count")
    if analysis.get("require_no_unmodeled_terminators") and actual["has_unmodeled_terminators"]:
        failures.append("has_unmodeled_terminators")
    return {"matched": not failures, "requirements": analysis, "actual": actual, "failures": failures}


def witness_status_for(status: str) -> str:
    """Map a finding status to a witness_status. Without a dynamic executor all findings are not_attempted."""
    if status == STATUS_SUPPRESSED:
        return WITNESS_STATUS_SUPPRESSED
    if status == STATUS_INCONCLUSIVE:
        return WITNESS_STATUS_INCONCLUSIVE
    return WITNESS_STATUS_NOT_ATTEMPTED


def severity_for(severity: str | None, coverage_ok: bool, counter_results: dict[str, Any]) -> str:
    severity = str(severity or "warning").lower()
    if not coverage_ok:
        return "medium" if severity in {"critical", "high"} else severity
    if counter_results.get("downgraded_by") or counter_results.get("downgrade_if_any"):
        return "medium" if severity in {"critical", "high"} else "low"
    if counter_results.get("inconclusive_by") or counter_results.get("inconclusive_if_any"):
        return "medium" if severity in {"critical", "high"} else severity
    if counter_results.get("manual_review_if_any"):
        return "medium" if severity in {"critical", "high"} else severity
    return severity
