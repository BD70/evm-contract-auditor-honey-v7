"""Finding assembly and counter-evidence helpers for the checker."""

from __future__ import annotations

from typing import Any

from .policy import STATUS_PROBABLE, confidence_for, severity_for, status_for, witness_status_for
from .witness import collect_witness


def build_function_finding(
    audit: dict[str, Any],
    fn: dict[str, Any],
    rule: dict[str, Any],
    details: dict[str, Any],
) -> dict[str, Any]:
    meta = rule["rule"]
    proof = rule["proof"]
    reporting = rule.get("reporting", {})
    coverage_ok = details["coverage_checks"]["matched"]
    witness = details.get("witness")
    proof_level = "P4" if witness else proof.get("min_level", "P2")
    status = status_for(coverage_ok, details["counter_evidence"], witness, meta.get("default_status", STATUS_PROBABLE))
    confidence = confidence_for(meta, details["coverage_checks"], witness, coverage_ok)
    return {
        "rule_id": meta["id"],
        "internal_name": meta.get("internal_name"),
        "title": meta["title"],
        "category": meta["category"],
        "severity": severity_for(meta.get("severity"), coverage_ok, details["counter_evidence"]),
        "status": status,
        "witness_status": witness_status_for(status),
        "witness_goal": rule.get("witness_goal"),
        "confidence": confidence,
        "proof_level": proof_level,
        "scope": meta.get("scope"),
        "function": fn.get("identity", {}),
        "evidence": {
            "actions": action_refs(fn),
            "flows": fn.get("flows", []),
            "arithmetic": fn.get("arithmetic", []),
            "accounting": fn.get("accounting", []),
            "details": details,
        },
        "counter_evidence_checked": details["counter_evidence"],
        "counter_evidence": rule.get("counter_evidence", {}),
        "exploit_preconditions": reporting.get("exploit_preconditions", []),
        "summary": reporting.get("summary"),
        "user_summary": reporting.get("user_summary"),
        "technical_summary": reporting.get("technical_summary"),
        "exploit_narrative": reporting.get("exploit_narrative"),
        "reporting": reporting,
        "proof": {
            "required": proof,
            "required_witness": proof.get("preferred_witness", "none"),
            "witness": witness,
        },
    }


def build_stateful_finding(
    audit: dict[str, Any],
    rule: dict[str, Any],
    sequences: list[dict[str, Any]],
    coverage_checks: dict[str, Any],
    counter_results: dict[str, Any],
) -> dict[str, Any]:
    meta = rule["rule"]
    reporting = rule.get("reporting", {})
    witness = collect_witness(audit, rule, context={"sequences": sequences})
    coverage_ok = coverage_checks["matched"]
    status = status_for(coverage_ok, counter_results, witness, meta.get("default_status", STATUS_PROBABLE))
    return {
        "rule_id": meta["id"],
        "internal_name": meta.get("internal_name"),
        "title": meta["title"],
        "category": meta["category"],
        "severity": severity_for(meta.get("severity"), coverage_ok, counter_results),
        "status": status,
        "witness_status": witness_status_for(status),
        "witness_goal": rule.get("witness_goal"),
        "confidence": confidence_for(meta, coverage_checks, witness, coverage_ok),
        "proof_level": "P4" if witness else rule.get("proof", {}).get("min_level", "P2"),
        "scope": meta.get("scope"),
        "function": None,
        "evidence": {
            "sequences": sequences,
            "state_model": audit.get("state_model", {}),
            "coverage_checks": coverage_checks,
        },
        "counter_evidence_checked": counter_results,
        "counter_evidence": rule.get("counter_evidence", {}),
        "exploit_preconditions": reporting.get("exploit_preconditions", []),
        "summary": reporting.get("summary"),
        "user_summary": reporting.get("user_summary"),
        "technical_summary": reporting.get("technical_summary"),
        "exploit_narrative": reporting.get("exploit_narrative"),
        "reporting": reporting,
        "proof": {
            "required": rule.get("proof", {}),
            "required_witness": rule.get("proof", {}).get("preferred_witness", "none"),
            "witness": witness,
        },
    }


def evaluate_sequence_counter_evidence(
    sequences: list[dict[str, Any]],
    rule: dict[str, Any],
    audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    suppress_tokens = set(rule.get("counter_evidence", {}).get("suppress_if_any", []))
    downgrade_tokens = set(rule.get("counter_evidence", {}).get("downgrade_if_any", []))
    inconclusive_tokens = set(rule.get("counter_evidence", {}).get("inconclusive_if_any", []))

    catalog_guards: set[str] = set()
    if audit:
        state_model = audit.get("state_model", {})
        for entry in state_model.get("guard_catalog", []):
            guard_id = entry.get("id", "")
            if guard_id:
                catalog_guards.add(guard_id)
            guard_type = entry.get("type", "")
            if guard_type:
                catalog_guards.add(guard_type)
        # Consume library_fingerprints — each entry's id is a counter-evidence token
        for fp_entry in state_model.get("library_fingerprints", []):
            fp_id = fp_entry.get("id", "")
            if fp_id:
                catalog_guards.add(fp_id)
        # Consume proxy_index pattern tokens
        for proxy_entry in state_model.get("proxy_index", []):
            if proxy_entry.get("proxy_standard"):
                catalog_guards.add(proxy_entry["proxy_standard"])
            if proxy_entry.get("slot_kind"):
                catalog_guards.add(proxy_entry["slot_kind"])
        # Consume tags from function behavior_tags (fingerprint tags propagated there)
        for fn in audit.get("functions", []):
            for tag in fn.get("behavior_tags", []):
                catalog_guards.add(tag)

    suppressed_by = []
    downgraded_by = []
    inconclusive_by = []
    for sequence in sequences:
        guards = {guard for step in sequence.get("steps", []) for guard in step_guard_refs(step)}
        guards |= catalog_guards
        suppress_hit = sorted(token for token in suppress_tokens if token in guards)
        downgrade_hit = sorted(token for token in downgrade_tokens if token in guards)
        inconclusive_hit = sorted(token for token in inconclusive_tokens if token in guards)
        if suppress_hit:
            sequence["suppressed_by"] = suppress_hit
            suppressed_by.extend(suppress_hit)
        if downgrade_hit:
            sequence["downgraded_by"] = downgrade_hit
            downgraded_by.extend(downgrade_hit)
        if inconclusive_hit:
            sequence["inconclusive_by"] = inconclusive_hit
            inconclusive_by.extend(inconclusive_hit)
    return {
        "suppressed_by": sorted(set(suppressed_by)),
        "downgraded_by": sorted(set(downgraded_by)),
        "inconclusive_by": sorted(set(inconclusive_by)),
    }


def step_guard_refs(step: dict[str, Any]) -> list[str]:
    refs = []
    for key in ("writer", "reader", "call"):
        refs.extend(step.get(key, {}).get("guard_refs", []))
    return refs


def action_refs(fn: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": action.get("id"),
            "type": action.get("type"),
            "offset": action.get("offset"),
            "block": action.get("block"),
            "semantic_effect": action.get("semantic_effect"),
        }
        for action in fn.get("actions", [])
    ]
