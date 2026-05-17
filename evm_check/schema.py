"""Schema and detector validation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from evm_core.schemas import BEHAVIOR_SCHEMA_V2, BEHAVIOR_SCHEMA_VERSION, STATE_MODEL_SCHEMA_V2


SUPPORTED_BEHAVIOR_SCHEMA = BEHAVIOR_SCHEMA_VERSION
LEGACY_BEHAVIOR_SCHEMAS = {"evm-audit.behavior", BEHAVIOR_SCHEMA_V2}
LEGACY_STATE_MODEL_SCHEMAS = {"evm-audit.state_model.v1", STATE_MODEL_SCHEMA_V2}
SUPPORTED_DETECTOR_SCHEMA = "1.0.0"
SUPPORTED_CORPUS_SCHEMA = "1.0.0"
CHECKER_SCHEMA = "evm-audit.checker"
DETECTOR_SCHEMA = "evm-audit.detector.v1"
CORPUS_SCHEMA = "evm-audit.corpus.v1"
RULE_VALIDATION_SCHEMA = "evm-audit.detector_validation"

REQUIRED_AUDIT_FIELDS = {
    "schema",
    "schema_version",
    "engine_version",
    "ruleset_version",
    "bytecode_identity",
    "bytecode",
    "contract",
    "functions",
    "storage",
    "memory",
    "arithmetic",
    "calls",
    "events",
    "flows",
    "invariants",
    "assumptions",
    "analysis_warnings",
    "coverage",
    "state_model",
    "checker_findings",
}

PROOF_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
SEVERITY_MIN_PROOF = {
    "critical": "P4",
    "high": "P3",
    "medium": "P2",
    "low": "P1",
    "info": "P0",
    "informational": "P0",
}

VALID_SCOPES = {"function", "contract", "cross_function", "multi_tx", "protocol"}
VALID_STATUSES = {
    "confirmed_vulnerability",
    "probable_vulnerability",
    "suspicious_behavior",
    "expected_protocol_behavior",
    "informational_observation",
    "suppressed_by_counter_evidence",
    "analysis_inconclusive",
}
VALID_WITNESSES = {
    "none",
    "dataflow_trace",
    "reachable_path",
    "invariant_argument",
    "symbolic_counterexample",
    "fuzz_counterexample",
    "transaction_sequence",
    "deterministic_arithmetic_witness",
    "deterministic_accounting_witness",
}
VALID_CONFIDENCE_CAP_POLICIES = {"min_required_input"}
VALID_CONFIDENCE_INPUTS = {
    "function_coverage",
    "storage_role_confidence",
    "path_reachability_confidence",
    "external_call_resolution_confidence",
}

REQUIRED_DETECTOR_SECTIONS = {
    "schema",
    "schema_version",
    "rule",
    "intent",
    "requires",
    "counter_evidence",
    "proof",
    "analysis_requirements",
    "fixture_requirements",
    "reporting",
}

REQUIRED_RULE_FIELDS = {
    "id",
    "internal_name",
    "title",
    "category",
    "severity",
    "scope",
    "lifecycle_status",
    "default_status",
    "confidence_policy",
    "disallow_primary_evidence",
}

REQUIRED_INTENT_FIELDS = {
    "vulnerability_class",
    "attack_thesis",
    "protected_asset_or_effect",
    "exploit_model",
}

REQUIRED_PROOF_FIELDS = {
    "min_level",
    "preferred_witness",
    "acceptable_witnesses",
    "witness_generation",
}

REQUIRED_ANALYSIS_FIELDS = {
    "min_function_coverage",
    "min_storage_role_confidence",
    "min_path_reachability_confidence",
    "max_unknown_action_expression_count",
    "max_unresolved_selector_count",
    "max_unresolved_paths",
    "require_no_unmodeled_terminators",
    "require_usable_primary_evidence",
}

REQUIRED_FIXTURE_FIELDS = {
    "corpus",
    "positive_fixtures_min",
    "negative_fixtures_min",
    "inconclusive_fixtures_min",
    "required_scenarios",
}

REQUIRED_REPORTING_FIELDS = {
    "title_template",
    "summary",
    "user_summary",
    "technical_summary",
    "exploit_narrative",
    "exploit_preconditions",
    "remediation_hints",
    "sarif",
}


def validate_audit(audit: dict[str, Any]) -> list[str]:
    errors = []
    if audit.get("schema") not in LEGACY_BEHAVIOR_SCHEMAS:
        errors.append("schema must be one of: " + ", ".join(sorted(LEGACY_BEHAVIOR_SCHEMAS)))
    missing = sorted(REQUIRED_AUDIT_FIELDS - set(audit))
    if missing:
        errors.append("missing required audit fields: " + ", ".join(missing))
    version = audit.get("schema_version")
    if version and str(version).split(".", 1)[0] not in {"1", "2"}:
        errors.append(f"unsupported behavior schema major version: {version}")
    if "state_model" in audit:
        state = audit["state_model"]
        if not isinstance(state, dict):
            errors.append("state_model must be an object")
        else:
            if state.get("schema") not in LEGACY_STATE_MODEL_SCHEMAS:
                errors.append("state_model.schema must be one of: " + ", ".join(sorted(LEGACY_STATE_MODEL_SCHEMAS)))
            for field in (
                "schema",
                "schema_version",
                "storage_entities",
                "slot_index",
                "path_index",
                "guard_catalog",
                "call_index",
                "economic_index",
                "proxy_index",
                "initializer_index",
                "evidence_index",
            ):
                if field not in state:
                    errors.append(f"state_model missing {field}")
    return errors


def validate_rule(rule: dict[str, Any], root: str | Path | None = None) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    missing_sections = sorted(REQUIRED_DETECTOR_SECTIONS - set(rule))
    if missing_sections:
        errors.append("detector missing required sections: " + ", ".join(missing_sections))

    if rule.get("schema") != DETECTOR_SCHEMA:
        errors.append(f"detector schema must be {DETECTOR_SCHEMA}")
    version = rule.get("schema_version")
    if version and not _same_major(version, SUPPORTED_DETECTOR_SCHEMA):
        errors.append(f"unsupported detector schema major version: {version}")

    meta = rule.get("rule", {})
    intent = rule.get("intent", {})
    requires = rule.get("requires", {})
    counter = rule.get("counter_evidence", {})
    proof = rule.get("proof", {})
    analysis = rule.get("analysis_requirements", {})
    fixtures = rule.get("fixture_requirements", {})
    reporting = rule.get("reporting", {})

    _require_fields("rule", meta, REQUIRED_RULE_FIELDS, errors)
    _require_fields("intent", intent, REQUIRED_INTENT_FIELDS, errors)
    _require_fields("proof", proof, REQUIRED_PROOF_FIELDS, errors)
    _require_fields("analysis_requirements", analysis, REQUIRED_ANALYSIS_FIELDS, errors)
    _require_fields("fixture_requirements", fixtures, REQUIRED_FIXTURE_FIELDS, errors)
    _require_fields("reporting", reporting, REQUIRED_REPORTING_FIELDS, errors)

    disallowed = set(meta.get("disallow_primary_evidence", []))
    if not {"function_name", "selector"} <= disallowed:
        errors.append("detector must disallow function_name and selector as primary evidence")

    severity = str(meta.get("severity", "warning")).lower()
    min_required = SEVERITY_MIN_PROOF.get(severity, "P2")
    declared_raw = str(proof.get("min_level", "P2"))
    declared = _normalize_proof(declared_raw)
    if declared_raw not in PROOF_ORDER:
        errors.append("proof.min_level must be one of P0, P1, P2, P3, P4")
    preferred_witness = str(proof.get("preferred_witness", "none"))
    witnesses = proof.get("acceptable_witnesses", [])
    if preferred_witness not in VALID_WITNESSES:
        errors.append(f"invalid proof.preferred_witness: {preferred_witness}")
    if not isinstance(witnesses, list) or not witnesses:
        errors.append("proof.acceptable_witnesses must be a non-empty list")
    else:
        invalid = sorted(w for w in witnesses if w not in VALID_WITNESSES)
        if invalid:
            errors.append("invalid acceptable witnesses: " + ", ".join(invalid))
    if PROOF_ORDER.get(declared, -1) < PROOF_ORDER[min_required]:
        errors.append(f"{severity} severity requires at least {min_required}, got {declared}")
    if preferred_witness not in set(witnesses):
        errors.append("proof.preferred_witness must be included in proof.acceptable_witnesses")

    status = meta.get("default_status", "probable_vulnerability")
    if status not in VALID_STATUSES:
        errors.append(f"invalid rule.default_status: {status}")
    scope = meta.get("scope")
    if scope not in VALID_SCOPES:
        errors.append(f"invalid rule.scope: {scope}")

    confidence_policy = meta.get("confidence_policy")
    if not isinstance(confidence_policy, dict):
        errors.append("rule.confidence_policy must be an object")
    else:
        for field in ("base", "with_witness", "inconclusive"):
            if field not in confidence_policy:
                errors.append(f"rule.confidence_policy missing {field}")
    confidence_cap_policy = meta.get("confidence_cap_policy")
    required_confidence_inputs = meta.get("required_confidence_inputs")
    if confidence_cap_policy is not None:
        if confidence_cap_policy not in VALID_CONFIDENCE_CAP_POLICIES:
            errors.append("rule.confidence_cap_policy must be one of: " + ", ".join(sorted(VALID_CONFIDENCE_CAP_POLICIES)))
        if not isinstance(required_confidence_inputs, list) or not required_confidence_inputs:
            errors.append("rule.required_confidence_inputs must be a non-empty list when confidence_cap_policy is set")
        else:
            invalid_inputs = sorted(value for value in required_confidence_inputs if value not in VALID_CONFIDENCE_INPUTS)
            if invalid_inputs:
                errors.append("invalid rule.required_confidence_inputs: " + ", ".join(invalid_inputs))
    elif required_confidence_inputs is not None:
        errors.append("rule.required_confidence_inputs requires rule.confidence_cap_policy")

    if not isinstance(counter, dict):
        errors.append("counter_evidence must be an object")
    else:
        for field in ("suppress_if_any", "downgrade_if_any", "inconclusive_if_any", "manual_review_if_any"):
            if field not in counter:
                errors.append(f"counter_evidence missing {field}")

    if "require_usable_primary_evidence" in analysis and not isinstance(analysis.get("require_usable_primary_evidence"), bool):
        errors.append("analysis_requirements.require_usable_primary_evidence must be a boolean")

    if scope in {"multi_tx", "cross_function", "protocol"}:
        sequence = requires.get("sequence")
        if not isinstance(sequence, list) or len(sequence) < 2:
            errors.append(f"{scope} detector requires a sequence with at least two steps")
        else:
            _validate_sequence(sequence, errors)

    if meta.get("scope") in {"multi_tx", "cross_function"} and not requires.get("stateful", True):
        errors.append("stateful cross-function or multi-tx detectors must set requires.stateful=true")

    if not _has_real_analysis_thresholds(analysis):
        errors.append("analysis_requirements are too permissive for production detectors")

    if fixtures.get("positive_fixtures_min", 0) < 1:
        errors.append("fixture_requirements.positive_fixtures_min must be at least 1")
    if fixtures.get("negative_fixtures_min", 0) < 1:
        errors.append("fixture_requirements.negative_fixtures_min must be at least 1")
    if fixtures.get("inconclusive_fixtures_min", 0) < 1:
        errors.append("fixture_requirements.inconclusive_fixtures_min must be at least 1")
    if not fixtures.get("required_scenarios"):
        errors.append("fixture_requirements.required_scenarios must not be empty")

    if root is not None:
        corpus_path = Path(root) / str(fixtures.get("corpus", ""))
        if not corpus_path.exists():
            errors.append(f"declared corpus does not exist: {corpus_path}")

    if not _has_effect_requirement(requires):
        errors.append("detector requires at least one sensitive effect constraint")

    return {
        "schema": RULE_VALIDATION_SCHEMA,
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
    }


def validate_corpus(manifest: dict[str, Any], expected_rule_id: str | None = None) -> dict[str, Any]:
    errors: list[str] = []
    if manifest.get("schema") != CORPUS_SCHEMA:
        errors.append(f"corpus schema must be {CORPUS_SCHEMA}")
    version = manifest.get("schema_version")
    if version and not _same_major(version, SUPPORTED_CORPUS_SCHEMA):
        errors.append(f"unsupported corpus schema major version: {version}")
    if "cases" not in manifest or not isinstance(manifest["cases"], list):
        errors.append("corpus must include a cases list")
    if "metrics" not in manifest or not isinstance(manifest["metrics"], dict):
        errors.append("corpus must include a metrics object")
    if "scenario_taxonomy" not in manifest:
        errors.append("corpus must include scenario_taxonomy")
    for case in manifest.get("cases", []):
        for field in ("id", "audit_json", "expectation"):
            if field not in case:
                errors.append(f"corpus case missing {field}: {case}")
        expectation = case.get("expectation", {})
        if expectation.get("kind") not in {"positive", "negative", "inconclusive"}:
            errors.append(f"invalid expectation.kind for case {case.get('id')}")
        ids = expectation.get("rule_ids", [])
        if expected_rule_id and expected_rule_id not in ids:
            errors.append(f"case {case.get('id')} does not validate detector {expected_rule_id}")
    return {
        "schema": "evm-audit.corpus_validation",
        "ok": not errors,
        "errors": errors,
    }


def enforce_rule(rule: dict[str, Any], root: str | Path | None = None) -> None:
    result = validate_rule(rule, root=root)
    if not result["ok"]:
        rid = rule.get("rule", {}).get("id", "<unknown>")
        raise ValueError(f"detector {rid} validation failed: " + "; ".join(result["errors"]))


def _validate_sequence(sequence: list[dict[str, Any]], errors: list[str]) -> None:
    bindings: set[str] = set()
    saw_join = False
    for idx, step in enumerate(sequence, start=1):
        if not step.get("id"):
            errors.append(f"sequence step {idx} missing id")
        match = step.get("match")
        if not isinstance(match, dict):
            errors.append(f"sequence step {idx} missing match object")
            continue
        bind = step.get("bind", {})
        if bind:
            for value in bind.values():
                if isinstance(value, str) and value.startswith("$"):
                    bindings.add(value)
        for join_field in ("same_slot_as", "same_guard_as", "same_delegate_target_as", "same_call_target_as"):
            if _join_uses_binding(match, join_field):
                saw_join = True
        if _step_needs_binding(match) and idx > 1 and not any(
            _join_uses_binding(match, field)
            for field in ("same_slot_as", "same_guard_as", "same_delegate_target_as", "same_call_target_as")
        ):
            errors.append(f"sequence step {idx} must join to a previous binding")
    if bindings and not saw_join:
        errors.append("sequence binds variables but never reuses them in a join")
    if not bindings:
        errors.append("sequence requires explicit bind variables for state joins")


def _join_uses_binding(match: dict[str, Any], join_field: str) -> bool:
    for value in match.values():
        if isinstance(value, dict) and isinstance(value.get(join_field), str) and value[join_field].startswith("$"):
            return True
    return False


def _step_needs_binding(match: dict[str, Any]) -> bool:
    return any(key in match for key in ("storage_read", "storage_write", "delegatecall", "proxy_write", "authorization_state", "external_call"))


def _has_real_analysis_thresholds(analysis: dict[str, Any]) -> bool:
    try:
        return (
            float(analysis.get("min_function_coverage", 0.0)) >= 0.5
            and float(analysis.get("min_storage_role_confidence", 0.0)) >= 0.5
            and float(analysis.get("min_path_reachability_confidence", 0.0)) >= 0.5
            and int(analysis.get("max_unknown_action_expression_count", 1_000_000)) < 1_000_000
            and int(analysis.get("max_unresolved_selector_count", 1_000_000)) < 1_000_000
            and int(analysis.get("max_unresolved_paths", 1_000_000)) < 1_000_000
        )
    except Exception:
        return False


def _has_effect_requirement(requires: dict[str, Any]) -> bool:
    if any(requires.get(key) for key in ("reachable_effect_any", "authorized_path_effect_any", "economic_effect_any")):
        return True
    for step in requires.get("sequence", []):
        match = step.get("match", {})
        if any(match.get(key) for key in ("reachable_effect_any", "authorized_path_effect_any", "economic_effect_any")):
            return True
    ext = requires.get("external_call", {})
    if ext and ext.get("return_flow_effect_any"):
        return True
    return False


def _require_fields(prefix: str, obj: dict[str, Any], required: set[str], errors: list[str]) -> None:
    if not isinstance(obj, dict):
        errors.append(f"{prefix} must be an object")
        return
    missing = sorted(required - set(obj))
    if missing:
        errors.append(f"{prefix} missing required fields: " + ", ".join(missing))


def _same_major(version: str, supported: str) -> bool:
    return str(version).split(".", 1)[0] == str(supported).split(".", 1)[0]


def _normalize_proof(value: str) -> str:
    aliases = {
        "observation": "P0",
        "dataflow": "P1",
        "path_evidence": "P2",
        "protocol_interpretation": "P3",
        "symbolic_counterexample": "P4",
    }
    value = str(value)
    return aliases.get(value, value if value in PROOF_ORDER else "P2")
