from __future__ import annotations

from typing import Any

from .errors import ValidationError
from .schemas import (
    API_SCHEMA_V2,
    API_SCHEMA_VERSION,
    BEHAVIOR_SCHEMA_V2,
    BEHAVIOR_SCHEMA_VERSION,
    STATE_MODEL_SCHEMA_V2,
    STATE_MODEL_SCHEMA_VERSION,
)


_REQUIRED_BEHAVIOR_FIELDS = {
    "analysis_context",
    "analysis_warnings",
    "arithmetic",
    "assumptions",
    "bytecode",
    "bytecode_identity",
    "calls",
    "checker_findings",
    "contract",
    "coverage",
    "diagnostics",
    "engine_version",
    "events",
    "flows",
    "functions",
    "invariants",
    "memory",
    "ruleset_version",
    "schema",
    "schema_version",
    "state_model",
    "storage",
    "timings",
}

_REQUIRED_STATE_MODEL_FIELDS = {
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
}

_REQUIRED_API_FIELDS = {
    "analysis",
    "bytecode_identity",
    "coverage",
    "diagnostics",
    "findings",
    "input",
    "ok",
    "schema",
    "schema_version",
}


def validate_behavior_document(document: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if document.get("schema") != BEHAVIOR_SCHEMA_V2:
        errors.append(f"schema must be {BEHAVIOR_SCHEMA_V2}")
    if document.get("schema_version") != BEHAVIOR_SCHEMA_VERSION:
        errors.append(f"schema_version must be {BEHAVIOR_SCHEMA_VERSION}")
    missing = sorted(_REQUIRED_BEHAVIOR_FIELDS - set(document))
    if missing:
        errors.append("missing required behavior fields: " + ", ".join(missing))
    state_model = document.get("state_model")
    if not isinstance(state_model, dict):
        errors.append("state_model must be an object")
    else:
        if state_model.get("schema") != STATE_MODEL_SCHEMA_V2:
            errors.append(f"state_model.schema must be {STATE_MODEL_SCHEMA_V2}")
        if state_model.get("schema_version") != STATE_MODEL_SCHEMA_VERSION:
            errors.append(f"state_model.schema_version must be {STATE_MODEL_SCHEMA_VERSION}")
        missing_state = sorted(_REQUIRED_STATE_MODEL_FIELDS - set(state_model))
        if missing_state:
            errors.append("state_model missing required fields: " + ", ".join(missing_state))
    if errors:
        raise ValidationError("behavior document validation failed", errors=errors)
    return document


def validate_api_document(document: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if document.get("schema") != API_SCHEMA_V2:
        errors.append(f"schema must be {API_SCHEMA_V2}")
    if document.get("schema_version") != API_SCHEMA_VERSION:
        errors.append(f"schema_version must be {API_SCHEMA_VERSION}")
    missing = sorted(_REQUIRED_API_FIELDS - set(document))
    if missing:
        errors.append("missing required api fields: " + ", ".join(missing))
    analysis = document.get("analysis")
    if not isinstance(analysis, dict):
        errors.append("analysis must be an object")
    else:
        for field in ("matched", "finding_count", "raw_match_count"):
            if field not in analysis:
                errors.append(f"analysis missing {field}")
    if errors:
        raise ValidationError("api document validation failed", errors=errors)
    return document
