from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any

from evm_core.schemas import DETECTOR_SCHEMA_SUPPORTED_VERSIONS


def load_rules(path: str | Path) -> list[dict[str, Any]]:
    root = Path(path)
    files = sorted(
        path for path in root.rglob("*")
        if path.suffix.lower() in {".json", ".yml", ".yaml"}
    ) if root.is_dir() else [root]

    rules: list[dict[str, Any]] = []
    for file in files:
        data = load_rule_file(file)
        if isinstance(data, list):
            rules.extend(data)
        else:
            rules.append(data)
    return rules


def load_rule_file(path: Path) -> Any:
    text = path.read_text()
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml  # type: ignore
        except Exception as exc:
            raise ValueError(f"YAML detector {path} requires pyyaml; use JSON or install pyyaml") from exc
        data = yaml.safe_load(text)
    _validate_schema_version(data, path)
    return data


def _validate_schema_version(data: Any, path: Path) -> None:
    if not isinstance(data, dict):
        return
    version = data.get("schema_version")
    if version and version not in DETECTOR_SCHEMA_SUPPORTED_VERSIONS:
        warnings.warn(
            f"Detector {path.name} has schema_version={version!r}; "
            f"supported: {DETECTOR_SCHEMA_SUPPORTED_VERSIONS}. "
            "Continuing, but unexpected fields may be ignored.",
            stacklevel=3,
        )
    # witness_goal is optional in both v1.0.0 and v1.1.0 — no validation needed
