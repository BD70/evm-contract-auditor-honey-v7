from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import validate_corpus


def load_corpus_manifest(path: str | Path, expected_rule_id: str | None = None) -> dict[str, Any]:
    manifest_path = Path(path) / "corpus.json"
    if not manifest_path.exists():
        raise ValueError(f"missing corpus manifest: {manifest_path}")
    corpus = json.loads(manifest_path.read_text())
    validation = validate_corpus(corpus, expected_rule_id=expected_rule_id)
    if not validation["ok"]:
        raise ValueError("; ".join(validation["errors"]))
    return corpus
