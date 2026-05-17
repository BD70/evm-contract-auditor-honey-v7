from __future__ import annotations

import json
import os
from pathlib import Path


class SelectorCache:
    def __init__(self, root: Path | None = None) -> None:
        base = root or (Path.home() / ".evm-decon" / "cache")
        self._path = base / "selectors.json"

    def load(self) -> dict[str, list[str]]:
        try:
            if self._path.exists():
                raw = json.loads(self._path.read_text())
                if not isinstance(raw, dict):
                    return {}
                cache: dict[str, list[str]] = {}
                for key, value in raw.items():
                    if not isinstance(key, str) or not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                        return {}
                    cache[key] = value
                return cache
        except (json.JSONDecodeError, OSError):
            return {}
        return {}

    def save(self, cache: dict[str, list[str]]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = self._path.with_suffix(".tmp")
            temp_path.write_text(json.dumps(cache, indent=2))
            os.replace(temp_path, self._path)
        except OSError:
            return
