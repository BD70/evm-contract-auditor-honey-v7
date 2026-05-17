"""Data-driven contract profile packs.

Profiles are JSON files loaded from user-controlled directories. They can add
selector signatures, storage anchors, protocol pattern definitions, and
function semantic overrides without baking contract families into Python code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import json


@dataclass(frozen=True)
class ProfileSignature:
    selector: str
    signature: str
    profile: str
    kind: str = "function"


@dataclass
class ProfilePack:
    name: str
    selectors: list[ProfileSignature] = field(default_factory=list)
    patterns: list[dict[str, Any]] = field(default_factory=list)
    storage_anchors: list[dict[str, Any]] = field(default_factory=list)
    function_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    expected_permissionless: list[str] = field(default_factory=list)
    suppress_patterns: list[str] = field(default_factory=list)


@dataclass
class ProfileRegistry:
    packs: list[ProfilePack] = field(default_factory=list)
    by_selector: dict[str, list[ProfileSignature]] = field(default_factory=dict)

    def lookup_selector(self, selector_hex: str) -> list[ProfileSignature]:
        normalized = selector_hex.lower().replace("0x", "")
        return list(self.by_selector.get(normalized, []))


def default_profile_dirs() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[1]
    paths = [repo_root / "profiles", repo_root / "contract_profiles"]
    return [path for path in paths if path.exists()]


def load_profile_registry(profile_dirs: list[str | Path] | None = None) -> ProfileRegistry:
    registry = ProfileRegistry()
    seen_dirs: set[Path] = set()
    seen_files: set[Path] = set()
    seen_signatures: set[tuple[str, str, str]] = set()
    for directory in profile_dirs or []:
        root = Path(directory)
        if not root.exists():
            continue
        resolved_root = root.resolve()
        if resolved_root in seen_dirs:
            continue
        seen_dirs.add(resolved_root)
        for file in sorted(root.rglob("*.json")):
            resolved_file = file.resolve()
            if resolved_file in seen_files:
                continue
            seen_files.add(resolved_file)
            pack = _load_pack(file)
            registry.packs.append(pack)
            for sig in pack.selectors:
                normalized = sig.selector.lower().replace("0x", "")
                key = (normalized, sig.signature, sig.profile)
                if key in seen_signatures:
                    continue
                seen_signatures.add(key)
                registry.by_selector.setdefault(normalized, []).append(sig)
    return registry


def _load_pack(path: Path) -> ProfilePack:
    data = json.loads(path.read_text())
    name = data.get("name") or path.stem
    selectors = [
        ProfileSignature(
            selector=row["selector"],
            signature=row["signature"],
            profile=name,
            kind=row.get("kind", "function"),
        )
        for row in data.get("selectors", [])
    ]
    return ProfilePack(
        name=name,
        selectors=selectors,
        patterns=list(data.get("patterns", [])),
        storage_anchors=list(data.get("storage_anchors", [])),
        function_overrides=dict(data.get("function_overrides", {})),
        expected_permissionless=list(data.get("expected_permissionless", [])),
        suppress_patterns=list(data.get("suppress_patterns", [])),
    )
