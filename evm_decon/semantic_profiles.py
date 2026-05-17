"""Profile-pack semantic helpers extracted from semantic_patterns."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .function_slicer import FunctionSliceResult
from .profile_packs import ProfileRegistry

if TYPE_CHECKING:
    from .semantic_patterns import PatternCard


def detect_profile_patterns(
    slices: FunctionSliceResult,
    names: dict[str, str],
    profile_registry: ProfileRegistry | None,
    *,
    pattern_card_type: type["PatternCard"],
) -> list["PatternCard"]:
    if not profile_registry:
        return []
    func_names = {names.get(f.selector, "") for f in slices.functions if names.get(f.selector, "")}
    cards = []
    for pack in profile_registry.packs:
        for pattern in pack.patterns:
            required = set(pattern.get("required_selectors", []))
            optional = set(pattern.get("optional_selectors", []))
            if not required:
                continue
            matched_required = sorted(required & func_names)
            matched_optional = sorted(optional & func_names)
            confidence = len(matched_required) / len(required)
            if len(matched_required) == len(required):
                confidence = float(pattern.get("confidence", 0.9))
            elif confidence < float(pattern.get("minimum_confidence", 0.5)):
                continue
            evidence = [f"profile {pack.name}: matched {len(matched_required)}/{len(required)} required selectors"]
            if matched_optional:
                evidence.append(f"optional selectors: {', '.join(matched_optional)}")
            cards.append(pattern_card_type(
                pattern_name=pattern.get("name", pack.name),
                confidence=min(confidence, 1.0),
                evidence=evidence,
                details={
                    "profile": pack.name,
                    "roles": pattern.get("roles", []),
                    "matched_required": matched_required,
                    "matched_optional": matched_optional,
                },
            ))
    return cards


def apply_profile_pattern_suppression(
    patterns: list["PatternCard"],
    profile_registry: ProfileRegistry | None,
) -> list["PatternCard"]:
    if not profile_registry:
        return patterns
    active_profile_patterns = {p.pattern_name for p in patterns if p.details.get("profile") and p.confidence >= 0.7}
    suppressed: set[str] = set()
    for pack in profile_registry.packs:
        if any(p.details.get("profile") == pack.name and p.pattern_name in active_profile_patterns for p in patterns):
            suppressed.update(pack.suppress_patterns)
    if not suppressed:
        return patterns
    return [pattern for pattern in patterns if pattern.pattern_name not in suppressed]
