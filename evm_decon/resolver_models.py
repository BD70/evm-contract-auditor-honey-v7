from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ResolvedSignature:
    selector: str
    text_signatures: list[str]
    source: str
    confidence: str


@dataclass
class ResolverResult:
    resolved: list[ResolvedSignature]
    unresolved: list[str]
    errors: list[str] = field(default_factory=list)
