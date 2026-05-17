"""
Selector resolution facade.

Compatibility module kept to preserve existing imports while the implementation
is split into service and infrastructure adapters.
"""

from __future__ import annotations

from .profile_packs import ProfileRegistry
from .resolver_models import ResolvedSignature, ResolverResult
from .resolver_service import SelectorResolverService


def resolve_selectors(
    selectors: list[str],
    use_api: bool = True,
    api_delay: float = 0.2,
    profile_registry: ProfileRegistry | None = None,
) -> ResolverResult:
    service = SelectorResolverService()
    return service.resolve(
        selectors,
        use_api=use_api,
        api_delay=api_delay,
        profile_registry=profile_registry,
    )


__all__ = ["ResolvedSignature", "ResolverResult", "resolve_selectors", "SelectorResolverService"]
