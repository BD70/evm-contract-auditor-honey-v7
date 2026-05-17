from __future__ import annotations

import time
import string

from evm_core.errors import RemoteDependencyError
from .known_signatures import lookup_selector
from .profile_packs import ProfileRegistry
from .resolver_cache import SelectorCache
from .resolver_http import SelectorHttpClient
from .resolver_models import ResolvedSignature, ResolverResult
from .resolver_store import SignatureStore


class SelectorResolverService:
    def __init__(
        self,
        *,
        cache: SelectorCache | None = None,
        store: SignatureStore | None = None,
        http_client: SelectorHttpClient | None = None,
        max_remote_errors: int = 4,
    ) -> None:
        self._cache = cache or SelectorCache()
        self._store = store or SignatureStore()
        self._http_client = http_client or SelectorHttpClient()
        self._max_remote_errors = max_remote_errors

    def resolve(
        self,
        selectors: list[str],
        *,
        use_api: bool = True,
        api_delay: float = 0.2,
        profile_registry: ProfileRegistry | None = None,
    ) -> ResolverResult:
        resolved: list[ResolvedSignature] = []
        unresolved: list[str] = []
        errors: list[str] = []
        cache = self._cache.load() if use_api else {}
        cache_modified = False
        remote_error_count = 0
        remote_open = True

        for selector in _dedupe_preserving_order(selectors):
            normalized = selector.lower().replace("0x", "")
            selector_with_prefix = f"0x{normalized}"
            if not _is_valid_selector_hex(normalized):
                errors.append(f"Invalid selector format: {selector_with_prefix}")
                unresolved.append(selector_with_prefix)
                continue

            profile_matches = profile_registry.lookup_selector(normalized) if profile_registry else []
            if profile_matches:
                signatures = [match.signature for match in profile_matches]
                profiles = sorted({match.profile for match in profile_matches})
                resolved.append(_resolved(selector_with_prefix, signatures, "profile_pack:" + ",".join(profiles)))
                continue

            try:
                sqlite_matches = self._store.lookup(selector_with_prefix)
            except Exception as exc:
                errors.append(f"SQLite lookup error for {selector_with_prefix}: {exc}")
                sqlite_matches = None
            if sqlite_matches:
                resolved.append(_resolved(selector_with_prefix, sqlite_matches, "local_sqlite"))
                continue

            bundled_matches = lookup_selector(normalized)
            if bundled_matches:
                resolved.append(_resolved(selector_with_prefix, bundled_matches, "bundled"))
                continue

            if normalized in cache:
                cached = cache[normalized]
                if cached:
                    resolved.append(_resolved(selector_with_prefix, cached, "cache"))
                else:
                    unresolved.append(selector_with_prefix)
                continue

            if not use_api:
                unresolved.append(selector_with_prefix)
                continue
            if not remote_open:
                errors.append(f"Remote selector resolution skipped for {selector_with_prefix}: error budget exhausted")
                unresolved.append(selector_with_prefix)
                continue

            try:
                api_results, source = self._query_remote_sources(normalized)
            except RemoteDependencyError as exc:
                remote_error_count += 1
                if remote_error_count >= self._max_remote_errors:
                    remote_open = False
                errors.append(f"API error for {selector_with_prefix}: {exc}")
                unresolved.append(selector_with_prefix)
                continue

            if api_results is not None and api_results:
                try:
                    self._store.insert(selector_with_prefix, api_results, source=source)
                except Exception as exc:
                    errors.append(f"SQLite insert error for {selector_with_prefix}: {exc}")
                resolved.append(_resolved(selector_with_prefix, api_results, source))
            elif api_results is not None:
                cache[normalized] = []
                cache_modified = True
                unresolved.append(selector_with_prefix)
            else:
                errors.append(f"API error for {selector_with_prefix}")
                unresolved.append(selector_with_prefix)

            if use_api and api_delay > 0:
                time.sleep(api_delay)

        if cache_modified:
            self._cache.save(cache)

        return ResolverResult(resolved=resolved, unresolved=unresolved, errors=errors)

    def _query_remote_sources(self, selector_hex: str) -> tuple[list[str] | None, str]:
        four_byte_results = self._http_client.query_4byte(selector_hex)
        if four_byte_results:
            return four_byte_results, "4byte_api"

        openchain_results = self._http_client.query_openchain(selector_hex)
        if openchain_results:
            return openchain_results, "openchain_api"
        if four_byte_results == [] or openchain_results == []:
            return [], ""
        return None, ""


def _resolved(selector: str, text_signatures: list[str], source: str) -> ResolvedSignature:
    return ResolvedSignature(
        selector=selector,
        text_signatures=text_signatures,
        source=source,
        confidence="exact_match" if len(text_signatures) == 1 else "multiple_matches",
    )


def _is_valid_selector_hex(value: str) -> bool:
    return len(value) == 8 and all(char in string.hexdigits for char in value)


def _dedupe_preserving_order(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped
