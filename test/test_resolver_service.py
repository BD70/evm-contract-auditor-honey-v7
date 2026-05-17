from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from evm_core.errors import RemoteDependencyError
from evm_decon.resolver_cache import SelectorCache
from evm_decon.resolver_service import SelectorResolverService
from evm_decon.resolver_store import SignatureStore


class FakeHttpClient:
    def __init__(
        self,
        fourbyte: dict[str, list[str] | None] | None = None,
        openchain: dict[str, list[str] | None] | None = None,
        *,
        fail_4byte: bool = False,
        fail_openchain: bool = False,
    ):
        self.fourbyte = fourbyte or {}
        self.openchain = openchain or {}
        self.fail_4byte = fail_4byte
        self.fail_openchain = fail_openchain
        self.calls: list[tuple[str, str]] = []

    def query_4byte(self, selector_hex: str) -> list[str] | None:
        self.calls.append(("4byte", selector_hex))
        if self.fail_4byte:
            raise RemoteDependencyError("4byte down")
        return self.fourbyte.get(selector_hex)

    def query_openchain(self, selector_hex: str) -> list[str] | None:
        self.calls.append(("openchain", selector_hex))
        if self.fail_openchain:
            raise RemoteDependencyError("openchain down")
        return self.openchain.get(selector_hex)


class SelectorResolverServiceTests(unittest.TestCase):
    def test_uses_sqlite_store_before_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = SignatureStore(root / "signatures.db")
            store.insert("0xdeadbeef", ["cached(uint256)"], source="test")
            http = FakeHttpClient()
            service = SelectorResolverService(
                cache=SelectorCache(root / "cache"),
                store=store,
                http_client=http,
            )

            result = service.resolve(["0xdeadbeef"], use_api=True, api_delay=0)

            self.assertEqual(len(result.resolved), 1)
            self.assertEqual(result.resolved[0].source, "local_sqlite")
            self.assertEqual(result.resolved[0].text_signatures, ["cached(uint256)"])
            self.assertEqual(http.calls, [])

    def test_falls_back_to_openchain_after_empty_4byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            http = FakeHttpClient(
                fourbyte={"deadbeef": []},
                openchain={"deadbeef": ["fallback(address)"]},
            )
            service = SelectorResolverService(
                cache=SelectorCache(root / "cache"),
                store=SignatureStore(root / "signatures.db"),
                http_client=http,
            )

            result = service.resolve(["0xdeadbeef"], use_api=True, api_delay=0)

            self.assertEqual(result.resolved[0].source, "openchain_api")
            self.assertEqual(result.resolved[0].text_signatures, ["fallback(address)"])
            self.assertEqual(
                http.calls,
                [("4byte", "deadbeef"), ("openchain", "deadbeef")],
            )

    def test_caches_negative_remote_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            http = FakeHttpClient(
                fourbyte={"deadbeef": []},
                openchain={"deadbeef": []},
            )
            cache = SelectorCache(root / "cache")
            service = SelectorResolverService(
                cache=cache,
                store=SignatureStore(root / "signatures.db"),
                http_client=http,
            )

            first = service.resolve(["0xdeadbeef"], use_api=True, api_delay=0)
            second = service.resolve(["0xdeadbeef"], use_api=True, api_delay=0)

            self.assertEqual(first.unresolved, ["0xdeadbeef"])
            self.assertEqual(second.unresolved, ["0xdeadbeef"])
            self.assertEqual(
                http.calls,
                [("4byte", "deadbeef"), ("openchain", "deadbeef")],
            )
            self.assertEqual(cache.load(), {"deadbeef": []})

    def test_rejects_invalid_selector_without_remote_calls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            http = FakeHttpClient()
            service = SelectorResolverService(
                cache=SelectorCache(root / "cache"),
                store=SignatureStore(root / "signatures.db"),
                http_client=http,
            )

            result = service.resolve(["0x123"], use_api=True, api_delay=0)

            self.assertEqual(result.unresolved, ["0x123"])
            self.assertTrue(any("Invalid selector format" in error for error in result.errors))
            self.assertEqual(http.calls, [])

    def test_remote_error_budget_stops_repeated_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            http = FakeHttpClient(fail_4byte=True)
            service = SelectorResolverService(
                cache=SelectorCache(root / "cache"),
                store=SignatureStore(root / "signatures.db"),
                http_client=http,
                max_remote_errors=2,
            )

            result = service.resolve(["0xdeadbeef", "0xfeedface", "0x12345678"], use_api=True, api_delay=0)

            self.assertEqual(len([call for call in http.calls if call[0] == "4byte"]), 2)
            self.assertEqual(result.unresolved, ["0xdeadbeef", "0xfeedface", "0x12345678"])
            self.assertTrue(any("error budget exhausted" in error for error in result.errors))
