from __future__ import annotations

import json
import urllib.error
import urllib.request

from evm_core.errors import RemoteDependencyError


class SelectorHttpClient:
    def __init__(self, *, timeout: int = 5) -> None:
        self._timeout = timeout

    def query_4byte(self, selector_hex: str) -> list[str] | None:
        normalized = _normalize_selector(selector_hex)
        url = f"https://www.4byte.directory/api/v1/signatures/?hex_signature={normalized}&format=json"
        data = self._fetch_json(url)
        results = data.get("results", [])
        if not results:
            return []
        sorted_results = sorted(results, key=lambda item: item.get("id", 0))
        return [item["text_signature"] for item in sorted_results]

    def query_openchain(self, selector_hex: str) -> list[str] | None:
        normalized = _normalize_selector(selector_hex)
        url = f"https://api.openchain.xyz/signature-database/v1/lookup?function={normalized}"
        data = self._fetch_json(url)
        if not data.get("ok"):
            return []
        result = data.get("result", {})
        function_results = result.get("function", {})
        matches = function_results.get(normalized, [])
        if not matches:
            return []
        return [match.get("name", "") for match in matches if match.get("name")]

    def _fetch_json(self, url: str) -> dict:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = resp.read().decode("utf-8")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RemoteDependencyError(f"remote selector request failed: {exc}") from exc
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RemoteDependencyError("remote selector response was not valid JSON") from exc
        if not isinstance(data, dict):
            raise RemoteDependencyError("remote selector response was not a JSON object")
        return data


def _normalize_selector(value: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    return normalized
