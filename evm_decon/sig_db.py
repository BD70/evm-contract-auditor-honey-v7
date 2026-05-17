"""Compatibility wrapper around selector signature store."""

from __future__ import annotations
from typing import List, Optional

from .resolver_store import SignatureStore


_STORE = SignatureStore()


def insert_signatures(hex_sig: str, text_sigs: List[str], source: str = "local_extraction"):
    _STORE.insert(hex_sig, text_sigs, source=source)


def lookup_signature(hex_sig: str) -> Optional[List[str]]:
    return _STORE.lookup(hex_sig)


def get_db_stats() -> int:
    return _STORE.stats()
