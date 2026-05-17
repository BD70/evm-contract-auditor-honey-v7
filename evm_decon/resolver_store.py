from __future__ import annotations

import sqlite3
from pathlib import Path


class SignatureStore:
    def __init__(self, db_file: Path | None = None, *, timeout_seconds: float = 2.0) -> None:
        self._db_file = db_file or (Path.home() / ".evm-decon" / "signatures.db")
        self._timeout_seconds = timeout_seconds

    def lookup(self, hex_signature: str) -> list[str] | None:
        normalized = _normalize_selector(hex_signature)
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT text_signatures FROM signatures WHERE hex_signature = ?", (normalized,))
            row = cur.fetchone()
            if row:
                return [value.strip() for value in row[0].split(";") if value.strip()]
            return None
        finally:
            conn.close()

    def insert(self, hex_signature: str, text_signatures: list[str], source: str = "local_extraction") -> None:
        if not text_signatures:
            return
        normalized = _normalize_selector(hex_signature)
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT text_signatures FROM signatures WHERE hex_signature = ?", (normalized,))
            row = cur.fetchone()
            existing = [value.strip() for value in row[0].split(";") if value.strip()] if row else []
            for signature in text_signatures:
                if signature not in existing:
                    existing.append(signature)
            cur.execute(
                """
                INSERT OR REPLACE INTO signatures (hex_signature, text_signatures, source)
                VALUES (?, ?, ?)
                """,
                (normalized, ";".join(existing), source),
            )
            conn.commit()
        finally:
            conn.close()

    def stats(self) -> int:
        conn = self._connect()
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM signatures")
            row = cur.fetchone()
            return row[0] if row else 0
        except sqlite3.Error:
            return 0
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        self._db_file.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_file, timeout=self._timeout_seconds)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(f"PRAGMA busy_timeout={int(self._timeout_seconds * 1000)}")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS signatures (
                hex_signature TEXT PRIMARY KEY,
                text_signatures TEXT,
                source TEXT
            )
            """
        )
        return conn


def _normalize_selector(value: str) -> str:
    normalized = value.lower()
    if not normalized.startswith("0x"):
        normalized = "0x" + normalized
    return normalized
