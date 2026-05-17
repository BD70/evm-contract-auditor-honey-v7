"""Deterministic checker for evm-audit behavior JSON."""

from .engine import check_audit, load_rules

__all__ = ["check_audit", "load_rules"]
