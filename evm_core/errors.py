from __future__ import annotations


class EvmAuditError(Exception):
    """Base application error for audit runtime failures."""


class ValidationError(EvmAuditError):
    """Raised when a boundary document fails validation."""

    def __init__(self, message: str, *, errors: list[str] | None = None) -> None:
        super().__init__(message)
        self.errors = errors or []


class ResourceLimitError(EvmAuditError):
    """Raised when an input or operation exceeds safe resource limits."""


class RemoteDependencyError(EvmAuditError):
    """Raised when a remote dependency fails or returns malformed data."""


class PersistenceError(EvmAuditError):
    """Raised when a local persistence adapter cannot safely read or write state."""
