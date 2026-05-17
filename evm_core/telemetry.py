from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from uuid import uuid4


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class StageTiming:
    stage: str
    started_at: str
    completed_at: str
    duration_ms: int
    degraded: bool = False
    details: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "degraded": self.degraded,
            "details": self.details,
        }


@dataclass(frozen=True)
class AnalysisContext:
    analysis_id: str
    created_at: str
    input_kind: str
    resolver_enabled: bool
    profiles_enabled: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "analysis_id": self.analysis_id,
            "created_at": self.created_at,
            "input_kind": self.input_kind,
            "resolver_enabled": self.resolver_enabled,
            "profiles_enabled": self.profiles_enabled,
        }


def build_analysis_context(
    *,
    input_kind: str,
    resolver_enabled: bool,
    profiles_enabled: bool,
) -> AnalysisContext:
    return AnalysisContext(
        analysis_id=str(uuid4()),
        created_at=_utc_now(),
        input_kind=input_kind,
        resolver_enabled=resolver_enabled,
        profiles_enabled=profiles_enabled,
    )


class AnalysisTimer:
    """Collect coarse stage timings for output diagnostics."""

    def __init__(self) -> None:
        self._records: list[StageTiming] = []

    def measure(self, stage: str):
        started_at = _utc_now()
        started = time.perf_counter()

        class _Scope:
            def __init__(self, owner: AnalysisTimer) -> None:
                self._owner = owner
                self._degraded = False
                self._details: dict[str, object] = {}

            def degrade(self, **details: object) -> None:
                self._degraded = True
                self._details.update(details)

            def __enter__(self) -> "_Scope":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                completed_at = _utc_now()
                duration_ms = int((time.perf_counter() - started) * 1000)
                details = dict(self._details)
                if exc is not None:
                    details.setdefault("error", str(exc))
                    self._degraded = True
                self._owner._records.append(
                    StageTiming(
                        stage=stage,
                        started_at=started_at,
                        completed_at=completed_at,
                        duration_ms=duration_ms,
                        degraded=self._degraded,
                        details=details,
                    )
                )
                return False

        return _Scope(self)

    def to_list(self) -> list[dict[str, object]]:
        return [record.to_dict() for record in self._records]
