from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from .models import PlannedAction


class TargetStatus(str, Enum):
    """Outcome of one target-model generation attempt.

    These statuses are intentionally separate from attack/security outcomes. A
    target that fails to return a usable plan is not counted as a resisted
    attack or a successful defense.
    """

    VALID_PLAN = "valid_plan"
    INVALID_PLAN = "invalid_plan"
    TRUNCATED = "truncated"
    TIMEOUT = "timeout"
    TRANSPORT_ERROR = "transport_error"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class GenerationMetadata:
    """Non-sensitive metadata captured for one target generation.

    VAIS deliberately does not persist model reasoning text. Only aggregate
    counts/diagnostics needed for reproducible evaluation are retained.
    """

    status: TargetStatus
    provider: str
    model: str
    finish_reason: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    reasoning_tokens: int | None = None
    reasoning_chars: int = 0
    latency_ms: float | None = None
    attempts: int = 1
    cache_hit: bool = False
    error_type: str | None = None
    error_message: str | None = None
    attempt_history: tuple[dict[str, Any], ...] = ()

    @property
    def valid(self) -> bool:
        return self.status == TargetStatus.VALID_PLAN

    def as_cache_hit(self) -> "GenerationMetadata":
        return replace(self, cache_hit=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "provider": self.provider,
            "model": self.model,
            "finish_reason": self.finish_reason,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "reasoning_chars": self.reasoning_chars,
            "latency_ms": self.latency_ms,
            "attempts": self.attempts,
            "cache_hit": self.cache_hit,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "attempt_history": [dict(item) for item in self.attempt_history],
        }


@dataclass(frozen=True)
class TargetRunResult:
    """Plan plus generation outcome returned by research-grade target adapters."""

    plan: tuple[PlannedAction, ...]
    generation: GenerationMetadata

    @property
    def valid(self) -> bool:
        return self.generation.valid

    def as_cache_hit(self) -> "TargetRunResult":
        return replace(self, generation=self.generation.as_cache_hit())
