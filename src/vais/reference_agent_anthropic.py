"""Claude as a reference-agent target, through the Anthropic Messages API (P1b-2).

The target sees exactly what an LM Studio target sees: the same system text, the same
user text and the same plan variants, converted by the same code. Four things differ,
because the API requires them, and each is recorded in the target's metadata:

- Structured output uses ``output_config.format``. The plan schema says ``anyOf`` where
  the LM Studio schema says ``oneOf``; the variants are distinguished by a ``const``
  tool name, so exactly one can match and the two mean the same. The array bounds
  (0 to 6 actions) are not supported by the API and are enforced after parsing, by the
  same check the LM Studio path uses.
- Temperature is not sent. Current models reject any non-default value, so runs are
  not greedy and a replay can differ.
- Thinking is requested with the API's own control, not ``reasoning_effort``. When
  thinking is on it is requested with ``display: "summarized"`` so its presence is
  observable; a thinking block whose text the API omitted still counts as reasoning.
- The model identifier is not a dated snapshot. The model string each response reports
  is recorded, so a run shows what actually served it.

A refusal (``stop_reason: "refusal"``) makes the step unevaluable, like an invalid plan,
and is recorded with its category. No refusal fallback is requested: a fallback would
let a different model answer, and a campaign measures one model.

The API key is never passed in: the SDK reads it from the environment
(``ANTHROPIC_API_KEY`` or a profile). Requests that fail because of configuration
(bad request, authentication, permission, unknown model) raise instead of being
counted as failed generations, so a misconfigured run stops at its first call.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import json
import time
from typing import Any

from .openai_compatible import TargetAdapterError
from .reference_agent import INCIDENT_RESPONSE, ReferenceApplication, ReferenceState, application_for
from .reference_agent_lmstudio import (
    _convert,
    _generation_attempt_snapshot,
    _messages,
    plan_format,
)
from .targeting import GenerationMetadata, TargetRunResult, TargetStatus


THINKING_MODES = ("adaptive", "between_tools", "disabled", "omit")
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")


class AnthropicConfigurationError(RuntimeError):
    """A request the API refused for a reason retrying cannot fix."""


def plan_schema(application: ReferenceApplication) -> dict[str, Any]:
    """The application's LM Studio plan schema, in the form the Anthropic API accepts."""
    source = plan_format(application)["json_schema"]["schema"]
    actions = dict(source["properties"]["actions"])
    variants = actions.pop("items")["oneOf"]
    actions.pop("minItems", None)
    actions.pop("maxItems", None)
    actions["items"] = {"anyOf": variants}
    return {**source, "properties": {"actions": actions}}


PLAN_SCHEMA = plan_schema(INCIDENT_RESPONSE)


@dataclass(frozen=True)
class AnthropicTargetConfig:
    model: str = "claude-opus-5-5"
    max_tokens: int = 16000
    thinking: str = "adaptive"
    effort: str | None = None
    timeout_seconds: float = 120.0
    max_retries: int = 2
    reasoning_mode_label: str | None = None
    truncation_retry_tokens: int | None = None

    def __post_init__(self) -> None:
        if self.thinking not in THINKING_MODES:
            raise ValueError(f"thinking must be one of {THINKING_MODES}")
        if self.effort is not None and self.effort not in EFFORT_LEVELS:
            raise ValueError(f"effort must be one of {EFFORT_LEVELS}")
        if self.thinking == "between_tools" and self.effort in {"xhigh", "max"}:
            raise ValueError("between_tools thinking accepts effort high or below")
        if self.max_tokens < 1 or self.max_retries < 0 or self.timeout_seconds <= 0:
            raise ValueError("max_tokens, max_retries and timeout_seconds must be positive")


def _sdk():
    try:
        import anthropic
    except ImportError as exc:  # pragma: no cover - exercised by the missing-SDK test
        raise AnthropicConfigurationError(
            "the Anthropic target needs the SDK: pip install 'verifiable-ai-security[anthropic]'"
        ) from exc
    return anthropic


def build_request(config: AnthropicTargetConfig, state: ReferenceState, turn: int, *, max_tokens: int) -> dict[str, Any]:
    system, user = _messages(state, turn)
    schema = plan_schema(application_for(state.workflow))
    output_config: dict[str, Any] = {"format": {"type": "json_schema", "schema": schema}}
    if config.effort is not None:
        output_config["effort"] = config.effort
    request: dict[str, Any] = {
        "model": config.model,
        "max_tokens": max_tokens,
        "system": system["content"],
        "messages": [{"role": "user", "content": user["content"]}],
        "output_config": output_config,
    }
    if config.thinking == "adaptive":
        request["thinking"] = {"type": "adaptive", "display": "summarized"}
    elif config.thinking in {"between_tools", "disabled"}:
        request["thinking"] = {"type": config.thinking}
    return request


class ReferenceAgentAnthropicTarget:
    provider = "anthropic"

    def __init__(self, config: AnthropicTargetConfig, *, target_id: str | None = None, client: Any = None) -> None:
        self.config = config
        self.target_id = target_id or f"anthropic:{config.model}"
        self._cache: dict[str, TargetRunResult] = {}
        self._client = client
        self._served_models: set[str] = set()

    def _messages_client(self):
        if self._client is None:
            self._client = _sdk().Anthropic(
                timeout=self.config.timeout_seconds, max_retries=self.config.max_retries
            )
        return self._client

    def metadata(self) -> dict[str, str]:
        data = {
            "adapter": "anthropic_reference_agent_structured_output",
            "provider": "anthropic",
            "model": self.config.model,
            "max_tokens": str(self.config.max_tokens),
            "thinking_request": self.config.thinking,
            "effort_request": self.config.effort or "model_default",
            "temperature": "not_sent_provider_default",
            "plan_schema": "anyOf_variants_array_bounds_enforced_after_parse",
            "refusal_fallback": "none",
            "sdk_max_retries": str(self.config.max_retries),
            "served_models": ",".join(sorted(self._served_models)) or "none_observed",
        }
        if self.config.truncation_retry_tokens is not None:
            data["truncation_retry_tokens"] = str(self.config.truncation_retry_tokens)
        if self.config.reasoning_mode_label is not None:
            data["reasoning_mode_label"] = self.config.reasoning_mode_label
            data["reasoning_mode_control"] = f"anthropic_thinking_{self.config.thinking}_posthoc_verified"
        return data

    def propose(self, state: ReferenceState, *, turn: int) -> TargetRunResult:
        request = build_request(self.config, state, turn, max_tokens=self.config.max_tokens)
        cache_key = json.dumps({k: v for k, v in request.items() if k != "max_tokens"}, sort_keys=True, ensure_ascii=False)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached.as_cache_hit()

        first = self._request_plan(state, request)
        retry_tokens = self.config.truncation_retry_tokens
        if first.generation.status == TargetStatus.TRUNCATED and retry_tokens is not None:
            second = self._request_plan(state, {**request, "max_tokens": retry_tokens})
            snapshot = _generation_attempt_snapshot(first.generation, max_tokens=self.config.max_tokens)
            result = TargetRunResult(
                second.plan,
                replace(
                    second.generation,
                    latency_ms=(first.generation.latency_ms or 0.0) + (second.generation.latency_ms or 0.0),
                    attempts=first.generation.attempts + second.generation.attempts,
                    attempt_history=first.generation.attempt_history + (snapshot,) + second.generation.attempt_history,
                ),
            )
        else:
            result = first
        self._cache[cache_key] = result
        return result

    def _request_plan(self, state: ReferenceState, request: dict[str, Any]) -> TargetRunResult:
        started = time.perf_counter()
        try:
            response = self._messages_client().messages.create(**request)
        except Exception as exc:
            status = _retryable_status(exc)
            return TargetRunResult(
                (),
                GenerationMetadata(
                    status=status,
                    provider=self.provider,
                    model=self.config.model,
                    latency_ms=(time.perf_counter() - started) * 1000.0,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                ),
            )
        latency_ms = (time.perf_counter() - started) * 1000.0

        served = getattr(response, "model", None)
        if isinstance(served, str) and served:
            self._served_models.add(served)
        stop_reason = getattr(response, "stop_reason", None)
        blocks = list(getattr(response, "content", None) or ())
        text = "".join(block.text for block in blocks if getattr(block, "type", None) == "text")
        # A thinking block proves reasoning happened even when the API omitted its text,
        # so each one counts as at least one character for the off-mode check.
        reasoning_chars = sum(
            max(len(getattr(block, "thinking", "") or ""), 1)
            for block in blocks
            if getattr(block, "type", None) in {"thinking", "redacted_thinking"}
        )
        usage = getattr(response, "usage", None)

        try:
            if stop_reason == "refusal":
                details = getattr(response, "stop_details", None)
                category = getattr(details, "category", None) if details is not None else None
                raise TargetAdapterError(f"model refused the request (category={category})")
            if stop_reason == "max_tokens":
                raise TargetAdapterError("reference-agent target hit max_tokens", status=TargetStatus.TRUNCATED)
            if not text.strip():
                raise TargetAdapterError("reference-agent target returned empty plan")
            try:
                raw = json.loads(text)
            except json.JSONDecodeError as exc:
                raise TargetAdapterError("reference-agent target returned non-JSON plan") from exc
            if not isinstance(raw, dict) or not isinstance(raw.get("actions"), list):
                raise TargetAdapterError("reference-agent plan must contain an actions array")
            plan = tuple(_convert(raw, state))
            status, error_type, error_message = TargetStatus.VALID_PLAN, None, None
        except TargetAdapterError as exc:
            plan = ()
            status = exc.status
            error_type = "ModelRefusal" if stop_reason == "refusal" else type(exc).__name__
            error_message = str(exc)
        return TargetRunResult(
            plan,
            GenerationMetadata(
                status=status,
                provider=self.provider,
                model=self.config.model,
                finish_reason=stop_reason,
                input_tokens=_int_or_none(getattr(usage, "input_tokens", None)),
                output_tokens=_int_or_none(getattr(usage, "output_tokens", None)),
                reasoning_tokens=None,
                reasoning_chars=reasoning_chars,
                latency_ms=latency_ms,
                error_type=error_type,
                error_message=error_message,
            ),
        )


def _retryable_status(exc: Exception) -> TargetStatus:
    """Map a failure the SDK already retried to a generation status, or raise.

    Only failures a later attempt could fix count against the target. Anything else
    is a configuration error and stops the run.
    """

    sdk = _sdk()
    if isinstance(exc, sdk.APITimeoutError):
        return TargetStatus.TIMEOUT
    if isinstance(exc, (sdk.RateLimitError, sdk.InternalServerError, sdk.APIConnectionError)):
        return TargetStatus.TRANSPORT_ERROR
    if isinstance(exc, sdk.APIStatusError) and exc.status_code in {408, 409}:
        return TargetStatus.TRANSPORT_ERROR
    if isinstance(exc, sdk.APIStatusError):
        raise AnthropicConfigurationError(f"Anthropic API rejected the request ({exc.status_code}): {exc}") from exc
    raise exc


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None
