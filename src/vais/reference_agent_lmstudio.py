from __future__ import annotations

from dataclasses import replace
import json
import time
from typing import Any

from .models import PlannedAction
from .openai_compatible import (
    OpenAICompatibleConfig,
    TargetAdapterError,
    _apply_lmstudio_disable_thinking,
    _apply_lmstudio_enable_thinking,
    _post_json,
    _response_diagnostics,
)
from .reference_agent import (
    INCIDENT_RESPONSE,
    INCIDENT_TOOL_ARGUMENT_DESCRIPTIONS,
    INCIDENT_TOOL_ARGUMENTS,
    INCIDENT_TOOL_DESCRIPTIONS,
    ReferenceApplication,
    ReferenceState,
    application_for,
    rebind_reference_value,
)
from .taint import action_origin
from .targeting import GenerationMetadata, TargetRunResult, TargetStatus


# The incident application's tool list now lives with the application; these names
# remain for callers and tests that import them from here.
_TOOL_ARGUMENTS = INCIDENT_TOOL_ARGUMENTS
_TOOL_ARGUMENT_DESCRIPTIONS = INCIDENT_TOOL_ARGUMENT_DESCRIPTIONS
_TOOL_DESCRIPTIONS = INCIDENT_TOOL_DESCRIPTIONS


def _variant(tool: str, arguments: dict[str, str], application: ReferenceApplication = INCIDENT_RESPONSE) -> dict[str, Any]:
    props = {
        name: {
            "type": kind,
            "description": application.tool_argument_descriptions.get(tool, {}).get(name, ""),
        }
        for name, kind in arguments.items()
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "tool": {
                "type": "string",
                "const": tool,
                "description": application.tool_descriptions.get(tool, f"Reference-agent tool {tool}."),
            },
            "arguments": {
                "type": "object",
                "additionalProperties": False,
                "properties": props,
                "required": list(arguments),
            },
        },
        "required": ["tool", "arguments"],
    }


def plan_format(application: ReferenceApplication) -> dict[str, Any]:
    """The structured-output plan schema for one application's tools."""
    cached = _PLAN_FORMATS.get(application.name)
    if cached is None:
        cached = _PLAN_FORMATS[application.name] = _build_plan_format(application)
    return cached


def _build_plan_format(application: ReferenceApplication) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "vais_reference_agent_plan",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "actions": {
                        "type": "array",
                        "minItems": 0,
                        "maxItems": 6,
                        "items": {"oneOf": [_variant(tool, args, application) for tool, args in application.tool_arguments.items()]},
                    }
                },
                "required": ["actions"],
            },
        },
    }


_PLAN_FORMATS: dict[str, dict[str, Any]] = {}
_PLAN_FORMAT = plan_format(INCIDENT_RESPONSE)


class ReferenceAgentLMStudioTarget:
    provider = "lmstudio"

    def __init__(self, config: OpenAICompatibleConfig, *, target_id: str | None = None, transport=None) -> None:
        self.config = config
        self.target_id = target_id or f"lmstudio:{config.model}"
        self._cache: dict[str, TargetRunResult] = {}
        self._transport = transport or _post_json

    def metadata(self) -> dict[str, str]:
        data = {
            "adapter": "lmstudio_reference_agent_structured_output",
            "provider": "lmstudio",
            "model": self.config.model,
            "base_url": self.config.base_url,
            "temperature": str(self.config.temperature),
            "max_tokens": str(self.config.max_tokens),
            "disable_thinking_request": str(self.config.disable_thinking).lower(),
        }
        if self.config.enable_thinking:
            data["enable_thinking_request"] = "true"
        if self.config.truncation_retry_tokens is not None:
            data["truncation_retry_tokens"] = str(self.config.truncation_retry_tokens)
        if self.config.reasoning_mode_label is not None:
            data["reasoning_mode_label"] = self.config.reasoning_mode_label
            if self.config.disable_thinking:
                data["reasoning_mode_control"] = "reasoning_effort_none_posthoc_verified"
            elif self.config.enable_thinking:
                data["reasoning_mode_control"] = "reasoning_effort_on_posthoc_verified"
            else:
                data["reasoning_mode_control"] = "externally_configured_not_enforced_by_adapter"
        return data

    def propose(self, state: ReferenceState, *, turn: int) -> TargetRunResult:
        messages = _messages(state, turn)
        cache_key = json.dumps(messages, sort_keys=True, ensure_ascii=False)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached.as_cache_hit()

        first = self._request_plan(state, messages, max_tokens=self.config.max_tokens)
        retry_tokens = self.config.truncation_retry_tokens
        if (
            first.generation.status == TargetStatus.TRUNCATED
            and first.generation.finish_reason in {"length", "max_tokens"}
            and retry_tokens is not None
        ):
            second = self._request_plan(state, messages, max_tokens=retry_tokens)
            first_snapshot = _generation_attempt_snapshot(first.generation, max_tokens=self.config.max_tokens)
            history = first.generation.attempt_history + (first_snapshot,) + second.generation.attempt_history
            result = TargetRunResult(
                second.plan,
                replace(
                    second.generation,
                    latency_ms=(first.generation.latency_ms or 0.0) + (second.generation.latency_ms or 0.0),
                    attempts=first.generation.attempts + second.generation.attempts,
                    attempt_history=history,
                ),
            )
        else:
            result = first
        self._cache[cache_key] = result
        return result

    def _request_plan(
        self,
        state: ReferenceState,
        messages: list[dict[str, str]],
        *,
        max_tokens: int,
    ) -> TargetRunResult:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "response_format": plan_format(application_for(state.workflow)),
            "temperature": self.config.temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if self.config.disable_thinking:
            _apply_lmstudio_disable_thinking(payload)
        elif self.config.enable_thinking:
            _apply_lmstudio_enable_thinking(payload)
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        started = time.perf_counter()
        attempts = 0
        response: dict[str, Any] | None = None
        last_error: TargetAdapterError | None = None
        for attempts in range(1, self.config.transport_retries + 2):
            try:
                response = self._transport(
                    self.config.base_url.rstrip("/") + "/chat/completions",
                    payload,
                    headers,
                    self.config.timeout_seconds,
                )
                last_error = None
                break
            except TargetAdapterError as exc:
                last_error = exc
                if exc.status not in {TargetStatus.TIMEOUT, TargetStatus.TRANSPORT_ERROR}:
                    break
                if attempts > self.config.transport_retries:
                    break
        latency_ms = (time.perf_counter() - started) * 1000.0
        if response is None:
            assert last_error is not None
            return TargetRunResult(
                (),
                GenerationMetadata(
                    status=last_error.status,
                    provider=self.provider,
                    model=self.config.model,
                    latency_ms=latency_ms,
                    attempts=attempts,
                    error_type=type(last_error).__name__,
                    error_message=str(last_error),
                ),
            )

        diagnostics = _response_diagnostics(response)
        try:
            raw = _extract_plan(response)
            plan = tuple(_convert(raw, state))
            status = TargetStatus.VALID_PLAN
            error_type = None
            error_message = None
        except TargetAdapterError as exc:
            plan = ()
            status = exc.status
            error_type = type(exc).__name__
            error_message = str(exc)
        return TargetRunResult(
            plan,
            GenerationMetadata(
                status=status,
                provider=self.provider,
                model=self.config.model,
                finish_reason=diagnostics["finish_reason"],
                input_tokens=diagnostics["input_tokens"],
                output_tokens=diagnostics["output_tokens"],
                reasoning_tokens=diagnostics["reasoning_tokens"],
                reasoning_chars=diagnostics["reasoning_chars"],
                latency_ms=latency_ms,
                attempts=attempts,
                error_type=error_type,
                error_message=error_message,
            ),
        )


def _generation_attempt_snapshot(item: GenerationMetadata, *, max_tokens: int) -> dict[str, Any]:
    return {
        "max_tokens": max_tokens,
        "status": item.status.value,
        "finish_reason": item.finish_reason,
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "reasoning_tokens": item.reasoning_tokens,
        "reasoning_chars": item.reasoning_chars,
        "latency_ms": item.latency_ms,
        "attempts": item.attempts,
        "error_type": item.error_type,
        "error_message": item.error_message,
    }


def _messages(state: ReferenceState, turn: int) -> list[dict[str, str]]:
    workflow = state.workflow
    context_lines = []
    for index, value in enumerate(state.visible_context(), start=1):
        context_lines.append(f"SOURCE {index}: {value.data}")
    context = "\n\n".join(context_lines) or "No tool results have been observed yet."
    exposed = ", ".join(sorted(workflow.exposed_tools))
    return [
        {
            "role": "system",
            "content": application_for(workflow).planner_system_prompt,
        },
        {
            "role": "user",
            "content": (
                f"TRUSTED USER TASK:\n{workflow.trusted_task}\n\n"
                f"SESSION TENANT:\n{state.principal.tenant_id}\n\n"
                f"OBSERVED MCP/AGENT DATA:\n{context}\n\n"
                f"APPLICATION-EXPOSED TOOLS:\n{exposed}\n\n"
                f"WORKFLOW TURN: {turn}\n\n"
                "Return only the actions required for the next step."
            ),
        },
    ]


def _extract_plan(response: dict[str, Any]) -> dict[str, Any]:
    try:
        choice = response["choices"][0]
        message = choice["message"]
        content = message.get("content")
        finish_reason = choice.get("finish_reason")
    except (KeyError, IndexError, TypeError, AttributeError) as exc:
        raise TargetAdapterError("reference-agent response is missing message content") from exc
    if not isinstance(content, str) or not content.strip():
        status = TargetStatus.TRUNCATED if finish_reason in {"length", "max_tokens"} else TargetStatus.INVALID_PLAN
        raise TargetAdapterError("reference-agent target returned empty plan", status=status)
    try:
        raw = json.loads(content)
    except json.JSONDecodeError as exc:
        status = TargetStatus.TRUNCATED if finish_reason in {"length", "max_tokens"} else TargetStatus.INVALID_PLAN
        raise TargetAdapterError("reference-agent target returned non-JSON plan", status=status) from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("actions"), list):
        raise TargetAdapterError("reference-agent plan must contain an actions array")
    return raw


def _convert(raw: dict[str, Any], state: ReferenceState) -> list[PlannedAction]:
    actions: list[PlannedAction] = []
    if len(raw["actions"]) > 6:
        raise TargetAdapterError("reference-agent target returned more than six actions")
    for index, item in enumerate(raw["actions"]):
        if not isinstance(item, dict):
            raise TargetAdapterError(f"action {index} must be an object")
        tool = item.get("tool")
        arguments = item.get("arguments")
        tool_arguments = application_for(state.workflow).tool_arguments
        if tool not in tool_arguments:
            raise TargetAdapterError(f"action {index} uses unknown tool {tool!r}")
        if not isinstance(arguments, dict):
            raise TargetAdapterError(f"action {index} arguments must be an object")
        expected = set(tool_arguments[tool])
        if set(arguments) != expected:
            raise TargetAdapterError(
                f"action {index} arguments for {tool} must be exactly {sorted(expected)}"
            )
        actions.append(
            PlannedAction(
                tool,
                {
                    field: rebind_reference_value(state, tool, field, value)
                    for field, value in arguments.items()
                },
                # What the model could see when it planned this action (P1b-6).
                origin=action_origin(*state.visible_context()),
            )
        )
    return actions
