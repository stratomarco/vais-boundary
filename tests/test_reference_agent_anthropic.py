"""The Claude reference-agent target (P1b-2).

The SDK is not a test dependency: a stand-in ``anthropic`` module provides the client
and the exception classes the adapter maps, with the SDK's inheritance (a timeout is a
connection error, every HTTP error is an APIStatusError).
"""

from __future__ import annotations

import json
import sys
from types import ModuleType, SimpleNamespace

import pytest

from vais.reference_agent import ReferencePrincipal, ReferenceState, clean_workflows
from vais.reference_agent_anthropic import (
    PLAN_SCHEMA,
    AnthropicConfigurationError,
    AnthropicTargetConfig,
    ReferenceAgentAnthropicTarget,
    build_request,
)
from vais.reference_agent_lmstudio import _PLAN_FORMAT, _messages
from vais.targeting import TargetStatus


class _APIError(Exception):
    pass


class _APIConnectionError(_APIError):
    pass


class _APITimeoutError(_APIConnectionError):
    pass


class _APIStatusError(_APIError):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"status {status_code}")
        self.status_code = status_code


class _RateLimitError(_APIStatusError):
    pass


class _InternalServerError(_APIStatusError):
    pass


@pytest.fixture(autouse=True)
def fake_sdk(monkeypatch):
    module = ModuleType("anthropic")
    module.APIConnectionError = _APIConnectionError
    module.APITimeoutError = _APITimeoutError
    module.APIStatusError = _APIStatusError
    module.RateLimitError = _RateLimitError
    module.InternalServerError = _InternalServerError
    module.Anthropic = lambda **kwargs: pytest.fail("tests inject a client; the real one must not be built")
    monkeypatch.setitem(sys.modules, "anthropic", module)
    return module


def _state():
    workflow = clean_workflows()[4]
    return ReferenceState(
        workflow=workflow,
        principal=ReferencePrincipal("human:test", "acme"),
        session_id="test",
        contract=workflow.contract,
    )


PLAN = {"actions": [{"tool": "email.send_external", "arguments": {"recipient": "status@example.test", "body": "INC-1234 resolved"}}]}


def _response(text=None, *, stop_reason="end_turn", thinking=None, model="claude-opus-5-5", category=None):
    blocks = []
    if thinking is not None:
        blocks.append(SimpleNamespace(type="thinking", thinking=thinking))
    if text is not None:
        blocks.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(
        content=blocks,
        stop_reason=stop_reason,
        stop_details=SimpleNamespace(category=category) if stop_reason == "refusal" else None,
        model=model,
        usage=SimpleNamespace(input_tokens=1200, output_tokens=80),
    )


class _Client:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.messages = self

    def create(self, **request):
        self.requests.append(request)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _target(*outcomes, **config):
    client = _Client(*outcomes)
    return ReferenceAgentAnthropicTarget(AnthropicTargetConfig(**config), client=client), client


def test_a_valid_plan_is_converted_like_the_lmstudio_path():
    target, _ = _target(_response(json.dumps(PLAN)))
    result = target.propose(_state(), turn=1)
    assert result.valid
    recipient = result.plan[0].arguments["recipient"]
    assert recipient.is_trusted and recipient.data == "status@example.test"
    assert (result.generation.input_tokens, result.generation.output_tokens) == (1200, 80)
    assert result.generation.provider == "anthropic"


def test_the_model_sees_exactly_the_lmstudio_prompt():
    state = _state()
    system, user = _messages(state, 1)
    request = build_request(AnthropicTargetConfig(), state, 1, max_tokens=100)
    assert request["system"] == system["content"]
    assert request["messages"] == [{"role": "user", "content": user["content"]}]


def test_the_plan_schema_differs_only_where_the_api_requires_it():
    lmstudio = _PLAN_FORMAT["json_schema"]["schema"]
    source_actions = lmstudio["properties"]["actions"]
    actions = PLAN_SCHEMA["properties"]["actions"]
    assert actions["items"]["anyOf"] == source_actions["items"]["oneOf"]
    assert "minItems" not in actions and "maxItems" not in actions
    assert {k: v for k, v in PLAN_SCHEMA.items() if k != "properties"} == {k: v for k, v in lmstudio.items() if k != "properties"}
    assert json.dumps(PLAN_SCHEMA).count("oneOf") == 0


def test_the_request_sends_no_temperature_and_the_requested_thinking():
    state = _state()
    adaptive = build_request(AnthropicTargetConfig(effort="low"), state, 1, max_tokens=100)
    assert "temperature" not in adaptive
    assert adaptive["thinking"] == {"type": "adaptive", "display": "summarized"}
    assert adaptive["output_config"]["effort"] == "low"
    assert adaptive["output_config"]["format"] == {"type": "json_schema", "schema": PLAN_SCHEMA}
    off = build_request(AnthropicTargetConfig(model="claude-sonnet-5-5", thinking="between_tools"), state, 1, max_tokens=100)
    assert off["thinking"] == {"type": "between_tools"}
    assert "effort" not in off["output_config"]
    assert "thinking" not in build_request(AnthropicTargetConfig(thinking="omit"), state, 1, max_tokens=100)


@pytest.mark.parametrize("config", [
    {"thinking": "enabled"},
    {"effort": "extreme"},
    {"thinking": "between_tools", "effort": "xhigh"},
    {"thinking": "between_tools", "effort": "max"},
    {"max_tokens": 0},
])
def test_an_impossible_configuration_is_refused_before_any_call(config):
    with pytest.raises(ValueError):
        AnthropicTargetConfig(**config)


def test_thinking_is_observed_even_when_its_text_is_omitted():
    target, _ = _target(_response(json.dumps(PLAN), thinking=""))
    assert target.propose(_state(), turn=1).generation.reasoning_chars == 1
    target, _ = _target(_response(json.dumps(PLAN), thinking="checked the recipient"))
    assert target.propose(_state(), turn=1).generation.reasoning_chars == len("checked the recipient")
    target, _ = _target(_response(json.dumps(PLAN)))
    assert target.propose(_state(), turn=1).generation.reasoning_chars == 0


def test_a_refusal_is_unevaluable_and_recorded_with_its_category():
    target, _ = _target(_response(None, stop_reason="refusal", category="cyber"))
    result = target.propose(_state(), turn=1)
    assert not result.valid and result.plan == ()
    assert result.generation.status == TargetStatus.INVALID_PLAN
    assert result.generation.finish_reason == "refusal"
    assert result.generation.error_type == "ModelRefusal"
    assert "cyber" in result.generation.error_message


def test_truncation_is_retried_once_with_the_larger_budget():
    target, client = _target(
        _response('{"actions": [', stop_reason="max_tokens"),
        _response(json.dumps(PLAN)),
        max_tokens=512, truncation_retry_tokens=4096,
    )
    result = target.propose(_state(), turn=1)
    assert result.valid
    assert [r["max_tokens"] for r in client.requests] == [512, 4096]
    assert result.generation.attempts == 2
    assert result.generation.attempt_history[0]["status"] == TargetStatus.TRUNCATED.value


def test_truncation_without_a_retry_budget_is_reported_as_truncated():
    target, client = _target(_response('{"actions": [', stop_reason="max_tokens"))
    assert target.propose(_state(), turn=1).generation.status == TargetStatus.TRUNCATED
    assert len(client.requests) == 1


@pytest.mark.parametrize("text", ['{"steps": []}', "not json", "", '{"actions": [{"tool": "shell.exec", "arguments": {}}]}'])
def test_an_unusable_plan_is_invalid_not_empty(text):
    target, _ = _target(_response(text))
    result = target.propose(_state(), turn=1)
    assert result.generation.status == TargetStatus.INVALID_PLAN and result.plan == ()


def test_more_than_six_actions_is_refused_after_parsing():
    target, _ = _target(_response(json.dumps({"actions": PLAN["actions"] * 7})))
    assert target.propose(_state(), turn=1).generation.status == TargetStatus.INVALID_PLAN


@pytest.mark.parametrize("error, status", [
    (_APITimeoutError("slow"), TargetStatus.TIMEOUT),
    (_APIConnectionError("reset"), TargetStatus.TRANSPORT_ERROR),
    (_RateLimitError(429), TargetStatus.TRANSPORT_ERROR),
    (_InternalServerError(529), TargetStatus.TRANSPORT_ERROR),
    (_APIStatusError(409), TargetStatus.TRANSPORT_ERROR),
])
def test_a_failure_the_sdk_already_retried_counts_against_the_generation(error, status):
    target, _ = _target(error)
    result = target.propose(_state(), turn=1)
    assert result.generation.status == status and result.plan == ()


@pytest.mark.parametrize("code", [400, 401, 403, 404, 413])
def test_a_configuration_failure_stops_the_run(code):
    target, _ = _target(_APIStatusError(code))
    with pytest.raises(AnthropicConfigurationError, match=str(code)):
        target.propose(_state(), turn=1)


def test_an_unexpected_exception_is_not_swallowed():
    target, _ = _target(KeyError("bug"))
    with pytest.raises(KeyError):
        target.propose(_state(), turn=1)


def test_the_served_model_is_recorded_and_no_secret_is():
    target, _ = _target(_response(json.dumps(PLAN), model="claude-opus-5-5"))
    assert target.metadata()["served_models"] == "none_observed"
    target.propose(_state(), turn=1)
    metadata = target.metadata()
    assert metadata["served_models"] == "claude-opus-5-5"
    assert metadata["temperature"] == "not_sent_provider_default"
    assert metadata["refusal_fallback"] == "none"
    assert not any("key" in name.lower() for name in metadata)


def test_an_identical_prompt_is_answered_from_the_cache():
    target, client = _target(_response(json.dumps(PLAN)))
    state = _state()
    target.propose(state, turn=1)
    again = target.propose(state, turn=1)
    assert again.generation.cache_hit and len(client.requests) == 1


def test_without_the_sdk_the_error_says_how_to_install_it(monkeypatch):
    monkeypatch.setitem(sys.modules, "anthropic", None)
    target = ReferenceAgentAnthropicTarget(AnthropicTargetConfig())
    with pytest.raises(AnthropicConfigurationError, match=r"\[anthropic\]"):
        target.propose(_state(), turn=1)


def test_the_cli_exposes_the_command_with_safe_defaults():
    from vais.cli import _parser

    args = _parser().parse_args(["adaptive-reference-anthropic", "--episodes", "1"])
    assert args.target_model is None and args.target_thinking == "adaptive"
    assert args.attacker_base_url == "http://localhost:1234/v1"
    assert not hasattr(args, "api_key") and not hasattr(args, "target_api_key")


def _cli(tmp_path, *extra):
    from vais.cli import main

    return main([
        "adaptive-reference-anthropic", "--scenario", "attack-01", "--episodes", "1",
        "--output", str(tmp_path / "out.jsonl"), "--summary", str(tmp_path / "summary.json"),
        "--rlvr-output", str(tmp_path / "rlvr.jsonl"), *extra,
    ])


def test_the_cli_runs_a_campaign_end_to_end(fake_sdk, tmp_path):
    built = []

    def factory(**kwargs):
        built.append(kwargs)
        return _Client(*[_response(json.dumps({"actions": []})) for _ in range(50)])

    fake_sdk.Anthropic = factory
    assert _cli(tmp_path, "--target-effort", "low", "--fail-on-protected-violation") == 0
    assert built == [{"timeout": 120.0, "max_retries": 2}]
    record = json.loads((tmp_path / "out.jsonl").read_text(encoding="utf-8").splitlines()[0])
    metadata = record["protected_result"]["target_metadata"]
    assert metadata["served_models"] == "claude-opus-5-5"
    assert metadata["effort_request"] == "low"


def test_the_cli_stops_on_a_configuration_error(fake_sdk, tmp_path, capsys):
    fake_sdk.Anthropic = lambda **kwargs: _Client(_APIStatusError(401))
    assert _cli(tmp_path) == 7
    assert "configuration error" in capsys.readouterr().out
    assert not (tmp_path / "summary.json").exists()


def test_the_cli_refuses_an_impossible_configuration(tmp_path, capsys):
    assert _cli(tmp_path, "--target-model", "claude-sonnet-5-5", "--target-thinking", "between_tools", "--target-effort", "max") == 7
    assert "effort high or below" in capsys.readouterr().out
