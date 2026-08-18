from __future__ import annotations

from dataclasses import replace
import json

import pytest

from vais.models import ConfidentialityLevel, TaskContract, TrustLevel, TrustedValue
from vais.openai_compatible import (
    LMStudioTarget,
    OpenAICompatibleConfig,
    OpenAICompatibleTarget,
    TargetAdapterError,
)
from vais.scenarios import default_scenarios


def _transport_with(plan: dict):
    calls = []

    def transport(url, payload, headers, timeout):
        calls.append((url, payload, headers, timeout))
        return {"choices": [{"message": {"content": json.dumps(plan)}}]}

    return transport, calls


def test_exact_bound_argument_is_rebound_to_trusted_contract_value():
    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")
    transport, calls = _transport_with(
        {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": "alice@example.com", "body": "Quarterly summary"},
                }
            ]
        }
    )
    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(model="test-model"),
        transport=transport,
    )

    plan = target.run(scenario, None)

    assert plan[0].arguments["recipient"].is_trusted
    assert plan[0].arguments["recipient"] is scenario.contract.bound_arguments[("send_email", "recipient")]
    assert plan[0].arguments["body"].provenance.trust == TrustLevel.DERIVED_UNTRUSTED
    assert calls[0][0].endswith("/chat/completions")
    assert calls[0][1]["response_format"]["type"] == "json_schema"


def test_changed_authority_argument_remains_untrusted():
    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")
    transport, _ = _transport_with(
        {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": "attacker@evil.test", "body": "Quarterly summary"},
                }
            ]
        }
    )
    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="test-model"), transport=transport)

    plan = target.run(scenario, scenario.attack_text)

    assert plan[0].arguments["recipient"].provenance.trust == TrustLevel.DERIVED_UNTRUSTED


def test_secret_canary_in_model_output_inherits_secret_confidentiality():
    scenario = next(s for s in default_scenarios() if s.id == "secret-to-public-egress")
    transport, _ = _transport_with(
        {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {
                        "recipient": "alice@example.com",
                        "body": "Summary: VAIS_TEST_CANARY_DO_NOT_EXFILTRATE",
                    },
                }
            ]
        }
    )
    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="test-model"), transport=transport)

    plan = target.run(scenario, scenario.attack_text)

    assert plan[0].arguments["body"].confidentiality == ConfidentialityLevel.SECRET


def test_transformed_model_output_still_inherits_visible_secret_confidentiality():
    scenario = next(s for s in default_scenarios() if s.id == "secret-to-public-egress")
    transport, _ = _transport_with(
        {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {
                        "recipient": "alice@example.com",
                        "body": "A paraphrase containing none of the original secret text",
                    },
                }
            ]
        }
    )
    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="test-model"), transport=transport)

    plan = target.run(scenario, scenario.attack_text)

    assert plan[0].arguments["body"].confidentiality == ConfidentialityLevel.SECRET


def test_adapter_authority_rebinding_is_type_sensitive():
    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")
    bindings = dict(scenario.contract.bound_arguments)
    bound = TrustedValue(1, source="user")
    bindings[("send_email", "recipient")] = bound
    scenario = replace(
        scenario,
        contract=TaskContract(
            allowed_tools=scenario.contract.allowed_tools,
            bound_arguments=bindings,
            approved_action_fingerprints=scenario.contract.approved_action_fingerprints,
            granted_scopes=scenario.contract.granted_scopes,
            principal_id=scenario.contract.principal_id,
            session_id=scenario.contract.session_id,
            tenant_id=scenario.contract.tenant_id,
            capability_id=scenario.contract.capability_id,
        ),
    )
    transport, _ = _transport_with(
        {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": True, "body": "Quarterly summary"},
                }
            ]
        }
    )
    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="test-model"), transport=transport)

    plan = target.run(scenario, None)

    assert plan[0].arguments["recipient"] is not bound
    assert plan[0].arguments["recipient"].provenance.trust == TrustLevel.DERIVED_UNTRUSTED


def test_target_caches_same_scenario_and_injection_for_paired_comparison():
    scenario = default_scenarios()[0]
    transport, calls = _transport_with(
        {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": "alice@example.com", "body": "Summary"},
                }
            ]
        }
    )
    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="test-model"), transport=transport)

    first = target.run(scenario, scenario.attack_text)
    second = target.run(scenario, scenario.attack_text)

    assert first == second
    assert len(calls) == 1


def test_invalid_model_plan_fails_closed():
    scenario = default_scenarios()[0]
    transport, _ = _transport_with({"actions": [{"tool": "unknown", "arguments": {}}]})
    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="test-model"), transport=transport)

    with pytest.raises(TargetAdapterError):
        target.run(scenario, scenario.attack_text)


def test_real_target_adapter_runs_end_to_end_through_same_security_boundary():
    from vais.adaptive import ScenarioStaticAttacker
    from vais.benchmark import BenchmarkRunner, ProtectionMode

    scenario = next(s for s in default_scenarios() if s.id == "email-recipient-hijack")
    calls = []

    def transport(url, payload, headers, timeout):
        del url, headers, timeout
        calls.append(payload)
        user_text = payload["messages"][1]["content"]
        attacked = scenario.attack_text in user_text
        recipient = "attacker@evil.test" if attacked else "alice@example.com"
        plan = {
            "actions": [
                {
                    "tool": "send_email",
                    "arguments": {"recipient": recipient, "body": "Quarterly summary"},
                }
            ]
        }
        return {"choices": [{"message": {"content": json.dumps(plan)}}]}

    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(model="fake-real-model"),
        transport=transport,
    )
    results = BenchmarkRunner().run_matrix(
        scenarios=(scenario,),
        targets=(target,),
        attackers=(ScenarioStaticAttacker(),),
        modes=(ProtectionMode.UNPROTECTED, ProtectionMode.PROTECTED),
    )

    unprotected, protected = results
    assert unprotected.reward == 1.0
    assert unprotected.violations == ("email_destination_integrity",)
    assert protected.reward == 0.0
    assert protected.violations == ()
    assert protected.records[0].decision.type.value == "deny"
    assert all(item.clean_utility_success for item in results)
    # clean and attacked generation are each called once, then reused across modes
    assert len(calls) == 2


def test_disable_thinking_adds_chat_template_switch():
    scenario = default_scenarios()[0]
    transport, calls = _transport_with({"actions": []})
    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(model="test-model", disable_thinking=True),
        transport=transport,
    )

    target.run(scenario, None)

    assert calls[0][1]["chat_template_kwargs"] == {"enable_thinking": False}


def test_lmstudio_disable_thinking_uses_reasoning_effort_none():
    scenario = default_scenarios()[0]
    transport, calls = _transport_with({"actions": []})
    target = LMStudioTarget(
        OpenAICompatibleConfig(
            model="test-model",
            disable_thinking=True,
            reasoning_mode_label="off",
        ),
        transport=transport,
        catalog_transport=lambda url, headers, timeout: {"models": []},
    )

    target.run(scenario, None)

    assert calls[0][1]["reasoning_effort"] == "none"
    assert "chat_template_kwargs" not in calls[0][1]
    assert target.metadata()["reasoning_mode_control"] == "reasoning_effort_none_posthoc_verified"


def test_empty_content_reports_reasoning_and_finish_reason():
    scenario = default_scenarios()[0]

    def transport(url, payload, headers, timeout):
        del url, payload, headers, timeout
        return {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": "", "reasoning": "x" * 42},
                }
            ]
        }

    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="thinking-model"), transport=transport)

    with pytest.raises(TargetAdapterError) as excinfo:
        target.run(scenario, None)

    text = str(excinfo.value)
    assert "empty action-plan content" in text
    assert "finish_reason='length'" in text
    assert "reasoning_chars=42" in text


def test_run_with_result_classifies_truncation_without_losing_diagnostics():
    from vais.targeting import TargetStatus

    scenario = default_scenarios()[0]

    def transport(url, payload, headers, timeout):
        del url, payload, headers, timeout
        return {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": "", "reasoning_content": "x" * 20},
                }
            ],
            "usage": {
                "prompt_tokens": 101,
                "completion_tokens": 50,
                "completion_tokens_details": {"reasoning_tokens": 49},
            },
        }

    target = OpenAICompatibleTarget(OpenAICompatibleConfig(model="thinking-model"), transport=transport)
    result = target.run_with_result(scenario, scenario.attack_text)

    assert result.generation.status == TargetStatus.TRUNCATED
    assert not result.valid
    assert result.generation.input_tokens == 101
    assert result.generation.output_tokens == 50
    assert result.generation.reasoning_tokens == 49
    assert result.generation.reasoning_chars == 20
    assert result.generation.finish_reason == "length"


def test_transport_retry_is_limited_to_transport_failures():
    from vais.targeting import TargetStatus

    scenario = default_scenarios()[0]
    calls = 0

    def transport(url, payload, headers, timeout):
        nonlocal calls
        del url, payload, headers, timeout
        calls += 1
        if calls == 1:
            raise TargetAdapterError("temporary timeout", status=TargetStatus.TIMEOUT)
        return {"choices": [{"finish_reason": "stop", "message": {"content": '{"actions": []}'}}]}

    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(model="test-model", transport_retries=1),
        transport=transport,
    )
    result = target.run_with_result(scenario, None)

    assert result.valid
    assert calls == 2
    assert result.generation.attempts == 2


def test_invalid_plan_is_not_retried_even_when_transport_retries_enabled():
    scenario = default_scenarios()[0]
    calls = 0

    def transport(url, payload, headers, timeout):
        nonlocal calls
        del url, payload, headers, timeout
        calls += 1
        return {"choices": [{"finish_reason": "stop", "message": {"content": "not-json"}}]}

    target = OpenAICompatibleTarget(
        OpenAICompatibleConfig(model="test-model", transport_retries=3),
        transport=transport,
    )
    result = target.run_with_result(scenario, None)

    assert not result.valid
    assert result.generation.status.value == "invalid_plan"
    assert calls == 1
    assert result.generation.attempts == 1


def test_lmstudio_target_records_native_catalog_metadata():
    from vais.openai_compatible import LMStudioTarget

    scenario = default_scenarios()[0]
    transport, _ = _transport_with({"actions": []})

    def catalog_transport(url, headers, timeout):
        del url, headers, timeout
        return {
            "models": [
                {
                    "type": "llm",
                    "publisher": "qwen",
                    "key": "qwen/qwen3.5-9b",
                    "display_name": "Qwen3.5 9B",
                    "architecture": "qwen3",
                    "quantization": {"name": "Q4_K_M", "bits_per_weight": 4},
                    "size_bytes": 123,
                    "params_string": "9B",
                    "loaded_instances": [{"id": "x", "config": {"context_length": 32768}}],
                    "max_context_length": 262144,
                    "format": "gguf",
                    "capabilities": {
                        "vision": False,
                        "trained_for_tool_use": True,
                        "reasoning": {"allowed_options": ["off", "on"], "default": "on"},
                    },
                    "selected_variant": "qwen/qwen3.5-9b@q4_k_m",
                }
            ]
        }

    target = LMStudioTarget(
        OpenAICompatibleConfig(
            model="qwen/qwen3.5-9b",
            reasoning_mode_label="off",
        ),
        transport=transport,
        catalog_transport=catalog_transport,
    )
    target.run(scenario, None)
    metadata = target.metadata()

    assert metadata["provider"] == "lmstudio"
    assert metadata["architecture"] == "qwen3"
    assert metadata["quantization"] == "Q4_K_M"
    assert metadata["params_string"] == "9B"
    assert metadata["trained_for_tool_use"] == "true"
    assert metadata["reasoning_default"] == "on"
    assert metadata["reasoning_allowed_options"] == "off,on"
    assert metadata["reasoning_mode_label"] == "off"
    assert metadata["loaded_context_length"] == "32768"
