from dataclasses import replace
import math
import threading

import pytest

from vais import (ApprovalStore, AuditTrail, PlannedAction, ReferenceMonitor,
                  TaskContract, TrustedValue, action_fingerprint, load_policy)
from vais.models import security_equal
from vais.policy import ArgumentPolicy, Policy, ToolPolicy


def contract(**identity):
    return TaskContract({"pay"}, {("pay", "amount"): TrustedValue(1, "user")},
                        principal_id=identity.get("principal", "p"),
                        session_id=identity.get("session", "s"),
                        tenant_id=identity.get("tenant", "t"),
                        capability_id=identity.get("capability", "c"))


def action(value=1, extra=False):
    args = {"amount": TrustedValue(value, "user")}
    if extra:
        args["shadow"] = TrustedValue("unexpected", "user")
    return PlannedAction("pay", args)


def exact_policy():
    return Policy("deny", {"pay": ToolPolicy(True, {"amount": ArgumentPolicy()},
                                                   exact_approval_required=True,
                                                   reject_undeclared_arguments=True)}, 4)


def test_nested_security_values_are_copied_and_recursively_immutable():
    source = {"nested": ["e\u0301", {"x": 1}]}
    value = TrustedValue(source)
    source["nested"][1]["x"] = 9
    assert value.data["nested"][0] == "é"
    assert value.data["nested"][1]["x"] == 1
    with pytest.raises(TypeError):
        value.data["nested"][1]["x"] = 2


def test_canonical_equality_is_type_sensitive_and_unicode_normalized():
    assert not security_equal(True, 1)
    assert not security_equal(1, 1.0)
    assert security_equal("e\u0301", "é")
    assert action_fingerprint(action("e\u0301")) == action_fingerprint(action("é"))


def test_action_and_contract_identifiers_normalize_without_alias_collisions():
    normalized = PlannedAction("paye\u0301", {"cafe\u0301": TrustedValue(1)})
    assert normalized.tool == "payé"
    assert tuple(normalized.arguments) == ("café",)
    with pytest.raises(ValueError, match="duplicate argument"):
        PlannedAction(
            "pay",
            {"e\u0301": TrustedValue(1), "é": TrustedValue(1)},
        )
    with pytest.raises(ValueError, match="duplicate allowed tools"):
        TaskContract({"paye\u0301", "payé"})


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_nonfinite_values_are_rejected_before_authorization(bad):
    with pytest.raises(ValueError):
        TrustedValue(bad)


def test_v4_rejects_undeclared_arguments():
    decision = ReferenceMonitor(exact_policy()).evaluate(action(extra=True), contract())
    assert decision.type.value == "deny"
    assert "undeclared_argument:shadow" in decision.reasons


def test_scoped_approval_is_consume_once_and_persistent(tmp_path):
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)
    store.grant(action(), contract())
    monitor = ReferenceMonitor(exact_policy())
    assert monitor.evaluate(action(), contract(), store).type.value == "allow"
    assert monitor.evaluate(action(), contract(), ApprovalStore(path)).type.value == "require_approval"


@pytest.mark.parametrize("changed", ["principal", "session", "tenant", "capability"])
def test_approval_cannot_cross_identity_boundary(changed):
    store = ApprovalStore()
    store.grant(action(), contract())
    assert ReferenceMonitor(exact_policy()).evaluate(
        action(), contract(**{changed: "other"}), store).type.value == "require_approval"


def test_concurrent_approval_consumption_allows_exactly_once():
    store = ApprovalStore()
    store.grant(action(), contract())
    monitor = ReferenceMonitor(exact_policy())
    outcomes = []
    threads = [threading.Thread(target=lambda: outcomes.append(
        monitor.evaluate(action(), contract(), store).type.value)) for _ in range(12)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert outcomes.count("allow") == 1


def test_policy_threshold_rejects_nonfinite(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text("version: 4\ntools:\n  pay:\n    allow: true\n    arguments:\n      amount: {}\n    approval:\n      field: amount\n      greater_than: .inf\n", encoding="utf-8")
    with pytest.raises(Exception, match="must be finite"):
        load_policy(path)


def test_policy_v4_cannot_opt_out_of_fail_closed_defaults(tmp_path):
    allow_default = tmp_path / "allow-default.yaml"
    allow_default.write_text("version: 4\ndefault_action: allow\ntools: {}\n", encoding="utf-8")
    with pytest.raises(Exception, match="requires fail-closed 'deny'"):
        load_policy(allow_default)

    allow_extra = tmp_path / "allow-extra.yaml"
    allow_extra.write_text(
        "version: 4\ndefault_action: deny\ntools:\n  pay:\n    allow: true\n"
        "    reject_undeclared_arguments: false\n    arguments:\n      amount: {}\n",
        encoding="utf-8",
    )
    with pytest.raises(Exception, match="requires fail-closed undeclared-argument"):
        load_policy(allow_extra)


def test_audit_chain_detects_tampering_and_freezes_details():
    source = {"fields": ["amount"]}
    trail = AuditTrail()
    event = trail.record("authorization_decision", tool="pay", decision="allow", details=source)
    source["fields"].append("secret")
    trail.record("effect_observed", tool="pay")
    assert event.details["fields"] == ("amount",)
    assert trail.verify()
    trail._events[0] = replace(trail._events[0], decision="deny")
    assert not trail.verify()


def test_audit_rejects_secret_bearing_fields():
    with pytest.raises(ValueError, match="secret-bearing"):
        AuditTrail().record("adapter_error", details={"api_token": "do-not-log"})
