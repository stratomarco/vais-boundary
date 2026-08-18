import pytest

from vais import PlannedAction, Provenance, TaskContract, TrustLevel, TrustedValue, Value, action_fingerprint


def test_contract_copies_sets_into_immutable_frozensets():
    tools = {"send_email"}
    scopes = {"email:send"}
    contract = TaskContract(allowed_tools=tools, granted_scopes=scopes)
    tools.add("shell_exec")
    scopes.add("shell:exec")
    assert "shell_exec" not in contract.allowed_tools
    assert "shell:exec" not in contract.granted_scopes


def test_contract_rejects_untrusted_bound_authority():
    with pytest.raises(ValueError):
        TaskContract(
            allowed_tools={"send_email"},
            bound_arguments={
                ("send_email", "recipient"): Value(
                    "attacker@evil.test",
                    Provenance("document", TrustLevel.UNTRUSTED),
                )
            },
        )


def test_action_fingerprint_changes_with_arguments():
    first = PlannedAction("make_payment", {"amount": TrustedValue(150)})
    second = PlannedAction("make_payment", {"amount": TrustedValue(151)})
    assert action_fingerprint(first) != action_fingerprint(second)
