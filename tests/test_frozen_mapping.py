"""Security mappings reject every in-place mutation ``dict`` offers (FIND-052).

``FrozenDict`` blocked ``__setitem__``, ``update`` and the rest but not ``|=``.
``dict.__ior__`` is implemented in C and does not call the overridden ``update``, so
``contract.bound_arguments |= {...}`` silently replaced a trusted binding and
``action.arguments |= {...}`` changed the action's fingerprint after the fact.

Each test below covers one mapping the enforcement path relies on and tries every
mutator, then checks the content is unchanged. The ``|=`` cases fail if the
``__ior__`` override is removed.
"""
from __future__ import annotations

import pytest

from vais import (
    ArgumentPolicy,
    PlannedAction,
    Policy,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    action_fingerprint,
)
from vais.models import FrozenDict
from vais.sandbox import SandboxExecutor


def _attempts(mapping, key, value):
    """Every in-place mutation a ``dict`` supports, as zero-argument callables."""

    def ior():
        target = mapping
        target |= {key: value}

    return {
        "setitem": lambda: mapping.__setitem__(key, value),
        "delitem": lambda: mapping.__delitem__(next(iter(mapping))),
        "clear": mapping.clear,
        "pop": lambda: mapping.pop(next(iter(mapping))),
        "popitem": mapping.popitem,
        "setdefault": lambda: mapping.setdefault(key, value),
        "update": lambda: mapping.update({key: value}),
        "ior": ior,
    }


def _assert_all_rejected(mapping, key, value):
    before = dict(mapping)
    for name, attempt in _attempts(mapping, key, value).items():
        with pytest.raises(TypeError, match="immutable"):
            attempt()
        assert dict(mapping) == before, f"{name} mutated the mapping"


def _recipient_action() -> PlannedAction:
    return PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com")})


def test_contract_binding_cannot_be_rewritten_in_place():
    contract = TaskContract(
        allowed_tools={"send_email"},
        bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com")},
    )
    _assert_all_rejected(
        contract.bound_arguments,
        ("send_email", "recipient"),
        TrustedValue("attacker@evil.test"),
    )
    assert contract.bound_arguments[("send_email", "recipient")].data == "alice@example.com"


def test_action_arguments_cannot_be_rewritten_after_fingerprinting():
    action = _recipient_action()
    fingerprint = action_fingerprint(action)
    _assert_all_rejected(action.arguments, "recipient", TrustedValue("attacker@evil.test"))
    assert action_fingerprint(action) == fingerprint


def test_policy_tool_table_cannot_gain_a_tool():
    policy = Policy(
        version=4,
        default_action="deny",
        tools={"send_email": ToolPolicy(allow=True, arguments={"recipient": ArgumentPolicy()})},
    )
    _assert_all_rejected(policy.tools, "shell_exec", ToolPolicy(allow=True))
    assert set(policy.tools) == {"send_email"}


def test_effect_attributes_cannot_be_rewritten():
    effect = SandboxExecutor().execute(_recipient_action())
    _assert_all_rejected(effect.attributes, "recipient", "attacker@evil.test")
    assert effect.attributes["recipient"] == "alice@example.com"


def test_non_mutating_union_still_returns_a_new_mapping():
    # ``|`` without assignment builds a new dict and must keep working, so only the
    # in-place form is blocked.
    original = FrozenDict({"a": 1})
    merged = original | {"b": 2}
    assert merged == {"a": 1, "b": 2}
    assert dict(original) == {"a": 1}
