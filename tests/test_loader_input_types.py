"""Regression locks for the two loader faults the P1-6 campaign found.

Both are the same class: a validator that assumed YAML would hand it a string.
The campaign found them because a mutator produces documents no human writes,
and they are pinned here so the ordinary suite keeps them closed without waiting
for a nightly run to rediscover them.

FIND-047, `policy.py`: `default_action not in {"allow", "deny"}` raises TypeError
for an unhashable operand, so `default_action: [allow, deny]` failed with
"unhashable type: 'list'" instead of a PolicyValidationError. The version check
immediately above already guarded with isinstance and short-circuits; this one
did not.

FIND-048, all three loaders: `_known_keys` sorted and joined the unknown keys
directly. YAML keys are not necessarily strings, so `1: x`, `true: x`, `~: x` and
a bare date each raised TypeError instead of reporting an unknown field. The
helper is copied into `policy.py`, `invariants.py` and `mcp.py`, so the same
latent fault existed three times.

Neither was a bypass. Both failed closed, in the sense that no Policy was
produced and the exception propagated. Both broke the loaders' declared contract,
which is that malformed input is rejected as PolicyValidationError, and an
application catching that to degrade gracefully would have missed them (LIM-039).
"""

from __future__ import annotations

import pytest

from vais import load_invariants, load_policy
from vais.exceptions import PolicyValidationError


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "value",
    ["[allow, deny]", "{a: 1}", "5", "null", "true", "1.5", "[]", "{}"],
)
def test_a_non_string_default_action_is_rejected_cleanly(tmp_path, value):
    """FIND-047. The unhashable cases are the ones that used to raise TypeError."""
    with pytest.raises(PolicyValidationError, match="must be 'allow' or 'deny'"):
        load_policy(write(tmp_path, "p.yaml", f"version: 1\ndefault_action: {value}\n"))


@pytest.mark.parametrize(
    "key",
    ["1", "true", "~", "1.5", "2026-01-01", "[a, b]" ],
)
def test_a_non_string_key_is_reported_as_an_unknown_field(tmp_path, key):
    """FIND-048 in the policy loader."""
    try:
        load_policy(write(tmp_path, "p.yaml", f"version: 1\n{key}: x\n"))
    except PolicyValidationError as exc:
        assert "unknown field(s)" in str(exc)
    except Exception as exc:  # noqa: BLE001 - the point is that nothing else is raised
        import yaml

        if not isinstance(exc, yaml.YAMLError):
            raise AssertionError(f"expected a clean rejection, got {type(exc).__name__}: {exc}")
    else:
        raise AssertionError("a policy with an unknown key was accepted")


def test_a_non_string_key_is_reported_by_the_invariant_loader(tmp_path):
    """FIND-048 in the second of the three copies."""
    with pytest.raises(PolicyValidationError, match="unknown field"):
        load_invariants(write(tmp_path, "i.yaml", "version: 1\n1: x\ninvariants: []\n"))


def test_a_non_string_key_is_reported_by_the_mcp_loader(tmp_path):
    """FIND-048 in the third copy. All three helpers were identical."""
    from vais.mcp import load_mcp_profile

    with pytest.raises(PolicyValidationError, match="unknown field"):
        load_mcp_profile(write(tmp_path, "m.yaml", "version: 1\n1: x\nservers: {}\n"))


def test_a_valid_policy_still_loads(tmp_path):
    """The guards reject more than before; they must not reject what is correct."""
    policy = load_policy(
        write(tmp_path, "ok.yaml", "version: 4\ndefault_action: deny\ntools:\n  send_email:\n    allow: true\n")
    )
    assert policy.default_action == "deny"
    assert policy.version == 4
    assert policy.tools["send_email"].allow is True
