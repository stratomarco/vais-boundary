from pathlib import Path

import pytest

from vais import PolicyValidationError, load_policy


def write_policy(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_rejects_quoted_boolean_that_could_weaken_policy(tmp_path):
    path = write_policy(
        tmp_path,
        """
version: 1
tools:
  send_email:
    allow: "false"
""",
    )
    with pytest.raises(PolicyValidationError):
        load_policy(path)


def test_rejects_misspelled_trust_requirement(tmp_path):
    path = write_policy(
        tmp_path,
        """
version: 1
tools:
  send_email:
    allow: true
    arguments:
      recipient:
        trust_required: trustd
""",
    )
    with pytest.raises(PolicyValidationError):
        load_policy(path)


def test_rejects_unknown_policy_field(tmp_path):
    path = write_policy(
        tmp_path,
        """
version: 1
default_acton: allow
""",
    )
    with pytest.raises(PolicyValidationError):
        load_policy(path)


def test_default_policy_loads():
    root = Path(__file__).resolve().parents[1]
    policy = load_policy(root / "policies" / "default.yaml")
    assert policy.default_action == "deny"
    assert policy.tools["send_email"].allow is True


def test_v1_policy_remains_supported(tmp_path):
    path = write_policy(
        tmp_path,
        """
version: 1
default_action: deny
tools:
  send_email:
    allow: true
    arguments:
      recipient:
        trust_required: trusted
""",
    )
    policy = load_policy(path)
    assert policy.version == 1
    assert policy.tools["send_email"].required_scope is None


def test_v1_rejects_v2_only_field(tmp_path):
    path = write_policy(
        tmp_path,
        """
version: 1
tools:
  send_email:
    allow: true
    required_scope: email:send
""",
    )
    with pytest.raises(PolicyValidationError):
        load_policy(path)


def test_v2_rejects_unknown_confidentiality_level(tmp_path):
    path = write_policy(
        tmp_path,
        """
version: 2
tools:
  send_email:
    allow: true
    arguments:
      body:
        max_confidentiality: top_secretish
""",
    )
    with pytest.raises(PolicyValidationError):
        load_policy(path)
