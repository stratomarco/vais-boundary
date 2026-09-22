"""Regression locks for three loader contract faults found during rc12.

The loaders' contract is that malformed input is rejected as PolicyValidationError.
All three faults below failed closed, since no profile or policy with the bad input
was used, but two broke that contract and the third silently changed meaning.

FIND-053, `policy.py`, found by the continuous campaign on its first rc12 run:
`trust_required not in {None, "trusted"}` hashes its operand, so `trust_required: {}`
raised TypeError. It is FIND-047 again, one field over; rc11 fixed `default_action`
and did not look for the same pattern elsewhere in the file.

FIND-054, `mcp.py`, found by reading the loader while triaging FIND-053: a ':' in a
server or tool name reached `canonical_mcp_tool` and escaped as ValueError. The MCP
profile loader is not a campaign target (LIM-054), which is why nothing caught it.

FIND-055, `mcp.py`, same reading: effect field names are NFC-normalised and then
assigned into a dict, so two distinct YAML keys that normalise alike collapsed into
one and the later silently replaced the earlier. The duplicate check rc9 added to
`MCPEffectMapping` never saw them, because the loader had already merged them. The
YAML a reviewer reads and the mapping the loader returns could disagree.
"""
from __future__ import annotations

import pytest

from vais import load_policy
from vais.exceptions import PolicyValidationError
from vais.mcp import load_mcp_profile


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


POLICY = """version: 4
default_action: deny
tools:
  make_payment:
    allow: true
    arguments:
      destination:
        trust_required: {value}
"""


@pytest.mark.parametrize("value", ["{}", "[]", "[trusted]", "{a: 1}", "1", "true", "TRUSTED", "untrusted"])
def test_trust_required_rejects_every_value_but_trusted(tmp_path, value):
    """FIND-053. The unhashable cases are the ones that used to raise TypeError."""
    with pytest.raises(PolicyValidationError, match="supported value is 'trusted'"):
        load_policy(write(tmp_path, "p.yaml", POLICY.format(value=value)))


@pytest.mark.parametrize("value", ["trusted", "null"])
def test_trust_required_still_accepts_trusted_and_absent(tmp_path, value):
    policy = load_policy(write(tmp_path, "p.yaml", POLICY.format(value=value)))
    expected = "trusted" if value == "trusted" else None
    assert policy.tools["make_payment"].arguments["destination"].trust_required == expected


@pytest.mark.parametrize("servers", [
    '  "a:b":\n    tools:\n      send: {}\n',
    '  ops:\n    tools:\n      "se:nd": {}\n',
])
def test_a_colon_in_an_mcp_name_is_a_validation_error(tmp_path, servers):
    """FIND-054. Used to escape as ValueError from canonical_mcp_tool."""
    with pytest.raises(PolicyValidationError, match="cannot contain ':'"):
        load_mcp_profile(write(tmp_path, "m.yaml", "version: 1\nservers:\n" + servers))


def test_nfc_duplicate_effect_fields_are_rejected_not_merged(tmp_path):
    """FIND-055. Precomposed and decomposed forms of the same name, mapped to different arguments."""
    text = (
        "version: 1\nservers:\n  ops:\n    tools:\n      send:\n        effect:\n"
        "          argument_fields:\n"
        '            "café": recipient\n'
        '            "café": body\n'
    )
    with pytest.raises(PolicyValidationError, match="duplicate effect field"):
        load_mcp_profile(write(tmp_path, "m.yaml", text))


def test_distinct_effect_fields_still_load(tmp_path):
    text = (
        "version: 1\nservers:\n  ops:\n    tools:\n      send:\n        effect:\n"
        "          kind: email_sent\n          argument_fields:\n"
        "            recipient: to\n            body: text\n"
    )
    (binding,) = load_mcp_profile(write(tmp_path, "m.yaml", text)).bindings
    assert dict(binding.effect.argument_fields) == {"recipient": "to", "body": "text"}
