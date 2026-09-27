"""An invariant that can never fire is found before it is trusted (LIM-041).

Evaluation still cannot tell a typo from a quiet run (tests/test_fault_injection.py keeps
that), so the check compares the invariants against an inventory of the effect kinds the
application produces: an MCP profile's tools, plus any kinds it names.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from vais.cli import main
from vais.exceptions import PolicyValidationError
from vais.invariants import load_invariants
from vais.mcp import MCPEffectMapping, MCPProfile, MCPToolBinding

DATA = Path(__file__).resolve().parents[1] / "src" / "vais" / "data"
INVARIANTS = """\
version: 1
invariants:
  - id: pay_bound
    description: payee is the bound one
    type: contract_binding
    effect: payment_sent
    field: payee
    binding: pay.payee
  - id: typo
    description: meant payment_sent
    type: forbidden_effect
    effect: payment_send
"""


@pytest.fixture
def invariants(tmp_path):
    path = tmp_path / "inv.yaml"
    path.write_text(INVARIANTS, encoding="utf-8")
    return path


def test_the_typo_is_named_and_the_real_invariant_is_not(invariants):
    engine = load_invariants(invariants)
    assert engine.effect_kinds() == {"payment_sent", "payment_send"}
    assert [item.id for item in engine.inert({"payment_sent"})] == ["typo"]
    with pytest.raises(PolicyValidationError, match=r"typo \(payment_send\)"):
        engine.require_effect_kinds({"payment_sent"})
    engine.require_effect_kinds({"payment_sent", "payment_send"})  # nothing inert, nothing raised


def test_a_profile_is_the_inventory_for_an_mcp_application():
    profile = MCPProfile((MCPToolBinding("pay", "send", "pay", effect=MCPEffectMapping("payment_sent")),
                          MCPToolBinding("mail", "send", "mail")))
    assert profile.effect_kinds() == {"payment_sent", "mcp_tool_called"}


def test_the_command_line_lists_inert_invariants_and_fails(invariants, capsys):
    assert main(["check-invariants", str(invariants), "--effect-kind", "payment_sent"]) == 1
    out = capsys.readouterr().out
    assert "inert: typo watches 'payment_send'" in out and "1 of 2 invariants" in out
    assert main(["check-invariants", str(invariants), "--effect-kind", "payment_sent", "--effect-kind", "payment_send"]) == 0
    assert main(["check-invariants", str(invariants)]) == 2


def test_the_shipped_defaults_against_the_example_profile(capsys):
    # The defaults are generic, so most watch kinds this small example never produces.
    code = main(["check-invariants", str(DATA / "default_invariants.yaml"), "--profile", str(DATA / "mcp_example_profile.yaml")])
    assert code == 1 and "3 of 7 invariants" in capsys.readouterr().out
