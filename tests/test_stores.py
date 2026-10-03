"""Declared stores and cross-session flows (DEC-070, FIND-075)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

import pytest

from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.exceptions import PolicyValidationError
from vais.gateway import ContractRegistry, Gateway
from vais.mcp import (
    MCPEffectMapping,
    MCPMintSpec,
    MCPProfile,
    MCPResultPolicy,
    MCPToolBinding,
    canonical_mcp_tool,
    load_mcp_profile,
)
from vais.models import ConfidentialityLevel as C
from vais.stores import store_flow_problems

ROOT = Path(__file__).resolve().parents[1]


def binding(tool, *, writes=(), reads=(), level=C.INTERNAL, mints=()):
    server, name = tool.split(".")
    return MCPToolBinding(server, name, tool, MCPResultPolicy(level), MCPEffectMapping(f"{name}_done"),
                          mints=mints, writes=writes, reads=reads)


WRITER = binding("kb.write", writes=("kb",))
READER = binding("kb.read", reads=("kb",))
SAFE_WRITE = ToolPolicy(True, {"text": ArgumentPolicy(max_confidentiality=C.INTERNAL)}, reject_undeclared_arguments=True)


def problems(*bindings, tools, default="deny"):
    return store_flow_problems(MCPProfile(bindings), Policy(version=6, default_action=default, tools=tools))


def test_no_declared_store_means_nothing_to_check():
    assert problems(binding("kb.write"), binding("kb.read"), tools={}) == ()


def test_a_store_only_written_or_only_read_has_no_round_trip():
    assert problems(WRITER, tools={"kb.write": ToolPolicy(True, {"text": ArgumentPolicy()})}) == ()
    assert problems(READER, tools={}) == ()


def test_a_writer_without_a_ceiling_is_a_problem():
    (problem,) = problems(WRITER, READER, tools={"kb.write": ToolPolicy(True, {"text": ArgumentPolicy()},
                                                                        reject_undeclared_arguments=True)})
    assert "kb.write.text may store any data" in problem and "kb.read returns as internal" in problem


@pytest.mark.parametrize("ceiling, ok", [(C.SECRET, False), (C.INTERNAL, True), (C.PUBLIC, True)])
def test_the_ceiling_must_not_exceed_what_the_store_returns(ceiling, ok):
    tools = {"kb.write": ToolPolicy(True, {"text": ArgumentPolicy(max_confidentiality=ceiling)},
                                    reject_undeclared_arguments=True)}
    assert (problems(WRITER, READER, tools=tools) == ()) is ok


def test_the_lowest_reader_sets_the_floor():
    public_reader = binding("kb.search", reads=("kb",), level=C.PUBLIC)
    (problem,) = problems(WRITER, READER, public_reader, tools={"kb.write": SAFE_WRITE})
    assert "kb.search returns as public" in problem


def test_undeclared_arguments_are_a_problem():
    tools = {"kb.write": ToolPolicy(True, {"text": ArgumentPolicy(max_confidentiality=C.INTERNAL)})}
    (problem,) = problems(WRITER, READER, tools=tools)
    assert "accepts undeclared arguments" in problem


def test_a_writer_the_policy_denies_writes_nothing():
    assert problems(WRITER, READER, tools={"kb.write": ToolPolicy(False)}) == ()
    assert problems(WRITER, READER, tools={}) == ()  # default deny


def test_a_writer_with_no_policy_under_default_allow_is_a_problem():
    (problem,) = problems(WRITER, READER, tools={}, default="allow")
    assert "no tool policy" in problem


def test_a_minting_reader_needs_an_approved_writer():
    minting = binding("kb.read", reads=("kb",), mints=(MCPMintSpec("account", (("pay.send", "account"),)),))
    pay = binding("pay.send")
    (problem,) = problems(WRITER, minting, pay, tools={"kb.write": SAFE_WRITE})
    assert "kb.read mints authority from it" in problem
    approved = ToolPolicy(True, SAFE_WRITE.arguments, exact_approval_required=True, reject_undeclared_arguments=True)
    assert problems(WRITER, minting, pay, tools={"kb.write": approved}) == ()


@pytest.mark.parametrize("field, value", [("writes", ("",)), ("reads", ("kb", "kb")), ("writes", (3,))])
def test_store_names_are_validated(field, value):
    with pytest.raises(ValueError):
        binding("kb.write", **{field: value})


def test_store_names_are_normalised():
    assert binding("kb.write", writes=("café",)).writes == ("café",)


PROFILE_YAML = """\
version: 1
servers:
  kb:
    tools:
      write: {{effect: {{kind: kb_written}}, {writes}}}
      read: {{effect: {{kind: kb_read}}, reads: [kb]}}
"""


def test_a_profile_file_declares_stores(tmp_path):
    path = tmp_path / "p.yaml"
    path.write_text(PROFILE_YAML.format(writes="writes: [kb]"), encoding="utf-8")
    profile = load_mcp_profile(path)
    assert profile.by_canonical_tool(canonical_mcp_tool("kb", "write")).writes == ("kb",)
    assert profile.by_canonical_tool(canonical_mcp_tool("kb", "read")).reads == ("kb",)


@pytest.mark.parametrize("writes", ["writes: kb", "writes: ['']", "writes: [kb, kb]", "stores: [kb]"])
def test_a_malformed_store_declaration_is_refused(tmp_path, writes):
    path = tmp_path / "p.yaml"
    path.write_text(PROFILE_YAML.format(writes=writes), encoding="utf-8")
    with pytest.raises(PolicyValidationError):
        load_mcp_profile(path)


class Upstream:
    async def call_tool(self, name, arguments=None):
        return {}


def gateway(tmp_path, tools):
    (tmp_path / "contracts").mkdir(exist_ok=True)
    return Gateway(profile=MCPProfile((WRITER, READER)),
                   monitor=ReferenceMonitor(Policy(version=6, default_action="deny", tools=tools)),
                   registry=ContractRegistry(tmp_path / "contracts"), sessions={"kb": Upstream()},
                   approval_store=ApprovalStore(), pending_dir=tmp_path / "pending")


def test_the_gateway_refuses_to_start_with_an_unsafe_store(tmp_path):
    with pytest.raises(PolicyValidationError, match="unsafe store flows: store kb"):
        gateway(tmp_path, {"kb.write": ToolPolicy(True, {"text": ArgumentPolicy()})})


def test_the_gateway_starts_when_the_store_is_safe(tmp_path):
    assert gateway(tmp_path, {"kb.write": SAFE_WRITE}) is not None


def test_the_cross_session_study_reproduces():
    """Every pre-registered prediction and every fix run of experiments/cross-session."""
    spec = importlib.util.spec_from_file_location("cross_session", ROOT / "experiments" / "cross-session" / "harness.py")
    harness = importlib.util.module_from_spec(spec)
    sys.modules["cross_session"] = harness  # its dataclasses look their module up
    try:
        spec.loader.exec_module(harness)
        results = harness.run_all()
    finally:
        sys.modules.pop("cross_session", None)
    assert len(results) == 12 and all(r["matches"] for r in results), [
        (r["scenario"], r["configuration"], r["observed"]) for r in results if not r["matches"]]


def test_the_library_client_refuses_an_unsafe_store_too():
    from vais.mcp import MCPProtectedClient
    unsafe = ReferenceMonitor(Policy(version=6, default_action="deny",
                                     tools={"kb.write": ToolPolicy(True, {"text": ArgumentPolicy()})}))
    with pytest.raises(PolicyValidationError, match="unsafe store flows"):
        MCPProtectedClient(server_id="kb", session=Upstream(), profile=MCPProfile((WRITER, READER)), monitor=unsafe)
    safe = ReferenceMonitor(Policy(version=6, default_action="deny", tools={"kb.write": SAFE_WRITE}))
    assert MCPProtectedClient(server_id="kb", session=Upstream(), profile=MCPProfile((WRITER, READER)), monitor=safe).profile is not None
