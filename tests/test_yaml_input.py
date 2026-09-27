"""Every way a security file can fail to be a YAML document is a PolicyValidationError (LIM-039).

Before rc14 a file with bad syntax escaped the policy, invariant and MCP-profile loaders as
yaml.YAMLError, one that was not UTF-8 as UnicodeDecodeError, and one nested deeply enough
as RecursionError, which also escaped the gateway's contract and configuration loaders.
"""
from __future__ import annotations

import pytest

from vais.exceptions import PolicyValidationError
from vais.gateway import ContractRegistry, load_gateway_contract, token_digest
from vais.gateway_server import load_gateway_config
from vais.invariants import load_invariants
from vais.mcp import load_mcp_profile
from vais.policy import load_policy

LOADERS = [load_policy, load_invariants, load_mcp_profile, load_gateway_contract, load_gateway_config]
NOT_A_DOCUMENT = {
    "bad syntax": b"version: [1\n",
    "not utf-8": b"\xff\xfeversion: 1\n",
    "deep nesting": b"[" * 20000,
}


@pytest.mark.parametrize("loader", LOADERS, ids=lambda f: f.__name__)
@pytest.mark.parametrize("case", NOT_A_DOCUMENT, ids=str)
def test_a_file_that_is_not_a_document_is_a_policy_validation_error(tmp_path, loader, case):
    path = tmp_path / "file.yaml"
    path.write_bytes(NOT_A_DOCUMENT[case])
    with pytest.raises(PolicyValidationError) as caught:
        loader(path)
    assert "20000" not in str(caught.value) and "\xff" not in str(caught.value)


def test_a_missing_file_is_still_an_os_error_for_the_library_loaders(tmp_path):
    for loader in (load_policy, load_invariants, load_mcp_profile):
        with pytest.raises(OSError):
            loader(tmp_path / "missing.yaml")


def test_the_contract_registry_skips_a_deeply_nested_file_and_serves_the_others(tmp_path):
    (tmp_path / "bomb.yaml").write_bytes(b"[" * 20000)
    (tmp_path / "alice.yaml").write_text(
        f"version: 1\ntoken_sha256: {token_digest('t-1')}\nprincipal_id: alice\nsession_id: s-1\n"
        "tenant_id: acme\ncapability_id: root\nallowed_tools: [ops.read]\n", encoding="utf-8")
    registry = ContractRegistry(tmp_path)
    contracts, problems = registry.scan()
    assert len(contracts) == 1 and len(problems) == 1
    assert registry.lookup("t-1").principal_id == "alice"
