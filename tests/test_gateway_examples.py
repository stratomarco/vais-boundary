"""The shipped gateway example stays loadable and consistent (docs/gateway.md uses it)."""
from __future__ import annotations

from pathlib import Path

from vais.gateway import load_gateway_contract, token_digest
from vais.gateway_server import load_gateway_config
from vais.mcp import load_mcp_profile
from vais.policy import load_policy

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "gateway"


def test_the_example_configuration_policy_profile_and_contract_agree(tmp_path):
    config = load_gateway_config(EXAMPLE / "gateway.yaml")
    policy = load_policy(config.policy)
    profile = load_mcp_profile(config.profile)
    assert (Path(config.upstreams[0].cwd) / config.upstreams[0].args[0]).resolve().is_file()
    assert "${env:OPS_API_KEY}" in config.upstreams[0].env["OPS_API_KEY"]

    template = (EXAMPLE / "contract.example.yaml").read_text(encoding="utf-8")
    rendered = tmp_path / "contract.yaml"
    rendered.write_text(template.replace("REPLACE_WITH_THE_DIGEST_FROM_vais_gateway-token", token_digest("t")),
                        encoding="utf-8")
    _, contract = load_gateway_contract(rendered)
    bound_tools = {binding.canonical_tool for binding in profile.bindings}
    assert contract.allowed_tools <= bound_tools <= set(policy.tools)
