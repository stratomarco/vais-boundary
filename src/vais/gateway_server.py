"""The VAIS gateway as an MCP server over streamable HTTP (P1b-5).

Requires the ``mcp`` extra. The gateway is an MCP server to the agent and an MCP client to
each upstream server. It opens the upstream sessions itself, with credentials resolved from
its own environment, so the agent's process never holds them: a call that does not come
through the gateway has nothing to authenticate with. That property holds only when the
deployment keeps the credentials out of the agent's reach and the upstreams unreachable
except from the gateway; ``docs/gateway.md`` describes how.

Configuration (paths are relative to the configuration file)::

    version: 1
    listen: {host: 127.0.0.1, port: 8765}
    policy: policy.yaml
    profile: mcp-profile.yaml
    contracts: contracts/          # operator-owned; see vais.gateway.ContractRegistry
    approvals: approvals.json      # shared ApprovalStore, written by operators
    pending: pending/              # approval requests, read by operators
    audit: audit.jsonl
    reason_disclosure: decision    # or "reasons"
    upstreams:
      ops:
        stdio: {command: python, args: [ops_server.py], env: {OPS_KEY: "${env:OPS_KEY}"}}
      crm:
        http: {url: "https://crm.internal/mcp", headers: {Authorization: "Bearer ${env:CRM_TOKEN}"}}
"""
from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
from typing import Any, AsyncIterator

import yaml

from .approvals import ApprovalStore
from .exceptions import PolicyValidationError
from .gateway import ContractRegistry, Gateway, exposed_name
from .mcp import MCPProfile, _fail, _known_keys, _mapping, _string, load_mcp_profile
from .monitor import ReferenceMonitor
from .policy import Policy, load_policy

_SECRET_REFERENCE = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True)
class UpstreamConfig:
    server_id: str
    transport: str  # "stdio" or "http"
    command: str | None = None
    args: tuple[str, ...] = ()
    cwd: str | None = None
    url: str | None = None
    # Values may contain ${env:NAME}, resolved from the gateway's environment at startup.
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class GatewayConfig:
    host: str
    port: int
    path: str
    policy: Path
    profile: Path
    contracts: Path
    approvals: Path
    pending: Path
    audit: Path
    reason_disclosure: str
    upstreams: tuple[UpstreamConfig, ...]


def load_gateway_config(path: str | Path) -> GatewayConfig:
    """Load the gateway configuration strictly. Secrets are referenced, never written in it."""
    location = str(path)
    base = Path(path).resolve().parent
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise PolicyValidationError(f"{location}: cannot read gateway configuration ({type(exc).__name__})") from None
    raw = _mapping(raw, location)
    _known_keys(raw, {"version", "listen", "policy", "profile", "contracts", "approvals", "pending",
                      "audit", "reason_disclosure", "upstreams"}, location)
    if raw.get("version") != 1 or isinstance(raw.get("version"), bool):
        _fail(f"{location}.version", "must be 1")

    listen = _mapping(raw.get("listen", {}), f"{location}.listen")
    _known_keys(listen, {"host", "port", "path"}, f"{location}.listen")
    port = listen.get("port", 8765)
    if isinstance(port, bool) or not isinstance(port, int) or not 0 < port < 65536:
        _fail(f"{location}.listen.port", "must be a TCP port")

    def local(key: str) -> Path:
        return base / _string(raw.get(key), f"{location}.{key}")

    disclosure = raw.get("reason_disclosure", "decision")
    if disclosure not in ("decision", "reasons"):
        _fail(f"{location}.reason_disclosure", "must be 'decision' or 'reasons'")

    upstreams: list[UpstreamConfig] = []
    for server_id, spec in _mapping(raw.get("upstreams"), f"{location}.upstreams").items():
        where = f"{location}.upstreams.{server_id}"
        server_id = _string(server_id, where)
        spec = _mapping(spec, where)
        _known_keys(spec, {"stdio", "http"}, where)
        if len(spec) != 1:
            _fail(where, "needs exactly one of 'stdio' or 'http'")
        if "stdio" in spec:
            stdio = _mapping(spec["stdio"], f"{where}.stdio")
            _known_keys(stdio, {"command", "args", "env", "cwd"}, f"{where}.stdio")
            args = stdio.get("args", [])
            if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
                _fail(f"{where}.stdio.args", "must be a list of strings")
            upstreams.append(UpstreamConfig(
                server_id, "stdio",
                command=_string(stdio.get("command"), f"{where}.stdio.command"),
                args=tuple(args),
                cwd=str(base / stdio["cwd"]) if "cwd" in stdio else None,
                env=_string_map(stdio.get("env", {}), f"{where}.stdio.env"),
            ))
        else:
            http = _mapping(spec["http"], f"{where}.http")
            _known_keys(http, {"url", "headers"}, f"{where}.http")
            upstreams.append(UpstreamConfig(
                server_id, "http",
                url=_string(http.get("url"), f"{where}.http.url"),
                headers=_string_map(http.get("headers", {}), f"{where}.http.headers"),
            ))

    return GatewayConfig(
        host=_string(listen.get("host", "127.0.0.1"), f"{location}.listen.host"),
        port=port,
        path=_string(listen.get("path", "/mcp"), f"{location}.listen.path"),
        policy=local("policy"), profile=local("profile"), contracts=local("contracts"),
        approvals=local("approvals"), pending=local("pending"), audit=local("audit"),
        reason_disclosure=disclosure,
        upstreams=tuple(upstreams),
    )


def _string_map(value: Any, path: str) -> dict[str, str]:
    mapping = _mapping(value, path)
    for key, item in mapping.items():
        if not isinstance(key, str) or not isinstance(item, str):
            _fail(path, "keys and values must be strings")
    return dict(mapping)


def resolve_secrets(values: dict[str, str], environ: dict[str, str] | None = None) -> dict[str, str]:
    """Substitute ``${env:NAME}`` from the gateway's environment; a missing name fails startup.

    The error names the variable, never a value.
    """
    environ = os.environ if environ is None else environ

    def substitute(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in environ:
            raise PolicyValidationError(f"environment variable {name} is referenced by the gateway configuration and not set")
        return environ[name]

    return {key: _SECRET_REFERENCE.sub(substitute, value) for key, value in values.items()}


def bearer_token(headers: Any) -> str | None:
    """The token from an ``Authorization: Bearer ...`` header, or None."""
    value = headers.get("authorization") if headers is not None else None
    if not isinstance(value, str):
        return None
    scheme, _, token = value.partition(" ")
    token = token.strip()
    return token if scheme.lower() == "bearer" and token else None


@asynccontextmanager
async def open_upstreams(upstreams: tuple[UpstreamConfig, ...]) -> AsyncIterator[tuple[dict[str, Any], dict[str, dict[str, Any]]]]:
    """Open one authenticated client session per upstream and list its tools.

    Yields ``(sessions, tools)``: ``sessions[server_id]`` is an initialized ``ClientSession``,
    ``tools[server_id][tool_name]`` the upstream's ``Tool``. A stdio upstream is started with
    the SDK's minimal default environment plus only the variables configured for it, so it
    does not inherit the gateway's other secrets.
    """
    import httpx2
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamable_http_client

    async with AsyncExitStack() as stack:
        sessions: dict[str, Any] = {}
        tools: dict[str, dict[str, Any]] = {}
        for upstream in upstreams:
            if upstream.transport == "stdio":
                parameters = StdioServerParameters(command=upstream.command, args=list(upstream.args),
                                                   env=resolve_secrets(upstream.env), cwd=upstream.cwd)
                read, write = await stack.enter_async_context(stdio_client(parameters))
            else:
                client = await stack.enter_async_context(
                    httpx2.AsyncClient(headers=resolve_secrets(upstream.headers)))
                read, write = await stack.enter_async_context(
                    streamable_http_client(upstream.url, http_client=client))
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
            sessions[upstream.server_id] = session
            tools[upstream.server_id] = {tool.name: tool for tool in listed.tools}
        yield sessions, tools


def build_app(config: GatewayConfig, *, policy: Policy | None = None, profile: MCPProfile | None = None):
    """Return the gateway's ASGI application. Upstreams open when the app starts."""
    from mcp import types
    from mcp.server.lowlevel.server import Server
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse

    policy = policy or load_policy(config.policy)
    profile = profile or load_mcp_profile(config.profile)
    registry = ContractRegistry(config.contracts)
    state: dict[str, Any] = {}

    def token_of(ctx: Any) -> str | None:
        request = getattr(ctx, "request", None)
        return bearer_token(getattr(request, "headers", None))

    async def list_tools(ctx: Any, params: Any) -> Any:
        gateway: Gateway = state["gateway"]
        listed = []
        for tool in gateway.tools_for(token_of(ctx) or ""):
            upstream = state["tools"][tool.binding.server_id][tool.binding.tool_name]
            # Descriptions come from the upstream and reach the model as-is; they are data,
            # and no authority depends on them (LIM-049).
            listed.append(types.Tool(name=tool.name, description=upstream.description,
                                     input_schema=upstream.input_schema))
        return types.ListToolsResult(tools=listed, cache_scope="private", ttl_ms=0)

    async def call_tool(ctx: Any, params: Any) -> Any:
        gateway: Gateway = state["gateway"]
        outcome = await gateway.call(token_of(ctx) or "", params.name, params.arguments or {})
        structured = None
        if outcome.is_error:
            text = outcome.message
        elif isinstance(outcome.result, str):
            text = outcome.result
        else:
            # Structured upstream output is passed on as structured output, with its JSON as
            # the text, which is how the SDK presents a tool's structured result.
            text = json.dumps(outcome.result, default=str, sort_keys=True)
            structured = outcome.result if isinstance(outcome.result, dict) else None
        return types.CallToolResult(content=[types.TextContent(type="text", text=text)],
                                    structured_content=structured, is_error=outcome.is_error)

    server = Server("vais-gateway", on_list_tools=list_tools, on_call_tool=call_tool)
    inner = server.streamable_http_app(streamable_http_path=config.path, host=config.host)

    @asynccontextmanager
    async def lifespan(app: Any) -> AsyncIterator[None]:
        async with open_upstreams(config.upstreams) as (sessions, upstream_tools):
            for binding in profile.bindings:
                if binding.tool_name not in upstream_tools.get(binding.server_id, {}):
                    raise PolicyValidationError(
                        f"profile binds {exposed_name(binding)!r}, which its upstream does not offer")
            state["tools"] = upstream_tools
            state["gateway"] = Gateway(
                profile=profile, monitor=ReferenceMonitor(policy), registry=registry, sessions=sessions,
                approval_store=ApprovalStore(config.approvals), pending_dir=config.pending,
                audit_path=config.audit, reason_disclosure=config.reason_disclosure,
            )
            async with server.session_manager.run():
                yield

    class RequireRegisteredToken:
        """Refuse any request whose bearer token names no registered contract, before MCP.

        Every tool call is authorized again from its own request's token, so this is a
        front door against unauthenticated sessions, not the authorization.
        """

        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] == "http":
                headers = {key.decode("latin-1").lower(): value.decode("latin-1")
                           for key, value in scope.get("headers", [])}
                token = bearer_token(headers)
                if token is None or registry.lookup(token) is None:
                    response = JSONResponse({"error": "unauthenticated"}, status_code=401,
                                            headers={"WWW-Authenticate": "Bearer"})
                    await response(scope, receive, send)
                    return
            await self.app(scope, receive, send)

    from starlette.middleware import Middleware

    return Starlette(routes=inner.routes, middleware=[Middleware(RequireRegisteredToken)], lifespan=lifespan)


def serve(config_path: str | Path) -> None:
    import uvicorn

    config = load_gateway_config(config_path)
    uvicorn.run(build_app(config), host=config.host, port=config.port, log_level="warning")
