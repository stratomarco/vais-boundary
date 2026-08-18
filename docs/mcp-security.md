# MCP security boundary

VAIS v0.7 introduced the first Model Context Protocol integration layer; v0.8 adds repeatable MCP-path benchmarking over the 125-case static corpus.

The design follows the same rule as the rest of VAIS:

> An MCP server can provide useful data or functionality, but neither MCP content nor model intent automatically carries application authority.

## Why MCP is a natural VAIS boundary

MCP separates model-facing applications from servers that expose resources, prompts and tools. Tools are model-controlled operations and can have side effects. That makes the host/client-to-server tool call an excellent place for complete mediation.

VAIS therefore treats the application architecture as:

```text
MCP result / resource
       |
       | labelled as non-authoritative data
       v
    LLM / agent
       |
       | proposed tool call
       v
+-------------------------+
|          VAIS           |
| task authority          |
| provenance              |
| capability scope        |
| confidentiality         |
| exact approval          |
| reference monitor       |
+------------+------------+
             |
      ALLOW only
             |
             v
        MCP ClientSession
             |
             v
         MCP Server
```

## Inbound rule: data is not authority

`label_mcp_input()` labels tool results, resources or prompt content as `UNTRUSTED` for authority purposes by default.

This is intentional. A Jira issue can be trusted as a source of ticket content without being trusted to choose a payment destination, email recipient or shell command. VAIS v0.7 uses a deliberately conservative single integrity domain, so remote MCP output is never upgraded to authority through the MCP profile.

Confidentiality is configurable because an MCP result may legitimately carry `internal`, `confidential` or `secret` data.

## Outbound rule: every consequential tool call is mediated

`MCPProtectedClient` wraps the minimal `ClientSession.call_tool()` interface. It accepts a `PlannedAction`, evaluates it through the normal `ReferenceMonitor`, and forwards only `ALLOW` decisions.

`DENY` and `REQUIRE_APPROVAL` never call the server.

The wrapper does not depend on MCP SDK types, so the VAIS core stays deterministic and lightweight. Live MCP applications can install the optional extra:

```bash
pip install -e '.[mcp]'
```

The extra is currently pinned to the current stable MCP Python SDK v2 line (`mcp>=2,<3`).

## Tool names and confused-deputy resistance

A remote MCP endpoint can be represented by a namespaced canonical tool:

```text
mcp:github:create_issue
mcp:ops:get_incident
```

An application may explicitly alias a remote tool into an existing domain tool such as `send_email`, but that alias is trusted configuration and is still constrained by the task contract and policy.

Different servers cannot silently collide on the same endpoint binding.

## Least-exposure tool catalogs

`MCPProfile.exposed_tools()` returns only bindings present in the current task contract. This lets a host avoid presenting irrelevant tools to the model.

Catalog filtering reduces attack surface but is **not** authorization. The reference monitor still evaluates every actual call because tool discovery can be stale, manipulated or bypassed.

## Effects and invariants

A generic MCP call emits `mcp_tool_called`. Profiles can map tools to application-domain effects:

```yaml
effect:
  kind: email_sent
  argument_fields:
    recipient: recipient
    body: body
```

That lets the existing invariant engine verify the same security properties regardless of whether `send_email` is a local Python function, an HTTP API or an MCP tool.

## Scope through v0.8

v0.7 is an **agent-host integration wrapper**, not yet a transparent wire proxy for arbitrary MCP applications.

Implemented:

- strict MCP integration profiles;
- namespaced tool bindings;
- least-exposure catalog filtering;
- default non-authoritative labeling for inbound MCP content;
- confidentiality labels on MCP results;
- deterministic pre-call enforcement;
- effect mapping into the existing invariant engine;
- in-memory and live stdio demos.

Not yet implemented:

- transparent forwarding proxy for an unmodified third-party MCP host;
- generic resource/prompt interception at the transport layer;
- OAuth/token-broker policy enforcement;
- distributed multi-server trace correlation;
- adaptive RLVR attacks against a live MCP agent.

Those are future steps, not properties implied by v0.7.

## Official MCP basis

As of August 2026, the stable Python SDK line supports clients and servers over stdio, SSE and Streamable HTTP and implements MCP tools, resources and prompts. VAIS uses only the minimal client tool-call interface in core code so protocol SDK evolution does not become part of the authorization logic.

- MCP specification: https://modelcontextprotocol.io/
- Official Python SDK: https://github.com/modelcontextprotocol/python-sdk

## Transport ambiguity

If an authorized MCP call raises after transmission, VAIS cannot safely assume that no side effect occurred. `MCPExecutionRecord.call_state` therefore distinguishes:

- `not_called`: VAIS blocked the request before the MCP session;
- `observed`: the MCP call returned and an effect can be recorded;
- `indeterminate`: the call was authorized and attempted, but transport/runtime failure makes the external outcome uncertain.

An `indeterminate` call is not counted as proof that the external effect did not happen. Production integrations should use idempotency keys, server-side audit receipts or domain-specific reconciliation for high-consequence tools.

## Real local-model demonstration

`examples/mcp_lmstudio_agent_demo.py` connects the deliberately vulnerable MCP server to a real LM Studio target. The flow is:

```text
trusted incident ID
      |
      v
VAIS -> MCP get_incident -> poisoned tool result (UNTRUSTED)
                                      |
                                      v
                                 LM Studio model
                                      |
                               proposed action plan
                                      |
                                      v
                                   VAIS
                                      |
                             ALLOW/DENY/APPROVAL
                                      |
                                      v
                              outbound MCP tool
```

Run it after installing the optional MCP SDK extra:

```powershell
pip install -e ".[dev,mcp]"
python .\examples\mcp_lmstudio_agent_demo.py --model "qwen/qwen3.5-9b" --reasoning-mode off
```

The script remains the smallest live integration demonstration. v0.8 additionally provides `vais benchmark-mcp-lmstudio`, which transports the full 125-case corpus as untrusted MCP tool-result content and executes outbound actions through the protected/unprotected MCP client paths.

## Protected and unprotected assessment paths

`MCPUnprotectedClient` is an explicitly unsafe baseline adapter for security evaluation. It forwards a configured tool binding without reference-monitor authorization while preserving the same effect mapping and result labelling. This lets an assessment compare the **same proposed action** under:

```text
unprotected MCP path -> observable effect / invariant result
protected MCP path   -> VAIS decision -> observable effect / invariant result
```

The class is intentionally named `Unprotected` and must not be used as a production client.


## v0.8 MCP-path benchmark

The bundled corpus `bundled:v0.8-mcp` contains the same 25 techniques across each of the five security objectives used in the direct v0.6 benchmark, but marks the delivery mechanism as `mcp_tool_result`.

The benchmark uses a deterministic in-process MCP-compatible session for outbound calls. This is intentional: the security experiment needs a repeatable effect oracle while still exercising `MCPProtectedClient`/`MCPUnprotectedClient`. It does **not** claim to emulate every MCP transport or server implementation.

Every episode records:

- MCP ingress source, trust and confidentiality;
- clean and attacked content hashes;
- model plan and target-generation health;
- VAIS decisions;
- MCP call state for each proposed action;
- number of remote calls attempted;
- mapped observable effects;
- independent invariant violations.

This is the bridge between VAIS as a security boundary and VAIS as an assessment framework for agent/MCP systems.
