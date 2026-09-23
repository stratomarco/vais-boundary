# The VAIS gateway

*0.12.0rc13, P1b-5. Requires the `mcp` extra: `pip install -e ".[mcp]"`.*

`MCPProtectedClient` is a library the agent host calls. The host decides which values are
trusted, which contract applies and whether a call goes through VAIS at all, and it holds the
tool credentials, so complete mediation is an assumption about the host (LIM-050). The gateway
is the same reference monitor in its own process: an MCP server to the agent and an MCP client
to each upstream server, and **the only holder of the upstream credentials**. An agent that
tries to reach a tool some other way has nothing to authenticate with.

That is only worth having if the gateway trusts nothing the agent sends. So three jobs the
library leaves to the caller move into the gateway:

| | Library (`MCPProtectedClient`) | Gateway |
|---|---|---|
| Contract | Passed in by the host | Operator file, found by the SHA-256 of the agent's session token |
| Trust labels | Set by the host on each value | Assigned by the gateway (below) |
| Approvals | Granted by whoever holds the store | Requested by the gateway, granted only by an operator |
| Credentials | Held by the host | Held by the gateway, resolved from its own environment |
| Denial reasons | Returned to the caller | Withheld from the agent by default, kept in the audit |

## How the gateway labels what the agent sends

Everything arriving from the agent is model output. An argument is labelled `derived_untrusted`
at the highest confidentiality the session has received through the gateway so far, the rule
`derive_model_output` already applies in the library, now applied at the boundary. The one
exception is a value **exactly equal to its contract binding**, which takes the binding's
trusted label, because its value is the one the operator wrote. This is the re-labelling step
LIM-053 describes as every integration's job, done once here.

It is stricter than the library path: a contract binding is the only route to trust. It is
also coarse: once a session has read `secret` data through the gateway, every later argument
counts as `secret` (DEC-051, LIM-061).

Effects are read back where the profile says how (P1b-7). A `confirm` block names a read tool on
an upstream, ideally the system of record rather than the server that acted; the gateway calls it
with its own credentials after the effect and records `confirmed` or `contradicted` in the audit.
A named server or tool that is missing fails startup.

Each action also gets an origin (P1b-6): trusted until the session receives its first tool
result, untrusted from then on. A tool whose policy sets `untrusted_origin: require_approval`
therefore needs an operator's approval for any call after the session has read something. That
is a deliberate human gate, not attack detection (FIND-057).

## Quick start

The files are in [`examples/gateway/`](../examples/gateway/); the upstream is the repository's
deliberately vulnerable demo server. From that directory:

```bash
vais gateway-token
```

Put the printed `token_sha256` into a copy of `contract.example.yaml` under `contracts/`, and
give the printed `token` to the agent's runtime. The contract fixes the session's tools and its
bound values; here the incident is `INC-1234` and the only email recipient is
`ir-team@acme.example`.

```bash
OPS_API_KEY=demo-key vais gateway --config gateway.yaml
```

(In PowerShell, set `$env:OPS_API_KEY` first. The example starts its upstream with `python`,
which must be an interpreter with the `mcp` extra installed.) The agent connects to
`http://127.0.0.1:8765/mcp` with `Authorization: Bearer <token>` and sees two tools,
`ops.get_incident` and `ops.send_email`. The incident record carries an injection asking for the
summary to go to `attacker@evil.test`; that call returns `denied` and never reaches the
upstream, while the email to `ir-team@acme.example` is sent. Every decision is in
`audit.jsonl`, hash-chained.

When a call needs an approval, the agent is told `approval_required` with a request id, and the
gateway writes the exact action to `pending/<id>.json`. An operator reviews it and runs:

```bash
vais gateway-approve --config gateway.yaml <id>          # add --ttl 600 to let it lapse
```

The agent's retry of the same call then succeeds once. The grant is bound to the exact action
and the requesting contract, and a request whose action was edited after the gateway wrote it is
refused. The requester's identity in the file is not protected the same way, which is one reason
`pending/` must be writable by operators only.

Revoking a session is deleting its contract file; the next call is unauthenticated.

## What a deployment must guarantee

The gateway makes complete mediation an architectural property **only if the deployment keeps
the agent away from everything the gateway holds**. VAIS cannot check any of this from inside
(LIM-060):

1. **Credentials.** Upstream secrets exist only in the gateway's environment. The agent's
   process, container or user cannot read them, the gateway configuration, or the gateway's
   process memory.
2. **Network.** Upstream servers accept connections only from the gateway. For HTTP upstreams,
   network policy; for stdio upstreams, the gateway starts them itself and nothing else can.
3. **Operator files.** `contracts/`, `approvals.json` and `pending/` are writable by operators
   and not by the agent. Anyone who can write a contract can grant themselves a session, and
   `pending/` holds argument values an approver needs to see.
4. **Transport.** The gateway listens on `127.0.0.1` by default. Across hosts, terminate TLS in
   front of it; the session token is a bearer secret.

A practical layout is the gateway and its upstream credentials in one container or service
account, the agent in another with network access to the gateway's port and nothing else.

## What the agent sees

- Tools named `server.tool`, only those its contract allows. The listing narrows what the model
  is offered; it is not the authorization, which the monitor makes on every call.
- Upstream tool descriptions, unchanged. They are data and carry no authority (LIM-049), but they
  do reach the model.
- For a refusal, the outcome only: `denied`, `approval_required; request <id> is waiting for an
  operator`, `indeterminate` or `unauthenticated`. Set `reason_disclosure: reasons` to add the
  monitor's reason codes, which help an attacker probe the policy (S13, IMP-003).

## Limits

- The guarantee is conditional on the deployment above (LIM-060).
- Labels are session-coarse, and the gateway cannot see data the agent obtained without it, such
  as secrets placed in the prompt (LIM-061).
- Only tools are proxied. Resources, prompts, sampling and elicitation are not, and results are
  passed on as text or structured data (LIM-062).
- Ledgers and the confidentiality level live in the gateway's memory; a restart starts fresh
  (LIM-055, LIM-063). The contract directory is read on every request.
