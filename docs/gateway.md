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

A contract can also list several values for one argument, where one binding is not enough
(DEC-067):

```yaml
allowed_values:
  mcp:ap:pay: {invoice_id: {values: [INV-1001, INV-1002], once: true}}
budgets:
  mcp:ap:pay: {amount: 4650.00}
```

A value exactly equal to a listed one takes that value's trusted label, any other value is
refused, and with `once` each value is accepted once per session. A budget caps the sum of a
numeric argument over the session's allowed calls. A value budget caps it separately for each
listed value of another argument, and must cap every one of them (DEC-069):

```yaml
value_budgets:
  mcp:ap:pay: {amount: {per: invoice_id, limits: {INV-1001: 1250.00, INV-1002: 3400.00}}}
```

All of them need the session's ledger, so with `state:` they survive a restart.

It is stricter than the library path: a contract binding or allowed value is the only route to trust. It is
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

## How its decisions compare with the library's

Every VAIS study runs on the library path, where the harness labels the model's arguments. To
check what the gateway would have decided for the same agents, `vais.gateway_replay` sends
recorded traces through a real `Gateway`, with upstreams that return the recorded results, and
compares each step up to the first decision that differs
([results](../experiments/gateway-equivalence/RESULTS.md)). Over 10,560 protected traces from
P1b-4 and RC7, **no gateway decision and no label was more permissive than the library's**, and
88.6% of traces were identical (FIND-063). With rc14's mint for the reference declassifier declared,
95.8% of 23,040 traces, the RC13 campaign's included, are identical and only the first reason below
remains. The gateway was stricter for two reasons:

- **A contract approval counts once.** An action listed in a contract file's
  `approved_action_fingerprints` is allowed the first time in a session and then needs an
  operator. The use is recorded in the approval store's file, so it stays spent after a restart
  and across gateways sharing the file. The library path without a store or ledger lets it
  authorize the same action again (LIM-044). Before DEC-060 the gateway ignored these approvals
  entirely, because an approval store hid them (FIND-062); the replay found that.
- **Authority minted during a session needed a declaration.** A trusted application transform,
  such as the reference application's declassifier, can create a value the library binds into
  the contract. A gateway contract is a fixed operator file, so until rc14 the value came back
  from the agent as model output and a tool requiring it trusted denied it (LIM-068). A declared
  mint now carries it (below); with the declassifier's mint declared, the replay's only remaining
  difference is single use.

## Values the application creates during a session

Some applications create a trusted value mid-session that a later tool requires, such as a
declassifier's public artifact id. An operator can declare in the MCP profile that a tool's
result is authority for named arguments of other tools:

```yaml
servers:
  status:
    tools:
      build_public_update:
        mints:
          - from: result               # or result.<field> of a structured result
            to: [email.send_public_update.artifact_id]
```

After the minting call is allowed and observed, an argument **exactly equal** to the value is
trusted, with the minting tool as its source, for the rest of that session, and only for targets
whose tool the session's contract allows. Any other value is model output, a contract binding for
the same argument still wins, and every mint is audited with a digest of the value rather than
the value. With `state:` set, minted values survive a restart like the rest of the session.
Declaring a mint trusts the minting server as part of the application (LIM-070): a compromised
minting server can mint whatever it likes for those arguments.

## Stores shared across sessions

The gateway labels a value when it is read, by the reading tool's result policy. It does not
remember what was known about the value when another session wrote it. Trust cannot be
laundered this way, since every read is untrusted, but confidentiality and minted authority
can (FIND-075). A profile can declare the stores each tool writes and reads:

```yaml
servers:
  notes:
    tools:
      write: {effect: {kind: note_written}, writes: [notes]}
      read:  {effect: {kind: note_read}, result_confidentiality: internal, reads: [notes]}
```

The gateway then refuses to start (DEC-070) unless, for every declared store:
- every argument of every writer has a `max_confidentiality` no higher than the store's lowest
  reader returns, and the writer rejects undeclared arguments;
- every writer of a store that a minting tool reads requires an exact approval.

Stores that are not declared are not checked (LIM-074).

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
`audit.jsonl`, hash-chained; `vais audit-verify audit.jsonl` checks the chain and names any break.

When a call needs an approval, the agent is told `approval_required` with a request id, and the
gateway writes the exact action to `pending/<id>.json`. An operator reviews it and runs:

```bash
vais gateway-approve --config gateway.yaml <id>          # add --ttl 600 to let it lapse
```

The agent's retry of the same call then succeeds once. The grant is bound to the exact action
and the requesting contract, and a request whose action was edited after the gateway wrote it is
refused. The requester's identity in the file is not protected the same way, which is one reason
`pending/` must be writable by operators only.

Revoking a session is deleting its contract file; the next call is unauthenticated. To withdraw
it while keeping the file, for the record, set `revocations:` in the configuration and run:

```bash
vais gateway-revoke --config gateway.yaml contracts/alice.yaml   # --capability-only for one capability
```

The running gateway reads the revocation list on every decision, so the next call is denied.

With `state:` set, each session's ledger and confidentiality level are kept in files there, so
call limits, single-use approvals and what the session has read survive a restart, and several
gateway processes on one machine sharing the directory act as one. Without it they live in the
gateway's memory and a restart starts every session fresh (LIM-063).

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
- Without `state:`, ledgers and the confidentiality level live in the gateway's memory and a
  restart starts fresh (LIM-055, LIM-063). With it they are files, shared by processes on one
  machine only. The contract directory is read on every request.
- An approval in a contract file authorizes its exact action once per session (DEC-060).
- A budget caps a session's total; how it is split between allowed values is capped only by
  a value budget the operator declares. Neither has currency or unit semantics (LIM-072).
- A value an application creates during the session becomes authority only through a declared
  mint, which trusts the minting server (LIM-068, LIM-070).
- Labels are not persisted. Only declared stores are checked for carrying confidentiality or minted
  authority into a later session (LIM-074).
