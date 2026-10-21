# Threat model

## What 1.0 covers

This threat model is about the boundary: the names `vais` publishes (`vais.__all__`), the
commands at the top level of `vais` (the gateway and its operator commands, the validators,
`check-invariants` and `audit-verify`), and the file formats in [`formats.md`](formats.md). The
benchmark and research tooling under `vais lab` produced VAIS's evidence; it is not part of
the boundary and is not covered here.

## Protected assets

- system/developer instructions;
- secrets, credentials and private data;
- user-authorized recipients and destinations;
- tool credentials and privileges;
- protected files/records;
- integrity of externally visible actions;
- integrity of security policy and task authorization.

## Adversary capabilities

The adversary may control or influence content marked untrusted, including:

- direct user text where the user is not itself an authority for the targeted operation;
- retrieved documents and web content;
- email/issues/tickets;
- third-party API/tool outputs;
- persistent memory derived from untrusted content;
- RAG entries;
- multimodal content once converted into model-consumable data.

The attacker may know the defense design and adapt prompts to it during a test campaign.

## Compromise assumption

The LLM may follow the attacker's instruction. The framework does not require prompt-injection detection to succeed before enforcing authorization.

## Security objectives

1. Untrusted information cannot create or expand authority.
2. Bound destinations cannot be changed by model/untrusted influence.
3. Tools require explicit task authorization and optional least-privilege capability scopes.
4. Data confidentiality cannot silently decrease through ordinary model transformation.
5. High-consequence operations can require independent approval.
6. Denied/unapproved actions do not produce an external effect.
7. Security impact can be verified independently through observable invariants.
8. Security decisions and effects can be audited deterministically.

## Assumptions

- policy, invariant files and enforcement code are loaded from an integrity-protected environment;
- the real tool cannot be reached through an alternate path that bypasses the enforcement boundary, meaning `ProtectedExecutor` or `MCPProtectedClient`. The library cannot enforce this because the application holds the tool credentials (LIM-050). From 0.12.0rc13 it can be checked after the fact: the `monitor_mediated` invariant reports any effect that no recorded `ALLOW` in the session ledger accounts for. Behind the gateway (`docs/gateway.md`), which is the only holder of the upstream credentials, it becomes an architectural property, provided the deployment keeps the agent away from those credentials, the upstreams and the operator files (LIM-060);
- adapters correctly label external sources and preserve labels across transformations, including re-labelling a model-produced value as trusted only when it exactly equals a contract binding (LIM-053);
- trusted upstream components are not already compromised, which includes the MCP servers VAIS dispatches to (LIM-049);
- an effect adapter accurately represents whether a consequential action occurred. On the MCP path the effect is the request VAIS dispatched, not state read back from the system of record, so this assumption is what lets the verifier treat a returned call as the effect it asked for (LIM-046). From 0.12.0rc13 an effect carries a confidence: a profile can require the reply to repeat the effect (acknowledged) and a read-back from the system of record to agree (confirmed), and a reply or read-back that disagrees marks it contradicted. Acknowledgement is still the server's own claim, and a read-back confirms only if the system it reads is independent of the server (LIM-065);
- processes sharing one `ApprovalStore` file run on one machine with a local disk. From 0.12.0rc13 consume-once holds across them, under an operating-system lock; it does not hold across machines or on network filesystems (LIM-057). Before rc13 it held only within one store instance (LIM-045);
- the host clock is correct, for contracts and grants that carry a time bound. They are checked against it when the monitor decides and not again when the effect happens (LIM-058);
- a sub-agent's contract is derived with `TaskContract.delegate`. The monitor does not check a delegate's lineage, so a contract built directly is taken at face value (LIM-059).

## Known gaps

Recorded in the research ledger rather than here, so they carry evidence and stay current:

- authority is fresh only when the caller asks for it. From 0.12.0rc13 a contract can carry a validity window, a grant a TTL, and a `RevocationList` withdraws a session or a capability; without them, authority stays valid for as long as it is used (LIM-047). Revocations live in memory in one process (LIM-056), and none of these is evaluated in VERIFY (LIM-058);
- authority is judged per argument, so an argument without a trust requirement can come from hostile content while the authority-bearing ones stay trusted (LIM-048). From 0.12.0rc13 an action can carry its origin, the join of what was visible when it was planned, and policy v6 can put a human in front of a tool whose action has an untrusted origin. Measured on RC7, that origin was untrusted for every model action, attacked or clean, so the rule is a per-tool human gate and not a detector (FIND-057, LIM-064);
- labels are not persisted: a value read back from a store is labelled by the reading tool, so a store can carry confidential data or minted authority into a later session unless the operator declares it and its writers are configured to match its readers (LIM-074, DEC-070); trust cannot be laundered this way (FIND-075);
- without an `ApprovalStore` or a `SessionLedger`, a contract-held approval is reusable for the life of the contract; VERIFY reports the reuse and ENFORCE does not prevent it (LIM-044);
- without a `SessionLedger`, a bound over several actions is checked in VERIFY and not enforced in flight (LIM-035). With one, `max_calls` is enforced in flight, but the ledger lives in one process and a restart starts a fresh one (LIM-055).
- a consequential call whose outcome is unknown holds its tool only if a version 2 profile marks the tool consequential; settling it as "did not happen" needs an operator whose identity is not authenticated, and an idempotency key prevents a duplicate only at a backend that honours it (LIM-078).

## Current non-goals

- proving arbitrary generated text harmless;
- classifying all prompt-injection strings;
- formal noninterference proofs;
- side-channel resistance;
- cryptographically tamper-evident audit storage;
- automatic safe declassification/endorsement of untrusted information;
- protecting applications that deliberately give the model unrestricted credentials outside VAIS;
- mediating the agent's final text answer or any reasoning trace. VAIS mediates tool calls only, so an application that displays or logs model text must treat it as a separate egress channel (LIM-051);
- detecting an MCP server that performs an effect other than the one requested (LIM-049).

## What VAIS leaves to other layers

VAIS decides whether a proposed action may run, from the provenance of its arguments, the task
contract and the session's history. It does not judge what text says. A deployment that needs
the following uses another layer for them, alongside VAIS:

- content safety, topic control, personal-data detection and grounding of the model's text:
  the guardrail frameworks assessed in [`guardrail-frameworks.md`](guardrail-frameworks.md);
- authentication of users, clients and MCP servers, such as OAuth for MCP;
- isolation of the agent and its tools: sandboxes, network egress controls, separate credentials;
- operational monitoring and incident response.

## Limitations 1.0 ships with

Stated here so a reader does not have to infer them from what is missing:

- **No independent security review** of the code or the design has been done.
- **State is coordinated on one machine.** Approvals, the session ledger and revocations hold
  across processes on one host with a local disk, not across machines (LIM-057).
- **Enforcement under a frontier model is untested in effect.** Neither available attacker moved
  Claude Sonnet 5.5 (FIND-067, FIND-068), so its zero protected violations show the boundary was
  not needed, not that it held. A stronger attacker against a frontier model (E3) has not run.
- **Evidence is bounded to what was recorded:** the models, quantisations, runtime, hardware,
  scenarios and episode budgets of each study. Per-model rates also depend on the inference
  engine's version (FIND-076, LIM-075). Zero observed violations in a finite campaign is not
  proof of universal security.
- **Observe-only mode enforces nothing while it lasts.** A gateway configured with `observe_until` forwards calls VAIS would refuse, for at most 14 days after it starts, and then enforces by itself ([`gateway.md`](gateway.md)). Whoever can edit the gateway configuration can turn it on, as they could already change the policy.
- **It is not a production-ready authorization service.** The known gaps above, and the research
  ledger's limitations, apply.

These boundaries must remain explicit so successful demos are not mistaken for stronger guarantees than the code actually provides.
