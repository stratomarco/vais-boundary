# Threat model

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
- the real tool cannot be reached through an alternate path that bypasses the enforcement boundary, meaning `ProtectedExecutor` or `MCPProtectedClient`. The library cannot enforce this because the application holds the tool credentials (LIM-050). From 0.12.0rc13 it can be checked after the fact: the `monitor_mediated` invariant reports any effect that no recorded `ALLOW` in the session ledger accounts for;
- adapters correctly label external sources and preserve labels across transformations, including re-labelling a model-produced value as trusted only when it exactly equals a contract binding (LIM-053);
- trusted upstream components are not already compromised, which includes the MCP servers VAIS dispatches to (LIM-049);
- an effect adapter accurately represents whether a consequential action occurred. On the MCP path the effect is the request VAIS dispatched, not state read back from the system of record, so this assumption is what lets the verifier treat a returned call as the effect it asked for (LIM-046);
- processes sharing one `ApprovalStore` file run on one machine with a local disk. From 0.12.0rc13 consume-once holds across them, under an operating-system lock; it does not hold across machines or on network filesystems (LIM-057). Before rc13 it held only within one store instance (LIM-045);
- the host clock is correct, for contracts and grants that carry a time bound. They are checked against it when the monitor decides and not again when the effect happens (LIM-058);
- a sub-agent's contract is derived with `TaskContract.delegate`. The monitor does not check a delegate's lineage, so a contract built directly is taken at face value (LIM-059).

## Known gaps

Recorded in the research ledger rather than here, so they carry evidence and stay current:

- authority is fresh only when the caller asks for it. From 0.12.0rc13 a contract can carry a validity window, a grant a TTL, and a `RevocationList` withdraws a session or a capability; without them, authority stays valid for as long as it is used (LIM-047). Revocations live in memory in one process (LIM-056), and none of these is evaluated in VERIFY (LIM-058);
- authority is judged per argument, and a proposed action carries no provenance of its own, so an argument without a trust requirement can come from hostile content while the authority-bearing ones stay trusted (LIM-048);
- without an `ApprovalStore` or a `SessionLedger`, a contract-held approval is reusable for the life of the contract; VERIFY reports the reuse and ENFORCE does not prevent it (LIM-044);
- without a `SessionLedger`, a bound over several actions is checked in VERIFY and not enforced in flight (LIM-035). With one, `max_calls` is enforced in flight, but the ledger lives in one process and a restart starts a fresh one (LIM-055).

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

These boundaries must remain explicit so successful demos are not mistaken for stronger guarantees than the code actually provides.
