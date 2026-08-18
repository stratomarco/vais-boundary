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
- the real tool cannot be reached through an alternate path that bypasses `ProtectedExecutor`;
- adapters correctly label external sources and preserve labels across transformations;
- trusted upstream components are not already compromised;
- an effect adapter accurately represents whether a consequential action occurred.

## Current non-goals

- proving arbitrary generated text harmless;
- classifying all prompt-injection strings;
- formal noninterference proofs;
- side-channel resistance;
- cryptographically tamper-evident audit storage;
- automatic safe declassification/endorsement of untrusted information;
- protecting applications that deliberately give the model unrestricted credentials outside VAIS.

These boundaries must remain explicit so successful demos are not mistaken for stronger guarantees than the code actually provides.
