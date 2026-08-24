# Why the project is called VAIS Boundary

The public-facing name is **VAIS Boundary — Verifiable Authority & Invariant Security**.

The name is an architectural description, not a declaration that an AI model, application or deployment has been proven secure. Each term corresponds to a specific responsibility implemented or evaluated by the project.

## Verifiable

VAIS produces inspectable policy decisions, traces, benchmark records and independently observed effect evidence. Given the same frozen inputs and deterministic components, those records can be checked again.

“Verifiable” is deliberately bounded. It does not mean formal verification of the entire application, universal noninterference, complete attack coverage or proof that no future attack will succeed. A benchmark with zero observed protected violations establishes only the recorded result for its declared models, scenarios, runtime, hardware and episode budget.

## Authority

Authority comes from trusted task contracts, capability scopes, policy and explicitly bound approvals—not from model output. The model may interpret, plan and propose, but it cannot enlarge its own permissions or redefine the user's task.

The boundary binds security-relevant decisions to canonical action details and, where applicable, principal, session and tenant identity. Approval is exact-action, consume-once authority rather than a reusable expression of general trust.

## Invariant

An invariant states a protected condition that should remain true despite adversarial influence over the model. Examples include preventing a changed payment destination, an unauthorized recipient, a forbidden tool call or secret-derived data reaching a public sink.

VAIS distinguishes model behavior from security outcome. A refusal is not automatically a secure result, and a model failure is not counted as successful defense. The verifier examines observable effects against declared invariants independently of the target model and, where possible, independently of the enforcement decision.

## Security

The project addresses a narrow security property: adversarial influence over an AI component must not produce an unauthorized externally observable effect protected by a declared invariant.

It does not claim to solve model safety, factual correctness, alignment, sandboxing, identity management, endpoint security or operational monitoring. Those remain separate controls in a complete system.

## Boundary

“Boundary” identifies where the trusted mechanism belongs. It mediates the transition from an untrusted or fallible model proposal to a consequential tool or external system. Before execution it can allow, deny or require approval. After execution an independent verifier checks the resulting effect, including explicit indeterminate outcomes when the effect cannot be established safely.

The boundary is therefore both:

1. an **authority boundary**, because the model cannot create permission; and
2. an **effect boundary**, because externally visible consequences—not persuasive text—determine the security result.

## Why the original expansion changed

The original name, *Verifiable AI Security*, was useful during research development but was too broad for a public release. It could be read as a claim that the project verifies AI security generally, while the implementation makes a more specific contribution: deterministic authority enforcement and invariant verification at the point where model proposals can become external effects.

The revised expansion keeps the established `VAIS` identity while making the roots of trust explicit. Adding “Boundary” communicates the deployment position and the core thesis in ordinary language: **the model may propose; authority outside the model decides; observable effects are independently checked**.

## Compatibility and historical record

The command remains `vais`, the Python import remains `vais`, and the current distribution name remains `verifiable-ai-security`. Renaming those identifiers would add migration cost without improving the security model.

Published releases, benchmark reports and frozen evidence retain the names recorded when they were produced. They should not be rewritten because their exact provenance is part of the evidence base.

The project name does not alter the bounded-claims policy, Apache-2.0 terms or third-party model and runtime licenses. Formal trademark clearance remains separate from this technical naming decision.
