# Security philosophy: AI security is not security AI

VAIS is deliberately **not AI-powered**.

The framework does not ask one model to decide whether another model is safe. It applies ordinary security-engineering controls around probabilistic, opaque and potentially compromised AI components.

The model is therefore **not part of the trusted computing base for authorization**.

## The core assumption

```text
Assume model compromise.
Constrain consequence.
Verify effects.
```

Model hardening remains useful defense in depth. A robust model reduces how often a dangerous plan is proposed. But model refusal, alignment, prompt filtering and model-based judging are not treated as the final authorization decision.

## Classic security principles applied to agents

VAIS intentionally reuses old ideas rather than inventing AI-specific substitutes for solved security problems:

- **complete mediation**: every consequential tool call crosses the reference monitor;
- **least privilege**: task contracts grant only the tools and scopes required for the current task;
- **fail-safe defaults**: missing bindings, unknown tools and ambiguous policy fail closed;
- **separation of privilege**: model intent is not authorization;
- **information-flow control**: provenance and confidentiality survive ordinary transformation;
- **exact authorization**: human approval binds to the concrete action, not merely a tool name;
- **independent verification**: post-effect invariants do not ask the enforcement component to grade itself;
- **defense in depth**: model robustness, detection and human review can reduce risk without becoming the root of trust.

## Why this matters for ML

ML systems make traditional trust assumptions harder: model behavior is opaque, data can modify behavior, deployment is highly connected and extensible, and behavior can change between versions or contexts.

VAIS responds by moving the security decision to a simpler boundary that can be inspected, tested and made deterministic.

## What VAIS does not claim

VAIS does not prove that a model cannot be manipulated. It does not prove universal noninterference. It does not make a compromised agent harmless by magic.

Its narrower goal is to let applications state concrete security invariants and enforce them outside the model, then actively test whether those invariants survive adversarial model behavior.
