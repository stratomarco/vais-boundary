# Security policy

VAIS is security research software and is **not production hardened**.

## Before public release

The repository owner should enable GitHub Private Vulnerability Reporting (or publish an equivalent private security contact) before accepting external users.

## What should be reported privately

Please avoid opening a public issue first when a report demonstrates or plausibly enables:

- bypass of the deterministic reference monitor;
- incorrect integrity/confidentiality propagation that weakens policy;
- an execution path that reaches a consequential tool after `DENY` or `REQUIRE_APPROVAL`;
- policy/invariant parser behavior that fails open;
- a benchmark oracle flaw that reports a real invariant violation as secure;
- exposure of data labelled confidential/secret through an allowed sink contrary to policy.

## Current scope

The project does not claim protection when a real application exposes an alternate tool path around `ProtectedExecutor`, labels attacker-controlled input as trusted, or misrepresents real external effects in an adapter.
