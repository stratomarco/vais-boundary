# Security policy

VAIS is security research software and is **not production hardened**.

## Private reporting

Use [GitHub Private Vulnerability Reporting](https://github.com/stratomarco/vais-boundary/security/advisories/new), or email `stratomarco@proton.me` with `VAIS SECURITY` in the subject. Include the affected version, a minimal reproduction, the expected security invariant and the observed externally visible effect when safe to do so. Do not include real credentials, personal data or third-party confidential material.

GitHub Private Vulnerability Reporting is enabled for the public repository. Do not open a public issue before using one of these private channels for a suspected vulnerability.

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

VAIS is research software and does not currently promise a fixed response or remediation service level.
