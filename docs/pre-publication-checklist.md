# Pre-publication checklist

Do not treat “tests pass” as the entire release decision. Before the first public GitHub push, resolve the following items deliberately.

## Required blockers

- [ ] Choose the software/content licensing model and replace the current license-decision placeholder.
- [ ] Put the real author/maintainer attribution in `CITATION.md` and package metadata if desired.
- [ ] Enable GitHub Private Vulnerability Reporting or provide a private security contact.
- [ ] Decide whether **VAIS / Verifiable AI Security** remains the public name after a final GitHub/PyPI/trademark search.
- [ ] Review the README security claim and keep it narrower than the evidence: this is not a formal noninterference proof.

## Security review

- [ ] Confirm every consequential demo path goes through `ProtectedExecutor`.
- [ ] Confirm all untrusted demo inputs are labelled in application code, never by model output.
- [ ] Review `policy.py` and `invariants.py` for fail-open parsing paths.
- [ ] Run tests under Python 3.11, 3.12, 3.13 and 3.14 where available.
- [ ] Run at least one clean-wheel install test, not only editable install tests.
- [ ] Confirm packaged default YAML resources are present inside the wheel.
- [ ] Review all example secrets/canaries and ensure none are real credentials.
- [ ] Confirm target failures are excluded from security denominators and visible in published summaries.
- [ ] Confirm reasoning text is not persisted in benchmark outputs.

## Research hygiene

- [ ] Clearly label the project as a research/engineering prototype.
- [ ] Separate capstone empirical results from new VAIS claims.
- [ ] Keep related-work attribution to CaMeL, FIDES, OWASP and future benchmark dependencies.
- [ ] Avoid claiming novelty for information-flow labels or reference-monitor concepts themselves.
- [ ] Freeze the expanded static control corpus and v0.5 metric definitions before running adaptive RLVR attacks.

## Repository hygiene

- [ ] Remove build artifacts, caches and local virtual environments from the source archive/repository.
- [ ] Confirm `.gitignore` excludes `.venv`, build, dist, caches and local result artifacts as intended.
- [ ] Add repository URL/project links to `pyproject.toml` only after the final GitHub path exists.
- [ ] Tag the first public release only after CI passes from a clean checkout.

## MCP integration review

- [ ] Keep the core MCP wrapper independent of server-provided trust claims.
- [ ] Confirm every live MCP side-effecting tool is called only after a VAIS `ALLOW` decision.
- [ ] Treat task-specific tool catalog filtering as attack-surface reduction, not authorization.
- [ ] Review all configured MCP tool aliases because integration profiles are trusted configuration.
- [ ] Pin and periodically review the optional stable MCP SDK dependency line before each release.
