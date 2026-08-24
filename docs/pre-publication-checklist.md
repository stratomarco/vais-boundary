# Pre-publication checklist

Do not treat “tests pass” as the entire release decision. Before the first public GitHub push, resolve the following items deliberately.

## Required blockers

- [x] Choose the software/content licensing model and replace the current license-decision placeholder.
- [x] Put the real author/maintainer attribution in `CITATION.md` and package metadata.
- [x] Provide a private security contact; also enable GitHub Private Vulnerability Reporting when the repository becomes public.
- [x] Adopt **VAIS Boundary / Verifiable Authority & Invariant Security** as the public-facing name and document its bounded meaning.
- [x] Treat the name as an unregistered project identifier; do not claim trademark clearance or registration without a separate formal search.
- [x] Review the README security claim and keep it narrower than the evidence: this is not a formal noninterference proof.

## Security review

- [x] Confirm every protected consequential demo path goes through `ProtectedExecutor`, `MCPProtectedClient` or an explicit `ReferenceMonitor` decision; direct execution exists only in clearly named unprotected assessment baselines.
- [x] Confirm all untrusted demo inputs are labelled in application code, never by model output.
- [x] Review `policy.py` and `invariants.py` for fail-open parsing paths; RC9 closes the discovered v4 opt-out, version-type, empty-invariant and non-finite-threshold paths.
- [x] Run tests under Python 3.11, 3.12, 3.13 and 3.14 where available.
- [x] Run at least one clean-wheel install test, not only editable install tests.
- [x] Confirm packaged default YAML resources are present inside the wheel.
- [x] Review all example secrets/canaries and ensure none are real credentials.
- [x] Confirm target failures are excluded from security denominators and visible in published summaries.
- [x] Confirm reasoning text is not persisted in benchmark outputs.

## Research hygiene

- [x] Clearly label the project as a research/engineering prototype.
- [x] Separate capstone empirical results from new VAIS claims in citation, project-history and evidence documentation.
- [x] Keep related-work attribution to CaMeL, FIDES, OWASP and benchmark dependencies.
- [x] Avoid claiming novelty for capabilities, information-flow labels, control/data separation or reference-monitor concepts themselves.
- [x] Preserve the v0.5.1 metric correction and frozen v0.6 125-case control corpus as historical predecessors to v0.10 adaptive verification.

## Repository hygiene

- [x] Remove build artifacts, caches and local virtual environments from the source archive.
- [x] Confirm `.gitignore` excludes `.venv`, build, caches and local result artifacts as intended; explicitly frozen release artifacts are the documented exception.
- [x] Add repository URL/project links to `pyproject.toml` after establishing the private canonical GitHub path.
- [x] Require CI to pass on the exact RC9 release commit before creating its tag; the tag and release steps remain blocked until that external gate is green.

## MCP integration review

- [x] Keep the core MCP wrapper independent of server-provided trust claims; profiles cannot configure remote results as trusted authority.
- [x] Confirm every protected live MCP side-effecting tool is called only after a VAIS `ALLOW` decision; the unprotected client is assessment-only and explicitly named unsafe.
- [x] Treat task-specific tool catalog filtering as attack-surface reduction, not authorization.
- [x] Review all configured MCP tool aliases because integration profiles are trusted configuration; canonical names and endpoint pairs remain unique and are Unicode-normalized in RC9.
- [x] Review the optional `mcp>=2,<3` dependency bound against the official stable v2 SDK line on 2026-08-24.
