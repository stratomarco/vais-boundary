# VAIS Research Evidence Base

This directory is the project research record for future technical reports, articles and papers.

The canonical knowledge is deliberately plain text (`knowledge/*.yaml` (including source registry) and `narrative/*.md`). The SQLite database and JSONL indexes under `db/` and `evidence/` are generated query artifacts. They can always be rebuilt from the canonical knowledge plus immutable experiment/release artifacts.

## Principles

1. **Evidence before narrative.** Empirical claims should point to raw or audited artifacts.
2. **Preserve corrections.** Measurement changes are research results, not history to erase.
3. **Negative results are first-class.** Failed attacks, target failures and inconclusive runs remain visible.
4. **Do not promote diagnostics into security outcomes.** Plan change, escalation, objective success, DENY and NOT_CALLED remain distinct from observable protected invariant violation.
5. **Bound every claim.** Zero observed violations means zero in the stated system, model, stories and budget; it is not universal proof.
6. **Database is derived.** SQLite helps query evidence but does not replace Git-reviewable source records.

## Build from a historical SSD

From a VAIS source checkout:

```powershell
vais research-build --history-root F:\ --research-dir .\research
vais research-summary --db .\research\db\vais-research.sqlite
vais research-doctor --db .\research\db\vais-research.sqlite
```

With `--history-root`, the scanner inspects only immediate sibling directories whose names look like VAIS version checkouts (for example `vais-v03`, `vais-v09`, `vais-v0.10`) and then indexes relevant artifacts inside those version roots. It does not crawl unrelated top-level directories on the drive. Common virtual-environment/cache directories and generated research indexes/databases are excluded. Use repeated `--root` only for explicit extra VAIS directories or source artifacts such as the capstone manuscript.

## Query

```powershell
vais research-query "attack objective" --db .\research\db\vais-research.sqlite
vais research-query "Gemma" --db .\research\db\vais-research.sqlite
```

The generated evidence indexes are:

- `evidence/artifact-index.jsonl`
- `evidence/experiment-index.jsonl`
- `evidence/observation-index.jsonl`
- `evidence/claim-evidence-links.jsonl`
- `evidence/build-manifest.json`

Do not commit private/sensitive raw experiment data merely because the scanner can index it. The index stores file paths and hashes; publication copies should be curated separately.

## Archive integrity

Historical VAIS folders intentionally contain repeated source, summary and result artifacts. These copies remain indexed for provenance, but they are not additional scientific repetitions. `research-summary` reports both raw archive records and content-addressed counts, while `research-doctor` audits duplicates and evidence-link integrity.

```powershell
vais research-doctor --db .\research\db\vais-research.sqlite
vais research-doctor --db .\research\db\vais-research.sqlite --strict
```

Sources marked `artifact_expected_external` (for example the capstone manuscript and author essays) may remain outside the public repository. Their expected SHA-256 values are retained in `knowledge/sources.yaml`; add local copies with `research-build --root <path>` when you want those source links resolved. Unexpected missing project evidence and hash mismatches are integrity failures.

Do not equate content-addressed experiment groups with statistically independent trials. Content addressing removes exact historical copies; independence must still be justified by the experimental design.
