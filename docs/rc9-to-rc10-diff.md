# What changed between v0.12.0rc9 and v0.12.0rc10

Base: tag `v0.12.0rc9` (2026-08-24). 23 commits, 144 files, **+15,121 / -31** lines.

Regenerate any figure below with:

```
git diff --stat v0.12.0rc9..v0.12.0rc10
```

## The headline

RC10 changes **one function** in the library. Everything else is tests, documentation,
research-ledger entries, the version bump, an unpackaged evidence tree and a website.

The 31 deletions are the whole story: nothing was removed, rewritten or re-tuned. If you are
reviewing this release for regression risk, the entire behavioural surface is
`src/vais/models.py`, +21 / -4. No other `.py` file under `src/` changed except the version
constant.

## Where the lines went

| Area | Files | Lines | What it is |
|---|---|---|---|
| `src/vais/models.py` | 1 | +21 / -4 | **The only change to library behaviour.** |
| `src/vais/_version.py` + 16 others | 17 | small | Version bump, rc9 convention (see below). |
| `tests/` | 8 (2 new) | +219 / -8 | Recursion and collision regression locks. |
| `docs/` | 7 (6 new) | +992 | Attack surface, incident mapping, related architectures, this file. |
| `research/knowledge/` + packaged copy | 6 | small | FIND-041/042, LIM-033/034, DEC-033/034. |
| `.github/ISSUE_TEMPLATE/`, `outreach/` | 6 | new | Reviewer intake forms and invitation. |
| `experiments/tier_a/` | 77 | +8,705 | Evidence tree. **Excluded from wheel and sdist.** |
| `website/` | 19 | +4,592 | Static site and Pages workflow. **Excluded from both, and from the gate.** |

## The one behavioural change

`deep_freeze` recursed without a depth bound.

```python
+MAX_SECURITY_DEPTH = 256
+
+def deep_freeze(value: Any, _depth: int = 0) -> Any:
+    if _depth > MAX_SECURITY_DEPTH:
+        raise ValueError(f"security value nesting exceeds maximum depth {MAX_SECURITY_DEPTH}")
```

Argument nesting past the interpreter's ~1000-frame limit raised `RecursionError` inside
`action_fingerprint`. `RecursionError` is not a `ValueError`, so it walked straight past the
`except ValueError` guards in `ReferenceMonitor.evaluate` that exist to return
`DENY action_not_fingerprintable`. **The monitor produced no decision and no audit record.** The
action failed closed only in the sense that it crashed the caller.

The bound is 256, well below the frame limit, and raises `ValueError` so the failure routes into
the path that was always meant to catch it. No broad `except` was added: converting unknown faults
into silent denials would erode the same property this fix restores (DEC-033).

`tests/test_fingerprint_recursion.py` fails with `RecursionError` on the rc9 tree and passes here.

**The residual is real and is shipping (LIM-033).** The DENY-plus-audit outcome holds only when
the nesting trips inside `action_fingerprint`. Nest deeper and the failure happens while the
*adapter* constructs the `Value` — before any `PlannedAction` or monitor decision exists. That is
fail-closed by exception, with no VAIS decision and no audit entry. Adapters building `Value`s
from model-controlled data must catch `ValueError` and record the denial themselves.

## What did not change

Stated explicitly, because a security release invites the opposite assumption:

- Canonicalization otherwise — NFC normalization, non-finite rejection, duplicate-key rejection.
- Fingerprint identity. `plain_arguments()` still excludes nothing; the fingerprint still binds
  the reference value, never the referent's contents.
- Every other fail-closed path, re-reviewed and unmodified.
- The audit trail: hash-chained, still not externally anchored.
- Approvals, policy, invariants, MCP.
- The frozen RC7 benchmark evidence, and every number derived from it. The README's 65.7% utility
  figure keeps its value and gains the paired-control argument beside it — **it is not an
  enforcement-cost figure**, and rc10 does not extend any benchmark claim.

## New in the docs

- `docs/ATTACK-SURFACE.md` — twelve input surfaces crossing a trust boundary into the monitor,
  each with entry point, intended property and existing coverage. Plus a thirteenth the input-side
  map did not cover: **the decision-reason output channel**. A reason like
  `bound_argument_changed:ticket_id` names the argument the contract binds. **No mitigation ships
  in rc10.** It is recorded as open, with a proposed direction.
- `docs/incident-mapping.md` — which disclosed 2026 incidents match an enforced mechanism and
  which conventional MCP flaws VAIS does not address. No incident is described as prevented.
- `docs/RELATED-ARCHITECTURES.md` — term-by-term mapping against Proof of Execution, and ARM,
  SPA, APPA, AgentProof added to related work. ARM already has proxy mediation, immutable
  capability tokens, a hash-chained audit log and integrity-lattice provenance, so rc10 **narrows**
  VAIS's claimed distinction against it to independent post-execution effect verification.

## New evidence: `experiments/tier_a`

Committed as reproducible evidence, excluded from both distributions (DEC-034): two
pre-registrations, frozen generated inputs with hashes verifiable from git, **6,351 raw episode
records** across seven runs, and an analyzer that regenerates every published table.

Read the results as bounded, because they are:

- **Both pre-registered primary outcomes failed to validate** — v1 family B produced 1 of the 40
  required 15; v2 family D produced 3–4 of 40. Reported as *not evaluable*, not as support.
- **A guardrail matched VAIS's catch rate.** The phi-4-mini judge caught 17/17 validated family-C
  attacks, equal to `VAIS_RESOLVE`. Had family C been the primary, H1 would have been **falsified
  on catch rate**. The separation is cost, not catch: the judge dropped 50% of legitimate
  retrieved documents; `VAIS_RESOLVE` dropped none.
- The most useful result is not an enforcement result at all: **adding one true in-tenant document
  cut attack success four- to eight-fold, and no payload ever succeeded with it present but failed
  without it.** Context integrity, not detection.
- LIM-034: one application, one tool, two agent models.

It is also the first release to ship attack text — **120 generated injection payloads**. Bounded
assessment: lab-scoped natural-language attempts to make a local training app close the wrong
support ticket, no exploit, no capability uplift, nothing absent from public literature, and the
results are not reproducible without them. Retained on that basis; the call is reversible.

## Version bump: 17 files, not 3

Verified against what rc9's own release commit touched, rather than assumed. Beyond
`pyproject.toml`, `_version.py` and `CITATION.cff`, the version is embedded in four benchmark
plans, two model panels, seven tests and two v0.10.2 snapshots. The adaptive snapshot also carries
a `configuration_hash` covering the version, which moves with it:

```
41305a365f6d2d9de297095828d27864218b7d4787f83e318496df44989c5b0c
```

## Gate status

| Step | Result |
|---|---|
| Full regression suite | **248 pass**, and 248 again from a fresh source-ZIP extraction |
| Policy + invariant validation | valid (schema 4, 4 tools; 6 invariants) |
| Deterministic protected benchmark smoke | attack success **0%**, default and MCP paths |
| Wheel + sdist build | built; `experiments` and `website` absent from both (0 entries each) |
| Isolated wheel install | version correct, `pip check` clean; deep nesting → `ValueError`, not `RecursionError` |
| Wheel reproducibility | byte-identical across two `SOURCE_DATE_EPOCH` builds |
| Source ZIP reproducibility | byte-identical across repeated builds |
| sdist reproducibility | **not** byte-reproducible; see below |
| Secret scan | clean in tracked content and in the archive |
| `research-doctor` | 32 issues, 0 hash mismatches — **same 23 unresolved refs as a clean rc9 tree** |

Two entries there deserve their full statement rather than a tick.

**The sdist is not byte-reproducible.** Two builds under an identical `SOURCE_DATE_EPOCH`
produce different SHA-256 values, because the gzip container records its own build time. The
archive members are identical. This has never been claimed for the sdist; the wheel and the
source ZIP are the artifacts to verify, and both are reproducible.

**`research-doctor` is not clean, and never was.** Its 32 are pre-existing on released rc9 too —
references to historical raw traces deliberately omitted from the portable tree. The claim
verified here is narrower and checkable: the *set* of unresolved references is identical to
rc9's, so RC10 adds none. Hash mismatches are 0 in both.
