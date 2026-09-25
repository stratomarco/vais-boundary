# What changed between v0.12.0rc12 and v0.12.0rc13

Base: tag `v0.12.0rc12` (2026-09-22). Before this document and the release review were added:
21 commits (20 plus one merge), 88 files, **+8,795 / -137** lines.

Every figure below is reproducible from the tags:

```
git diff --stat v0.12.0rc12..v0.12.0rc13
git rev-list --count v0.12.0rc12..v0.12.0rc13
```

## The headline

RC12 published what the monitor could not do. **RC13 builds most of it, opt-in, and measures
two things it could not have claimed before.** A session ledger makes limits and single-use
approvals hold in flight; authority can expire, be revoked and be delegated only downward; a
gateway takes the tools' credentials away from the agent; effects say whether they were only
requested, acknowledged or confirmed. A pre-registered study found zero protected violations
with a language model attacking reasoning targets, and a pre-registered replay found that a
proposed origin rule gates a tool without detecting an attack.

**With nothing configured, nothing changes.** Both benchmark snapshots regenerate with only the
version moved, and the adaptive configuration hash, recomputed with the version set back to
rc12, reproduces rc12's value.

If you are reviewing for regression risk, the behavioural surface is 20 library files,
**+1,777 / -70**, and about half of it is new code in four new modules:

| File | Lines | Why |
|---|---|---|
| `src/vais/gateway.py`, `gateway_server.py` | +834 / -0 | The gateway (new) |
| `src/vais/mcp.py` | +200 / -11 | Acknowledgement, read-back, confidence on the MCP path |
| `src/vais/approvals.py` | +121 / -10 | Grant TTL, a file-locked store across processes |
| `src/vais/monitor.py` | +115 / -38 | Ledger, validity, revocation and origin checks; one approval decision (FIND-056) |
| `src/vais/invariants.py` | +103 / -4 | `monitor_mediated`, `trusted_origin`, `effect_confidence`, `verdict_basis` |
| `src/vais/ledger.py`, `revocation.py` | +117 / -0 | Session ledger and revocation list (new) |
| `src/vais/models.py`, `sandbox.py`, `taint.py`, `policy.py` | +187 / -2 | Validity window, delegation, origin, confidence, policy v5 and v6 |
| everything else in `src/vais` | +100 / -5 | CLI commands, adapters, exports, version |

Everything else is tests (+1,730, nine new modules), two regenerated benchmark snapshots, the
research ledger, two experiments with their results, the gateway example, and documentation.

## Phase 1b, item by item

| Item | Result | Evidence |
|---|---|---|
| P1b-3, stateful monitor | Done | FIND-056, DEC-044 to DEC-046, LIM-055 |
| P1b-4, reasoning and an LLM attacker | Done; Q1 held | FIND-058, FIND-059, DEC-059, LIM-067, `experiments/p1b4/RESULTS.md` |
| P1b-5, gateway | Done | DEC-051 to DEC-054, LIM-060 to LIM-063, `docs/gateway.md` |
| P1b-6, action provenance | Done; not a default | FIND-057, DEC-055, DEC-056, LIM-064, `experiments/p1b6/RESULTS.md` |
| P1b-7, receipts and effect confidence | Done | DEC-057, DEC-058, LIM-065, LIM-066 |
| P1b-8, freshness, revocation, delegation | Done | DEC-047 to DEC-050, LIM-056 to LIM-059 |
| P1b-2, API target adapter | Deferred until a result needs frontier models | — |

## Found while releasing

The release campaign reported a `real` fault on the policy loader. The loader was right and the
campaign's declared rule was stale: it did not know policy v6 (FIND-060). The rule is current and
a test now keeps it so.

## Still shipping unmitigated

S13 on the library path, limits for stateless callers (LIM-035, LIM-044), model text (LIM-051),
and arguments without a trust requirement (LIM-048). See the release review.

## Gate status

See `docs/v0.12.0rc13-release-review.md` and `benchmarks/rc/v0.12.0rc13-release-review.json`.
