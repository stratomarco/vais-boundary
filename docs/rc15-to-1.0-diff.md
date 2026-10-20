# What changed between v0.12.0rc15 and v1.0.0

Base: tag `v0.12.0rc15` (2026-10-02). Before this document and the release review were added:
23 commits, 197 files, **+25,255 / -429** lines, most of them recorded experiment summaries and
evidence (Tier-A v3 alone is 70 files).

Every figure below is reproducible from the tags:

```
git diff --stat v0.12.0rc15..v1.0.0
git rev-list --count v0.12.0rc15..v1.0.0
```

## The headline

RC15 broadened the evidence; **1.0 fixes the boundary.**
- `vais` exports the boundary's 61 names and nothing else; the benchmark and research tooling is
  imported from its own modules.
- The command line keeps the boundary's ten commands at the top level and moves the tooling under
  `vais lab`.
- The distribution is `vais-boundary`.
- Every file format the boundary reads or writes is frozen, with samples and a decisions snapshot
  each 1.x release must reproduce.
- The gateway gains an observe-only mode that expires by itself within 14 days.

1.0 also ships the work since rc15: caps per allowed value (DEC-069), declared stores (DEC-070),
and FIND-072 to FIND-076.

**Recorded decisions did not move.** Both benchmark snapshots regenerated identical except for
`framework_version` and the configuration hash that covers it.

## If you are reviewing for regression risk

The behavioural surface is these library files:

| File | What changed |
|---|---|
| `monitor.py`, `models.py`, `ledger.py` | caps per allowed value (DEC-069) |
| `stores.py` (new), `mcp.py` | declared stores and the startup check (DEC-070) |
| `gateway.py`, `gateway_server.py` | the store check at gateway start; observe-only mode and configuration version 2 (DEC-072) |
| `__init__.py`, `cli.py` | the public interface and the command-line split (DEC-071) |
| `gateway_replay.py`, `reference_finance.py` | replaying the accounts-payable traces through the gateway (FIND-073) |

The rest of `src/vais/` changed in versions, the packaged ledger, one help message and the command
spelling in the campaign automation.

## What breaks for a 0.12 user

| If you did | Do instead |
|---|---|
| `pip install verifiable-ai-security` | `pip install vais-boundary` |
| `from vais import BenchmarkRunner` (or any of 76 tooling names) | `from vais.benchmark import BenchmarkRunner`; the module is named in `tests/test_core_boundary.py` |
| `vais benchmark-default` (or any of 20 tooling commands) | `vais lab benchmark-default`; the old form exits with code 2 and names the new one |

Policies, invariants, MCP profiles, gateway configurations and contracts written for 0.12.0rc15
load unchanged.

## Where to read more

- [`v1.0.0-release-review.md`](v1.0.0-release-review.md): the release review and its gate.
- [`formats.md`](formats.md): the frozen formats and the 1.x rules.
- [`threat-model.md`](threat-model.md): what 1.0 covers, leaves to other layers and ships without.
- [`guardrail-frameworks.md`](guardrail-frameworks.md): how VAIS compares with fourteen guardrail
  frameworks.
