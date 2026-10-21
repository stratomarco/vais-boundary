# File formats, frozen for 1.0

VAIS reads files an operator writes, and writes files of its own state. From 1.0, each of these
formats is frozen: every 1.x release loads the samples in
[`tests/data/formats-1.0/`](../tests/data/formats-1.0/) and decides the sample actions exactly as
[`expected-decisions.json`](../tests/data/formats-1.0/expected-decisions.json) records.
`tests/test_formats_frozen.py` checks both.

Benchmark and research outputs (results JSONL, campaign summaries, reports) are not boundary
formats and are not covered.

## What is frozen

**Written by an operator.** Loading is strict at every version: an unknown key is an error, never
ignored.

| Format | Versions | Loader | Sample |
|---|---|---|---|
| Policy | 1 to 6 | `vais.load_policy` | `policy-v1.yaml` to `policy-v6.yaml` |
| Invariants | 1 | `vais.load_invariants` | `invariants-v1.yaml` |
| MCP integration profile | 1, 2 | `vais.load_mcp_profile` | `mcp-profile-v1.yaml`, `mcp-profile-v1-full.yaml`; 1.1: `mcp-profile-v2.yaml` |
| Gateway configuration | 1, 2 | `vais.gateway_server.load_gateway_config` | `gateway/gateway.yaml`, `gateway/gateway-v2.yaml` |
| Gateway contract | 1 | `vais.load_gateway_contract` | `contract-v1.yaml` |

What each policy version added:

| Version | Adds |
|---|---|
| 1 | tools, `allow`, `trust_required` arguments, approval thresholds |
| 2 | `required_scope`, `max_confidentiality` |
| 3 | `exact_approval_required` |
| 4 | fail-closed: `default_action` must be `deny`, undeclared arguments are rejected |
| 5 | `max_calls` |
| 6 | `untrusted_origin` |

Gateway configuration version 2 adds one key, `observe_until`, for observe-only mode ([`gateway.md`](gateway.md)); version 1 files keep their meaning and reject it.

MCP profile version 2 (1.1, DEC-074) adds three keys per tool: `consequential`,
`idempotency_argument` and `receipt` ([`gateway.md`](gateway.md)). Version 1 files keep their
meaning and reject them.

`mcp-profile-v1-full.yaml` uses every binding feature: effect mapping, `acknowledge`, a read-back
`confirm`, `mints`, and declared stores (`writes`, `reads`; DEC-070). `contract-v1.yaml` uses every
contract field, including `allowed_values`, `budgets`, `value_budgets` (DEC-067, DEC-069) and a
validity window.

**Written by VAIS.**

| Format | Version | Written by | Sample |
|---|---|---|---|
| Approval store | format 1, unversioned: a JSON list of grants | `ApprovalStore` with a path | `state/approvals.json` |
| Revocation list | 1 | `RevocationList` with a path | `state/revocations.json` |
| Session ledger | 1 | `SessionLedger` with a path | `state/ledger.json` |
| Gateway session context | 1 | the gateway, per session | `state/session-context.json` |
| Pending approval request | 1 | the gateway, one file per request | `state/pending-request.json` |
| Audit log | format 1, unversioned: hash-chained JSONL | `AuditTrail.write_jsonl`, the gateway | `state/audit.jsonl` |
| Indeterminate call record (1.1) | 1 | the gateway, one file per call in `pending/indeterminate/` | 1.1: `state/indeterminate-call.json` |
| Indeterminate call resolution (1.1) | 1 | `vais gateway-resolve` | 1.1: `state/indeterminate-resolution.json` |

Samples marked 1.1 are in [`tests/data/formats-1.1/`](../tests/data/formats-1.1/), frozen the same
way and checked by `tests/test_formats_frozen_1_1.py`, which also pins the idempotency key a
recorded call is retried with.

The audit log's format is its envelope: one hash-chained event per line with its type, tool,
decision, reasons and details. New event types and new detail keys are additions within format 1,
as observe-only mode's were in 1.0; a reader must ignore event types and keys it does not know.

## The rules for 1.x

1. **The samples load and decide as recorded.** A change that makes a sample fail to load, or
   changes a recorded decision, is incompatible with 1.0.
2. **Operator files change only through a new version.** A new key, or a new meaning for an
   existing one, needs a new version number, and every older version keeps its meaning, as
   policy versions 1 to 6 already do. The MCP profile gained `writes` and `reads` within version 1
   before 1.0; from 1.0 that is no longer done.
3. **State files change only by adding or raising a version.** A file in a frozen format still
   loads. The two unversioned formats, the approval store and the audit log, are format 1 as they
   stand; a change to either adds a version field and keeps reading the old shape.
4. **A security fix is the one exception.** If a recorded decision turns out to be unsafe, the
   fix changes it in a dated commit that says so, with a research ledger entry. It is never
   changed silently.
5. **The samples are never regenerated.** `tests/data/formats-1.0/generate.py` wrote them once,
   on 2026-10-20, and refuses to overwrite them.
