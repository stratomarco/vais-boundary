# Attack surface of the VAIS enforcement layer

**Status:** v2, current as of 0.12.0rc12.
**Source base:** written against `6e0aad0` (rc7), re-verified against `bf38ab0` (the rc9
TCB-hardening base) on 2026-09-09, and updated for the rc10 recursion bound in S3.

This document enumerates every input that crosses a trust boundary into the VAIS reference
monitor / invariant engine, names its entry function as `module:function`, states the security
property it is supposed to uphold, and records **existing test coverage**. It is a map, not a
fuzzing campaign — no adversarial harness is written here.

**Method.** Every row was read in source. Where the expected-surface list written from the README
disagrees with the code, the code wins and the correction is called out. Claims about
*undemonstrated* weaknesses are labelled **[hypothesis]** and are not asserted as findings; a
finding requires a failing test. The one hypothesis that produced a failing test became FIND-041
and is fixed in rc10; the rest remain hypotheses.

**Base note (v2).** This document was first written against the RC7 tree (`6e0aad0`)
and has been re-verified against `bf38ab0`. Of the
enforcement-path modules, only **`models.py`, `invariants.py`, `policy.py`, `mcp.py`,
`sandbox.py`** changed under rc8/rc9; `monitor.py`, `audit.py`, `taint.py`, `approvals.py`,
`executor.py`, `behavioral_gate.py` are **byte-identical** to `77eb7e7`, so their line refs are
unchanged. rc8/rc9 is a **TCB-hardening pass** and its net effect on this map is: **it closes the
Unicode/name-collision families under S3 and adds type-sensitive comparison under S9** — the
"no coverage" optimism of v1 is corrected below, and the remaining S3 target is narrowed to
*structural* and *reference-vs-referent* collisions, which the NFC work does not touch.

**rc10 note.** The unbounded-recursion weakness recorded under S3 was reproduced with a failing
test and fixed: `deep_freeze` now bounds nesting at `MAX_SECURITY_DEPTH` and raises `ValueError`,
so the failure routes through the existing fail-closed path (FIND-041). The residual in §4 —
nesting that fails inside an adapter before any monitor decision exists, leaving no audit entry —
is recorded as LIM-033 and is **not** fixed. S13 also ships unmitigated.

**rc11 campaign note (P1-6).** The P1-2 to P1-5 work is now continuous: `campaigns/` runs
deterministic mutation campaigns against the policy loader, the invariant loader and security-value
canonicalization, short on every push and long nightly, gated on triage verdict rather than on
whether anything was raised. It found two loader faults in its first hour, both the same class of a
validator assuming YAML hands it a string, and both fixed (FIND-047, FIND-048). Faults that die
inside a dependency are reported and do not gate (LIM-043), and the campaign is not coverage-guided
(LIM-042). The gate is known to fire because reverting the FIND-047 fix makes it fire.

**rc11 fault-injection note (P1-5).** Config faults all fail closed: a missing file raises, a
corrupt or over-permissive one is rejected, and an **empty policy file loads as deny-all rather
than allow-all**, which is the cell that mattered most. Invariant faults fail closed too: an
absent effect field reports `missing_effect_provenance`, and an evaluator that raises propagates
rather than reading as "nothing was violated", because no broad handler exists anywhere in the
enforcement path. The approval store did **not** fail closed and is fixed (FIND-046). Three cells
have no mechanism to test and are recorded rather than quietly dropped: there is no clock in the
enforcement path so clock skew cannot move a decision, there is no timeout so a fault that never
returns hangs instead of denying (LIM-040), and OOM is not reproducible in a unit test.

**rc11 note.** S14 was added after an external reviewer found that the central property covers
only the flow half of composition and not the volume half; the VERIFY half is closed and the
ENFORCE half is LIM-035. S4 and S5 were then tested properly (FIND-044). The lattice holds through
derivation, with no laundering path found across seeded DAGs of depth ≥ 12 and five separate
mutations of the lattice rules each caught by the suite. What that work surfaced is not a bug but
an **asymmetry**: integrity defaults to the cautious end of the lattice and confidentiality
defaults to `public`, its bottom. The consequence is LIM-036, and it is the reason S5's guarantee
is weaker than S4's in practice.

**rc12 note (P1b-1).** A second external reviewer and a full re-read looked at the edges of the
monitor rather than its decision function: what is passed into it, what the verifier is told,
what persists and what is claimed. Nothing bypassed a DENY. Seven defects were found and fixed,
each with a test that fails on revert. Under S6, the MCP client could not take an approval store
so consume-once never held there (FIND-049), the verifier could not see store grants and flagged
correctly approved effects (FIND-050), and no invariant counted how often one approval was used
(FIND-051). Under S16, `FrozenDict` blocked `update` but not `|=` (FIND-052). Under S1, the
campaign found FIND-047 again one field over (FIND-053), and reading the MCP loader found a
`ValueError` escaping (FIND-054) and NFC-equal effect fields merged silently (FIND-055). The
review also published what it could not fix as LIM-044 to LIM-054, including every point the
reviewer raised. S15 was added: the agent's text and reasoning are not mediated at all.

**rc13 note (P1b-3).** The monitor can now be given a `SessionLedger`. With one, S14's ENFORCE half
closes: policy v5's `max_calls` is denied in flight, checked and recorded under one lock. A
contract-held approval becomes single-use, closing LIM-044 for callers that pass a ledger, and
the new `monitor_mediated` invariant reads the same ledger to report effects no recorded `ALLOW`
accounts for, the first after-the-fact check on the complete-mediation assumption (LIM-050).
Restructuring the approval path for this found FIND-056: a tool requiring both an exact and a
threshold approval consumed the store grant twice and could never be allowed.

**rc13 note (P1b-8).** Authority can now expire, be withdrawn, and be handed on only in part, which
answers LIM-047 for callers that use the new fields. A `TaskContract` can carry `not_before` and
`not_after`, an approval grant can carry a TTL, and a `RevocationList` given to the monitor
withdraws a session or one capability; all three are checked before anything else and read the
clock only when authority carries a time bound (DEC-047, DEC-048). Under S6, the store's file is
now the source of truth, locked and reloaded around every operation, so processes sharing it on
one machine consume a grant exactly once, closing LIM-045 on one machine (DEC-049, LIM-057).
`TaskContract.delegate` derives a sub-agent contract that can only narrow, and shares its
parent's session ledger (DEC-050). What this does not cover is published as LIM-056 to LIM-059:
revocations live in one process, the lock does not cross machines, time bounds are checked in
ENFORCE only, and the monitor does not verify a delegate's lineage.

**rc13 note (P1b-5).** The gateway (`docs/gateway.md`) runs the monitor in its own process as an
MCP server over streamable HTTP, and is the only holder of the upstream credentials. Under S8,
complete mediation becomes an architectural property for deployments that keep the agent away
from the gateway's credentials, the upstreams and the operator files (LIM-060), rather than an
assumption about the host (LIM-050). The gateway accepts nothing from the agent but a bearer
token and plain arguments: contracts come from operator files by token digest, labels are
assigned at the boundary (DEC-051), approvals are granted only by an operator (DEC-052), and
reasons are withheld from the agent by default, IMP-003's proposal applied at the gateway only
(DEC-053). Its own surface is S17.

**rc13 note (P1b-6).** An action can carry an origin, the join of the labels visible when it was
planned, and policy v6's `untrusted_origin` can escalate or deny a tool's actions whose origin is
not trusted; the `trusted_origin` invariant checks the same in VERIFY (DEC-055). It addresses
the control-flow half of provenance behind LIM-048 from labels alone, so the monitor still never
reads content. Measured by a pre-registered replay of RC7, the origin was untrusted for every
model action in clean and attacked runs alike, so the rule gates a tool behind a human and does
not detect an injection. It is not a default (FIND-057, LIM-064, DEC-056).

---

## 0. Two corrections to the planned surface list

1. **"Task contract parser (YAML)" does not exist as written.** The `TaskContract` (`models.py:198`)
   is constructed **programmatically** by trusted application code, not parsed from YAML. It
   validates its own fields in `__post_init__` (non-empty identity strings, `(tool, argument)`
   binding keys, trusted-only bound values). The YAML-parsing surfaces are three *other* files:
   `policy.py:load_policy`, `invariants.py:load_invariants`, `mcp.py:load_mcp_profile`. Surface
   S1 below is retargeted accordingly.
2. **"Wildcard semantics" in capability scope resolution does not exist.** Scope matching is
   exact string membership (`required_scope not in contract.granted_scopes`, `monitor.py:64`).
   There is no globbing, hierarchy, or prefix match to widen. That is conservative; S2 records
   it as such rather than as a hunting ground.

---

## 1. Surface summary

**Reading the Owner column.** The `P0-x` / `P1-x` / `IMP-xxx` labels are this project's internal
work-item identifiers, kept so each row says where its follow-up lives rather than leaving the
gaps unattributed. They group the remaining work as follows, and none of them is a claim that the
work is done:

| Label | Means |
|---|---|
| `P1-1` | Mapped in this document; no gap identified, nothing further planned. |
| `P1-2` | Fingerprint and approval identity. **Closed for recursion in rc10** (FIND-041); reference-vs-referent TOCTOU remains an accepted application-level risk. |
| `P1-3` | Provenance and confidentiality lattice under adversarial flows. **Done in rc11** (FIND-044): no laundering path found through derivation, and the defaults are recorded as asymmetric (LIM-036). |
| `P1-4` | Audit-chain adversarial testing beyond single-event tampering. **Done in rc11** (FIND-045): the boundary is whether the attacker rebuilds, not which manipulation is used (LIM-037, LIM-038). |
| `P1-5` | Fault injection against config parsing and invariant evaluation. **Done in rc11**; found and fixed a fail-open in the approval store (FIND-046) and recorded LIM-039 to LIM-041. |
| `P1-6` | Continuous campaigns in CI. **Done in rc11**; found FIND-047 and FIND-048 in the loaders (LIM-042, LIM-043). |
| `P1b-1` | The rc12 review of the monitor's edges. **Done in rc12**: FIND-049 to FIND-055 fixed, LIM-044 to LIM-054 published. |
| `P1b-3` | Stateful monitor with one ledger shared by ENFORCE and VERIFY. **Done in rc13**: `SessionLedger`, policy v5 `max_calls`, `monitor_mediated`; found and fixed FIND-056. |
| `P1b-8` | Freshness, revocation, multi-process approvals, delegation. **Done in rc13**: contract validity windows, grant TTL, `RevocationList`, a file-locked store, `TaskContract.delegate`; LIM-056 to LIM-059 published. |
| `P1b-5` | Gateway with credential exclusivity. **Done in rc13**: `vais gateway` (MCP over streamable HTTP), labels at the boundary, operator-file contracts and approvals; S17 added, LIM-060 to LIM-063 published. |
| `P1b-6` | Action provenance. **Done in rc13**: `PlannedAction.origin`, policy v6 `untrusted_origin`, `trusted_origin`; replayed on RC7 (FIND-057): a per-tool human gate, not a detector, so not a default (DEC-056). |
| `IMP-003` | Decision-reason disclosure (S13). Proposed, **unmitigated through rc12**. |

| ID | Surface | Entry point (`module:function`) | Trust boundary | Intended property | Existing coverage | Owner |
|---|---|---|---|---|---|---|
| S1 | Config file parsing (policy / invariants / MCP profile) | `policy.py:load_policy`, `invariants.py:load_invariants`, `mcp.py:load_mcp_profile` | integrity-protected config → in-memory policy | Strict schema; unknown field / wrong type / bad version rejected; default is `deny` | strong, plus `test_fault_injection` (missing, empty, truncated, malformed, wrong-typed and over-permissive files) | **P1-5 done**; an empty file is deny-all, not allow-all. YAML errors are not `PolicyValidationError` (LIM-039). rc12 fixed FIND-053 to FIND-055; the MCP loader is not campaigned (LIM-054) |
| S2 | Capability scope resolution | `monitor.py:ReferenceMonitor.evaluate` (scope block, l.64) | model-proposed action → contract scopes | Required scope must be present exactly; model cannot add scopes | `test_reference_monitor::test_denies_missing_capability_scope` | P1-1 (no gap; exact-match) |
| S3 | **Canonical action fingerprinting** | `models.py:action_fingerprint` → `plain_arguments`, `deep_freeze`, `canonical_json` | proposed action → approval identity | Two security-distinct actions must not share a fingerprint | rc9 closed Unicode/name classes; **P1-2 fixed unbounded-recursion** (`test_fingerprint_recursion`) + recorded reference-vs-referent risk and inverse-utility negative evidence (`test_fingerprint_collisions`) | **P1-2 (recursion done; TOCTOU→S6)** |
| S4 | Provenance lattice transitions | `taint.py:derive_value`, `taint.py:derive_model_output` | untrusted data → derived label | `derived_untrusted` never launders back to `trusted` without explicit declassification | `test_taint` plus `test_provenance_lattice` (seeded DAGs, depth >= 12, mutation-checked) | **P1-3 done; no laundering path through derivation** |
| S5 | Data-classification propagation | `taint.py:_max_confidentiality` (join in `derive_value`); enforced at `monitor.py` (l.77-86) and `invariants.py` `confidentiality_ceiling` | secret data → egress effect | Confidentiality is monotone (`join = max`); `secret` cannot silently drop to `public` | as S4, plus the ceiling tests | **P1-3 done; defaults are asymmetric, see LIM-036** |
| S6 | Approval binding & replay window | `approvals.py:ApprovalStore.grant/consume`; `monitor.py` approval blocks (l.91-127) | approval grant → later execution | Consume-once; identity-scoped `(fingerprint, principal, session, tenant, capability)`; approval for action A never authorizes action B | strong (`test_tcb_hardening`) plus `test_fault_injection` (durability under a failed write), `test_mcp_approval_store`, `test_approval_verify`, `test_authority_lifecycle` (expiry, revocation, processes racing on one file) | **P1-2** (reference-vs-referent TOCTOU); FIND-046 fixed in rc11; FIND-049 to 051 fixed in rc12; FIND-056 fixed in rc13. Consume-once needs a store or a ledger (LIM-044, LIM-055); a store file holds across processes on one machine from rc13 (LIM-057). Freshness is opt-in from rc13: contract windows, grant TTL, revocation (P1b-8; LIM-056, LIM-058) |
| S7 | Audit hash chain | `audit.py:AuditTrail.record/verify` | recorded history → verifier | Append-only; partial modification detected. Fork, tail truncation and any rebuilt chain are **not** detectable without a signed head (G-B1) | `test_audit_chain_integrity` (23 tests, mutation-checked) plus `test_tcb_hardening`, `test_audit_identity` | **P1-4 done; boundary demonstrated, LIM-037/038**. rc12: events carry the action fingerprint and contract identity (DEC-043) |
| S8 | MCP call mediation | `mcp.py:MCPProtectedClient.execute`, `label_mcp_input`, `extract_mcp_result_data`, `canonical_mcp_tool` | remote MCP server ↔ tool call | Only `ALLOW` reaches `session.call_tool`; remote data is `UNTRUSTED`, never authority | strong (`test_mcp`, 10 tests) plus `test_mcp_approval_store`, `test_audit_identity` | P1-1 (see S8 notes). The effect is the dispatched request (LIM-046); a malicious server is out of scope (LIM-049); complete mediation is assumed on the library path (LIM-050) and architectural behind the gateway under its deployment conditions (P1b-5, LIM-060) |
| S9 | Invariant evaluation | `invariants.py:DeclarativeInvariantEngine.evaluate`, `_violation_reason` | observed effects → violation verdict | A malformed / unknown invariant must fail **closed**, never silently pass | `test_invariants` (6) plus `test_fault_injection` | **P1-5 done**; an evaluator that raises propagates rather than reading as no-violations. An invariant on an effect kind never produced is inert (LIM-041). rc12: sees store grants (FIND-050), `approval_single_use` (FIND-051); an indeterminate call is not scored as defended (DEC-040) |
| S10 | Static-policy gap under `default_action: allow` | `monitor.py:ReferenceMonitor.evaluate` (l.48-54) | tool in contract but absent from static policy | Dynamic contract authorizes; bound-arg checks still apply | `test_reference_monitor::test_bound_argument_is_enforced_even_when_static_default_is_allow` | P1-1 (see S10 notes) |
| S11 | Executor fail-closed seam | `executor.py:ProtectedExecutor.run` (l.51) | authorized decision → real effect | Only `DecisionType.ALLOW` executes; DENY / REQUIRE_APPROVAL emit no effect | `test_protected_executor` (2) | P1-5 |
| S12 | Numeric threshold coercion | `monitor.py` (l.109-115), `invariants.py` (l.116-122) | model-supplied numeric field → threshold test | `bool` and non-finite rejected; non-numeric → DENY / `invalid_numeric_field` | `test_tcb_hardening::test_policy_threshold_rejects_nonfinite` | P1-1 (no gap) |
| S13 | Decision-reason disclosure (output channel) | `monitor.py:ReferenceMonitor.evaluate` return value; `mcp.py:MCPProtectedClient.execute` | reference monitor → caller / agent loop | Enforcement outcomes must not hand an adaptive attacker a probing oracle | none | IMP-003 |
| S14 | **Effect-set cardinality (volume composition)** | `monitor.py:ReferenceMonitor.evaluate` (one action); `executor.py:ProtectedExecutor.run` (loop, no accumulator); `invariants.py` aggregate path | many individually authorized actions → one unauthorized aggregate | A bound over a *set* of effects must be expressible and checkable | `test_invariant_cardinality` (13 tests, VERIFY side; the stateless limitation is asserted) plus `test_session_ledger` (ENFORCE with a ledger; ENFORCE and VERIFY agree over 200 seeded traces) | **VERIFY closed in rc11; ENFORCE closed in rc13 when a `SessionLedger` is supplied**; stateless callers keep LIM-035 |
| S15 | **Model text and reasoning output** | none; outside every enforcement path | model → user, logs, UI | Confidential context must not leave through a channel no decision covers | none | **Unmediated (LIM-051)**; a non-goal in the threat model |
| S16 | Security mapping immutability | `models.py:FrozenDict` (contract bindings, action arguments, policy tools, effect attributes) | integration code → security state after construction | Authority and fingerprinted state cannot be changed in place after construction | `test_frozen_mapping` (every mutator, including `\|=`) | **FIND-052 fixed in rc12**; deliberate unbound `dict` calls are not preventable in Python and are outside the threat model |
| S17 | **Gateway front door and operator files** | `gateway_server.py:build_app` (bearer check, `list_tools`, `call_tool`), `gateway.py:ContractRegistry.lookup`, `label_agent_action`, `grant_pending_request` | agent process ↔ gateway; operator files → gateway | Only a registered token reaches MCP; each call is authorized from its own request's token; nothing the agent sends is trusted except a value equal to its binding; only an operator grants | `test_gateway` (14 tests), `test_gateway_server` (real upstream over stdio, real HTTP), 8 mutants killed | **P1b-5, rc13.** Conditional on the deployment (LIM-060); coarse labels (LIM-061); tools only (LIM-062); in-memory state (LIM-063) |

---

## 2. Per-surface detail

### S1 — Config file parsing (policy / invariants / MCP profile)
- **Entry:** `policy.py:load_policy`, `invariants.py:load_invariants`, `mcp.py:load_mcp_profile`.
  All three use `yaml.safe_load` and then a hand-written strict validator (`_known_keys`,
  `_mapping`, `_strict_bool`, per-type coercers).
- **Property:** unknown fields rejected; `default_action` defaults to `deny`; versions are an
  explicit allow-list (policy `{1,2,3,4}`, invariants `{1}`, mcp `{1}`); quoted booleans rejected
  so a stringly-typed `allow: "false"` cannot silently weaken policy.
- **Verified good:** strict `_known_keys` on every mapping; `_strict_bool` (`policy.py:67`)
  blocks the classic YAML truthiness footgun; `test_policy_validation` covers 7 cases including
  quoted-boolean and misspelled trust requirement. **rc9 added `_non_empty_string` (`policy.py:73`,
  NFC-normalizing)** used for approval/scope field names, so a quoted empty or whitespace-only
  field name is now rejected at load and names are NFC-canonical.
- **[hypothesis – P1-5]** `yaml.safe_load` is safe against arbitrary object construction but is
  **not** immune to alias-expansion / "billion laughs" resource exhaustion. Config is
  integrity-protected per the threat model, so this is DoS-on-trusted-input, low priority — but
  P1-5's fault-injection matrix should include "policy file is a YAML bomb" and confirm it fails
  closed (raises, denies) rather than hanging the monitor.
- **[hypothesis – P1-5]** behavior when the config file is **missing** or **truncated mid-document**
  is untested. `load_policy` will raise (file open / parse error); confirm the caller treats a
  raised loader as fail-closed rather than falling back to a permissive default.

### S2 — Capability scope resolution
- **Entry:** `monitor.py:ReferenceMonitor.evaluate`, scope block `if tool_policy.required_scope
  and tool_policy.required_scope not in contract.granted_scopes` (l.64).
- **Property:** the model cannot introduce a scope; scopes come only from the trusted
  `TaskContract.granted_scopes`. Matching is exact-string membership — **no wildcards, no
  hierarchy** — so there is no widening primitive. Recorded as conservative, not a target.

### S3 — Canonical action fingerprinting  ·  **highest-value, P1-2**
- **Entry:** `models.py:action_fingerprint` (`:135`) = `sha256(canonical_json({"tool": …,
  "arguments": action.plain_arguments()}))`.
- **Verified facts (carry into P1-2):**
  - `plain_arguments()` (`models.py:131`) **excludes nothing** — it maps every argument key to
    its `Value.data`. The P1-2 brief said "audit `plain_arguments()` exclusions"; there
    are **no exclusions**, so that sub-task is answered: the fingerprint covers the full argument
    set. Residual risk is *canonicalization collisions*, not excluded fields.
  - `deep_freeze` (`models.py:148`) applies `unicodedata.normalize("NFC", …)` to every string and
    every mapping key, **rejects non-finite floats**, and **rejects a mapping whose keys collapse
    to a duplicate under NFC**. NFC (not NFKC) is deliberate — do not "fix" it.
  - **rc9 hardening (new since v1):** NFC normalization + NFC-duplicate rejection is now also
    applied *earlier and wider* — to **argument names** in `PlannedAction.__post_init__`
    (`models.py:122-124`), and to **tool names, scopes, approval fingerprints, contract identity,
    and binding keys** in `TaskContract.__post_init__` (`models.py:227-253`), plus provenance
    `source`/`detail`/`parents` in `Provenance.__post_init__` (`models.py:52-71`). So a
    canonicalization collision on a *name/key* is now rejected at object construction, before a
    fingerprint is ever computed.
  - `canonical_json` (`models.py:179`) sorts keys and uses type-sensitive encoding via
    `deep_freeze`. `security_equal` (`models.py:189`) is built on it.

- **S3 collision-class re-check (the rc9 question):**

  | Collision class | Status under `bf38ab0` | Why |
  |---|---|---|
  | Unicode NFC-equivalent **argument names** | **CLOSED** | rejected in `PlannedAction` (`:122-124`) and `deep_freeze` (`:161-163`) |
  | Unicode NFC-equivalent **tool names / scopes / approvals / identity / binding keys** | **CLOSED (new in rc9)** | rejected in `TaskContract.__post_init__` (`:227-253`) |
  | Homoglyph / zero-width in names (distinct codepoints, *not* NFC-equal) | **not a collision** | survive NFC as **distinct** strings → distinct fingerprints; by design, not a bypass |
  | `True` vs `1`, `1` vs `1.0` vs `"1"`, `null` vs absent key, `{}` vs `[]` | **CLOSED** | type-sensitive `canonical_json`: `json.dumps` emits `true`/`1`/`1.0`/`"1"`/`null` distinctly; absent key ≠ `null` key |
  | **Reference-vs-referent** (arg is a handle/path/id whose backing content changes between approval and execution) | **SURVIVES — accepted risk (documented)** | fingerprint binds the reference *value*, never the referent's contents; no argument hashing can see this. Demonstrated in `tests/test_fingerprint_collisions.py::test_fingerprint_is_blind_to_referent_contents`. **Mitigation is application-level:** bind a content hash into the arguments, or treat reference-typed arguments as non-approvable. Not fixable in the fingerprint. |
  | **Cross-field / structural smuggling** (same effective payload arranged into different argument structures) | **NOT EXPRESSIBLE here** | different structures yield *different* fingerprints (all keys covered). The only collapse vector — an MCP effect mapping folding two args into one field — is impossible: `MCPEffectMapping` is one-field-←-one-arg and rc9 rejects duplicate effect fields (see S8). Downgraded from v1. |
  | Deeply-nested mixed-type structures / recursion limits | **CONFIRMED (v1 hypothesis) → FIXED in `ace1012`** | see the confirmed-finding note below |

- **CONFIRMED FINDING — unbounded `deep_freeze` recursion (fixed in `ace1012`).**
  At the default recursion limit (`sys.getrecursionlimit() == 1000`, verified), an action whose
  arguments nest deeper than the remaining C-stack raised **`RecursionError`** inside
  `action_fingerprint → canonical_json → deep_freeze`. `RecursionError` is **not** a `ValueError`
  (verified: `issubclass(RecursionError, ValueError) is False`), so it **bypassed the
  `except ValueError` guards at `monitor.py:92` and `:117`** whose purpose is to return
  `Decision(DENY, "action_not_fingerprintable")`. The outcome was fail-closed *by crash*: the
  broad `except Exception` at `mcp.py:275` sits *after* the ALLOW decision, so the monitor
  produced **no DENY decision and no audit record**.
  - **Repro / regression:** `tests/test_fingerprint_recursion.py` — a 5000-deep structure raised
    `RecursionError` pre-fix (RED), and the monitor path yielded no `DENY`/audit.
  - **Fix:** `deep_freeze` now takes a bounded `_depth` and raises **`ValueError`** past
    `MAX_SECURITY_DEPTH = 256` (`models.py`), chosen well below the 1000 recursion limit so the
    `ValueError` always precedes any `RecursionError`. This routes into the existing
    `action_not_fingerprintable` DENY path, which the executor audits. **No broad `except` was
    added.** Full suite: 248 passed (235 pre-existing + 13 new).
  - **Depth numbers:** limit 1000; bound 256; a value at depth 256 constructs, but
    `action_fingerprint` wraps it two levels deeper (`{"tool":…, "arguments":{…}}`) → 258 > 256 →
    `ValueError` → `DENY(action_not_fingerprintable)` + audit event (asserted in
    `test_monitor_denies_unfingerprintable_deep_action_and_audits`).
  - **Two failure regimes (review finding, 2026-09-13).** The DENY-plus-audit path holds only in a
    two-level band. Measured with the fix applied:

    | Argument nesting depth | Where it fails | Outcome |
    |---|---|---|
    | ≤ 254 | nowhere | normal |
    | 255–256 | `action_fingerprint`'s two-level wrap, inside the monitor | `DENY(action_not_fingerprintable)` + audit event |
    | ≥ 257 | `Value.__post_init__` → `deep_freeze`, before any `PlannedAction` exists | `ValueError` at construction: no monitor, no DENY, no audit |

    The regression test nests to exactly `MAX_SECURITY_DEPTH` on purpose, to pin the monitor band.
    At depth ≥ 257 the outcome is still fail-closed (no effect), but the failure happens in the
    adapter, where VAIS records nothing. The guard is `_depth > MAX_SECURITY_DEPTH` with the root
    at depth 0, so the deepest accepted value sits at depth 256 (257 levels counting the root).
  - **Adapter contract (required).** An adapter that constructs `Value`s from model-controlled data
    **MUST catch `ValueError` from `Value` construction and record a denial.** Otherwise
    pathological nesting avoids the audit trail by failing one layer before the monitor. This is
    one instance of the cross-cutting adapter item in §4.

- **P1-2 outcome (`ace1012`):** the Unicode/name and scalar-type families are **closed by
  rc8/rc9** (regression-locked in `tests/test_fingerprint_collisions.py`); pathological nesting is
  **fixed in `ace1012`**; **reference-vs-referent** is recorded as an **accepted, documented risk** with an
  application-level mitigation; the **inverse utility bug** was searched and **not found** —
  key-order, list/tuple, and NFC-equivalent forms all produce identical fingerprints, and the only
  intentional difference (`1` vs `1.0`, `True` vs `1`) is by-design type-sensitivity, kept.
  Recorded honestly as negative evidence.

### S4 — Provenance lattice transitions  ·  **P1-3**
- **Entry:** `taint.py:derive_value` (l.15), `taint.py:derive_model_output` (l.41).
- **Verified facts:** `derive_value` sets `TRUSTED` only if `inputs and all(is_trusted)`;
  any untrusted input → `DERIVED_UNTRUSTED`. `derive_model_output` injects an
  always-`DERIVED_UNTRUSTED` `model_output` origin, so a model can never emit `trusted`. There
  is **no code path that raises trust** — the only constructor of `TRUSTED` values is
  `TrustedValue`/`Provenance` in trusted application code. This matches the docstring: the design is correct, and P1-3's job is to prove the
  *implementation* matches under composition.
- **[hypothesis – P1-3]** the classic laundering path is **round-trip through storage / MCP**:
  the label lives on the in-memory `Value`, the data does not. `mcp.py` re-labels returned data
  via `label_mcp_input` as `UNTRUSTED` (good), but any *application* adapter that reads a value
  back from a file/DB and forgets to re-wrap it would launder it. P1-3 must generate mixed-
  provenance DAGs (depth ≥10) and assert the join holds on every node, including a
  write→read round trip.

### S5 — Data-classification propagation  ·  **P1-3**
- **Entry:** `taint.py:_max_confidentiality` (l.8), applied in `derive_value`; enforced at
  `monitor.py` (confidentiality ceiling, l.77-86) and `invariants.py` `confidentiality_ceiling`
  (l.84).
- **Verified:** join is `max(rank)` over inputs (monotone up the lattice
  `public<internal<confidential<secret`). `derive_model_output` inherits `max` of visible
  inputs, so a model cannot summarize a secret down to public.
- **[hypothesis – P1-3]** same round-trip concern as S4: confirm `secret` survives derivation +
  transformation + storage. Note the monitor's confidentiality check is **skipped for tools
  absent from the static policy** (see S10) — a confidentiality ceiling only fires for a tool
  with a policy entry declaring `max_confidentiality`.

### S6 — Approval binding & replay window  ·  **P1-2 (TOCTOU)**
- **Entry:** `approvals.py:ApprovalStore.grant` / `consume`; keyed by `_key` = `(fingerprint,
  principal_id, session_id, tenant_id, capability_id)`.
- **Verified:** consume-once (`grant.consumed` flips atomically under `RLock`), identity-scoped,
  persisted atomically (`.tmp` + `replace`), rejects malformed fingerprints (must be lowercase
  64-hex) and duplicate identities on load. Concurrency is tested
  (`test_concurrent_approval_consumption_allows_exactly_once`).
- **Gap (P0-5 cross-ref G-B4):** there is **no validity window and no revocation** on an
  approval or contract. An approval, once granted and not consumed, is valid indefinitely. PoE
  binds `[t_nb, t_na]` into the contract; VAIS does not. P1-2's replay analysis should treat the
  absence of a window as the replay surface (there is no *time* to expire out of).
  *(Historical, rc10. From rc13 a contract can carry `not_before`/`not_after`, a grant a TTL, and
  a `RevocationList` withdraws a session or a capability, all optional (P1b-8, DEC-047, DEC-048).
  Consume-once also holds across processes sharing one store file on one machine (DEC-049).
  Without these fields the gap above still describes the behaviour.)*
- **[hypothesis – P1-2]** reference-vs-referent TOCTOU: the fingerprint (S3) binds argument
  *values*; if an argument is a handle/path/id whose backing content changes between `grant` and
  `consume`, the approval is replayed against different effective content. This is the S3
  reference-vs-value item viewed from the approval side.

### S7 — Audit hash chain  ·  **P1-4**
- **Entry:** `audit.py:AuditTrail.record` (chains `previous_hash`), `AuditTrail.verify`.
- **Verified:** each event hashes `{sequence, event_type, tool, decision, reasons, details,
  previous_hash}` with SHA-256; `verify()` re-walks and checks `sequence == expected` (1..N),
  `previous_hash == previous event_hash`, and hash recomputation. The chain is **unsigned**
  (P0-5 gap G-B1) — the threat model lists cryptographic tamper-evidence as an explicit non-goal.
- **P1-4 result (rc11, `test_audit_chain_integrity`).** The hypothesis was right about
  truncation and fork and wrong about splice/reorder in one important way. The line is drawn by
  whether the attacker **rebuilds**, not by which manipulation is used, because rebuilding needs
  only public SHA-256 and the chain holds no key.
  **Caught:** any in-place field edit (8 fields, parameterised); dropping events from the front;
  naive reorder; naive splice; a first event not starting from zero. Each of the verifier's three
  checks is additionally tripped in isolation, so removing any one of them fails the suite.
  **Not caught (LIM-037):** truncating the tail, which needs no rebuild at all and is therefore
  the cheapest attack; splicing a forged `allow` then rebuilding; deleting an event then
  rebuilding; reversing the chain then rebuilding; and a fork, which is invisible from either
  branch by construction. Each is asserted by a test expected to fail if a signed head or external
  commitment is added.
  **Also recorded (LIM-038):** `verify()` returns a bare `bool` with no locus, so an investigator
  cannot distinguish one edited record from a wholly rewritten prefix.
- **Related:** `_reject_secret_fields` (`audit.py:85`) fails closed on secret-bearing detail keys
  — already tested (`test_audit_rejects_secret_bearing_fields`).

### S8 — MCP call mediation  ·  **rc8/rc9 delta triaged here**
- **Entry:** `mcp.py:MCPProtectedClient.execute` (`:239`), `label_mcp_input` (`:181`),
  `extract_mcp_result_data` (`:381`), `canonical_mcp_tool` (`:168`), `_effect_from_binding`
  (`:407`); effect construction in `sandbox.py:Effect.__post_init__` (`:19`).
- **Verified (mediation logic — unchanged from `77eb7e7`):** binding must exist
  (`by_canonical_tool`) and `server_id` must match, else DENY before any network call; the
  reference monitor evaluates the action and **only `ALLOW`** calls `session.call_tool` (`:274`)
  with `plain_arguments()`; the return is re-labelled `UNTRUSTED` via `label_mcp_input`.
  `canonical_mcp_tool` rejects `:` in server/tool to keep the `mcp:server:tool` namespace
  unambiguous. The profile loader forbids upgrading remote results to `trusted`.
- **Triage of the rc8/rc9 delta (mcp.py +42, sandbox.py +33) — all hardening, no logic change:**
  1. `MCPEffectMapping.__post_init__` (`mcp.py:63`, new): NFC-normalizes effect field names and
     argument names and **rejects NFC-duplicate effect fields**, freezing to `FrozenDict`.
  2. `MCPToolBinding.__post_init__` (`mcp.py:88`) and `canonical_mcp_tool` (`:168`) and
     `label_mcp_input` (`:181`) and the loader `_string` helper (`:457`) all now **NFC-normalize**
     server/tool/canonical/primitive/name — so a compatibility-variant string can no longer mint a
     second binding or a second effect-field alias. `MCPProfile.__post_init__` (`:109`) hardened
     its version guard.
  3. `sandbox.py:Effect.__post_init__` (`:19`, new): requires `attributes` to be a mapping
     (`deep_freeze`→`FrozenDict`), NFC-normalizes `kind` and provenance keys, **rejects
     NFC-duplicate provenance keys**, and type-checks `tool`/`action_fingerprint`. Every MCP and
     sandbox effect now passes this.
  4. `extract_mcp_result_data` (`:381`) is **unchanged** — still walks `structuredContent` /
     `content[].text` and falls back to `str(raw_result)`.
- **Consequence for S3 cross-field collapse:** the MCP effect mapping is **one effect field ← one
  argument** and rc9 rejects duplicate effect fields, so two arguments **cannot** be collapsed
  into a single effect field here. The S3 "structural smuggling" concern is therefore *not*
  expressible through `argument_fields`; downgrade it accordingly.
- **Boundary note:** parameter smuggling / path traversal *inside* a tool argument value is the
  **downstream tool's** responsibility — VAIS binds those values to the contract (S3/S6) and
  labels provenance. It is a VAIS concern only where such an argument is a *bound* or *authority*
  field; otherwise out of scope for the enforcement layer.
- **[hypothesis – P1-1/P1-5]** `extract_mcp_result_data` (unchanged) returns data that is
  *labelled untrusted* immediately, so it cannot create authority, but a hostile SDK object could
  make it return something large/surprising — still worth a fuzz case that it never raises
  unhandled and never yields an authority-bearing value. rc9 did not touch this path.

### S9 — Invariant evaluation (fail-open audit)  ·  **P1-5**
- **Entry:** `invariants.py:DeclarativeInvariantEngine.evaluate` (`:45`), `_violation_reason` (`:67`).
- **Verified fail-closed behavior:** missing effect provenance → violation
  (`missing_effect_provenance`); missing bound value → `missing_contract_binding`; non-numeric
  threshold field → `invalid_numeric_field`; missing fingerprint on a high-value effect →
  `missing_effect_action_fingerprint`. An **unsupported invariant type** reaching
  `_violation_reason` hits `raise AssertionError(...)` (`:131`) — it raises rather than passes,
  which is fail-closed *if the caller does not swallow it*.
- **rc9 hardening (new since v1):** `contract_binding` now compares with
  `security_equal(actual, trusted.data)` (`:82`) instead of `!=`, closing a **type-confusion
  evasion** at the invariant layer (e.g. an effect field of `1`/`1.0`/`True` no longer matches a
  bound `1` by Python coercion); `exact_action_approval` gained `bool` / `math.isfinite` guards
  (`:118`), matching the monitor. These are the `test_invariants` (+71) additions.
- **[hypothesis – P1-5]** two things P1-5 must confirm:
  1. the only way to reach the `AssertionError` is by **constructing `InvariantDefinition`
     directly** (the loader's `supported` set blocks unknown types), so verify no benchmark/CLI
     path builds definitions bypassing `load_invariants`;
  2. confirm no caller wraps `evaluate()` in a bare `except` that would turn a raised evaluator
     into a silent "no violation" (a fail-open). This is exactly the "evaluator raises" cell of
     P1-5's fault matrix.

### S10 — Static-policy gap under `default_action: allow`
- **Entry:** `monitor.py:ReferenceMonitor.evaluate`, l.48-54: when a tool has **no** `ToolPolicy`
  entry, if there are bound-argument reasons it DENYs, else it follows `default_action`
  (`allow` → ALLOW; `deny` → DENY with `tool_not_in_policy`).
- **Consequence (by design, but a real surface):** a tool that is in `contract.allowed_tools` but
  absent from the static policy, under `default_action: allow`, is **allowed without** capability-
  scope, confidentiality-ceiling, undeclared-argument, or approval checks — because all of those
  live on the (absent) `ToolPolicy`. Bound-argument integrity is *still* enforced (tested). This
  is the documented "dynamic contract authorizes; static policy only constrains further" model,
  but it means **`default_action: deny` is the safe posture** and any deployment using
  `allow` must enumerate every consequential tool in the policy. P1-5 should assert this in the
  fault matrix (a consequential tool missing from a `default_action: allow` policy must not
  silently skip its confidentiality ceiling).

### S11 — Executor fail-closed seam
- **Entry:** `executor.py:ProtectedExecutor.run`, l.51:
  `effect = self.executor.execute(action) if decision.type == DecisionType.ALLOW else None`.
- **Property:** DENY and REQUIRE_APPROVAL produce no effect; structurally, not just by policy.
  P1-5 fault matrix owns the adverse-condition variants (audit write fails, executor raises).

### S12 — Numeric threshold coercion
- **Entry:** `monitor.py` l.109-115 and `invariants.py:116-122`. `bool` rejected before
  `float()`, non-finite rejected, non-numeric → DENY / `invalid_numeric_field`. Tested; no gap.
  (rc9 made the invariant-side guard identical to the monitor-side one — see S9.)

---

### S13 — Decision-reason disclosure (output channel)  ·  **IMP-003**
- **Why it is listed separately:** S1–S12 are all *inputs* crossing into the monitor. S13 is an
  *output*: the verdict and its reason strings are returned to the caller
  (`ExecutionRecord.decision`, `MCPExecutionRecord.decision`), and whether they reach the model
  depends on the integration. The agent loop is attacker-influenced by assumption.
- **The attack:** ARM (arXiv 2604.04035) names the denial-feedback channel. A denied action is an
  observable event, so an attacker can probe a protected action, learn from the denial, and act on
  the inference through a later benign call.
- **Why reasons matter more than verdicts:** a verdict leaks about one bit per probe. A reason
  such as `bound_argument_changed:{field}` names the argument the contract binds, which tells the
  attacker which field to leave alone and where to push instead.
- **[hypothesis – IMP-003]** a configurable redaction policy for reasons returned to the model,
  with the audit trail keeping full detail, is likely the cheapest real mitigation. Not
  implemented. `docs/threat-model.md` currently covers this only under a generic side-channel
  non-goal.

### S14 — Effect-set cardinality (volume composition)  ·  **VERIFY closed rc11, ENFORCE open**

Reported by an external reviewer in [issue #2](https://github.com/stratomarco/vais-boundary/issues/2),
and every code claim in that report was verified before it was accepted.

- **The gap.** The central property is stated over "**an** unauthorized externally observable
  effect", singular. Composition has two halves and the wording covers one. The **flow** half — a
  secret read followed by a public send, where each step is legitimate and the ordering is not —
  is expressible, and was named in the v0.9.0 changelog. The **volume** half — N individually
  authorized effects whose *count* is the problem — was not expressible at all.
- **Verified mechanism.** `ReferenceMonitor.evaluate` (`monitor.py:28`) takes one
  `PlannedAction`. `ProtectedExecutor.run` (`executor.py:38`) receives `list[PlannedAction]` and
  dissolves it in a `for` loop; nothing produced in one iteration re-enters a later decision. The
  invariant engine folded `for index, effect in enumerate(effects)`, per effect. The policy field
  allowlist (`policy.py:130`) is closed — `allow`, `arguments`, `approval`, `required_scope`,
  `exact_approval_required`, `reject_undeclared_arguments` — so a cardinality field would have
  been rejected at load rather than ignored.
- **Why that framing matters.** The closed schema is the right decision and it is also what turns
  "no quota was found" into "a quota is not expressible". An operator could not have added one.
- **rc11 — VERIFY closed.** `max_effect_count` evaluates over the whole effect list the engine
  already receives. One violation per invariant, naming the effect that crossed the bound.
- **rc11 — ENFORCE open (LIM-035).** Denying the action that would breach the bound needs
  per-task state threaded through `evaluate`'s signature and through every adapter. That is the
  same obligation LIM-033 already shows adapters can silently drop, so it is not attempted here.
  `tests/test_invariant_cardinality.py` asserts that six identically authorized actions still
  produce six `ALLOW` decisions; if a later release enforces the bound, that test should fail and
  be rewritten.
- **rc13 — ENFORCE closed when a `SessionLedger` is supplied (P1b-3).** The state went into a
  ledger passed to `evaluate` rather than into the monitor, which keeps one monitor usable across
  sessions. Policy v5's `max_calls` is checked and recorded under the ledger's lock, before any
  approval is consumed, and a declared limit with no ledger is denied rather than ignored. The
  rc11 test above still passes and is still correct, because it exercises the stateless path,
  which is unchanged; the ledger path is tested in `tests/test_session_ledger.py`, including a
  property test that ENFORCE and VERIFY agree over 200 seeded traces when they share a ledger.

## 3. Coverage gaps mapped to owning tasks (the P1 to-do, for the owner)

- **P1-2 (S3) — DONE in `p1-2-fingerprint-hardening`:** unbounded `deep_freeze` recursion
  **confirmed and fixed** (bounded to `ValueError` at `MAX_SECURITY_DEPTH=256` → routes to
  `action_not_fingerprintable` + audit; see S3 confirmed-finding note and
  `tests/test_fingerprint_recursion.py`). rc8/rc9's Unicode/name and scalar-type closures are
  **regression-locked** (`tests/test_fingerprint_collisions.py`). **Reference-vs-referent** is an
  **accepted, documented risk** (mitigation is application-level). The **inverse utility bug** was
  searched and **not found** (negative evidence). `plain_arguments()` has no exclusions — closed.
- **P1-2 residual → owned by P1-6 (S6):** reference-vs-referent is fundamentally an
  approval-binding/TOCTOU concern, not a fingerprint bug; carry it into the S6 approval-window
  analysis rather than re-opening S3.
- **P1-3 (S4, S5):** provenance stateful DAG tests (depth ≥10) incl. storage round-trip;
  confidentiality-join survival through transformation.
- **P1-4 (S7):** fork / truncate / splice / reorder harness; truncation is the predicted weak
  spot given the unsigned, length-agnostic `verify()`.
- **P1-5 (S1, S9, S10, S11):** fault-injection matrix — missing/corrupt/YAML-bomb policy file,
  evaluator raises, audit write fails, `default_action: allow` with a consequential tool absent
  from policy. Every cell must DENY / raise, never allow.

P1-2's fingerprint work (recursion fix + collision characterization) is complete on branch
`p1-2-fingerprint-hardening`. *(Historical, rc10. The P1-3, P1-4 and P1-5 harnesses were written
and shipped in rc11; see the legend in §1.)* The P1-3/P1-4/P1-5 harnesses above are **not** written yet — they
remain the map's to-do.

---

## 4. Cross-cutting: adapters are where provenance is dropped

Several separately found gaps are one defect class: **the adapter that turns application data into
`Value`s is where provenance and audit coverage are lost.**

- **S3, depth ≥ 257:** `Value` construction fails in the adapter, before the monitor, with no audit.
- **S4/S5, storage round trip:** labels live on in-memory `Value`s, not on the data. An adapter
  that reads a value back from a file, database, memory store or retrieval index and forgets to
  re-wrap it launders untrusted data into trusted.
- **Cross-session flows (IMP-006):** a task-A write read back in task B crosses exactly this
  boundary, so whether provenance survives deserialization is the question to test.

The core enforces correctly on the labels it is given. Adapters decide whether those labels are
true. Track this as one item, and give every adapter the same two obligations: catch `ValueError`
from `Value` construction and record a denial; re-derive provenance on every read from persistent
storage rather than trusting the stored data.

## Sources
- VAIS source at `bf38ab0`: `models.py`, `monitor.py`, `policy.py`, `executor.py`,
  `approvals.py`, `taint.py`, `audit.py`, `invariants.py`, `behavioral_gate.py`, `mcp.py`,
  `sandbox.py`. Files re-read for the rc9 delta: `models.py`, `invariants.py`, `policy.py`,
  `mcp.py`, `sandbox.py`; the rest verified byte-identical to `77eb7e7`.
- Existing tests read: `tests/test_reference_monitor.py`, `tests/test_attack_corpus.py`,
  and function inventories of `test_policy_validation`, `test_policy_v3`, `test_taint`,
  `test_audit`, `test_protected_executor`, `test_mcp`, `test_invariants`, `test_task_contract`,
  `test_tcb_hardening`.
- P0-5 cross-references: `docs/RELATED-ARCHITECTURES.md` (gaps G-B1, G-B4).
