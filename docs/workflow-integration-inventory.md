# Workflow integration and pilot: current-state inventory

*2026-10-20, against VAIS 1.0.0. The first deliverable of the owner's workflow-integration and
pilot requirements (plan of record, Annex A): what the code already implements, what needs
integration work, and what remains unverified. Checked against the code, not the documents.*

The published benchmark evidence and its limits are unchanged by this inventory
([`evidence-index.md`](evidence-index.md), [`threat-model.md`](threat-model.md)). VAIS is not yet a
production-ready authorization service.

## Requirement by requirement

| | Implemented in 1.0 | Integration work needed | Unverified |
|---|---|---|---|
| **R1 Trusted authority** | A contract fixed before untrusted content is read: allowed tools, scopes, bound arguments (destinations, resource IDs), allowed values, budgets, principal, tenant, session, capability. Library `TaskContract`; gateway contract files mapped from a session token. Delegation can only narrow it. | Building the contract from an **authenticated** user or application request. Today an operator writes the contract file and hands the agent a token; no identity provider is integrated. | Authority derived from a real identity system and real requests. |
| **R2 Complete mediation** | Every call through `ProtectedExecutor`, `MCPProtectedClient` or the gateway is decided first; refused and approval-required calls are never sent (`not_called`). The gateway alone holds the upstream credentials, and tests check the agent and upstreams never see them. The `monitor_mediated` invariant reports any effect no recorded allow explains, after the fact. | A test in the reference workflow that **fails if a bypass is introduced**, checked against the backend's own records: every backend change must match a gateway allow. | Isolation in a real deployment: credentials, network paths, operator files (LIM-050, LIM-060). |
| **R3 Provenance and confidentiality** | Labels assigned from sources (each tool's result confidentiality, MCP results untrusted); model output inherits what it read; per-argument trust requirements and confidentiality ceilings; the gateway's session high-water mark; declared stores checked at startup (DEC-070). | Classifying the real backend's data sources in the profile. | Labels against real data; adapters that drop provenance (`ATTACK-SURFACE.md` §4); stores that are not declared (LIM-074). |
| **R4 Exact approvals** | A grant is bound to the action's fingerprint and to principal, session, tenant and capability; consumed once; optional expiry; file-backed under an operating-system lock, so it holds across processes and restarts on one machine. Operators grant pending gateway requests with `vais gateway-approve`. | Approvals made by an **authenticated approver**, with the approver's identity recorded. Today an approval is an operator command. | Across machines (LIM-057). |
| **R5 Effects and uncertainty** | Every call is `not_called`, `observed` or `indeterminate`; an effect is recorded only after the call returns, with a confidence (requested, acknowledged, confirmed by a read-back from the system of record, or contradicted). An indeterminate call is never scored as a defence (DEC-040). Decision and effect are linked by the action fingerprint. | **Gap:** nothing requires reconciliation before an indeterminate high-consequence call is retried; a repeated proposal is decided and sent again. **Gap:** the backend's receipt is not captured; the effect records fields, not the receipt. **Gap (found with the sandbox):** an MCP error result is not an exception, so a call whose reply is an error is recorded as `observed` with a `requested` effect, although the backend may or may not have made the change. | Reconciliation against a real backend. |
| **R6 Duplicate prevention** | Where configured, single-use allowed values, call limits and consume-once approvals refuse a repeated proposal. | **Gap:** no idempotency key reaches the backend; the fingerprint never leaves VAIS. A transport failure after dispatch followed by a retry can duplicate an effect unless the backend deduplicates. | Both cases the requirements name: a repeated proposal and a transport failure after dispatch. |
| **R7 Independent verification** | Declarative invariants evaluated over effects, separately from the decision; utility checks in the reference applications; read-back reconcilers query a system of record. | A verifier that reads the **backend's own state or receipts**, not VAIS's effect records. | Against a real backend. |
| **R8 Auditability** | A hash-chained audit (`vais audit-verify`) with decisions, reasons, contract identity, action fingerprints, call state and effect confidence; secrets are refused in audit details and minted values recorded as digests; benchmark records carry a configuration hash. | **Gaps:** no per-call correlation ID (two identical calls share a fingerprint); the gateway's audit records no policy or configuration digest; no backend receipt; invariant verdicts are not in the gateway's audit. | A reviewer tracing a verdict from action to backend evidence to invariant. |

## Evaluation requirements against the existing harness

| Requirement | State |
|---|---|
| Frozen workflow, scenarios, outcome definitions and pass criteria before the final run | In place for the measured studies; `evidence-index.md` shows which were pre-registered |
| Attempted unauthorized actions, actual effects, indeterminate effects, completion and false alarms reported separately, with failed and unevaluable runs in the denominators | In place in the benchmark scorers (DEC-040) |
| Malicious retrieved content, changed authority arguments, cross-tenant access, secret egress, approval replay | In the reference applications' attacks |
| Duplicate effects | Partly: duplicate payments by proposal (accounts payable `attack-06`); not after a transport failure |
| Transport uncertainty | Unit tests with failing transports; not in a workflow evaluation |
| An attempted bypass | Not in any corpus |
| Legitimate recovery after a denial | Not measured as its own outcome |

## The workflow to take end to end

**Recommended: an accounts-payable payment run.** It has everything the requirements ask for, and
VAIS already has its attacks, matched controls, policies and verifier (`reference_finance.py`,
DEC-066 to DEC-069):
- a trusted requester: a clerk authorised to pay an approved batch;
- untrusted material: invoices, vendor emails, a supplier portal;
- a consequential action: a payment;
- an independently checkable outcome: the payment ledger.

What is missing is a **stateful sandbox backend** in place of the simulated tools: a small payment
service in its own process, with its own database and credentials, idempotency keys, receipts and
a read API, served over MCP behind the gateway.

## Proposed sequence

1. **Sandbox backend** with idempotency keys, receipts and a read API. **Done:**
   `examples/ap_sandbox/` (its README), tested in `tests/test_ap_sandbox.py`, including faults
   after commit sent through `MCPProtectedClient`.
2. **Close the gaps in VAIS** that the requirements need, each a 1.x change under the format rules
   (`formats.md`). **Done** (DEC-074, FIND-078, LIM-078; `gateway.md`, consequential tools), except
   invariant verdicts, which the step 3 verifier reports against the backend's records, joined to
   the audit by call id and receipt:
   - reconciliation required before retrying an indeterminate high-consequence call (R5);
   - an MCP error reply from a high-consequence tool treated as uncertain, not observed (R5);
   - an idempotency key sent to backends that accept one (R6);
   - per-call correlation IDs, a configuration digest at gateway start, receipt digests and
     invariant verdicts in the audit (R8).
3. **Reference integration:** gateway as the only path, configuration, an example contract,
   policies, invariants, an operator guide, and the bypass test (R2).
4. **Frozen evaluation:** pre-registered, with the attacks above plus transport failures after
   dispatch, retries, a bypass attempt and recovery after a denial.
5. **Evidence packet and pilot handoff:** raw action and effect records, an independent
   verification report, limitations, and what identity, persistence, reconciliation, monitoring
   and independent evidence a real pilot would need.

## Decisions for the owner

- Whether the accounts-payable payment run is the workflow: **yes** (2026-10-20).
- Whether the sandbox backend lives in this repository, under `examples/`, or in its own:
  **`examples/`** (2026-10-20).
- Who the workflow owner is for the pilot, when one is available. Until then, the project owner.
