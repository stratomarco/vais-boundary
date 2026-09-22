# Related architectures: VAIS ↔ "Proof of Execution"

**Status:** v2, current as of 0.12.0rc12.
**Source base:** VAIS claims verified against `bf38ab0` (the rc9 TCB-hardening base) on
2026-09-09. The one rc10 change to the enforcement path, the `deep_freeze` recursion bound, is
noted where it affects a row.
**Primary comparison:** *Proof of Execution: Runtime Verification for Governed AI Agent
Actions*, arXiv 2607.05397 (Jul 2026) — referred to below as **PoE**.

This document maps VAIS concepts onto PoE's term by term, records where each system is
genuinely ahead of the other, and recommends where VAIS should adopt PoE vocabulary. It is a
positioning and interoperability document, not a claim of priority. This is a
standardisation race, and interoperability beats purity.

All VAIS claims below were verified against source at **`bf38ab0`** (the rc9
TCB-hardening base) on 2026-09-09. An earlier v1 was verified against the RC7 tree
(`6e0aad0`); line references and the canonicalization notes have been refreshed for rc9. Every PoE claim is quoted or paraphrased from arXiv 2607.05397 (HTML version).

---

## 0. One-paragraph summary

PoE and VAIS are the same architecture derived independently. Both intercept every
consequential action at a single authoritative gate, evaluate it against authorization fixed
*before* untrusted content is introduced, forbid any external effect on a denied action, and
record the outcome in a tamper-evident, append-only history. PoE's contribution is **formal**:
it packages these properties into a single runtime-checkable predicate `PoE(C,T,R)` with a
clean separation of cryptographic from deployment assumptions, and cryptographically *seals*
the history (EUF-CMA signatures + Merkle commitments). VAIS's contribution is **empirical and
information-flow-centric**: it adds **provenance/taint tracking** and **confidentiality
propagation** as first-class policy inputs — which PoE does not model at all — and it has an
executed **cross-model measurement campaign** (RC7: 15 models, 3,360 episodes) that PoE has no
equivalent of. The two systems are complementary, and VAIS should adopt PoE's validator
vocabulary where it is strictly clearer.

---

## 1. Term-by-term mapping

| Concept | PoE term | VAIS term (verified location) | Notes |
|---|---|---|---|
| Authorization fixed before execution | **Contract** `C`; `id(C)=H(C)`; fields: principal, authorized capability set, policy snapshot, validity window `[t_nb, t_na]`, revocation ref, replay config | **`TaskContract`** (`models.py:198`): `allowed_tools`, `bound_arguments`, `approved_action_fingerprints`, `granted_scopes`, `principal_id`, `session_id`, `tenant_id`, `capability_id` | Same role. PoE's contract is content-addressed (`H(C)`) and carries a **validity window** and **revocation reference**; VAIS's `TaskContract` has **neither a time window nor revocation** — see gap G-B4. VAIS adds `bound_arguments` (exact trusted argument values), which PoE folds into "capability set." |
| The actor | **principal** | `principal_id` (+ `session_id`, `tenant_id`, `capability_id`) on `TaskContract` | VAIS's 4-tuple identity is finer-grained; PoE keys on a single principal. VAIS approvals are keyed on `(fingerprint, principal_id, session_id, tenant_id, capability_id)` (`approvals.py`). |
| Single authoritative decision point | **Gateway** (PEP+PDP); "all effectful execution passes through exactly one authoritative Gateway evaluation"; "echoes the Reference Monitor discipline" | **`ReferenceMonitor`** (`monitor.py`), enforced ahead of **`ProtectedExecutor`** (`executor.py`) | Identical discipline (complete mediation). Both explicitly invoke the classic reference-monitor concept. |
| Per-action decision | `decision ∈ {allow, deny, ⊥}` | `DecisionType ∈ {ALLOW, DENY, REQUIRE_APPROVAL}` (`models.py:268`) | **Vocabulary difference worth noting:** VAIS has a *three-valued* decision including `REQUIRE_APPROVAL` (human-in-the-loop), which PoE lacks. PoE's `⊥` is "undefined/no decision," not "escalate." See §3 adoption note. |
| What actually happened | **effect_type ∈ {none, mutation, external}**, plus `resource_id`, `delta_hash` | **`Effect`** (`sandbox.py` → invariant engine), e.g. `email_sent`, `payment_sent`, `shell_executed`; effects preserve per-field provenance | PoE's effect taxonomy is a *coarse* 3-way {none/mutation/external}. VAIS's effects are *domain-typed* and carry **provenance labels per field** — richer, and the basis of the information-flow invariants PoE cannot express. |
| Tamper-evident history | **ECES** (Execution Causal Event Stream): append-only causal DAG `T=(V,E,≺,ℓ)`, "cryptographically sealed"; each event has `prev_event_hash`, `commit_seq`, `envelope_hash`, signature `σ` | **`AuditTrail`** (`audit.py`): append-only JSONL, SHA-256 hash chain via `previous_hash`, monotone `sequence` | **Key gap — G-B1.** Both are hash-chained and append-only, but PoE's history is **signed** (EUF-CMA, key in TCB) and Merkle-committed; VAIS's is an **unsigned** SHA-256 chain. VAIS's own threat model (`docs/threat-model.md`) lists "cryptographically tamper-evident audit storage" as an **explicit non-goal**. PoE also models a *causal DAG*; VAIS records a *linear sequence*. |
| Provenance / taint | *Absent.* Paper cites PROV-DM but models only a causal event DAG; no integrity/confidentiality labels on data | **`taint.py`**: `TrustLevel {trusted, untrusted, derived_untrusted}`, `ConfidentialityLevel {public, internal, confidential, secret}`; `derive_value()`, `derive_model_output()` propagate conservatively | **VAIS's principal lead — G-A1.** PoE has no data-provenance or information-flow model. This is also what distinguishes VAIS from policy engines such as OPA and Kyverno, and it is *further* ahead of PoE than of the policy-engine baselines. |
| Data classification | *Absent* (only `authorized_scope`/`capability` as permission boundary) | `ConfidentialityLevel` join: `confidentiality = max(inputs)` in `derive_value()` (`taint.py:28`); enforced by `confidentiality_ceiling` invariant | **VAIS lead — G-A2.** Monotonic confidentiality propagation. PoE cannot express "secret data must not egress." |
| Approvals / high-consequence gating | Gateway allow/deny decisions (binary); no human-approval tier | **`approvals.py`** grant/consume keyed on `(fingerprint, principal, session, tenant, capability)`; `exact_action_approval` invariant; `REQUIRE_APPROVAL` decision | VAIS binds approval to the **exact canonical action fingerprint** (`action_fingerprint`, `models.py:135`) and independently re-checks it at the invariant layer, catching approval replay after action mutation. PoE has no comparable replay-after-mutation check at the effect layer. |
| Canonical action identity | `input_hash`, `tool_schema_hash` per event | **`action_fingerprint`** = `sha256(canonical_json({tool, plain_arguments()}))` (`models.py:135`); NFC normalization, finite-float rejection, duplicate-key rejection in `deep_freeze` (`models.py:148`). **rc9 extends NFC + NFC-duplicate rejection to argument names, tool names, scopes, contract identity, and provenance fields** (`models.py:122`, `:227`; `:52`). | Both hash the action. VAIS's fingerprint covers the **full argument set** (`plain_arguments()` excludes nothing — verified `models.py:131`) with strict canonicalization. |
| Fail-closed on deny | **I3 (Null Effect on Deny):** every causal descendant of a `deny` has `effect_type=none ∧ delta_hash=⊥` | Threat-model objective #6: "Denied/unapproved actions do not produce an external effect"; only `ALLOW` reaches `ProtectedExecutor` (`executor.py`) | Same property, different framing. PoE states it as a *checkable invariant over the trace*; VAIS enforces it *structurally* (deny never reaches the executor). See §3: VAIS should also express this as a post-hoc validator, not only structurally. |
| Replay / determinism | **I5a (Envelope Closure)** + **replayability** in contract's replay config; `envelope_hash` binds planner version, policy snapshot, tool schema, seeds, captured inputs | Deterministic episode replay via JSONL snapshots (`architecture.md §9`); seeds/temperature recorded per episode; **no per-action `envelope_hash`** binding planner+policy+seed+inputs | **Gap — G-B2.** VAIS replays *whole benchmark episodes* for regression, but does not bind a *per-action* replay envelope into the audit record the way PoE's `envelope_hash` does. PoE's replayability is a first-class validator invariant; VAIS's is a test-harness convenience. |
| Adversary model | PPT adversary: crafted requests, **compromised planner**, network replay, direct tool invocation off-path, environmental non-determinism | `docs/threat-model.md`: LLM may follow attacker instruction ("assume model compromise"); attacker controls untrusted content and knows the defense | Very close. PoE additionally models **network replay** and **off-path direct tool invocation** explicitly; VAIS assumes the real tool "cannot be reached through an alternate path that bypasses `ProtectedExecutor`" (an *assumption*, not an enforced property). PoE's threat classes T1–T6 are a cleaner enumeration. |
| Trust boundary of the trace | **A4–A5:** recorder signing key + sealing root in TCB; **Trace Completeness** (A5); **Effector-exclusive credentialing** (Lemma 1) discharges A5 | Threat-model assumptions: tool unreachable except via `ProtectedExecutor`; adapters correctly label sources | PoE's **Effector-exclusive credentialing** (only the enforced effector holds the credential, so no off-path effect can occur) is a concrete architectural discipline VAIS should adopt to *justify* its "no alternate path" assumption — see G-B3. |

---

## 2. Where each system is genuinely ahead

### 2.1 VAIS is ahead (predicted leads, all verified)

- **G-A1 — Provenance / taint tracking.** PoE has none. VAIS's `TrustLevel` lattice
  (`trusted` / `untrusted` / `derived_untrusted`) with conservative propagation
  (`taint.py:15`, `derive_value`) is the single largest capability PoE lacks. It is what lets
  VAIS answer "was this action's *intent* influenced by untrusted content?", which authorization
  alone cannot.
- **G-A2 — Data-classification propagation.** VAIS's monotonic confidentiality join
  (`confidentiality = max(inputs)`, `taint.py:28`) plus the `confidentiality_ceiling` invariant
  expresses "secret data must not leave via this effect." PoE cannot state this property at all.
- **G-A3 — The empirical cross-model campaign.** VAIS RC7 ran a 15-model panel (14 completing the
  common full stage): 3,360 full-stage episodes, zero observed protected-invariant violations,
  65.7% aggregate protected utility and a 38.9% attack-added-event rate. PoE's evaluation is a
  **single-node latency/overhead microbenchmark** (TypeScript prototype; +65.9%→+4.4% overhead)
  plus 10,000 tamper-detection trials on synthetic traces. PoE measures the *runtime overhead* of
  enforcement; VAIS measures *security and utility outcomes across real models*. The 65.7%
  aggregate is not itself an enforcement-cost figure: the paired control analysis (LIM-009,
  Qwen v0.10) shows attacked protected runs succeeding at nearly the control rate. Neither the
  model panel nor a utility axis exists in PoE.
- **G-A4 — Independent effect-layer oracle.** VAIS's invariant engine is deliberately separate
  from the reference monitor (`security-invariants.md`), giving a second, independent oracle
  that can catch monitor implementation bugs. PoE's validator checks the *trace* the Gateway
  produced; it is not an independent re-derivation of the effect from observed outcomes.

### 2.2 PoE is ahead (VAIS gaps to close)

- **G-B1 — Cryptographic sealing of the audit chain.** PoE signs every event (EUF-CMA) and
  Merkle-commits; the signing root is in the TCB. VAIS's `AuditTrail` (`audit.py`) is an
  **unsigned** SHA-256 hash chain — it detects accidental corruption and naive edits but not a
  motivated attacker who recomputes the chain. VAIS lists this as a non-goal today; PoE shows it
  is achievable at ~0.8 ms/event. **This is the clearest place VAIS is behind.**
- **G-B2 — Per-action replay envelope (formal replayability).** PoE's `envelope_hash` (I5a)
  binds planner version + policy snapshot + tool schema + seeds + captured inputs into each
  event, and replayability is a checkable validator invariant. VAIS replays whole episodes for
  regression but has no per-action envelope in the audit record. Adopting an `envelope_hash`
  field would make individual VAIS decisions independently replayable.
- **G-B3 — Effector-exclusive credentialing.** PoE derives "no off-path effect" from a concrete
  discipline (only the enforced effector holds the credential) rather than assuming it. VAIS
  currently *assumes* the tool is unreachable except via `ProtectedExecutor`. Adopting PoE's
  discipline would upgrade a VAIS assumption into an architectural guarantee.
- **G-B4 — Contract validity window + revocation.** PoE contracts carry `[t_nb, t_na]` and a
  revocation reference. `TaskContract` has neither, so there is no built-in notion of an
  approval/contract *expiring* or being *revoked* mid-session — relevant to the TOCTOU/replay
  surface that P1-2 will fuzz.
- **G-B5 — Formal validator framing.** PoE packages everything into one predicate
  `PoE(C,T,R)=1 ⟺ WF ∧ I₁ ∧ I₂ ∧ I₃ ∧ I₄ ∧ I₅ₐ`, with cryptographic vs deployment assumptions
  separated explicitly (A1–A2 vs A3–A7). VAIS's properties are equally real but stated prose-wise
  across `threat-model.md` and enforced procedurally. A single VAIS validity predicate would
  make the guarantee auditable in one place.

---

## 3. Vocabulary VAIS should adopt (interop over purity)

Adopt where PoE's term is not worse; keep VAIS's where it carries more meaning.

| Adopt from PoE | For VAIS concept | Rationale |
|---|---|---|
| **"Null effect on deny"** (name of I3) | Threat-model objective #6 | PoE's phrase is crisp and already the paper's canonical name; use it verbatim in VAIS docs and name a corresponding validator. |
| **`effect_type ∈ {none, mutation, external}`** as a *coarse axis alongside* VAIS's domain effects | `Effect` metadata | Adding PoE's coarse axis as a tag on each VAIS `Effect` makes VAIS traces machine-comparable with PoE traces without losing VAIS's domain typing. |
| **`envelope_hash`** | new per-action audit field | Directly closes G-B2; the name is descriptive and paper-canonical. |
| **`commit_seq`** | rename/alias VAIS's audit `sequence` | Trivial alignment; lets a PoE validator read VAIS traces. |
| **Threat classes T1–T6** | reorganize `threat-model.md` adversary section | PoE's enumeration (unauthorized exec / gateway bypass / deny-with-effect / trace mutation / replay / credential escape) is cleaner than VAIS's current prose list. |
| **"validity predicate"** framing | a single `verify(contract, trace, result)` entry point | Gives VAIS the one-place auditable guarantee of G-B5. |

**Do not adopt / keep VAIS's term:**

- Keep **`REQUIRE_APPROVAL`** — PoE has no human-approval tier and `⊥` does not mean "escalate."
- Keep **`TrustLevel` / `ConfidentialityLevel`** — no PoE equivalent exists to align to.
- Keep VAIS's **domain-typed effects** (`email_sent`, `payment_sent`, …) as the primary effect
  identity; PoE's `{none, mutation, external}` is a secondary tag, not a replacement.

---

## 4. Concrete gaps named (acceptance criterion: ≥3 in either direction)

Ten concrete gaps are named above and cross-referenced by ID:

- **VAIS ahead:** G-A1 (provenance/taint), G-A2 (confidentiality propagation),
  G-A3 (cross-model campaign + utility retention), G-A4 (independent effect oracle).
- **VAIS behind:** G-B1 (cryptographic sealing), G-B2 (per-action replay envelope),
  G-B3 (effector-exclusive credentialing), G-B4 (contract validity window + revocation),
  G-B5 (single formal validity predicate).

The acceptance criterion ("names at least three concrete gaps in either direction") is met with
margin in both directions.

---

## 5. Recommended follow-ups (not part of P0-5)

These are logged for the project owner; none are executed here.

1. **G-B1 is a candidate to pull forward** if the audit chain is to survive P1-4's fuzzing as a
   *security* control rather than an integrity-check convenience. P1-4 tests fork/truncate/splice
   detection against the current unsigned chain; the results will quantify exactly what the
   missing signature costs.
2. **G-B4 (validity window + revocation) intersects P1-2's TOCTOU surface.** Approval replay
   across an expired window is unexpressible today because there is no window. Worth noting in the
   P1-1 attack-surface map.
3. **Reach out to the PoE authors** (outreach task P4-3) once vocabulary alignment lands — matching the
   paper's terms is the cheapest route to being *the* implementation the paper's readers cite.

---

## Sources

- PoE: *Proof of Execution: Runtime Verification for Governed AI Agent Actions*,
  arXiv 2607.05397 — https://arxiv.org/html/2607.05397
- VAIS source at `bf38ab0` — `models.py`, `taint.py`, `audit.py`, `approvals.py`,
  `monitor.py`, `executor.py`, and `docs/{architecture,threat-model,security-invariants}.md`.
  (`taint.py`, `audit.py`, `approvals.py`, `monitor.py`, `executor.py` are byte-identical to the
  RC7 tree (`6e0aad0`); `models.py` changed under rc8/rc9 and its line refs were refreshed.)
