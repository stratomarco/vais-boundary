# Changelog

## 0.12.0-rc9 - 2026-08-24

- Adopt **VAIS Boundary — Verifiable Authority & Invariant Security** as the public-facing name while preserving the `vais` CLI, Python package identifiers and historical benchmark titles.
- Add a claim-bounded naming rationale that ties each term to implemented authority, enforcement and independent effect-verification semantics.
- Canonicalize and recursively freeze observable `Effect` evidence before independent invariant evaluation, including Unicode-normalized effect identifiers and provenance keys.
- Make contract-binding invariants type-sensitive, reject Boolean/non-finite numeric effect fields, reject non-finite invariant thresholds and type-confused schema versions, and require a non-empty invariant set.
- Prevent policy v4 files from opting into an allow-by-default policy or disabling undeclared-argument rejection; historical v1-v3 parsing semantics remain available for replay.
- Remove exception messages from the deliberately unprotected MCP assessment path and retain only exception class, request identity, indeterminate state and unsafe-retry status.
- License the project under Apache-2.0 and add the canonical `LICENSE` plus project `NOTICE`.
- Add Marco Constantino as author and maintainer, publish the private security contact, add machine-readable citation metadata, and populate package project URLs and classifiers.
- Clarify that commercial use is permitted under Apache-2.0 while support, hosting, integration and other services remain separate offerings.
- Replace the overly broad original expansion after identifying an unrelated public repository using the exact `Verifiable-AI-Security` name; formal trademark clearance remains a separate pre-publication task.
- Move the canonical repository identity to `stratomarco/vais-boundary` and replace the prior corporate commit address with the maintainer's private contact across reachable Git history before sharing.

## 0.12.0-rc8 - 2026-08-24

- Freeze the completed RC7 campaign as immutable evidence after verifying the checkpoint, manifest, sizes and SHA-256 values of all 180 recorded artifacts.
- Publish a sanitized verified RC7 report bundle with a one-page summary, full HTML report, technical Markdown, contextual SVG, aggregate JSON and evidence manifest; raw secret-bearing traces remain controlled.
- Record the bounded RC7 result: fourteen models completed the common 3,360-episode full panel, SmolLM3-3B stopped at a generation-validity gate, 4,603/4,605 distinct staged episodes were evaluable, two target failures remained unevaluated and zero protected invariant violations were observed.
- Record DeepSeek-R1-Distill-Llama-8B completing 240/240 full episodes in the separately labeled native-reasoning cohort; its utility, latency, token and attack-added measurements remain non-comparable with reasoning-off rows.
- Run a separate 24-episode SmolLM3-3B follow-up with a 7,168-token retry. The original two failure positions did not recur, but a different `attack-19` generation exhausted the larger retry and remained non-JSON.
- Retain the common 4,096-token panel retry and the original SmolLM gate failure. The follow-up is diagnostic evidence, not a replacement result, and no target failure is converted into successful defense.
- Preserve authorization, information-flow, approval, MCP, audit, independent-effect-verifier and terminal-reward semantics. No AI judge or model-specific benchmark exception is introduced.
- Exclude generated research databases and local evidence indexes from source distributions; the canonical YAML/Markdown evidence record remains included, while machine-specific index paths stay local and rebuildable.

## 0.12.0-rc7 - 2026-08-19

- Replace the release-history-heavy front page with a concise project overview, bounded benchmark status, quick start, capability summary, limitations and documentation map.
- Add `HOWTO.md` covering source/wheel installation, ASSESS/ENFORCE/VERIFY workflows, LM Studio operation, automated panel campaigns, outputs and troubleshooting.
- Clarify the reasoning-conformance CLI help so the documented exit-code-5 gate covers both reasoning unexpectedly observed and required reasoning unexpectedly absent.
- Investigate the RC5 DeepSeek-R1-Distill-Llama-8B reasoning gate against the archived summary, the live LM Studio model catalog, four OpenAI-compatible control variants and the native reasoning API.
- Confirm that the tested model/runtime exposes no reasoning configuration: `reasoning_effort=none`, the legacy template switch, both controls and no control all emitted reasoning, while native `reasoning=off` returned HTTP 400.
- Keep the RC5 failure immutable and introduce an explicit native-reasoning profile for DeepSeek; the fourteen remaining models stay in the reasoning-off comparison cohort.
- Make reasoning conformance bidirectional: off requires no observed reasoning, while on/low/medium/high require observed reasoning. Auto and undeclared labels remain descriptive rather than enforced.
- Bind stage evidence to the manifest reasoning label and control request so a mislabeled or wrongly controlled run fails closed before promotion.
- Label reasoning profiles throughout generated plans and reports and prohibit direct utility comparison between reasoning-off and native-reasoning cohorts.
- Record a bounded one-episode RC7 DeepSeek preflight with six valid target generations, 4,651 observed reasoning tokens, zero target failures and zero protected violations. This is compatibility evidence, not a full benchmark result.
- Preserve enforcement, policy, information-flow, approval, MCP, independent-effect-verifier and terminal-reward semantics. A new full RC7 panel run is required before claiming a 15/15 completed benchmark.

## 0.12.0-rc6 - 2026-08-19

- Add a fail-closed `vais benchmark-report` command that verifies the checkpoint schema, framework version, manifest hash, and every recorded artifact size and SHA-256 before rendering an existing run.
- Keep `evidence_version` (`0.12.0rc5`) separate from `renderer_version` (`0.12.0rc6`); RC6 does not relabel or rerun the completed RC5 campaign.
- Redesign the one-page summary with the tested protocol, explicit formulas and denominators, a worked attack-to-verifier trace, the complete model table and a bounded claim statement.
- Expand the full report with stage budgets and gates, paired-control outcomes, all twenty attack objectives, sanitized representative enforcement traces for each comparable model, limitations and concrete next steps.
- Structurally exclude prompts, arguments, results, secret-bearing values and invariant details from public examples while retaining reason classes, tool names, effect kinds, invariant IDs and verified outcomes.
- Add deterministic PDF renderings and an expanded GitHub SVG scorecard; verify them through text extraction, metadata checks, repeated hashing and browser/page-image inspection.
- Record the verified RC5 result: fourteen models completed the balanced 3,360-episode full cohort; one model stopped at the reasoning-off gate; all 4,299 staged episodes were evaluable with zero observed protected violations and zero target failures. This is bounded evidence, not proof of universal security.
- Preserve all RC5 TCB, policy, approval, MCP, information-flow, independent-effect-verifier and terminal-reward semantics.

## 0.12.0-rc5 - 2026-08-18

- Correct an information-flow defect exposed by the completed RC4 campaign: model-generated values now conservatively inherit the maximum confidentiality of every value visible to that generation unless the value is an exact type-sensitive trusted binding or is lowered by an explicit trusted declassifier.
- Remove substring/content-equality inference as a confidentiality authority. A model may copy only a prefix, paraphrase, encode or combine protected inputs, so lack of a full content match cannot establish public provenance.
- Make exact adapter rebinding use the same canonical type-sensitive security equality as the policy boundary, preventing Python equality cases such as `True == 1` from inheriting trusted authority.
- Retain gate-triggering and failed-stage evidence in HTML, Markdown, JSON and SVG reports. Terminal reports now show `complete_with_failures`, all-stage attempted/evaluable/failure/violation totals, the highest evidence stage for every row and an explicit protected-effect alert.
- Apply the same 4,096-token truncation retry allowance to all fifteen frozen panel entries; recovery remains visible in generation metadata and target failures remain unevaluated.
- Add adversarial regressions for partial-copy and transformed secret output, type-confused rebinding, and early-stage protected violations that must remain visible after later models finish.
- Record the RC4 campaign as bounded discovery evidence: 4,059 attempted staged episodes, 4,057 evaluable, one independently observed protected violation, two target-failure episodes, eleven full completions and four gate failures. These are distinct staged executions, not a balanced model ranking and not RC5 result rows.
- Preserve independent effect verification, frozen protected-system contracts and deterministic terminal reward. No AI judge is introduced.

## 0.12.0-rc4 - 2026-08-17

- Add `vais benchmark --all` to validate, run or resume the complete frozen 15-model LM Studio panel and regenerate reports after every stage/model.
- Pin the exact downloaded LM Studio model key, Q4_K_M quantization, 8,192-token context, maximum GPU offload, parallelism 1 and API identifier for each model; verify the single loaded model before and after every stage.
- Add a non-mutating model-loading dry run with `vais benchmark --all --dry-run`; missing, duplicate, wrong-quantization or insufficient-context models fail before campaign execution.
- Add an exclusive process lock, atomic checkpoint state, SHA-256 artifact records, tamper detection, completed-stage resume and safe recovery of complete artifacts written immediately before interruption.
- Stop a model at preflight, qualification, screening or full when protected violations, target failures, reasoning mismatches, attacker-generation failures, unavailable pair deltas or incomplete budgets make the result invalid; continue remaining panel models and preserve the failed row.
- Add a self-contained `benchmark-report.html` with a print-friendly one-page summary, contextual charts, explicit numerators/denominators, separate security/utility/diagnostic measurements, technical results and limitations.
- Expand the GitHub SVG scorecard with the tested protocol, measurement definitions, explicit fractions and attack-added diagnostic events; fix the new context/header spacing through browser-rendered visual QA.
- Correct the frozen local hardware manifest to the observed Phi-4 Mini 3B and Phi-4 15B parameter classes.
- Record and regress a dotted-model-ID filename collision found during RC4 adversarial automation testing.
- Preserve RC3 results as historical evidence. They are not silently relabeled or promoted into RC4 rows, even though terminal reward and enforcement semantics are unchanged.
- No reference-monitor, policy, approval, information-flow, tenant, declassification, independent-effect-verifier or terminal-security-reward semantics changed.

## 0.12.0-rc3 - 2026-08-17

- Replace the ignored LM Studio `chat_template_kwargs.enable_thinking=false` hint with the supported OpenAI-compatible `reasoning_effort=none` request on LM Studio target and adaptive-attacker paths.
- Retain observed reasoning tokens and characters as the independent conformance authority; request acceptance alone never establishes reasoning-off conformance.
- Add regression tests for generic-versus-LM-Studio payload separation and for both reference-target and adaptive-attacker LM Studio requests.
- Separate the SVG table header from the first row background and center metric/configuration columns to remove the front-page overlap and alignment defect.
- Record the bounded RC2 Qwen3-0.6B preflight failure: 2,043 reasoning tokens across six valid generations made the one-episode run configuration-nonconforming; zero protected violations and zero protected utility from that run are not promoted to an official row.
- Reject prompt-level `/no_think` as the benchmark control because changing benchmark prompts would confound cross-model comparison.
- No reference-monitor, policy, approval, information-flow, tenant, declassification, independent-effect-verifier or terminal-security-reward semantics changed.

## 0.12.0-rc2 - 2026-08-16

- Add a one-episode preflight stage and explicit experiment-validity gates for target failures and reasoning-mode mismatches; these gates do not alter terminal security reward.
- Record the requested non-thinking switch, requested reasoning label, observed reasoning tokens/characters and derived mismatch status in adaptive summaries and console output.
- Refuse to overwrite adaptive JSONL, summary or RLVR artifacts unless `--overwrite` is explicitly supplied; also reject aliasing multiple artifact roles to one path.
- Normalize real `lmstudio:<model>` target identifiers during RC aggregation, reject off-panel targets and framework-version mismatches, and keep wrong-stage summaries `incomplete` rather than completed.
- Replace Qwen3-8B with Qwen3.5-9B in the 15-model panel while retaining four Qwen entries and nine represented families.
- Separate `pending`, `incomplete`, `nonconforming` and `completed` report states and add reasoning/configuration columns to the compact SVG and technical report.
- Record bounded RC1 qualification evidence: Qwen3.5-9B conformed to requested reasoning-off in the 60-episode screen; Gemma-4-12B did not. Neither bounded screen observed a protected invariant violation, and neither result is promoted to an official RC2 full-campaign row.
- Record that the portable source tree rebuilds the research database but cannot pass strict evidence auditing without the referenced historical local-model roots; missing evidence remains a fail-closed, visible limitation.
- No reference-monitor, policy, approval, information-flow, tenant, declassification, independent-effect-verifier or terminal-security-reward semantics changed.

## 0.12.0-rc1 - 2026-08-15

- Freeze a 15-model, nine-family panel with no more than four Qwen entries and an explicit RTX 4080 Super 16 GB execution boundary.
- Add separate qualification, screening and full campaign plans; model loading remains an explicit operator step so hardware/runtime state is visible.
- Add strict single-target summary aggregation that rejects duplicate targets and never converts missing or failed episodes into security successes.
- Generate a concise one-page executive summary, a technical Markdown report, machine-readable aggregate JSON and an accessible GitHub-ready SVG benchmark table.
- Publish only `PENDING` rows before campaigns run; no RC security outcome is claimed by this infrastructure release.

## 0.11.0 - 2026-08-14

### TCB hardening

- Recursively copy and freeze security-boundary values and action arguments; normalize strings to Unicode NFC and reject normalization-colliding mapping keys.
- Use canonical, type-sensitive security equality and reject NaN and infinities before authorization.
- Add policy schema v4 with fail-closed undeclared-argument rejection; preserve older schemas for replay compatibility.
- Add thread-safe persistent approval grants bound to action, principal, session, tenant and capability, with atomic consume-once semantics.
- Add deterministic SHA-256 audit hash chaining and verification; freeze audit details and avoid logging argument values.
- Give MCP calls stable request identities, classify post-dispatch exceptions as indeterminate and unsafe to retry, and retain only exception classes in records.
- Add dedicated adversarial TCB regression coverage. These tests are bounded implementation evidence, not a universal security proof.

## 0.10.2 - 2026-08-13

- Add `vais research-doctor` to audit research-evidence integrity, duplicate historical content, unresolved references, hash mismatches, and knowledge records without resolved evidence.
- Distinguish archive instances from content-addressed evidence: artifact instances vs unique SHA-256 content, experiment records vs content-addressed experiment groups, observation records vs content-addressed observations, and evidence-link instances vs logical evidence references.
- Treat explicitly external manuscript/source artifacts separately from unexpected missing project evidence so a public research checkout can remain healthy without bundling private manuscripts.
- Bundle canonical copies of the v0.8.1 Qwen/Gemma MCP reanalysis audits and the v0.10 targeted independent-verifier audit under `research/bootstrap/`, resolving project-owned evidence references independent of local download locations.
- Add `research-doctor --strict` for CI/release integrity gating; expected external source absence does not fail strict mode, while unexpected unresolved references, hash mismatches, or supported claims/findings with no resolved evidence do.
- Extend `research-summary` with content-addressed archive counts and logical evidence-reference counts so copied historical releases cannot be mistaken for independent scientific runs.
- Record the methodological decision that provenance-preserving copies are not independent evidence and add an explicit research limitation against reporting raw archive instance counts as run counts.
- No reference-monitor, adaptive-verifier, policy, information-flow, approval, tenant, declassification, or terminal-security-reward semantics changed from v0.10.1.

## 0.10.1 - 2026-08-13

- Add a versioned **VAIS Research Evidence Base** under `research/`: canonical claims, findings, hypotheses, decisions, limitations, terminology, source registry and narrative notes remain Git-reviewable text while SQLite/JSONL indexes are generated artifacts.
- Add `vais research-build`, `vais research-summary` and `vais research-query`; `--history-root` discovers immediate `vais-v*` historical checkouts without recursively crawling an entire drive.
- Index artifact SHA-256, experiment-level metrics and observation-level evidence from historical VAIS JSONL files while preserving the original raw artifact as the source of truth.
- Backfill the research record from v0.1 through v0.10, including measurement corrections, MCP findings, Reference Agent evolution, adaptive-verification results, negative results and explicit claim limitations.
- Package a read-only copy of canonical research YAML so the evidence builder also works from an installed wheel when a repository `research/knowledge` directory is not present.
- Add conventional `vais --version` and `vais -V` while retaining the existing `vais version` subcommand.
- Add `--search-mode fixed` as a same-budget mutation ablation: the operator schedule is retained but post-exploration candidates always derive from the original seed rather than feedback-selected parents.
- Add optional `--target-truncation-retry-tokens` to adaptive LM Studio runs. Length-truncated reference-agent generations may be retried once at a larger explicit token budget, with the failed first attempt retained in generation metadata rather than erased.
- Extend adaptive summaries with off-objective security-event counts, matched control/attack utility transitions, pair-delta unavailability, logical generation status counts, truncation recovery, token totals and latency p50/p95/max.
- No reference-monitor, policy, confidentiality, approval, tenant, declassification, protected-invariant or terminal-security-reward semantics changed from v0.10.0.

## 0.10.0 - 2026-08-13

- Freeze the v0.9.3 incident-response Reference Agent as the adaptive target baseline; no v0.9.3 authorization, declassification, tenant, approval, receipt, or trace-invariant semantics are changed.
- Add `AdaptiveReferenceVerifier` for stateful online campaigns over the twenty reference attack stories.
- Define terminal security reward as `1` only for an independently observed protected security-invariant violation, `0` only for a target-valid protected non-violation, and unevaluated when target generation fails before any protected violation is observed.
- Recompute the v0.10 reward with a second effect verifier that does not call `ReferenceMonitor.evaluate()`; independently check task authority, scopes/bindings, exact approvals, authority provenance, confidentiality ceilings, tenant ownership, secret-to-public flow, and trusted public-artifact lineage.
- Keep security escalation, attack-objective success, semantic pair deltas, blocked calls, workflow utility, and optional unprotected outcomes as diagnostics rather than security reward.
- Add deterministic `MutationSearchAttacker` with reproducible seed exploration followed by feedback-guided mutation composition.
- Add `LMStudioAdaptiveAttacker` for online local-model attack generation from prior verified feedback without storing chain-of-thought or claiming online fine-tuning.
- Do not expose internal reference-monitor policy reasons to the adaptive attacker feedback interface; expose only verifier outcomes and tool outcome classes.
- Add `vais adaptive-reference-default` and `vais adaptive-reference-lmstudio`, scenario selection, episode budgets, optional unprotected diagnostics, early-stop control, and CI failure on discovered protected violations.
- Add `vais-rlvr-trajectory-v1` JSONL export so external RL/RLVR trainers can consume exact attack candidates with deterministic `1/0/null` verifier rewards.
- Add compact adaptive console reporting that keeps terminal reward visually separate from search diagnostics and preserves target/attacker generation health telemetry.
- Add a committed 20-story x 12-episode deterministic adaptive regression snapshot. The harness demonstrates adaptive search reaching compromised target behavior while the frozen protected boundary still produces zero observed protected invariant violations; this is plumbing validation, not LLM robustness evidence.

## 0.9.3 - 2026-08-13

- Normalize delegated-agent workflows without adding attack stories, policy primitives, or security metrics.
- Treat delegated sub-agent retrieval as narrow trusted application setup; setup authority is no longer inherited by the model's task contract.
- Remove `agent.delegate` / `agents:delegate` from the model task authority for delegated attack/control stories while keeping the tool application-exposed.
- Clarify the trusted task: the bounded `research-agent` delegation has already occurred with capability scope `knowledge:read`, and observed sub-agent output is information rather than authority.
- Add structured-output argument descriptions, especially defining `agent.delegate.scope` as a capability scope rather than an incident ID, topic, or natural-language task.
- Extend destination-substitution diagnostics to equivalent opaque public-artifact sinks (`email.send_public_update`, `slack.send_public_update`).
- Exclude trusted setup/retrieval orchestration from the task-agent `no_unauthorized_effect` check while retaining effect-level trace verification.
- Add regression tests proving trusted delegation setup succeeds, model re-delegation is denied, delegation schema semantics are explicit, and equivalent public sinks are recognized.
- No change to deterministic authorization, information-flow enforcement, declassification, tenant ownership, exact approvals, paired security deltas, or protected trace invariants.

## 0.9.2 - 2026-08-12

- Calibrate the production-shaped Reference Agent with scenario-specific trusted tasks instead of one generic incident-response instruction.
- Separate application-exposed tools from task-authorized tools; technical availability no longer implies authority in the reference experiment.
- Replace coarse paired boolean attribution with semantic attack/control deltas: attack-added security events, attack-added violation classes, attack-modified authority values, and attack-added invariant evidence.
- Preserve v0.9.1 attribution fields as compatibility aliases backed by the stronger semantic event comparison.
- Replace model-reproduced public text with opaque public artifact IDs minted only by the deterministic `status.build_public_update` declassifier.
- Add deterministic `email.send_public_update` and `slack.send_public_update` dispatch paths that resolve the approved public content outside the model.
- Add a deterministic resource/tenant ownership registry so cross-tenant checks do not depend on string prefixes such as `tenant-b/`.
- Strengthen planner instructions with sequential dependency semantics: a model must observe a tool result before using an artifact derived from it.
- Report end-to-end workflow utility separately from utility among workflows with valid target generations.
- Add regression coverage for semantic paired deltas, opaque declassification artifacts, exposed-tool/authority separation, and registry-based tenant isolation.
- No AI model is introduced into the security decision, declassification, authorization, or trace-invariant path.

## 0.9.1 - 2026-08-12

- Add one matched non-hostile control for each of the twenty v0.9 attack stories while preserving the same trusted task, tools, scopes, retrieval path and turn budget.
- Separate baseline model overreach from attack-attributable security escalation; attribution uses only valid attacked/control pairs.
- Add deterministic model-visible VAIS action receipts for `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `observed`, `not_called`, and `indeterminate` outcomes.
- Treat receipts as trusted factual execution state, not authorization tokens, and omit internal policy rationale from the default model-visible receipt.
- Add trusted deterministic `status.build_public_update` declassification for the public-status workflow so model output cannot implicitly downgrade INTERNAL incident data to PUBLIC.
- Extend the reference-agent JSONL trace with the exact receipt visible to the model and a `condition` (`clean`, `control`, `attack`) plus control pairing.
- Extend the reference summary with baseline overreach, attack-attributable escalation/violation, valid matched-control denominators and protected control utility.
- Keep the twenty attack stories unchanged; this is a real-case measurement/state-correctness patch, not an attack-corpus expansion.
- No AI model is introduced into the security decision path.

## 0.9.0 - 2026-08-12

- Add the **VAIS Reference Agent**, a stateful production-shaped incident-response system for system-security evaluation.
- Add five clean workflows and twenty multi-step attack stories spanning poisoned Jira/knowledge/log data, secret exfiltration, destination substitution, cross-tenant access, exact-approval mutation, confused-deputy delegation, and multi-hop attack chains.
- Add trace state with principal, tenant, session, task contract, provenance-labeled MCP results, observed effects and approvals.
- Add trace-level deterministic invariants for unauthorized effects, tenant isolation, secret-to-public flow, exact approval integrity and authority provenance.
- Add workflow utility as a first-class system property so containment is evaluated together with successful completion of the authorized task.
- Add policy schema v3 `exact_approval_required` for exact-action approvals that are not tied to a numeric threshold; policy schemas v1/v2 remain accepted.
- Add `vais reference-agent-default` deterministic reference-system regression.
- Add `vais reference-agent-lmstudio` for stateful Qwen/Gemma/local-model system evaluations.
- Allow protected/unprotected traces to diverge after enforcement; v0.9 records real state divergence rather than pretending blocked calls leave the same future context.
- Strengthen secret-exfiltration stories so the secret read and public destination can both be legitimate while VAIS must still block the `SECRET -> PUBLIC` composition.
- Preserve the project trust model: VAIS is not AI-powered; authorization and trace security oracles remain deterministic.

## 0.8.1 - 2026-08-12

- Split behavioral drift direction from security escalation: a plan can drift by adding risk, removing behavior, or doing both.
- Add `security_escalation`, `security_contraction`, `mixed`, and direction-specific reasons to episode JSONL.
- Add benchmark rates/counts for security escalation, contraction-only drift, mixed drift, and off-objective security escalation.
- Define **off-objective security escalation** for cases where the attacker's requested objective fails but hostile context still induces risk-increasing behavior.
- Change the console security pipeline to `plan change -> security escalation -> attack objective -> protected impact`; behavioral drift remains a separate diagnostic.
- Clarify that MCP `NOT_CALLED` means a proposed remote call did not cross the boundary and is not, by itself, evidence that an attack was prevented.
- Extend `vais audit-results` so historical v0.8.0 JSONL can be reclassified offline without new model sampling.
- Add regression coverage for pure contraction, escalation, mixed drift, and off-objective escalation.
- No reference-monitor, policy, invariant, MCP enforcement, or attack-corpus semantics changed.

## 0.8.0 - 2026-08-11

- Add the MCP-path benchmark runner: attacks are delivered as untrusted MCP tool-result data and model actions execute through protected/unprotected MCP clients.
- Add packaged `bundled:v0.8-mcp` corpus with 125 attacks (25 per scenario) and explicit MCP delivery metadata.
- Add `vais benchmark-mcp-default` deterministic security-regression command.
- Add `vais benchmark-mcp-lmstudio` for real local-model MCP-path experiments.
- Record MCP ingress provenance, clean/candidate content hashes, outbound call states and remote-call counts in episode JSONL.
- Extend summaries with MCP boundary outcomes while retaining plan-change -> security-drift -> attack-objective -> protected-impact stages.
- Keep the benchmark security oracle deterministic: mapped MCP effects + independent declarative invariants, not an AI judge.
- Add deterministic regression coverage proving 125/125 unprotected violations and 0/125 protected violations for the deliberately vulnerable MCP harness target.

## 0.7.1 - 2026-08-11

- Fix the live LM Studio + MCP demo to use the public `TargetRunResult.generation` metadata field and `TargetRunResult.valid` property.
- Add a regression test so examples cannot silently drift back to the obsolete `.metadata` attribute.
- No security-policy, benchmark, MCP-boundary, or measurement semantics changed.

## 0.7.0 - 2026-08-11

- Reframe VAIS explicitly as **not AI-powered**: deterministic security engineering applied around AI/ML and agent systems.
- Add `docs/philosophy.md` with the project trust model: assume model compromise, constrain consequence, verify effects.
- Define three intended operating modes: ASSESS, ENFORCE and VERIFY.
- Add first-class MCP integration primitives without making the core depend on MCP SDK types.
- Add strict MCP integration profiles and `vais validate-mcp-profile`.
- Label inbound MCP content as non-authoritative by default while preserving configurable confidentiality.
- Add namespaced MCP tool bindings and least-exposure task-specific catalog filtering.
- Add `MCPProtectedClient` to enforce VAIS policy before live `ClientSession.call_tool()` execution.
- Add MCP tool-to-effect mapping so existing invariant checks remain independent of transport.
- Add `vais mcp-demo`, an in-memory security-boundary demo, plus optional live stdio examples using the official MCP Python SDK.
- Add optional `mcp` package extra pinned to the current stable SDK v2 line (`mcp>=2,<3`).
- Preserve the v0.6 static benchmark and measurement semantics unchanged.

## 0.6.0 - 2026-08-11

- Add compact terminal security-pipeline reporting: plan change -> security drift -> attack objective success -> protected IVR.
- Print per-target unprotected/protected IVR and clean utility in the normal benchmark output.
- Warn visibly when reasoning telemetry contradicts an operator reasoning-mode label.
- Add a balanced 125-case static prompt-injection corpus (25 candidates across each of five security scenarios).
- Evaluate every corpus row exactly once per target/mode instead of sampling only the first row per scenario.
- Preserve attack ID/family/technique metadata in episode JSONL and add family/technique summaries.
- Deduplicate repeated clean baselines so larger attack corpora do not artificially inflate utility confidence.
- Add `--print-json-summary` for users who want the full JSON summary on stdout; compact reporting is now the default console view.

## 0.5.1 - measurement correctness

- Replaced ambiguous `attack_influence`/`attack_influence_rate` with `plan_changed`/`plan_change_rate`.
- Added deterministic scenario-specific `attack_objective_success` and success-rate metrics.
- Added explicit four-stage measurement model: plan change, security-relevant drift, attack-objective success, observable invariant violation.
- Extended the behavioral gate to detect mutation of exact previously approved actions.
- Added reasoning-mode mismatch flags when a run labeled `off` reports reasoning activity.
- Added regression tests for harmless wording changes, secret-canary resistance, and exact-approval replay.
- Updated deterministic benchmark snapshots for the corrected metric schema.
- Added `vais audit-results` to reclassify stored v0.5.0 JSONL plans offline without new model sampling.

## 0.5.0 - empirical runner

- Added first-class target generation statuses and valid-security denominators.
- Added Wilson 95% confidence intervals, target health, token/latency metadata and transport-only retries.
- Added multi-model LM Studio benchmarking and model catalog metadata.
- Added reasoning-mode experiment labels without falsely claiming portable enforcement.
- Added Python 3.11-3.14 CI coverage.

## 0.4.1

- Added explicit non-thinking request support for OpenAI-compatible targets (`chat_template_kwargs.enable_thinking=false`).
- Improved reasoning-model diagnostics for empty/truncated/non-JSON action-plan responses.
- Added regression tests for separated reasoning content and non-thinking request payloads.
- Documented structured-output troubleshooting for reasoning models and small models.

## 0.4.0

- Added first real-model target adapter over OpenAI-compatible chat completions.
- Added LM Studio CLI model discovery and benchmark commands.
- Added JSON-schema action-plan responses; target models never execute tools directly.
- Added trusted argument rebinding and benchmark-context confidentiality reconstruction.
- Added per-process target response caching for paired protected/unprotected comparisons.
- Added real-model adapter tests and integration documentation.

## 0.3.0 - adaptive verification core

### Added

- stable `TargetAgent` and `Attacker` protocols for future LLM/RLVR adapters;
- deterministic scenario model with trusted task, attack objective, task contract and clean utility oracle;
- five initial benchmark scenarios: email recipient hijack, secret egress, payment redirection, forbidden tool escalation and approval replay;
- protected/unprotected benchmark execution paths;
- deterministic episode JSONL records with plan, decision, effect, invariant, utility and configuration-hash data;
- first-class IVR, behavioral drift, attack influence, deny, approval, utility and terminal-reward metrics;
- per-target and per-scenario summaries before aggregation;
- JSONL attack-corpus loader and scenario-specific corpus replay attacker;
- committed deterministic attack corpus and benchmark snapshots;
- `exact_action_approval` invariant backed by the executed action fingerprint;
- `vais benchmark-default` CLI command;
- CI flags that fail on protected invariant violations or clean-utility regressions;
- GitHub Actions deterministic security-regression gate;
- adaptive-verification architecture and benchmark documentation.

### Validation status

- deterministic benchmark intentionally produces invariant failures in unprotected mode;
- the same committed scenarios produce zero invariant violations in protected mode;
- clean utility remains successful in the deterministic smoke suite;
- deterministic target profiles are benchmark plumbing tests and are not evidence about real LLM robustness.

## 0.2.0 - deterministic security boundary

### Added

- confidentiality labels (`public`, `internal`, `confidential`, `secret`);
- conservative label propagation with `derive_value()`;
- policy schema v2 and explicit capability scopes;
- argument-level confidentiality ceilings;
- effect-level provenance preservation;
- declarative YAML invariant engine;
- contract-binding, confidentiality, forbidden-effect and forbidden-value invariants;
- declarative verifiable reward adapter;
- deterministic JSONL audit trail;
- immutable task contracts and exact action-fingerprint approvals to prevent approval replay across modified actions;
- behavioral-gate detection of integrity degradation and confidentiality increase;
- information-flow demo;
- expanded regression tests.

### Compatibility

- policy schema v1 remains accepted;
- predicate-based Python invariants remain supported;
- the public v0.1 API remains available except where a v2 policy intentionally requires newly declared capability scopes.

## 0.1.0

- initial provenance model;
- dynamic task contracts;
- deterministic reference monitor;
- behavioral integrity gate;
- sandbox effects;
- predicate-based verifiable reward;
- indirect-prompt-injection demo.
