# Roadmap

*Current state, updated 2026-10-20. Everything below "Completed in v0.11.0" is the earlier
record, kept as it was written.*

## Where the project is

- **Released: v1.0.0.** 1.0 is the boundary: the reference monitor, contracts, provenance labels,
  approvals, session rules, declared stores, audit, revocation, and the MCP gateway with mints.
  Its public interface, command line and file formats are fixed for 1.x ([`formats.md`](formats.md)).
  The benchmark and research tooling that produced the evidence stays in the repository, under
  `vais lab`.
- **What 1.0 does not claim** is in [`threat-model.md`](threat-model.md): no independent security
  review, state coordinated on one machine, enforcement under a frontier model untested in
  effect, evidence bounded to what was recorded.
- **Every study** is listed in [`evidence-index.md`](evidence-index.md) with its registration,
  findings and bounds.

## After 1.0

1. **What the nearest system can express: done** (FIND-077). On VAIS's 93 reference workflows a
   Dogwood policy, AgentCore Policy's language, made every decision VAIS made once its authority
   sources were declared, and VAIS's positioning was narrowed accordingly (DEC-073).
   `experiments/dogwood-expressibility/`.
2. **One complete reference workflow, then a pilot.** Take one consequential workflow end to end:
   trusted authorization, a model-proposed action, enforcement before the effect, real tool
   execution and independent verification against the backend, with an evidence packet another
   developer can reproduce, and a handoff for a scoped external pilot.
3. **A stronger attacker against a frontier model.** Neither available attacker moved Claude
   Sonnet 5.5 (FIND-067, FIND-068), so enforcement on a frontier model is untested in effect.
4. **Detection rules against equivalent variants.** Operating-system telemetry and community Sigma
   rules for four ATT&CK techniques, in a separate repository; its fidelity gate is
   pre-registered. Whether and when it resumes is open.

## Open bounded work, in 1.x when needed

- externally anchored, append-only audit storage (LIM-037)
- approval and session state coordinated across machines (LIM-057)
- a framework adapter with a dry-run mode
- a general declassification adapter that recovers the utility conservative lineage costs (LIM-023)
- application-specific MCP effect-reconciliation adapters
- an independent security review, and independent reproduction on a separately managed machine

## Completed in v0.11.0

- TCB canonicalization, recursive immutability and type-confusion hardening
- scoped consume-once approvals and policy-v4 undeclared-argument rejection
- audit hash chaining and MCP indeterminate/retry identity semantics

## Next bounded work, as listed after v0.11.0 (superseded by the sections above)

- externally anchored/append-only audit storage
- distributed approval coordination across machines (multi-process on one machine is done in 0.12.0rc13; LIM-057)
- application-specific MCP idempotency and effect-reconciliation adapters
- broader parser differential testing and cross-runtime canonicalization vectors
- independent security review and multi-version Python CI before public-release claims
- repeat a preregistered subset of the frozen RC7 campaign to measure run-to-run stability before interpreting small cross-model differences
- investigate structured-output runaway behavior without weakening target-failure gates or granting model-specific benchmark budgets
- seek independent reproduction on a separately managed machine and preserve its runtime, model and artifact identity as a distinct evidence set
- publish the explanatory RC7 evidence report for review while keeping raw secret-bearing traces controlled
- create a private remote backup only after repository and secret scanning; public source release remains a separate decision
- verify `reasoning_effort=none` across the frozen model panel and retain the observed-reasoning fail gate for model/runtime combinations that reject or ignore it
- add explicit application declassification adapters and measure the utility cost of conservative model-output lineage without weakening the default fail-closed rule
- add cryptographic model-file or trusted catalog-revision identity when LM Studio exposes a portable stable digest; RC5 records exact keys, quantization and runtime configuration but does not hash multi-gigabyte GGUF files

## Completed in v0.12.0-rc6

- verified the immutable RC5 checkpoint, manifest and 171 artifact hashes before offline report rendering
- separated RC5 evidence identity from the RC6 renderer identity
- explained score derivation with formulas, stage budgets, paired outcomes and a worked verifier trace
- added structurally sanitized per-model examples and deterministic HTML, SVG and PDF artifacts
- preserved the no-composite-score rule and all RC5 security semantics

## Completed in v0.12.0-rc7

- traced the DeepSeek RC5 gate to an unsupported reasoning-off configuration rather than a generation or security failure
- tested the current adapter control, legacy template control, their combination and LM Studio's native reasoning-off request without suppressing observed evidence
- introduced separate reasoning-off and native-reasoning cohorts, with DeepSeek assigned to the latter
- made explicit reasoning conformance bidirectional and bound stage summaries to the manifest label and control request
- passed a bounded strict DeepSeek native-reasoning preflight while retaining the requirement for a new full panel run

## Completed in v0.12.0-rc8

- verified all 180 immutable RC7 checkpoint artifacts before freezing the public report
- recorded fourteen completed full-stage models, one SmolLM generation gate, 4,603/4,605 evaluable staged episodes and zero observed protected violations
- confirmed DeepSeek full-stage compatibility in its separately labeled native-reasoning cohort
- tested a larger SmolLM retry in a separate diagnostic and retained the original gate after a different generation still exhausted 7,168 tokens
- preserved the common protocol, target-failure semantics and all protected security-boundary behavior
