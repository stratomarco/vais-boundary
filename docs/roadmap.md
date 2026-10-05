# Roadmap

*Current state, updated 2026-10-03. Everything below "Completed in v0.11.0" is the earlier
record, kept as it was written.*

## Where the project is

- **Released:** v0.12.0rc15. On `main` since then, unreleased:
  - caps on an amount for each allowed value (DEC-069);
  - the gateway replay for the accounts-payable application (FIND-073);
  - the Tier-A guardrail cost study (FIND-074).
- **Releases are held** until there is substantially more to ship. The next may be 0.13 rather
  than another release candidate.
- **Every study is listed with its result in `research/knowledge/findings.yaml`.** The
  pre-registered ones live under `experiments/`.

## This round: completing the VAIS evidence

1. **Cross-session flows: done** (FIND-075, DEC-070). Trust does not survive a store, but
   confidentiality and minted authority can; profiles can now declare their stores, and the
   gateway refuses to start while a declared store is unsafe. `experiments/cross-session/`.
2. **Stability of the RC7 result: done** (FIND-076). Exactly reproducible on a fixed inference
   engine; across llama.cpp versions per-model rates moved by up to 11.7 points, so RC7's
   per-model rates are one draw (LIM-075). Zero violations reproduced. `experiments/rc7-stability/`.
3. **A stronger attacker against a frontier model.** Neither available attacker moved Claude
   Sonnet 5.5 (FIND-067, FIND-068), so enforcement on a frontier model is untested in effect.
4. **One evidence index:** every study with its registration commit, result, bounds and the
   location of its raw records.

## Next round: detection rules against equivalent variants

Operating-system telemetry and community Sigma rules, for four ATT&CK techniques, in a separate
repository for detection engineers. Its telemetry fidelity gate is pre-registered. Real execution
of every variant is preferred over synthesised telemetry.

## Open bounded work, after these rounds

- externally anchored, append-only audit storage (LIM-037)
- approval and session state coordinated across machines (LIM-057)
- a framework adapter with a dry-run mode
- a general declassification adapter that recovers the utility conservative lineage costs (LIM-023)
- application-specific MCP effect-reconciliation adapters
- broader parser differential testing and cross-runtime canonicalization vectors
- an independent security review, and independent reproduction on a separately managed machine
- structured-output runaway behaviour, without weakening target-failure gates
- `reasoning_effort=none` verified across a model panel, keeping the observed-reasoning fail gate
- cryptographic model-file identity when the runtime exposes a portable digest

Done since this list was first written: CI across Python 3.11 to 3.14 with and without the `mcp`
extra; the RC7 evidence report, published with the releases; the private remote backup; and
multi-process approval coordination on one machine (0.12.0rc13).

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
