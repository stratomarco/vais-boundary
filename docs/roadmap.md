# Roadmap

## Completed in v0.11.0

- TCB canonicalization, recursive immutability and type-confusion hardening
- scoped consume-once approvals and policy-v4 undeclared-argument rejection
- audit hash chaining and MCP indeterminate/retry identity semantics

## Next bounded work

- externally anchored/append-only audit storage
- transactional approval persistence with multi-process or distributed coordination
- application-specific MCP idempotency and effect-reconciliation adapters
- broader parser differential testing and cross-runtime canonicalization vectors
- independent security review and multi-version Python CI before public-release claims
- repeat selected RC5 campaigns to measure run-to-run stability before interpreting small cross-model differences
- run the complete RC7 panel from a clean output directory; do not mix RC5 summaries with the new reasoning-profile manifest
- seek independent reproduction on a separately managed machine and preserve its runtime, model and artifact identity as a distinct evidence set
- publish the explanatory RC5 evidence report for review while keeping raw secret-bearing traces controlled
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
