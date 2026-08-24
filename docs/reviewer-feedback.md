# Reviewing VAIS Boundary

VAIS Boundary is looking for skeptical review, not endorsement. The most useful feedback identifies where the trust boundary, installation path, evidence, or limitations are unclear or incorrect.

Allow about 30–60 minutes. A useful review does not require running the fifteen-model benchmark.

## Suggested review path

1. Read the [README](../README.md) for the thesis, boundary and bounded results.
2. Read the [one-page benchmark summary](../benchmarks/rc/report/rc7-full-evidence/executive-summary.html).
3. Use the [full report](../benchmarks/rc/report/rc7-full-evidence/benchmark-report.html) when a denominator, attack story or model row needs more detail.
4. Follow the [HOWTO](../HOWTO.md) through installation and the no-model quick tour if you can run Python locally.

The published campaign contains two comparison cohorts. Fourteen models were configured for reasoning off. DeepSeek-R1-Distill-Llama-8B completed 240/240 full-stage episodes in a separately labelled native-reasoning cohort after RC7 corrected the experimental configuration assumption. SmolLM3-3B was the sole gate-failed model, with two target failures left unevaluated.

## Three questions

1. Could you understand what VAIS protects and what remains trusted or outside scope?
2. Could you install and run it? If not, where did the path fail or become unclear?
3. Do you trust how the benchmark results and denominators were derived? What evidence is missing?

Use the [reviewer feedback form](https://github.com/stratomarco/vais-boundary/issues/new?template=reviewer_feedback.yml) for public feedback. Use the dedicated [installation form](https://github.com/stratomarco/vais-boundary/issues/new?template=installation_problem.yml) or [benchmark reproduction form](https://github.com/stratomarco/vais-boundary/issues/new?template=benchmark_reproduction.yml) when one of those better fits the observation.

Suspected security vulnerabilities must not be filed as public issues. Use [GitHub private vulnerability reporting](https://github.com/stratomarco/vais-boundary/security/advisories/new) or the private contact in [SECURITY.md](../SECURITY.md).

## Evidence boundaries

- Zero observed protected violations is bounded evidence for the recorded executions, not proof of universal security or model safety.
- Workflow utility is task completion under protection, not a security score.
- Attack-added events are diagnostic behavioral drift, not protected invariant violations.
- Target failures are unevaluated, never successful defense.
- Utility and attack-added rates should not be compared across different reasoning profiles as if they were one controlled cohort.
- Do not post credentials, personal data, confidential application details, private prompts, or raw secret-bearing trajectories.

Reviewer names and contact details should remain in the reviewer's or maintainer's private address book. Public issues should contain only the technical observation and evidence needed to evaluate it.
