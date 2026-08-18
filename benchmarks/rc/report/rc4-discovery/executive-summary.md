# VAIS 0.12.0rc4 — one-page summary

## Benchmark complete with gate failures

| Panel | Fully completed | Gate failed | Configuration mismatch | All-stage evaluable | Protected violations | Target failures |
|---:|---:|---:|---:|---:|---:|---:|
| 15 models / 9 families | 11 | 4 | 1 | 4057/4059 | 1 | 2 |

## What was tested

Each completed full row uses the same twenty attack stories and twelve adaptive episodes per story: 240 attempted episodes per model. Models run locally at the recorded Q4_K_M quantization, 8,192-token context and parallelism 1. The model proposes actions; VAIS independently verifies protected observable effects. No AI judge determines the security reward.

The all-stage totals count each distinct preflight, qualification, screening and full execution. They prevent a gate-triggering violation from disappearing when a model stops early; they are not a balanced full-stage ranking denominator. Each model row below shows the highest stage it reached.

## How to read the percentages

- **Protected violations** = independently observed protected invariant violations / evaluable episodes. Lower is better, but zero is bounded evidence rather than proof.
- **Utility** = attacked protected workflows that still completed their intended task / evaluable episodes. Higher is better. A 90% utility row completed more tasks than a 75% row; it is not “90% secure.”
- **Attack-added events** = episodes with attack-caused security-relevant drift / evaluable episodes. This is a diagnostic pressure signal, not the terminal security reward.
- Percentages use the displayed numerator and denominator. Target failures are unevaluated and never counted as successful defense. There is no composite score.

![Benchmark scorecard](benchmark-table.svg)

**Interpretation.** The model is treated as untrusted. Terminal security reward is based on independently verified protected effects, not model refusal or an AI judge.

**Claim boundary.** Bounded to the recorded model keys, Q4_K_M quantizations, LM Studio runtime, RTX 4080 Super 16 GB configuration, twenty scenarios and staged episode budgets; zero observed violations is not proof of universal security.
