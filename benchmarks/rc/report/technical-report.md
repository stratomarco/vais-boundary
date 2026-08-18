# VAIS RC cross-model benchmark

## Executive summary

# VAIS 0.12.0rc5 — one-page summary

## Results pending

| Panel | Fully completed | Gate failed | Configuration mismatch | All-stage evaluable | Protected violations | Target failures |
|---:|---:|---:|---:|---:|---:|---:|
| 15 models / 9 families | 0 | 0 | 0 | 0/0 | 0 | 0 |

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

## Model results

| Model | Family | Class | Evidence stage | Status | Eval | Protected violations | Attack-added events | Utility | Failures | Reasoning |
|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|
| qwen3-0.6b | Qwen | 0.6B | — | pending | — | — | — | — | — | — |
| qwen3-4b-instruct | Qwen | 4B | — | pending | — | — | — | — | — | — |
| qwen2.5-7b-instruct | Qwen | 7B | — | pending | — | — | — | — | — | — |
| qwen3.5-9b | Qwen | 9B | — | pending | — | — | — | — | — | — |
| llama-3.2-1b-instruct | Meta | 1B | — | pending | — | — | — | — | — | — |
| llama-3.1-8b-instruct | Meta | 8B | — | pending | — | — | — | — | — | — |
| gemma-3-1b-it | Google | 1B | — | pending | — | — | — | — | — | — |
| gemma-4-12b | Google | 12B | — | pending | — | — | — | — | — | — |
| phi-4-mini-instruct | Microsoft | 3B | — | pending | — | — | — | — | — | — |
| phi-4 | Microsoft | 15B | — | pending | — | — | — | — | — | — |
| mistral-7b-instruct | Mistral | 7B | — | pending | — | — | — | — | — | — |
| granite-4.1-8b | IBM | 8B | — | pending | — | — | — | — | — | — |
| deepseek-r1-distill-llama-8b | DeepSeek | 8B | — | pending | — | — | — | — | — | — |
| smollm3-3b | Hugging Face | 3B | — | pending | — | — | — | — | — | — |
| lfm2.5-1.2b-instruct | Liquid AI | 1.2B | — | pending | — | — | — | — | — | — |

## Method

Fifteen locally runnable instruction models are evaluated with the frozen twenty-story reference system and deterministic adaptive mutation search. Preflight, qualification, screening and full campaigns remain distinct. Gate-triggering evidence remains visible at the highest stage reached. Target failures are unevaluated, never security successes. Reasoning-mode mismatches are configuration failures, never security rewards. Percentages are separate measurements with explicit denominators; VAIS does not collapse security and utility into a composite score.

## Limitations

Quantization and runtime configuration are part of each tested system. The model key and runtime metadata are recorded, but the large model file is not cryptographically hashed by the runner. Family and size comparisons are descriptive; this benchmark does not identify causal effects of model family or parameter count. All-stage totals contain separate executions from multiple budgets and must not be interpreted as a balanced model ranking.
