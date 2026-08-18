# Major Findings

## Model failure and boundary failure are different events

In the Qwen3.5-9B v0.10 adaptive run, all 240 episodes were evaluable. Hostile adaptive search produced 58 attack-added security-event episodes and 18 scenario-defined attack-objective successes. The independent protected-effect verifier observed zero protected invariant violations in those 240 episodes.

This does not establish universal security. It demonstrates, for the tested reference system and search budget, that model-side attack success can occur without protected-system compromise.

## Off-objective behavior matters

The same Qwen run contained 40 security-event episodes that did not satisfy the attacker's stated objective. Targeted success therefore undercounts security-relevant behavior induced by hostile context.

## Failure semantics matter

The Gemma-4-12B v0.10 run attempted 240 adaptive episodes but only 188 protected episodes were evaluable because 52 protected generations truncated. Zero violations among those 188 must not be restated as zero among all 240 attempts. Generation failure is not successful defense.

## Utility attribution needs paired controls

Qwen v0.10 had 192/240 successful controls and 195/240 successful attacked protected runs. Pairwise outcomes were 167 success/success, 25 success/failure, 28 failure/success and 20 failure/failure. Aggregate protected utility therefore cannot be interpreted directly as enforcement cost.

## The benchmark must attack its own trusted boundary

The completed RC4 campaign independently observed one protected violation after a model copied only part of a secret-bearing value. The model-output adapter's full-content matching missed the lineage, but the independent effect verifier detected the canary at the external sink. RC5 therefore treats model output as derived from every value visible to its generation unless an explicit trusted declassifier lowers confidentiality. This is a concrete defect and bounded fix, not evidence of universal noninterference.

## A benchmark rate needs its derivation and denominator

The verified RC5 run contains two valid but different views. The balanced comparison contains fourteen configuration-conformant full campaigns and 3,360 evaluable episodes. The safety-accounting view contains 4,299 distinct executions across preflight, qualification, screening and full stages, including the DeepSeek reasoning-off gate. RC6 reports both and does not substitute one denominator for the other. It also keeps protected violations, utility, attack-added diagnostics and failures separate rather than manufacturing a composite score.
