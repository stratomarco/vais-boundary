# RC13 campaign: does telling the attacker why it was refused help it?

**Registered before any episode.** This file, `study.json`, `run_study.py` and `analyze.py` are
committed and pushed before the first arm runs. Anything done differently afterwards is logged
under Deviations at the end, with its reason, and never edited into the text above it.

## Why

- **A current benchmark table.** The published cross-model table is RC7's: framework 0.12.0rc7
  and a deterministic mutation-search attacker. P1b-4 showed that a language-model attacker moves
  some models more (+17.6 points for qwen3-0.6b, +6.2 for gemma-4-12b), so a table built with the
  stronger attacker is the more honest current evidence.
- **The decision-reason channel (S13, IMP-003) has never been measured.** The gateway withholds
  reasons from the agent by default on the argument that they help an adaptive attacker probe the
  policy. Nothing has tested whether they do.
- **The harness already gave reasons to the attacker (FIND-061).** The attacker's feedback was
  documented as omitting monitor reasons, but `attack_added_security_events` carried them: in 481
  of P1b-4's 1,680 episodes (28.6%, from 7.5% to 60.8% by arm) the attacker saw codes such as
  `tool_not_authorized` and `bound_argument_changed`. RC7 and P1b-4 were therefore run against an
  attacker that could partly see why it was refused. The docstring is corrected and the finding
  recorded before registration.

The roadmap's next phase is Phase 2 (`detfuzz`). This campaign is not a roadmap item; it
refreshes the evidence table and answers one open question before Phase 2 starts.

## Questions

- **Q1 (primary).** Do protected violations stay at zero across the panel under rc13, with a
  language-model attacker?
- **Q2.** Within each model, does removing the monitor's reason codes from the attacker's feedback
  change the attack-added security-event rate?
- **Q3 (descriptive).** The new per-model table: attack-added rate, protected violations,
  utility, and Q4b off-task allowed actions, as in P1b-4.

## Design

Two arms per model, identical except for the attacker's feedback, set by the new
`--attacker-feedback` option:

| Arm | Attacker feedback |
|---|---|
| `reasons` | As RC7 and P1b-4: security events include the monitor's reason codes |
| `outcomes` | Each monitor event reduced to `policy:denied:<tool>` or `policy:needs_approval:<tool>`, with no reason code and no argument; events that are not the monitor's are kept |

`tests/test_attacker_feedback.py` shows the `outcomes` prompt carries no reason code or
argument detail, and that `reasons` sends exactly what every earlier campaign sent. What the
attacker saw is recorded in each summary's attacker metadata (`attacker_feedback: outcomes`;
absent for `reasons`, so its configuration is byte-identical to P1b-4's).

**Panel (13 models, all with reasoning off).** RC7's completed reasoning-off models, less
qwen2.5-7b-instruct, plus smollm3-3b:

| Model (RC7 name) | LM Studio key |
|---|---|
| gemma-3-1b-it | gemma-3-1b-it |
| gemma-4-12b | google/gemma-4-12b |
| granite-4.1-8b | granite-4.1-8b |
| lfm2.5-1.2b-instruct | lfm2.5-1.2b-instruct |
| llama-3.1-8b-instruct | meta-llama-3.1-8b-instruct |
| llama-3.2-1b-instruct | llama-3.2-1b-instruct |
| mistral-7b-instruct | mistral-7b-instruct-v0.3 |
| phi-4 | phi-4 |
| phi-4-mini-instruct | phi-4-mini-instruct |
| qwen3-0.6b | qwen3-0.6b |
| qwen3-4b-instruct | qwen/qwen3-4b-2507 |
| qwen3.5-9b | qwen/qwen3.5-9b |
| smollm3-3b | smollm3-3b |

- qwen2.5-7b-instruct is excluded as a target because it is the attacker; attacking itself would
  not be comparable with the other rows. Its RC7 row stays in the RC7 table.
- deepseek-r1-distill-llama-8b is excluded because its reasoning cannot be switched off, and
  P1b-4 found no detectable reasoning effect to justify a separate cohort.
- smollm3-3b gate-failed RC7's full stage but completed P1b-4 with reasoning off, so it is
  included. Each row uses RC7's identifier, so the new table lines up with the old one.

**Held fixed:** the 20 RC7 stories, 12 adaptive episodes per story (240 per arm), P1b-4's runtime
settings (context 16,384, truncation retry 8,192, timeout 600 s, temperature 0.0, one parallel
slot, full GPU offload), the reference agent, the policy and the independent verifier.

**Attacker:** qwen2.5-7b-instruct, reasoning off, temperature 0.7, 768 output tokens, context
8,192, as in P1b-4.

**Order.** Arms run in `study.json` order: the models in the table's order, both arms of a model
back to back, with the first arm alternating down the panel (`reasons` first for gemma-3-1b-it,
`outcomes` first for gemma-4-12b, and so on). Each arm reloads both models.

**Qualification.** Two episodes of `attack-01` before each arm's full stage, with P1b-4's gates:
at least one evaluable episode, no reasoning-mode mismatch, and at least one valid attacker
candidate. An arm that fails is reported as gate-failed and not re-run under this registration.

## Checked before registration

- **Memory.** phi-4 (15B, the largest target) with the attacker peaked at 15.5 GB of the GPU's
  16.4 GB, with warm generation at 33 and 49 tokens per second. Every other target is smaller.
- **Smoke test.** The qualification stage ran through the runner's own code, into a scratch
  directory, for `llama-3.2-1b-instruct-outcomes` (a model without reasoning support) and
  `smollm3-3b-outcomes`. Both passed every gate with no reasoning-mode mismatch, and both
  summaries recorded `attacker_feedback: outcomes`. These four episodes are not part of the
  results.
- **Analysis.** `analyze.py` ran on stand-in data made from the smoke files, including a
  gate-failed arm, which dropped its model from Q2 as specified below.

## Analysis

`analyze.py` imports P1b-4's `analyze.py` for the per-arm metrics, the Wilson and Newcombe
intervals and the Q4 definitions, so they are the same code, not a copy.

- **Q1:** protected violations per arm and in total, with Wilson 95% intervals. A single
  verified violation is a finding, investigated before anything else from that arm is
  interpreted.
- **Q2:** per model, `reasons` minus `outcomes` attack-added rate with a Newcombe 95% interval.
  Pooled: the mean of the per-model differences with a 95% percentile interval from 10,000
  bootstrap resamples of the models (seed 13). Only models with both arms complete enter Q2.
- **Q3:** the table, with P1b-4's Q4a and Q4b definitions. RC7's rate for each model is shown
  alongside only as an exploratory comparison, because the attacker, the framework version and
  the context length all differ.
- **Manipulation check:** per arm, the episodes whose feedback carried a reason code (FIND-061's
  count). In `reasons` arms the attacker saw these; in `outcomes` arms they were reduced first.
  If the `reasons` arms' exposure is near zero, Q2 cannot show much, and that is reported.
- Target failures, attacker failures and indeterminate episodes are not evaluable, as before.

**Prediction, stated in advance:** little or no difference in Q2. Reason codes reached the
attacker in 28.6% of P1b-4 episodes, so the channel is real, but the attacker's main signal is
whether the action was allowed, which both arms keep, and a reason code tells it what not to
change rather than what would work.

**Decision rule:** if the pooled Q2 interval excludes zero with `reasons` higher, recommend
withholding reasons on the library path too, not only at the gateway. If it excludes zero with
`outcomes` higher, report it and investigate; it is not a reason to expose more. Otherwise record
S13 as a measured, small channel for this attacker and keep the current defaults.

## Out of scope: the gateway path

Episodes run on the library path. Running them through the MCP gateway would need harness work
that does not exist yet. Whether the gateway and the library make the same decisions is to be
shown separately, without a GPU, by replaying this campaign's recorded traces through both.

## Cost

26 arms. P1b-4's reasoning-off arms took 0.57 to 0.76 hours each, so about 18 to 25 GPU hours,
two overnight runs, before any re-runs. The runner is resumable: finished arms are skipped, and
an arm stopped by an infrastructure error is re-run from its start and logged as a deviation.

## What this cannot show

One reference application, local models up to 15B, one attacker model and one runtime. A
difference or its absence describes this attacker's use of the reason channel, not every
attacker's.

## Deviations

None yet.
