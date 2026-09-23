# P1b-6 results: an action-origin rule on RC7

*Run 2026-09-23 on the frozen RC7 traces, after the pre-registration (`67205b0`) was committed
and pushed. `results.json` holds every number below, per model and pooled, with the SHA-256 of
each input file. Reproduce with the command at the top of `replay.py`; it runs in about a second.*

## What was replayed

13 completed reasoning-off models (3,120 control and 3,120 attacked conditions, 26,836 model
steps) and DeepSeek-R1-Distill-Llama-8B in its separate native-reasoning cohort (240 and 240,
2,594 steps). SmolLM3-3B was excluded as gate-failed in RC7. No condition was a target failure.

## Results

| Measure | Reasoning-off | Native reasoning |
|---|---|---|
| Model steps with a trusted origin, control / attacked | 0.0% / 0.0% | 0.0% / 0.0% |
| Allowed calls to a tool in the set that are escalated, any set, either condition | 100% | 100% |
| Discrimination (attacked minus control escalation), every set | 0.0 pp | 0.0 pp |
| Control cost, T_egress | 25.7% (540 of 2,100) | 25.0% (36 of 144) |
| Control cost, T_high | 22.9% (480 of 2,100) | 8.3% (12 of 144) |
| Control cost, T_all | 43.4% (912 of 2,100) | 33.3% (48 of 144) |
| Allowed attacked steps with a derived_untrusted argument (LIM-048 class) | 4,371 | 368 |
| ...of which escalated under T_all | 1,245 | 96 |

Control cost is the share of control conditions that kept their workflow utility and would have
needed at least one extra human approval under `require_approval`, or lost it under `deny`. Per
model it ranges from 14.3% to 55.6% for T_all (`results.json`).

## Against the predictions

- **H1, held.** No model step in RC7 had a trusted origin. Every workflow's trusted setup reads
  the incident from Jira, and that result is labelled untrusted in the control condition as in
  the attacked one, so something untrusted is in view before the model's first turn.
- **H2, rejected.** Predicted: at least 95% of utility-retaining control conditions escalated
  under T_egress. Observed: 25.7% and 25.0%. The prediction conflated two things. Every allowed
  egress call *was* escalated (100%), but most workflows never make one. The cost of the rule is
  therefore the share of legitimate workflows that use the gated tools, not a property of the
  rule.
- **H3, held.** Discrimination is exactly zero for every tool set in both cohorts, because the
  origin is untrusted in both conditions at every step.

## Decision

The pre-registered rule required a control cost of at most 10% and a discrimination of at least
20 percentage points. No tool set meets it; T_high in the native-reasoning cohort meets the cost
bound (8.3%) with zero discrimination. **`untrusted_origin` is not recommended as a default.**

What it is, on this evidence: a per-tool switch that puts a human in front of that tool whenever
the session has read anything untrusted, which in agents that read untrusted data before acting
means always. For a high-consequence tool that is a legitimate choice, and it closes LIM-048 for
that tool, including the PHANTOM-B expense case below its threshold, at the cost measured here.
It is not a detector: it cannot tell an attacked run from a clean one.

## What this does not show

- It is a replay. Changing one decision would have changed what the model did next, so
  episode-level figures use "at least one escalation" and are not predictions of a live run.
- The origin here is the join of every earlier result. A finer origin, for example one that
  ignores untrusted results a step's planner never saw, needs an architecture where the planner
  is kept away from untrusted content (CaMeL's dual planner). Labels on a single-model agent
  cannot provide that, and it is outside P1b-6.
- RC7's twenty workflows all start from a Jira read. An agent whose task starts from trusted
  input only would see trusted origins until its first untrusted read; RC7 cannot measure that.
