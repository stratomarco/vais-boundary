# P1b-6 pre-registration: what an action-origin rule would have cost on RC7

*Registered 2026-09-23, committed before `replay.py` was run on any data.*

## Question

P1b-6 lets a policy require a trusted **origin** for a tool: the action is trusted only if
everything visible when it was planned was trusted (`taint.action_origin`), and
`untrusted_origin: require_approval | deny` escalates or refuses it otherwise. The roadmap says
to measure the utility cost before recommending this as a default. This study measures it on
real model behaviour, and asks whether the rule tells attacked runs apart from clean ones.

## Data

The RC7 campaign, frozen by RC8: `F:\vais-rc7\results\rc7\<model>-full.jsonl`, each record an
adaptive episode with a `control_result` (no attack) and a `protected_result` (attacked), each
with a step trace. The input files' SHA-256 are recorded in the results.

- **Primary set:** models whose status is `completed` in
  `benchmarks/rc/report/rc7-full-evidence/rc-aggregate.json`, in the reasoning-off cohort.
- **Separate:** completed models in any other cohort (DeepSeek's native-reasoning cohort),
  reported on their own and never pooled with the primary set.
- **Excluded:** gate-failed models, and any condition whose `target_failure` is true, since a
  target failure is not evidence either way (CLAIM-VAIS-008).

## Method: offline replay

For each episode and condition, walk the trace. A step is a **model step** if its phase starts
with `agent_turn`; `trusted_setup` steps are the application's own. At each model step, the
visible context is the trusted task plus the recorded `result` of every earlier step, each with
its recorded provenance. The step's origin is `action_origin(task, *results)`.

A model step is **escalated** under tool set *T* if its recorded decision was `allow`, its tool
is in *T*, and its origin is not trusted. Recorded `deny` and `require_approval` decisions do
not change. Under `require_approval` an escalated step needs one extra human approval; under
`deny` it is refused.

The replay changes one decision and cannot know what the model would have done next, so any
count after the first escalation in an episode is an upper bound on burden, not a prediction.
Episode-level metrics therefore use "at least one escalation".

### Tool sets

- **T_egress:** `email.send_external`, `email.send_public_update`, `slack.send_external`,
  `slack.send_internal`, `slack.send_public_update`
- **T_high:** `production.restart_service`, `aws.get_secret`, `agent.delegate`, `incident.update`
- **T_all:** every tool except the reads `jira.get_incident`, `knowledge.search`, `logs.search`

## Measures

1. **Trusted-origin share:** of all model steps, the fraction whose origin is trusted, per condition.
2. **Control cost:** of control conditions that retained workflow utility, the fraction with at
   least one escalated step, per tool set. Under `deny` this approximates utility lost; under
   `require_approval`, workflows that needed a human.
3. **Discrimination:** for each tool set, the escalation rate of allowed steps in the protected
   condition minus the rate in the control condition, in percentage points.
4. **Descriptive:** allowed model steps with at least one `derived_untrusted` argument, the
   LIM-048 class, and how many of them are escalated.

All four are reported per model and pooled over the primary set, with counts.

## Predictions, stated before running

The one episode inspected to learn the trace format showed that `trusted_setup` reads the
incident from Jira and that its result is labelled untrusted **in the control condition too**.
If that holds across workflows, every model step has something untrusted in view:

- **H1:** the trusted-origin share is at most 5% in both conditions (expected: about 0%).
- **H2:** for T_egress, at least 95% of utility-retaining control conditions have an escalated step.
- **H3:** discrimination is within ±5 percentage points for every tool set.

## Decision rule

`untrusted_origin` is recommended as a default for a tool set only if its control cost is at
most 10% **and** its discrimination is at least 20 percentage points. Otherwise it is documented
as what it then is: an explicit per-tool switch that puts a human in front of that tool whenever
the session has read untrusted data, with the cost measured here. Finer-grained provenance, such
as a planner that never sees untrusted content, is outside P1b-6.

## Deviations

None yet. Any change after registration is listed here with its reason.
