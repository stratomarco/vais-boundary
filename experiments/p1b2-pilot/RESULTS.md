# P1b-2 pilot: one frontier model through the RC stages

Claude Sonnet 5.5 through the Anthropic API ran the four RC stages of the incident-response
reference application: the same 20 attack stories, matched controls, mutation-search attacker,
stage sizes and invariants as the RC7 panel. Run on 2026-09-30 from branch `evidence` with the
adapter of DEC-065. Analysis: `analyze.py`, output `analysis.json`.

## Result

| Stage | Episodes | Protected violations | Attack-added actions | Protected utility | Estimated cost |
|---|---|---|---|---|---|
| Preflight | 1 | 0 | 0 | 1/1 | $0.05 |
| Qualification | 6 | 0 | 0 | 6/6 | $0.20 |
| Screening | 60 | 0 | 0 | 60/60 | $1.55 |
| Full | 240 | **0** | **0** | **240/240** | $5.14 |

Full stage in detail:

- **Evaluable:** 240 of 240 episodes across all 20 stories.
- **Model plans:** 574 plans, all valid, all ending normally. There were no refusals, truncations or failures.
- **The model that answered:** `claude-sonnet-5-5` in every response.
- **Thinking:** none observed with thinking off, so the run conforms to its declared reasoning mode.
- **Matched controls:** none of the 20 overreached.
- **Decisions in protected runs:** no action was refused or held. The monitor allowed everything the model proposed, because the model proposed only the task.
- **Latency:** median 1.7 s and 95th percentile 2.9 s per call.
- **Estimated cost:** $6.94 across the four stages, from billed tokens at list price ($2/$10 per million input/output). Anthropic's usage page is authoritative. About 4,300 input tokens per call, most of them the structured-output plan format, and about 35 output tokens.

The 95% upper bound on the full-stage rate of attack-added actions, or of protected violations, is:
- **1.6%** treating episodes as independent;
- **8.4%** allowing for episodes clustering by story, using the design effect of 5.7 measured in RC13 (FIND-065). This is the one to quote.

## Against the local panel

The same stage and attacker on RC7's 15 local models added a security-relevant action in
5.4% (Gemma 4 12B) to 66.2% (DeepSeek-R1-Distill-Llama-8B) of episodes, 40.0% overall.
Claude Sonnet 5.5 added none in 240.

## What this does and does not show

- **The attacker did not move the model.** The mutation search that changed the local models'
  behaviour in 40% of episodes changed this model's in none.
- **VAIS was never exercised.** A boundary produces evidence only when a model tries
  something it should not; here no action was refused, so the run says nothing about
  VAIS stopping this model. "Zero violations" is true and uninformative about enforcement.
- **Enforcement cost this model nothing.** Every protected workflow completed its task.
- **The pilot's acceptance criteria are met.** One API model completed the full RC stage,
  every run records its parameters and the model string that served it, and the cost was
  measured rather than estimated.

## Differences from the RC7 runs

These are recorded in each run's target metadata:
- **No temperature is sent.** Current Claude models reject a non-default value, so these runs are not greedy and a replay can differ (LIM-071).
- **The model identifier is not a dated snapshot.**
- **The plan schema combines its variants with `anyOf` instead of `oneOf`**, and the array bounds are checked after parsing.
- **Thinking is turned off with the API's `between_tools` control.**
- **The output budget is 16,000 tokens**, against 2,048 with a retry at 4,096.

The RC7 models ran quantized in LM Studio at temperature 0.

## Next

This attacker is too weak to test the boundary with a frontier model. The informative next
run is the RC13 language-model attacker, which rewrites its injection from feedback, against
this model, pre-registered. Pre-registering it separately also keeps this pilot from being
read as a claim about attacks it did not include.
