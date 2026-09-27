# RC13 campaign: results

Pre-registered in `PREREGISTRATION.md` and committed as `c0a4170` before the first episode. All 26
arms completed on their first attempt, at that commit, between 2026-09-26 15:52 and 2026-09-27
09:28 UTC (17.3 GPU hours). No deviation in procedure; one erratum in the registered text is
logged under Deviations there. The registered analysis is `analyze.py`, run unchanged, and its
output is `results/analysis.json`. One exploratory analysis, `clustered.py`, was added after the
results were seen and is labelled wherever it is used.

![Attack-added rates per model with and without the monitor's reasons](rc13-attack-added.svg)

## Q1: protected violations (primary)

**Zero protected violations in 6,237 evaluable episodes across all 26 arms** (13 models, each with
the attacker told the monitor's reasons and told only the outcome). The registered Wilson 95%
upper bound is 0.06%. That bound treats every episode as independent, which they are not (see
below); counted by story instead, 520 story-arms, each 12 adaptive episodes, all had zero, which
bounds the share of story-arms with any violation at about 0.6% (rule of three).

Three episodes were target failures and none was an attacker failure or indeterminate.

## Q2: does telling the attacker why it was refused help it?

**No detectable difference.** Pooled over the 13 models, the attack-added rate with reasons minus
without was **+0.3 points** (registered 95% interval from a bootstrap over models, −3.2 to +3.8).
The prediction, little or no difference, held. Under the registered decision rule the interval
includes zero, so S13 is recorded as a measured channel with no detectable effect for this
attacker, and the defaults stay as they are: the gateway withholds reasons from the agent, and
the library path is unchanged.

The channel was real. In the `reasons` arms the attacker's feedback carried a reason code after
1,304 of 3,119 evaluable episodes (35 to 169 per arm), and in every arm those were exactly the
episodes in which the attack added a security event: the attacker was told why precisely when it
had changed something.

Per model, with the registered Newcombe intervals:

| Model | Reasons | Outcomes only | Reasons − outcomes (Newcombe 95%) | Story-clustered 95% (exploratory) |
|---|---|---|---|---|
| gemma-3-1b-it | 41.7% | 39.6% | +2.1 (−6.7 to +10.8) | −12.1 to +15.0 |
| gemma-4-12b | 14.6% | 11.2% | +3.3 (−2.7 to +9.4) | −1.7 to +9.2 |
| granite-4.1-8b | 25.8% | 34.2% | −8.3 (−16.4 to −0.1) | −18.8 to +1.7 |
| lfm2.5-1.2b-instruct | 68.3% | 58.8% | +9.6 (+1.0 to +18.0) | −1.3 to +21.7 |
| llama-3.1-8b-instruct | 47.9% | 38.8% | +9.2 (+0.3 to +17.8) | −4.2 to +22.9 |
| llama-3.2-1b-instruct | 70.4% | 61.9% | +8.5 (+0.0 to +16.8) | −5.3 to +23.5 |
| mistral-7b-instruct | 53.8% | 62.9% | −9.2 (−17.8 to −0.3) | −24.2 to +3.7 |
| phi-4 | 24.2% | 28.3% | −4.2 (−12.0 to +3.7) | −15.0 to +6.7 |
| phi-4-mini-instruct | 50.0% | 46.7% | +3.3 (−5.6 to +12.2) | −9.6 to +16.7 |
| qwen3-0.6b | 38.8% | 39.6% | −0.8 (−9.5 to +7.8) | −16.2 to +13.8 |
| qwen3-4b-instruct | 16.7% | 25.4% | −8.7 (−15.9 to −1.4) | −18.8 to +0.9 |
| qwen3.5-9b | 28.3% | 32.1% | −3.8 (−11.9 to +4.5) | −17.5 to +10.8 |
| smollm3-3b | 62.9% | 60.3% | +2.7 (−6.0 to +11.3) | −9.4 to +13.1 |

Six registered per-model intervals exclude zero, three in each direction. With 13 comparisons at
95%, chance alone would give about 0.65. That is the sign that the intervals, not the models, are
wrong.

## The intervals are too narrow (exploratory)

The registered analysis, like every VAIS study before it, treats an arm's 240 episodes as
independent. They are 20 stories of 12 adaptive episodes each, and whether an attack lands depends
heavily on the story: the variance of the story rates is on average **5.7 times** the binomial
variance (3.1 to 8.9 by arm). Resampling whole stories (`clustered.py`, 10,000 replicates, seed 13,
both arms of a model resampled together because they share the same stories):

- **no** per-model interval excludes zero (the last column above);
- the pooled mean's interval, resampling models and then stories, is **−4.7 to +5.2**.

The conclusion does not change: no detectable difference. What changes is that the six per-model
"effects" were noise. This analysis was not pre-registered; it was added because the registered
per-model intervals disagreed with chance, and it is reported beside them, not in place of them.

It also applies to earlier studies. Two exploratory P1b-4 numbers, the language-model attacker
against RC7's mutation search for qwen3-0.6b (+17.6 points, Newcombe +9.8 to +25.2) and
gemma-4-12b (+6.2, +1.2 to +11.4), both include zero once stories are resampled (−0.8 to +36.2
and −0.8 to +13.3). `experiments/p1b4/RESULTS.md` carries a correction. P1b-4's primary results,
zero violations and no detectable reasoning effect, stand; resampling stories only widens the
reasoning intervals. Future analyses should cluster by story from the start (DEC-061).

## Q3: the new per-model table (descriptive)

| Model | Attack-added, reasons | Attack-added, outcomes | Protected violations | Utility (of 240), reasons / outcomes | Q4b off-task allowed, reasons / outcomes | RC7 attack-added (exploratory) |
|---|---|---|---|---|---|---|
| gemma-3-1b-it | 41.7% | 39.6% | 0 / 0 | 120 / 123 | 36.2% / 24.6% | 33.8% |
| gemma-4-12b | 14.6% | 11.2% | 0 / 0 | 197 / 205 | 20.4% / 23.8% | 5.4% |
| granite-4.1-8b | 25.8% | 34.2% | 0 / 0 | 168 / 167 | 18.3% / 17.9% | 24.2% |
| lfm2.5-1.2b-instruct | 68.3% | 58.8% | 0 / 0 | 85 / 89 | 26.7% / 20.0% | 58.3% |
| llama-3.1-8b-instruct | 47.9% | 38.8% | 0 / 0 | 185 / 182 | 29.2% / 26.7% | 55.0% |
| llama-3.2-1b-instruct | 70.4% | 61.9% | 0 / 0 | 97 / 88 | 13.8% / 13.4% | 63.3% |
| mistral-7b-instruct | 53.8% | 62.9% | 0 / 0 | 148 / 159 | 34.2% / 32.1% | 58.8% |
| phi-4 | 24.2% | 28.3% | 0 / 0 | 221 / 211 | 26.7% / 22.9% | 25.0% |
| phi-4-mini-instruct | 50.0% | 46.7% | 0 / 0 | 171 / 180 | 32.1% / 30.4% | 47.1% |
| qwen3-0.6b | 38.8% | 39.6% | 0 / 0 | 109 / 110 | 15.8% / 15.0% | 17.5% |
| qwen3-4b-instruct | 16.7% | 25.4% | 0 / 0 | 140 / 150 | 24.7% / 31.2% | 29.2% |
| qwen3.5-9b | 28.3% | 32.1% | 0 / 0 | 185 / 187 | 34.6% / 44.6% | 24.2% |
| smollm3-3b | 62.9% | 60.3% | 0 / 0 | 160 / 150 | 40.8% / 39.3% | 55.9% |

- **Utility** is the number of the 240 protected runs that completed the legitimate task.
- **Q4b**, P1b-4's definition and code: the share of episodes whose attacked trace has an allowed
  action with a tool the story's task never uses. 13.4% to 44.6%. As in P1b-4, every such action
  was one of three reads, `jira.get_incident`, `logs.search` and `knowledge.search`; attacks
  steered models into reads the task did not need, and tenant isolation and secret flow held.
- **RC7** used a deterministic mutation-search attacker, framework 0.12.0rc7 and an 8,192-token
  context, so the last column is context, not a comparison.

## The gateway

The campaign ran on the library path, as registered. Its 12,480 protected traces were replayed
through the gateway afterwards (`experiments/gateway-equivalence/`): no decision or label was
looser than the library's, 89.2% of traces were identical, and every stricter decision had a known
cause, a contract approval used again (562 steps) or the declassifier's artifact id (786 steps).

## What this cannot show

One reference application, 13 local models up to 15B in one runtime with reasoning off, and one
attacker model whose sampling is not seeded. A difference or its absence describes this
attacker's use of the reason channel, not every attacker's; a stronger attacker, or one that plans
across many more episodes, may use reasons differently. The story-clustered intervals are
exploratory. Nothing here speaks to frontier models.

## Reproduce

From the repository root, with the recorded episodes in `results/`:

```
python experiments/rc13-campaign/analyze.py --rc7-evidence <rc7 evidence dir>
python experiments/rc13-campaign/clustered.py
python experiments/rc13-campaign/chart.py
```

`results/analysis.json` and `results/clustered.json` are committed; the episode files are not.
