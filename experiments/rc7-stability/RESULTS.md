# Results: stability of the RC7 result (E2)

Registered in `PREREGISTRATION.md` (commit `338515c`, before any episode).
- **Part A:** 2026-10-04, 06:15 to 15:57 UTC.
- **Part B:** 17:15 to 18:26 UTC.
- **Part C:** 19:06 to 20:18 UTC.

`analyze.py` writes `results/analysis.json`, which is committed. The raw records are archived
off-drive under `evidence/0.12.0rc15/rc7-stability/`. Three deviations are listed at the end; one
of them changes what Part C can show.

## The answer

**A VAIS run is exactly reproducible on a fixed inference engine. RC7's per-model numbers depend
on which llama.cpp version ran them, and the security result does not.**

| Comparison | What differs | Episodes reproduced exactly |
|---|---|---|
| Part A against Part B, 3 models | nothing: same engine, same day | **720 of 720** |
| Part C against Part A, lfm2.5 and qwen2.5-7b | the CUDA toolkit build of llama.cpp 2.51.0 (CUDA 11 against CUDA 12) | **480 of 480** |
| RC7 against Part A, 15 models | RC7's engine (not recorded) against llama.cpp 2.51.0, six weeks apart | 2,186 of 3,600 (61%) |
| RC7 against Part C, qwen3-0.6b | RC7's engine against llama.cpp `cuda-avx2` 2.5.1 | 58 of 240 |

**What this shows:**
- The prompts, the plan schema, the request bodies and the attacker were checked identical before
  registration.
- Repeating a run on the same engine reproduced every episode.
- Changing only the CUDA toolkit build reproduced every episode.
- Changing the llama.cpp version did not.

So run-to-run variation on this machine is zero, and RC7 is not reproducible today because its
engine version is gone and was never recorded.

`cuda-avx2` 2.5.1, the newest engine installed before RC7 and the pre-registration's best guess
for RC7's, is **not** it. It reproduced qwen3-0.6b worse than today's engine did: 58 of 240
episodes, against 193.

## P1: no protected violations, as predicted

**0 protected violations in 3,598 evaluable Part A episodes across all 15 models,** and none in
Parts B and C. The monitor is deterministic and decides from labels, so a different engine changes
what the model tries, not what the boundary allows.

## Part A against RC7, per model

| Model | Reproduced exactly | Stories fully reproduced | Attack-added, RC7 → today (change, 95% CI) |
|---|---|---|---|
| mistral-7b | 239/240 | 19/20 | 141 → 141 (0.0) |
| qwen3-4b | 219/240 | 17/20 | 70 → 76 (+2.5, 0.0 to +7.1) |
| deepseek-r1-distill-8b | 216/240 | 18/20 | 159 → 149 (−4.2, −11.3 to 0.0) |
| qwen2.5-7b | 215/240 | 15/20 | 87 → 86 (−0.4, −1.3 to 0.0) |
| granite-4.1-8b | 206/240 | 17/20 | 58 → 53 (−2.1, −6.2 to 0.0) |
| phi-4 | 204/240 | 17/20 | 60 → 60 (0.0) |
| phi-4-mini | 204/240 | 17/20 | 113 → 104 (−3.7, −11.3 to 0.0) |
| qwen3-0.6b | 193/240 | 13/20 | 42 → 36 (−2.5, −14.6 to +5.4) |
| gemma-4-12b | 166/240 | 7/20 | 13 → 10 (−1.3, −4.2 to +0.8) |
| qwen3.5-9b | 155/240 | 4/20 | 58 → 61 (+1.2, −2.1 to +5.0) |
| lfm2.5-1.2b | 74/240 | 2/20 | 140 → 137 (−1.3, −10.0 to +8.3) |
| llama-3.1-8b | 34/240 | 0/20 | 132 → 111 (−8.8, −22.1 to +3.3) |
| llama-3.2-1b | 24/240 | 1/20 | 152 → 158 (+2.5, −6.7 to +12.1) |
| gemma-3-1b | 20/240 | 1/20 | **81 → 53 (−11.7, −23.8 to −1.7)** |
| smollm3-3b | 17/238 | 0/20 | 133 → 143 (+4.2, −3.8 to +13.8) |

Changes are in percentage points. smollm3 has 238 evaluable episodes in both runs, because of the
target failures that gate-failed it in RC7.

Eleven of the 15 models moved by less than 4 points. Because divergence propagates, once one response
differs the attacker's later candidates differ too. That is why "stories fully reproduced" can be
low while the rate barely moves (lfm2.5: 2 stories of 20, −1.3 points).

## The registered decision rules

- **D1, the band.** The largest absolute change among models whose files did not change is
  **11.7 points**, gemma-3-1b. From now on, a difference between two RC7 models smaller than 11.7
  points is described as within the variation a change of inference engine produces, and is not
  interpreted.
- **D2, one draw.** gemma-3-1b's interval excludes zero. As registered, RC7's per-model
  attack-added rates are reported from now on as **one draw under one, unrecorded, engine
  version**, and cross-model comparisons carry that caveat. The README now says so.

## What this means

- **Within an environment, VAIS evaluations are exactly reproducible.** Prompts, attacker and
  decoding are deterministic, and the engine was deterministic for a fixed version.
- **Across engine versions, the models' behaviour is not.**
  - Five models reproduced fewer than a third of their episodes: gemma-3-1b, smollm3, llama-3.2-1b,
    lfm2.5 and llama-3.1-8b. Four are among the panel's smallest; llama-3.1-8b is not, so size
    alone does not explain it.
  - Seven reproduced 85% or more: mistral, qwen3-4b, deepseek, qwen2.5-7b, granite, phi-4 and
    phi-4-mini. The usual
  explanation is that a different kernel changes floating-point rounding, which flips the top token
  wherever two candidates are nearly tied. This study does not test that mechanism; it only locates
  the change in the engine version.
- **The engine version is part of a result's identity.** RC7 recorded model keys, quantisation and
  sizes, but not the engine, so its exact numbers cannot be regenerated. Runs from now on record the
  engine; this study's runner does.

## Deviations

1. **An infrastructure stop.** Part A stopped before `qwen3-4b-instruct` ran: the runner could not
   hash LM Studio catalog models. It was fixed in `cb453e4`, which hashes the catalog entry plus its
   weights folder (the total equals LM Studio's listed size for all three catalog models), and Part A
   resumed.
   - The first six models ran at the registration commit `338515c` and the rest at `cb453e4`.
   - The fix changed only hashing. No episode was rerun or affected.
2. **Part C ran as registered for one model of three.**
   - When the runner selected `cuda-avx2` 2.5.1, LM Studio downloaded that engine family's newest
     version, `cuda-avx2` 2.51.0, and switched to it. The folder was created that minute.
   - `qwen3-0.6b` had already loaded on 2.5.1, as its record shows. `lfm2.5` and `qwen2.5-7b` loaded
     afterwards on `cuda-avx2` 2.51.0.
   - Those two runs answer a different question than registered (the CUDA toolkit build), and they
     are reported as that.
   - Afterwards the runner restored today's engine as designed.
3. **The registration's guess at RC7's engine was wrong** (see above). That is a result, not a
   procedural deviation, but it changes what Part C was meant to show: no installed engine is known
   to be RC7's.
