# Pre-registration: stability of the RC7 result (E2)

Registered 2026-10-03, before any episode of this study runs. The commit that adds this file is the
timestamp. The owner approved the design and Part C's engine switch on 2026-10-03.

## Why

RC7, the frozen 15-model panel run on 22 and 23 August 2026, is cited throughout the project.
Its per-model attack-added rates range from 5.4% to 66.3%, and the reports compare models with
them. Nobody has measured how much those numbers move when the same thing is run again. Until
that is known, a small difference between two models may be noise.

`docs/roadmap.md` has listed this as open work since rc8.

## Why a rerun can isolate run-to-run variation

Checked before registration, on 2026-10-03, against RC7's executed code (`F:\vais-rc7` at
`77eb7e7`) and current `main`:
- the model-facing prompts and plan schema are byte-identical, for every workflow and turn;
- the request bodies sent to LM Studio are byte-identical, captured from both trees with a
  recording transport: model, messages, response format, temperature 0, `max_tokens` 2048,
  `reasoning_effort: none`, `stream: false`;
- the mutation-search attacker has no randomness. Each candidate depends only on the story and the
  feedback from earlier episodes.

**So any difference between the rerun and RC7 comes from below VAIS:** the LM Studio runtime and
inference engine, the model files, or non-determinism in GPU inference. That is the variation a
reader of RC7 needs to know about.

**The inference engine has changed since RC7.**
- The engine selected today is `llama.cpp-win-x86_64-nvidia-cuda12-avx2@2.51.0`.
- RC7 did not record its engine, and LM Studio's server logs from 22 and 23 August do not name it.
- The CUDA 12 engine line was installed only from 19 September.
- The newest CUDA engine installed before RC7 is `llama.cpp-win-x86_64-nvidia-cuda-avx2@2.5.1`,
  installed 10 March 2026. That is the best inference for RC7's engine, not a record.

So the study has three parts, each separating one cause.

## Design

- **Part A, the panel today (primary). First night.** All 15 models of the RC7 panel, in RC7's
  run order, on today's selected engine. Same model keys, `Q4_K_M` quantisation, context length
  8192, `parallel` 1 and GPU offload `max`. This is what anyone reproducing RC7 now would get.
  - The full stage took 22 to 64 minutes per model in RC7, about 7.5 hours in all.
  - No subset is chosen, so nothing is selected.
- **Part B, repeatability (second night).** `qwen3-0.6b`, `lfm2.5-1.2b-instruct` and
  `qwen2.5-7b-instruct` are run again on today's engine. Comparing B with A for the same model
  isolates run-to-run variation with the environment held fixed.
  - The models were chosen before any run: the two fastest in RC7 and one mid-sized model.
- **Part C, the engine (second night).** The same three models on `cuda-avx2@2.5.1`, RC7's probable
  engine.
  - If C reproduces RC7 where A did not, the difference is the engine.
  - This needs LM Studio's runtime selection switched for those runs and restored afterwards.
    **[HUMAN]**: the owner approves that switch, or Part C is not run.
- **Stage:** RC7's full stage only, 20 stories × 12 episodes. The command and flags are exactly
  `benchmarks/rc/full-plan.ps1`'s, as RC7 ran them. RC7's earlier gates are not repeated: they
  admitted models to the full stage and did not change it.
- **Code:** the commit that adds this file.
- **Environment, recorded per model before it runs:**
  - the LM Studio version and inference runtime;
  - the loaded model's key, quantisation, size and path;
  - the SHA-256 of its model file. RC7 did not hash model files, so from now on the hash is the
    identity.
  - **Model file check:** if a model's file size differs from RC7's recorded size, it is a
    different file. That model is still run, and its comparison is reported as "model file
    changed", not as run-to-run variation.
- **Comparison:** RC7's raw records, archived under `evidence/rc7/`, against the rerun's.
- **Checked before registration:** all 15 model files are installed under the same keys, and every
  file's size equals RC7's recorded size to the byte. The runner records the SHA-256 at run time.
- **Tools:**
  - `run_study.py --part A|B|C` runs each part, resumably. For Part C it restores the previously
    selected engine afterwards, whatever happens.
  - `analyze.py --rc7 <archived RC7 records>` decides everything below and writes
    `results/analysis.json`.
  - **Analysis validated before registration:**
    - the attack-added counts it computes from RC7's raw records equal the frozen RC7 report's, for
      all 15 models;
    - comparing RC7 with itself gives 240 of 240 episodes reproduced exactly and zero change;
    - one altered action is detected at its story and episode.
- **Raw records** go to `results/`, which is not in git, and are archived off-drive with the
  others when the study is reported.

## Measures

1. **Exact reproduction, per model.** The share of RC7's 240 episodes, matched by story and
   episode number, where the rerun produced:
   - the same attack candidate, by content hash;
   - the same sequence of proposed actions (tool and argument values), in the protected attacked
     run, the unprotected run and the matched control.

   Divergence propagates: one different response changes the feedback and therefore every later
   candidate in that story. So the first divergent episode of each story is also reported.
2. **Attack-added rate, per model and pooled:** the rerun minus RC7.
   - Per model, with a 95% interval that resamples stories, since episodes cluster by story
     (FIND-065).
   - Pooled over the models whose file did not change.
3. **Protected violations**, per model.
4. **Utility, target failures and gate outcomes**, as RC7 reported them.

## Predictions and decision rules

**P1. No protected violation in any model,** as in RC7. A violation is a finding and is reported
first.

**P2. No prediction on exact reproduction.** It is the measurement. RC7 was run six weeks earlier,
and whether LM Studio's runtime has changed since is not known in advance.

**P3, no prediction on the parts.** No prediction is made on whether B reproduces A exactly, or
whether C reproduces RC7. The three-way comparison is what attributes the change:
- RC7 against A: time, engine and files;
- A against B: pure repetition;
- RC7 against C: everything except the engine.

**D1, the reading rule for RC7.**
- After this study, a difference between two RC7 models is called "within run-to-run variation"
  if it is smaller than the largest per-model absolute change Part A observes among models whose
  file did not change.
- If every unchanged model reproduces exactly, the rule is that differences need only clear
  RC7's own sampling intervals.

**D2.**
- If, for any unchanged model, the story-resampled 95% interval of the change in its attack-added
  rate (Part A minus RC7) excludes zero, RC7's per-model rates are reported from then on as one
  draw. The cross-model comparisons in the reports get a caveat.
- If none does, the per-model rates are reported as stable to within the observed change.

## Deviations

These are logged in `RESULTS.md`:
- an infrastructure stop and rerun;
- a model no longer available;
- a changed model file;
- anything not done exactly as written.

A model that cannot be loaded is reported as not rerun. It is not replaced.
