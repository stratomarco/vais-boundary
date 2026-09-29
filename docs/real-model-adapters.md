# Real model adapters

VAIS v0.5 treats the target model as a **planner**, never as the executor.

The model receives the scenario and returns a structured action plan. VAIS then:

1. parses the plan;
2. rebinds exact task-contract arguments to their original trusted values;
3. marks all other model-created values as `derived_untrusted`;
4. propagates confidentiality for registered benchmark context values/canaries;
5. compares clean and attacked plans;
6. sends the candidate through either the unprotected sandbox path or deterministic protected boundary;
7. verifies observable effects with the independent invariant engine.

This preserves the distinction between model influence and application security impact.

## LM Studio research adapter

`LMStudioTarget` uses two documented LM Studio surfaces for different purposes:

- `/v1/chat/completions` for JSON-schema structured target plans;
- `/api/v1/models` for native model metadata and capabilities.

The model catalog can expose architecture, quantization, parameter string, maximum context, loaded context, tool-use capability, selected variant, and supported/default reasoning modes.

Start the LM Studio server and list the native catalog:

```powershell
vais list-lmstudio-models
```

For full metadata:

```powershell
vais list-lmstudio-models --json
```

Then run one target:

```powershell
vais benchmark-lmstudio `
  --model "qwen/qwen3.5-9b" `
  --reasoning-mode off `
  --max-tokens 2048 `
  --attack-corpus .\benchmarks\attacks\default.jsonl `
  --output .\results\qwen35-v050.jsonl `
  --summary .\results\qwen35-v050-summary.json
```

`--reasoning-mode` is an **experiment label**. Configure the actual mode in LM Studio before the run. VAIS intentionally does not claim that the OpenAI-compatible endpoint can portably enforce model-specific reasoning controls.

Compare multiple model families in one run by repeating `--model`:

```powershell
vais benchmark-lmstudio `
  --model "qwen/qwen3.5-9b" `
  --model "google/gemma-4-12b" `
  --max-tokens 2048 `
  --attack-corpus .\benchmarks\attacks\default.jsonl `
  --output .\results\multi-model-v050.jsonl `
  --summary .\results\multi-model-v050-summary.json
```

Only use a shared `--reasoning-mode` label when it accurately describes all targets in that command. Otherwise run the configurations separately.

## Anthropic API adapter (Claude)

`vais adaptive-reference-anthropic` runs the reference-agent campaign with a Claude model as the target, through the Anthropic Messages API (P1b-2, DEC-065). The attacker, when one is used, is still a local LM Studio model; the RC stages use the deterministic mutation search and need no attacker model.

Install the optional SDK and give it a credential in the environment. VAIS never takes the key as an argument and never records it:

```powershell
pip install "verifiable-ai-security[anthropic]"
$env:ANTHROPIC_API_KEY = "<your key>"   # or `ant auth login`
```

The model sees the same prompt as an LM Studio target and returns the same plan, converted by the same code. The differences the API forces are recorded in every run's target metadata:

- **Plan schema.** Structured output uses `output_config.format`. The variants are combined with `anyOf` instead of `oneOf` (each is fixed by a `const` tool name, so they mean the same), and the 0 to 6 array bounds are checked after parsing, as on the LM Studio path.
- **No temperature.** Current Claude models reject a non-default temperature, so runs are not greedy and a replay can differ (LIM-071).
- **Thinking.** `--target-thinking adaptive` (the default) requests thinking with a summarized display, so its presence is observable; `between_tools` turns thinking off on Claude Sonnet 5.5; Claude Opus 5.5 cannot run with thinking off. `--target-effort` sets `output_config.effort`. A thinking block whose text the API omitted still counts as observed reasoning, so a declared `--target-reasoning-mode off` fails closed.
- **Served model.** Model identifiers are not dated snapshots; the model string each response reports is recorded as `served_models`.
- **Refusals.** `stop_reason: "refusal"` makes the step unevaluable (`finish_reason: refusal`, `error_type: ModelRefusal`, with the category). No refusal fallback is requested, because a fallback would let a different model answer inside the campaign.
- **Errors.** The SDK retries rate limits, overload and server errors (`--target-max-retries`); what still fails counts as a transport failure or timeout. A bad request, authentication or permission failure, or an unknown model stops the run with exit code 7 after its first call.

A preflight run measures the real cost per call before a full stage:

```powershell
vais adaptive-reference-anthropic `
  --target-model claude-opus-5-5 --target-effort low --target-reasoning-mode low `
  --scenario attack-01 --episodes 1 `
  --output .\results\api\opus-5-5-preflight.jsonl `
  --summary .\results\api\opus-5-5-preflight-summary.json `
  --rlvr-output .\results\api\opus-5-5-preflight-rlvr.jsonl `
  --fail-on-target-failure --fail-on-reasoning-mode-mismatch --fail-on-protected-violation
```

## Target failures are data

A malformed or truncated target response no longer aborts the benchmark.

For example, a reasoning model that spends its output budget before producing the final JSON plan is recorded as:

```json
{
  "target_status": "truncated",
  "security_evaluated": false,
  "generation": {
    "candidate": {
      "finish_reason": "length",
      "reasoning_tokens": 2047
    }
  },
  "terminal_security_reward": null
}
```

The exact fields depend on what the runtime returns. VAIS never interprets this as "attack resisted" or "defense succeeded".

## Retry policy

`--transport-retries` retries only timeout/transport failures. Invalid/truncated model plans are never silently regenerated.

This is deliberate: repeatedly sampling until a model returns a valid or favorable answer can bias the measured security outcome.

## Inference metadata

When the OpenAI-compatible response exposes usage data, VAIS records input/output/reasoning token counts and measured request latency. It stores only the **length/count** of separated reasoning text, not the reasoning content itself.

The summary deduplicates cached generation records so paired protected/unprotected comparisons do not double-count model work.

## Provenance reconstruction boundary

A model response is not trusted just because it contains the correct text. Only an exact value matching an immutable task-contract binding is rebound to the original trusted `Value`. Other model outputs remain `derived_untrusted`.

For v0.5, confidentiality reconstruction still uses explicit benchmark context values and literal canary matching. This is intentionally limited and is not presented as general semantic taint tracking through neural inference.

## Authentication

If LM Studio API authentication is enabled, VAIS reads either `LM_STUDIO_API_KEY` or `LM_API_TOKEN` from the process environment.

## Runtime references

Implementation behavior was checked against LM Studio's official developer documentation:

- Native REST API overview: https://lmstudio.ai/docs/developer/rest
- Native model catalog: https://lmstudio.ai/docs/developer/rest/list
- OpenAI-compatible structured output: https://lmstudio.ai/docs/developer/openai-compat/structured-output
