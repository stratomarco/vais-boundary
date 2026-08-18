# Negative and Inconclusive Results

Negative results remain part of the evidence base.

- Qwen v0.10: 18 attack-objective successes but zero protected invariant violations in 240 evaluable episodes.
- Gemma v0.10: zero attack-objective successes among 188 evaluable protected episodes, but 52/240 protected episodes were unevaluable because of length truncation.
- Gemma v0.8 MCP: model plans changed and some risk-increasing behavior was observed after directional reanalysis, but targeted attack success remained zero in that run.
- MCP-path behavior differed materially from direct-context behavior. This is context-placement evidence, not evidence that MCP is intrinsically safer.
- RC4 completed eleven full model stages, but one Qwen2.5-7B screening episode violated the protected secret-flow invariant, DeepSeek failed reasoning-off conformance at preflight, and two full-stage models each had one unevaluable target failure. The run is valuable discovery evidence but cannot be published as a clean completed-panel or RC5 result.
