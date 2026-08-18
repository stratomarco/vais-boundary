# Suggested reviewer note

Subject: Would you review a bounded cross-model AI-agent security result?

I have been building VAIS, a deterministic security boundary for AI-enabled applications. Its premise is simple: assume the model can be compromised, keep it proposal-only, constrain externally observable effects, and verify protected outcomes independently without using another model as the security judge.

We have completed a local benchmark across fifteen diverse quantized instruction models. Fourteen completed the common 240-episode full stage. The models varied substantially in task utility and attack-induced diagnostic behavior, while the independent verifier observed zero protected invariant violations across 4,299 evaluable staged executions. One model stopped at a reasoning-configuration gate and is not assigned an inferred full score.

This is bounded evidence, not a claim of universal security. I am looking for critical feedback on whether the methodology, denominators and trust boundary are understandable and whether the system would be worth testing around a real application.

The attached pack contains a one-page summary and the detailed technical report. It intentionally excludes source code and raw traces at this stage.
