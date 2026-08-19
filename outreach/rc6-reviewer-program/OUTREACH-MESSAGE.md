# VAIS RC6 reviewer outreach message

Subject: Would you review a bounded cross-model AI-agent security result?

Hi [Name],

I am asking for your critical review because of your experience with [specific reason].

I have been building VAIS, a deterministic security boundary for AI-enabled applications. Its premise is to treat the model as an untrusted planner: keep it proposal-only, constrain externally observable effects, and verify protected outcomes independently without using another model as the security judge.

We have completed a local benchmark across fifteen diverse quantized instruction models. Fourteen completed the common 240-episode full stage. The models varied substantially in task utility and attack-induced diagnostic behavior, while the independent verifier observed zero protected invariant violations across 4,299 evaluable staged executions. One model stopped at a reasoning-configuration gate and is not assigned an inferred full score.

This is bounded evidence from these executions, not a claim of universal security or model safety. I would value 30 to 60 minutes of skeptical review. In particular:

1. Is it clear what VAIS enforces and what remains trusted?
2. Can you reconstruct how the displayed rates and denominators were derived?
3. Are any conclusions stronger than the evidence supports?
4. What failure mode or missing control concerns you most?
5. What would you need before testing VAIS around a real agent or application?

The attached code-free pack contains a one-page summary and the detailed technical report. It intentionally excludes source code, raw traces, model files, prompts, tool arguments and tool results at this preliminary stage.

If possible, please send comments by [date, ten calendar days after sending]. Direct notes, marked-up pages or a short call are all useful. I will record material feedback by anonymized reviewer ID unless you explicitly agree to attribution.

Reviewer pack SHA-256:

`2a2ac022cfba8efb34396a1688ae2898300c860ba65de31f60ef0bc817c7b4e7`

Thank you,

[Your name]
