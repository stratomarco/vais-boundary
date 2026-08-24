# RC9 reviewer invitation

Personalize the first sentence and send this to five to ten people with complementary perspectives. Keep names, email addresses and responses containing personal information outside the public repository.

Suggested mix: AI/agent security, evaluation or red teaming, security architecture, agent development, and governance or assurance. Seek disagreement and practical experience rather than only people already aligned with the thesis.

## Message

Subject: Could you give me critical feedback on VAIS Boundary?

Hi [Name],

I am asking because of your experience with [specific reason].

I have been building VAIS Boundary, an open-source security boundary for AI-enabled applications. It treats the model as an untrusted planner: the model may propose actions, while deterministic policy decides authority and an independent verifier checks protected observable effects. It does not use another model as the security judge.

RC9 is now public, together with a bounded fifteen-model local benchmark. Fourteen models completed the full stage, including DeepSeek in a separately labelled native-reasoning cohort. SmolLM3 was the sole gate-failed model. The verifier observed zero protected invariant violations in the recorded campaign, which is bounded evidence rather than a claim of universal security.

Would you spend 30–60 minutes on three questions?

1. Could you understand what VAIS protects?
2. Could you install and run it?
3. Do you trust how the benchmark results and denominators were derived?

Repository: https://github.com/stratomarco/vais-boundary

Reviewer guide: https://github.com/stratomarco/vais-boundary/blob/main/docs/reviewer-feedback.md

RC9 release: https://github.com/stratomarco/vais-boundary/releases/tag/v0.12.0rc9

Direct notes are welcome, or you can use the structured reviewer form linked from the guide. Please report suspected security vulnerabilities privately rather than in a public issue.

Thank you,

Marco
