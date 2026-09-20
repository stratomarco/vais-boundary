# RC10 reviewer invitation

Personalize the first sentence and send this to five to ten people with complementary perspectives. Keep names, email addresses and responses containing personal information outside the public repository.

Suggested mix: AI/agent security, evaluation or red teaming, security architecture, agent development, and governance or assurance. Seek disagreement and practical experience rather than only people already aligned with the thesis.

## Message

Subject: Could you give me critical feedback on VAIS Boundary?

Hi [Name],

I am asking because of your experience with [specific reason].

I have been building VAIS Boundary, an open-source security boundary for AI-enabled applications. It treats the model as an untrusted planner: the model may propose actions, while deterministic policy decides authority and an independent verifier checks protected observable effects. It does not use another model as the security judge.

RC10 is now public. It carries the bounded fifteen-model local benchmark unchanged from RC9: fourteen models completed the full stage, including DeepSeek in a separately labelled native-reasoning cohort, SmolLM3 was the sole gate-failed model, and the verifier observed zero protected invariant violations in the recorded campaign. That is bounded evidence rather than a claim of universal security, and RC10 adds nothing to it.

What RC10 does add is a fail-closed fix in canonicalization, an attack-surface map that includes one surface shipping unmitigated, and a lab experiment whose two pre-registered primary outcomes both failed to validate. In that experiment a content-filter guardrail matched the enforced arm's catch rate; the difference showed up as cost, not catch. I would rather you saw that than a clean story.

Would you spend 30-60 minutes on three questions?

1. Could you understand what VAIS protects?
2. Could you install and run it?
3. Do you trust how the benchmark results and denominators were derived?

Repository: https://github.com/stratomarco/vais-boundary

Reviewer guide: https://github.com/stratomarco/vais-boundary/blob/main/docs/reviewer-feedback.md

RC10 release: https://github.com/stratomarco/vais-boundary/releases/tag/v0.12.0rc10

Direct notes are welcome, or you can use the structured reviewer form linked from the guide. Please report suspected security vulnerabilities privately rather than in a public issue.

Thank you,

Marco
