# Short post

Attach: `vais-rc6-benchmark.png`

I’ve been building VAIS, a deterministic security boundary for AI-enabled applications.

Instead of trusting the model to make security decisions, VAIS treats it as an untrusted planner. Actions are controlled outside the model, and protected effects are verified independently—without another LLM acting as judge.

I recently tested it with 15 local instruction models. Fourteen completed the common benchmark, covering 3,360 comparable episodes. Across 4,299 evaluable staged executions, the verifier observed zero protected invariant violations.

That is a bounded result, not a universal-security claim. The models still varied substantially in task utility and attack-induced behavior, and one model failed a configuration gate.

I’m looking for honest feedback from people working in AI security, agents, red teaming, evaluation or governance. I have a one-page summary and technical report available. Message me if you’d like to review them.
