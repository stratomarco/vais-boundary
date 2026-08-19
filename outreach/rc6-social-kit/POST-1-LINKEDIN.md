# Main post

Attach: `vais-rc6-benchmark.png`

I’ve been building something called VAIS, and I’m at the point where I’d really like some outside feedback.

The basic idea is that an AI model should not be trusted to enforce its own security. VAIS treats the model as an untrusted planner: the model can propose actions, but deterministic controls decide what is actually allowed, and protected effects are verified independently. There is no second LLM acting as the security judge.

I recently ran a local benchmark with 15 different instruction models on a 16 GB GPU.

Fourteen models completed the common 240-episode evaluation, giving 3,360 comparable episodes. Across all completed stages, VAIS independently evaluated 4,299 episodes. The models behaved very differently in terms of task completion and attack-induced activity, but the verifier observed zero protected invariant violations in these particular runs.

That is bounded evidence, not proof that the system is universally secure. One model also failed the required reasoning-mode configuration check, so I did not give it an inferred full score.

I now have a one-page summary and a more detailed technical report explaining the methodology, attack scenarios, scoring, limitations and examples.

I’m looking for people who work with AI agents, security, red teaming, evaluation or AI governance and are willing to challenge the work. I’m especially interested in hearing what is unclear, what you don’t trust yet, and what evidence you would need before trying something like this around a real application.

If that sounds relevant, leave a comment or send me a message and I’ll share the review pack.
