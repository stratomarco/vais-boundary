---
layout: ../../layouts/Article.astro
title: "Trust the People: On the Human Half of the Security Problem"
description: "Thompson said to trust the people. But the people are subject to structural failures of judgment too, and the evidence for that is now uncomfortably good."
date: "2026-07-23"
canonical: "https://medium.com/@maconstantino/trust-the-people-on-the-human-half-of-the-security-problem-52769c13f94c"
---

*Third in a series. The first piece, [Trust Me, I am Compiled](../trust-me-i-am-compiled/), traced Ken Thompson's "Reflections on Trusting Trust" into the age of poisoned models. The second, [The Double Trinity](../the-double-trinity/), names six structural forces, inherited and native, that make ML systems hard to defend.*

There is a line near the end of my first piece that I have been thinking about ever since I wrote it.

Thompson closed his 1984 lecture with two sentences. The first is the famous one: "You can't trust code that you did not totally create yourself." The second is quieter and, I think, more important: "Perhaps it is more important to trust the people who wrote the software."

I used that line to close the practical wisdom section of that first article. The argument was straightforward: technical controls have limits. Cryptographic signatures prove provenance, not trustworthiness. Audit trails stop at the origin of whatever you trusted to start the chain. At some point, what you are really trusting is a set of human decisions made by people you may never meet. Thompson understood this in 1984. The AI supply chain makes it more true, not less.

What I did not ask, and should have, is this: what if the people cannot be trusted either? Not because they are malicious. Because they are human.

## The Assumption Inside the Double Trinity

The Double Trinity, as I mapped it in the previous piece, names six structural forces that make ML systems hard to defend. Three inherited from software security: Connectivity, Extensibility, and Complexity. Three native to machine learning: Opacity, Data Entanglement, and Adaptability. The framework is a map of how the machine operates against the defender. It says nothing about what the defender does to themselves.

The Trinity of Trouble that McGraw and Hoglund described in 2004 made the same implicit assumption: that there is a vigilant human on the other side. Someone who reads the threat model, implements the controls, and monitors the system post-deployment. Both frameworks are addressed to people who are paying attention.

But paying attention is not the default state. It is an effortful, fragile, intermittently available condition. And there is now evidence about what happens when we study it directly.

## The Empirical Answer

Shaw and Nave, in a 2026 preregistered working paper out of Wharton, ran three experiments with 1,372 participants across 9,593 trials.¹ The setup was deliberately clean: participants solved reasoning problems with and without access to an AI assistant. The AI's accuracy was manipulated. On some trials, it gave correct answers. On others, it gave confidently stated wrong answers. Participants retained full autonomy over their final responses. Nobody was told they had to follow the AI.

They followed it anyway. On trials where participants consulted the AI, and it was wrong, they accepted the wrong answer roughly 80% of the time. The researchers called this cognitive surrender: not a strategic delegation of judgment, but an uncritical abdication of it. The user stops constructing an answer and instead adopts one.

The effect was large and robust. It persisted under time pressure. It persisted when participants were given financial incentives for accuracy and immediate feedback after each question. Incentives and feedback reduced cognitive surrender. They did not eliminate it. Participants with higher trust in AI showed greater surrender. Those with higher analytical ability and a greater need for cognition showed more resistance. But the baseline pattern held across every condition tested.

Shaw and Nave frame their finding as a design and education challenge, which is fair. What it also is, for the purposes of this series, is an empirical answer to the question article one left open. We said we should minimize the trust surface. We said we should document our trust models. We said we should build resiliency and monitor for post-deployment drift. The question is whether the people responsible for doing those things are structurally positioned to do them when the system they are auditing is fluent, confident, and always ready with an answer. The data suggests they are not.

## The Narrative Above the Data

Alex Edmans, in "May Contain Lies," makes an argument that runs parallel from a different direction.² His concern is a chain of cognitive upgrades that happens so automatically we rarely notice it: a statement becomes a fact, a fact becomes data, data becomes evidence, and evidence becomes proof, with our biases quietly greasing each transition. The mechanism is not dishonesty. It is the way confident, well-packaged claims get processed by minds that are already inclined toward a particular conclusion. Stories, statistics, and studies all exploit it, because they all arrive dressed as things more certain than they are.

In the ML security context, this chain runs constantly. The model passed its safety evaluation: statement. The model is safe: a fact we conclude. Here are the benchmark scores: data. This is evidence of trustworthiness: evidence. The model is ready to deploy: proof we act on. None of the individual steps is fraudulent. The leap from statement to proof is nonetheless unjustified. A safety benchmark measures performance on a specific test set, under specific conditions, against specific threat models. We take it to mean trustworthiness in deployment, under novel conditions, against threats the benchmark was not designed to detect. A signed model tells you about provenance, as the first article put it. We take it to mean safety. The packaging arrives with the trappings of evidence: benchmarks, certifications, and responsible AI commitments. Our biases do the rest.

What makes this directly relevant to the series is that the Edmans failure and the Shaw and Nave failure are not simultaneous. They are sequential. The Edmans failure happens before the evaluation begins: by the time a security practitioner sits down to assess an AI system, their priors have already been shaped by vendor documentation, benchmark reports, and certification claims. They arrive at the evaluation having already accepted a narrative. The Shaw and Nave failure then happens during the evaluation itself: when they interact with the system, they tend to defer to its confident outputs. The practitioner has been epistemically shaped upstream by narrative and then cognitively surrendered downstream in practice. The two failures bracket the entire evaluation. Nothing in between reliably compensates for both.

## Where the Two Failures Compound

This is where the Double Trinity and the human evidence meet, and where the interaction becomes uncomfortable.

Opacity, the fourth force in the Double Trinity, means that ML systems cannot be meaningfully inspected. There is no source code to audit. The weights are unreadable. The behavior under adversarial conditions is not visible in the artifact. This is a structural property of the machine. Shaw and Nave show that even when inspection is possible, humans frequently do not perform it. On trials where the AI was wrong, participants who consulted it accepted the wrong answer four times out of five. The barrier to cognitive surrender is low when the output is fluent and confident. ML outputs are almost always fluent and confident. The machine's opacity and the human's tendency toward surrender are not independent vulnerabilities. They are compounding ones.

Adaptability, the sixth force, means that security properties expire post-deployment. A model changes through fine-tuning, continued training, and distributional drift. What was verified at release is not necessarily what is running six months later. Catching this requires sustained, deliberate monitoring by people whose attention does not drift. But sustained deliberate attention is precisely what cognitive surrender erodes. The same disposition that leads a participant to accept a wrong answer in a laboratory setting leads a practitioner to accept last quarter's safety evaluation as sufficient for this quarter's deployment. The vigilance that Adaptability demands is the vigilance that cognitive surrender structurally undermines.

## What We Have Named and What We Have Not

Across the first two pieces, we named six structural forces in ML systems, described what they mean in practice, and noted, following McGraw, that structural problems require structural responses. What we have not named is the structure on the other side.

The Double Trinity assumes a defender. Shaw and Nave describe what defenders actually do when the system they are supposed to scrutinize produces a confident output. Edmans describes how the benchmarks and certifications surrounding that system shape the story the defender tells themselves about whether scrutiny is even necessary. Together, they suggest that the human half of the ML security problem is not a matter of training, awareness, or good intentions. It is structural in the same sense as the Double Trinity. The forces are different. The altitude is different. But the logic is the same: these are not bugs in individual practitioners. They are properties of how humans engage with authoritative-seeming systems under conditions of complexity and time pressure.

Thompson said to trust the people. That remains the right instinct. But trusting the people requires understanding what they are actually up against, including the forces acting on their judgment.

That is the question this piece leaves open. And it is the one the next piece will try to answer.

---

¹ Shaw, S. D., & Nave, G. (2026). *Thinking — Fast, Slow, and Artificial: How AI is Reshaping Human Reasoning and the Rise of Cognitive Surrender.* Working paper, The Wharton School, University of Pennsylvania. [ssrn.com/abstract=6097646](https://ssrn.com/abstract=6097646)

² Edmans, A. (2024). *May Contain Lies: How Stories, Statistics, and Studies Exploit Our Biases — And What We Can Do About It.* Penguin Random House.

---

*A note on this version: section headings from the author's original draft have been restored for readability. The text is otherwise as published.*
