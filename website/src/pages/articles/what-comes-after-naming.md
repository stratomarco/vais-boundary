---
layout: ../../layouts/Article.astro
title: "What Comes After Naming"
description: "Three pieces named the problem: six structural forces in the machine, and two more in the defender. This one is the answer, and it is not a better assessment."
date: "2026-09-21"
---

*Fourth in a series. The first piece, [Trust Me, I am Compiled](../trust-me-i-am-compiled/), traced Ken Thompson's "Reflections on Trusting Trust" into the age of poisoned models. The second, [The Double Trinity](../the-double-trinity/), named six structural forces that make ML systems hard to defend. The third, [Trust the People](../trust-the-people/), showed that the people meant to defend against those forces are subject to structural failures of their own.*

The third piece ended with a question I left deliberately open. We had named six structural forces in the machine. We had then shown, following Shaw and Nave, that practitioners defer to confident AI outputs rather than scrutinise them, and, following Edmans, that the benchmarks and certifications surrounding a system have already shaped the practitioner's priors before the evaluation begins. The two failures bracket the assessment. Nothing in between reliably compensates for both.

Given all of that, what do we actually do?

I want to start with the answer I spent two months building and then decided not to publish, because the reason I set it aside is the argument of this piece.

## The instrument I did not ship

I built an assessment framework. Six domains, one per force. Seventy-two checks across three tiers, sequenced so a practitioner always has a defensible place to stop. Every check requires a written status and evidence notes, with no checkboxes, because the act of writing down what you could not assess is itself a security practice. The output was a trust map rather than a score, and a long residual risk register counted as an honest assessment rather than a failed one.

I still think the design is right. It is finished. I am not publishing it, and the reason is simple enough that I am slightly embarrassed it took me two months to see.

An assessment framework depends on the assessor's judgment at the moment of assessment. That is precisely the thing the third piece argued is structurally compromised, twice over, before and during. I had built the human-layer risk prompts into each domain as required interruptions, designed to interrupt exactly those failures. But a prompt asking someone to notice their own bias is close to the weakest intervention the evidence supports. The practitioner most likely to skim it is the one who most needs it.

I had answered "humans are unreliable assessors" with more assessing.

There is a second reason, and it is the one the draft of this piece already admitted at length. BSIMM earned its authority from observational data, starting with nine organisations and growing across successive versions. It measured practice. My framework described what I believed organisations should examine. Those are different claims with different epistemic weight, and shipping the second while gesturing at the first is the exact move Edmans describes: a statement dressed as evidence.

So the framework sits where it is until it has been run against real deployments. What follows is what I did instead.

## Stop improving the trust decision. Remove it.

Thompson's moral was that you cannot trust code you did not totally create yourself. Software security spent twenty years answering that with better inspection: code review, architectural risk analysis, threat modelling, a maturity model to measure who was doing it. That answer worked, partially, because inspection was possible. Difficult and incomplete, but possible.

Machine learning removes that premise. Opacity is not a degree of difficulty; it is a property of the artifact. There is no human-readable representation of what a model knows or intends. Code review has no equivalent. A backdoor implanted through data poisoning may be undetectable by any inspection of the model itself.

The second piece said the response to opacity was to invest seriously in interpretability and model auditing. I want to revise that, not quietly.

Interpretability is worth funding and I hope it succeeds. But it is a bet on a research programme with no delivery date, and in the meantime we are deploying these systems into ticketing, into medical triage, into code that runs in production. Making a decision contingent on interpretability arriving is a way of deferring the decision. Worse, it keeps the security property in the wrong place: inside the model, where you cannot check it.

There is another move available, and it is old. It is what memory-safe languages did to buffer overflows. Not "audit more carefully for pointer arithmetic errors" but "make the class of error unrepresentable." It is what capability security did to ambient authority. It is what "assume breach" did to network perimeters.

Applied here: stop trying to establish that the model is trustworthy. Assume it is compromised. Constrain what it is able to cause, and verify independently what it actually did.

## What that looks like when you build it

The model becomes an untrusted planner. It may propose any action it likes. It proposes into a boundary that sits between the proposal and the tool.

Authority does not come from the model, and it does not come from anything the model read. It comes from a task contract written when the task was defined: which tools are in scope, which arguments are bound to values established from trusted input, which capability scopes are granted. A document retrieved at inference time can influence what the model proposes. It cannot widen what the model is permitted to do, because it was never a source of authority.

Data carries provenance through the system. A value derived from an untrusted document stays untrusted, and confidentiality joins upward rather than downward, so a secret does not quietly become public by passing through an intermediate step.

And after execution, a separate component checks the observable effects against declared invariants. Not the model's account of what it did. The effects. That verifier is deliberately independent of the thing that made the authorization decision, so it can catch bugs in the authorizer.

Three modes, in the order you would actually use them: understand the exposure, keep authority outside the model, check what happened.

## Why this answers the third piece and an assessment framework does not

Here is the part that matters, and it is not a performance claim.

A deterministic boundary does not require a vigilant human at the moment of decision. Its behaviour does not depend on whether anyone read the threat model this quarter, or whether the practitioner was persuaded by a benchmark report before they sat down, or whether the model's output was fluent and confident enough to be believed. The decision is made by a reference monitor against a contract, and it comes out the same way whether the operator is paying attention or asleep.

That is the specific property the third piece was asking for. Not a control that helps a vigilant defender. A control whose correctness does not depend on vigilance at the point where vigilance is known to fail.

This does not remove humans, and I want to be precise about where they remain. Somebody writes the contract. Somebody writes the invariants. Those are trust decisions, and they can be wrong. But they are small, written down, reviewable, and made once, in advance, away from the moment of pressure. A default policy is a few dozen lines. Six invariants fit on a page. That is a very different object from a judgment call made in real time while looking at a confident answer.

The trust decision has not vanished. It has moved somewhere you can read it.

## Which of the six forces this touches, and which it does not

This is where most security tools stop being honest, so let me be specific.

**Extensibility** is the direct target. Retrieval, tool access, agent loops, documents arriving at inference time: this is the force that made the whole class of problem urgent, and mediating the proposal-to-tool boundary addresses it head on. Untrusted content can influence behaviour and cannot grant authority.

**Connectivity** is constrained in consequence, not in surface. The attack surface is exactly as unbounded as it was. What changes is what reaching it can cause.

**Adaptability** is addressed in an unusual way. The sixth force says security properties do not persist across model updates. These properties do persist, because they are not properties of the model. Swap the model, fine-tune it, let it drift: the contract and the invariants are unchanged and still enforced. That is a genuine answer to force six, and it is narrow. Nothing here tells you the new model got worse at its job. It tells you the new model cannot exceed the same authority.

**Complexity** is partially addressed, by relocation. The model remains incomprehensible. What becomes comprehensible is the boundary, which is small enough to read in an afternoon.

**Opacity** is not reduced at all. I want this stated plainly, because it is the revision I owe the second piece. This approach does not make the model inspectable. It removes the need to resolve opacity *for this class of risk*, by making the model's trustworthiness irrelevant to whether an unauthorized effect can occur. Opacity remains total for every other question you might want to ask, including whether the model is any good.

**Data Entanglement** is untouched. A poisoned model is still a poisoned model. Nothing in this approach reaches the training pipeline, validates a dataset, or detects a backdoor. It constrains what a backdoored model can do once it is deployed behind a boundary. If the harm you care about happens during training, this is not the tool.

Three forces meaningfully addressed, one relocated, one sidestepped, one untouched. That is the honest count.

## The evidence, including what failed

A framework built from first principles is a hypothesis. I said that about the assessment instrument and it applies here too, so the boundary was measured.

A recorded campaign ran fifteen local models through staged attack and control workflows. Fourteen completed the full stage. One, SmolLM3-3B, stopped at a generation-validity gate and is excluded from completed-model conclusions rather than quietly dropped. Of 4,605 staged episodes, 4,603 were evaluable; the two remaining target failures are left unevaluated rather than counted as successful defences. The independent verifier observed zero protected invariant violations. Attacked protected workflows retained utility in 2,207 of 3,360 cases.

That last number is not the cost of enforcement, and I have to say so because the shape of the aggregate invites the wrong reading. In the paired control, discordant pairs split almost evenly, twenty-five going from success to failure and twenty-eight going the other way. Zero observed violations in a finite campaign is bounded evidence about that campaign. It is not proof of universal security.

Then the parts that did not work.

A separate lab experiment compared effect-level enforcement against content-filter guardrails on an agent application. Both pre-registered primary outcomes failed to validate enough attacks to be evaluable, twice, for opposite reasons. On the exploratory family, a content filter matched the enforced arm's catch rate exactly. The separation that did appear was cost rather than catch: the filter dropped half of all legitimate retrieved documents while the enforced arm dropped none. Had that family been the pre-registered primary, the main hypothesis would have been falsified on catch rate.

The strongest effect measured in that experiment was not enforcement at all. Adding one legitimate document naming the correct record cut attack success four to eight fold, was strictly protective across every run, and cost nothing in false positives. Context integrity beat every detector tested, and it is not a detector.

One enforcement surface ships unmitigated: the reasons returned to the caller can disclose which argument a contract binds, which hands an adaptive attacker a probing oracle. It is documented as open rather than fixed.

And then the result that belongs in this series more than any of the others. An external reviewer read the enforcement path, reproduced the suite offline, and found that the central property covers only half of composition. A sequence, such as a secret read followed by a public send, was expressible. A *volume*, meaning many individually authorized effects whose count is the problem, was not expressible at all, because the policy schema is a closed allowlist that would have rejected the field. Their framing was the sharp part: the closed schema is a good decision, and it is also what turns "no quota was found" into "a quota cannot be written."

They were right on every point. I checked each claim in the code before accepting it.

That is the third piece happening to me. I had written about the structural unreliability of the defender's judgment, and I had a gap in my own central claim that I did not see and an outsider found in an afternoon. The half that could be closed has been. The half that requires changing the signature of the central security function is documented as an open limitation with no promised date, and there is a test asserting the limitation so that it stays visible.

## What comes after naming

Naming was the necessary first step. So was admitting that the namer is as compromised as everyone else.

What comes after is not a better assessment, because assessment is downstream of the judgment we have good evidence to distrust. It is building things whose correctness does not depend on anyone being vigilant at the moment it matters, keeping the trust decisions that remain small enough to read, and then publishing the evidence with the failures in it so that other people can check your work.

Thompson said that perhaps it is more important to trust the people who wrote the software. He was right, and the third piece was right that the people are structurally unreliable. Both can be true. The way through is to give those people less to be reliable about, and to make what remains inspectable by someone other than themselves.

The tool I built is called VAIS Boundary. The [benchmark report](../../evidence/rc7-benchmark-report.html) and its [evidence manifest](../../evidence/rc7-report-evidence-manifest.json) are published, along with the [source, the open limitations and the reviewer's findings](https://github.com/stratomarco/vais-boundary), including the experiments that did not support the thesis. Read the checks. Question the grounding. Report what does not hold.

That has been the point from the first piece.
