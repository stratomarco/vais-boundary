---
layout: ../../layouts/Article.astro
title: "The Double Trinity: How Machine Learning Didn't Replace the Old Security Problems, It Doubled Them"
description: "Three structural forces inherited from software security, three native to machine learning, and why point solutions keep failing against all six at once."
date: "2026-05-18"
canonical: "https://medium.com/@maconstantino/the-double-trinity-how-machine-learning-didnt-replace-the-old-security-problems-it-doubled-them-74bf210bec14"
---

In 2004, Greg Hoglund and Gary McGraw published *Exploiting Software: How to Break Code*. Buried in the first chapter was a deceptively simple idea: software security isn't hard because developers are careless. It's hard because of three structural forces, which they call the Trinity of Trouble. Connectivity. Extensibility. Complexity. Together, these three trends made software an increasingly hostile surface to defend, and they still do.

The Trinity of Trouble was never meant to be exhaustive. It was a lens, not a checklist. McGraw's point was that the problem was structural: baked into how modern software is built and deployed, not just a product of individual bugs. Fix one buffer overflow, and another appears. The Trinity explains why.

Twenty years later, we've graduated from software to machine learning systems. And here's the thing about the Trinity: it didn't go away. It didn't get solved. Machine Learning didn't replace the original problem: It doubled it. Three forces inherited from software security, still operating, now at a different altitude. And three new forces, native to Machine Learning, that McGraw and Hoglund had no framework for. Together, they form what I'm calling the Double Trinity: two generations of structural risk compounding.

If we want to reason clearly about Machine Learning security, as I started to do in my previous piece, tracing the line from Ken Thompson's *Reflections on Trusting Trust* to today's poisoned models, then we need an updated map. This is an attempt at that map. Not a final answer. A starting point.

## The Original Three, Twenty Years Later

Before we add anything, we should be honest about what the original Trinity still explains.

**Connectivity** exposed the Internet to attack surfaces that previously didn't exist. An air-gapped system is much harder to attack. A networked one is not. In the Machine Learning world, connectivity has become almost architectural. Models are trained on data scraped from the open web. They're deployed behind APIs that anyone can query. They're distributed across federated learning nodes that span organizational and national boundaries. Model weights travel through supply chains, from research lab to Hugging Face to your application, with the same casual trust we once placed in third-party code libraries. The attack surface McGraw described in 2004 was wide. The one we're operating in now is unbounded.

**Extensibility** was about the ability to add behavior to a running system: plugins, scripting, and mobile code arriving at runtime. The problem was that an attacker can always repurpose extensibility designed for legitimate use. In Machine Learning systems, extensibility has taken on a new character. You don't extend a model with code anymore; you extend it with behavior. LoRA adapters. Fine-tuning pipelines. Retrieval-Augmented Generation architectures that let a model reach out and consume external documents at inference time. Agents with tool access that can browse the web, write files, and execute code. The system is extensible in ways that are simultaneously more powerful and more difficult to audit than anything Hoglund and McGraw could have anticipated.

**Complexity** was the most honest of the three. Large software systems are too complex for any human to fully understand, which means they contain surprises, and some of those surprises are security vulnerabilities. Machine learning has taken this to a philosophical extreme. A large language model with billions of parameters isn't just complex in the engineering sense. It's complex in a way that resists the very idea of complete understanding. Emergent behaviors appear at scale that were not present in smaller versions of the same architecture. A model can exhibit capabilities and failure modes that weren't explicitly trained. Complexity in traditional software was a problem of scale. Complexity in Machine Learning is an epistemological problem.

The first Trinity, then, is still with us. It just operates at a different altitude. That's the first half of the problem.

## The Second Trinity

The first Trinity describes pressures inherited from software engineering. What follows describes pressures that are native to machine learning, forces that have no real analog in McGraw and Hoglund's framework because they emerge from the fundamental nature of how Machine Learning systems are built. This is the second half of the Double Trinity.

### Opacity

Ken Thompson ended *Reflections on Trusting Trust* with a line that has aged remarkably well: "You can't trust code that you did not totally create yourself." He was talking about compilers. But he was really talking about opacity: the problem of trusting systems whose internals you cannot inspect.

Machine Learning systems have taken opacity to a new level. In traditional software, you can audit source code. It's difficult, time-consuming, and often incomplete, but the inspection artifact exists. A model is different. Its "source code" is a training process applied to a dataset, producing billions of floating-point weights. Those weights are opaque, not because anyone is hiding them, an open-weights model is just as opaque as a closed one, but because there is no human-readable representation of what the model "knows" or "intends." Interpretability research is making progress, but slowly. In the meantime, we deploy systems whose internal logic is fundamentally unexaminable.

This isn't just an academic concern. It means that the traditional security practice of code review has no equivalent in Machine Learning. It means that a backdoor implanted through data poisoning, the modern version of Thompson's compiler hack, may be effectively undetectable by any inspection of the model itself. The attack hides not in the code but in the learned behavior, activated only under specific conditions that the attacker controls.

Opacity is the Thompson problem, fully realized.

### Data Entanglement

In classical software, data and code are separate concerns. You can reason about a program's logic independently of the data it operates on. Security vulnerabilities in the code are, in principle, separable from the database's content.

Machine Learning collapses this distinction. The training data is the program, in a meaningful sense. A model's behavior is a function of what it was trained on, and that training data is typically massive, heterogeneous, and largely unverifiable. The ImageNet dataset, once a gold standard, was found to contain significant labeling errors and biases. Language model training corpora include the open web, which is noisy, manipulated, and, in some cases, deliberately adversarial.

Data poisoning attacks exploit this entanglement directly. By corrupting a fraction of the training data, sometimes a surprisingly small fraction, an attacker can implant behaviors that persist through the training process into the final model. Ross Anderson's foundational work on security engineering taught us to think carefully about trust relationships at system boundaries. The training pipeline introduces a trust boundary that most organizations treat with far less rigor than they apply to their software supply chains, even though it is at least as dangerous.

The attack surface has moved upstream. Security teams accustomed to thinking about runtime defenses are often poorly equipped to reason about what happened months or years earlier during training, in a pipeline they may not have controlled end to end.

### Adaptability

Once deployed, traditional software is largely static. It does what it was compiled to do until someone changes the code. This made security analysis tractable, not easy, but tractable. You could audit a version, establish its properties, and have reasonable confidence that those properties held until the next release.

Machine Learning systems break this assumption. Models change post-deployment through fine-tuning, continued training, RLHF updates, and distributional drift. A model that behaves safely today may not do so tomorrow, not because anyone changed the code, but because the system learned from new interactions or was updated in ways that weren't fully characterized. In agentic contexts, models accumulate context across long interactions in ways that can shift their effective behavior without any deliberate modification.

This means security guarantees in Machine Learning have an expiry date that is often unknown. The alignment or safety properties verified at deployment may not hold after adaptation. The threat surface isn't a fixed target; it's a moving one. Any security framework built on the assumption of static deployments will fail to account for this.

## The Double Trinity

Put them together, and you have the Double Trinity: two sets of three, one inherited, one native, both structural.

| | Dimension | Core Insight |
|---|---|---|
| **First Trinity** | | *Inherited from software security* |
| 1 | **Connectivity** | The attack surface has no perimeter |
| 2 | **Extensibility** | Behavior can be added or changed at runtime |
| 3 | **Complexity** | The system cannot be fully understood by its builders |
| **Second Trinity** | | *Native to machine learning* |
| 4 | **Opacity** | The system cannot be meaningfully inspected |
| 5 | **Data Entanglement** | The training pipeline is the attack surface |
| 6 | **Adaptability** | Security properties do not persist across model updates |

The doubling matters. These two trinities don't simply add together: They interact. Complexity makes Opacity worse. Connectivity amplifies Data Entanglement. Extensibility compounds Adaptability. A machine learning system under real-world conditions is subject to all six forces simultaneously, which is why point solutions keep failing. You can't patch your way out of a structural problem, let alone two of them at once.

Like the original Trinity, this isn't exhaustive. Other dimensions could be proposed, such as the concentration of power in a small number of foundation model providers, the role of hardware and inference infrastructure, and the emergent risks of multi-agent systems. But these six have something in common: they are structural. They aren't bugs. They aren't failures of implementation. They are properties of how Machine Learning systems are built and deployed, which means they won't be solved by patching individual vulnerabilities.

## What This Means in Practice

McGraw's insight and the reason the Trinity of Trouble has lasted twenty years is that structural problems require structural responses. If the problem is architectural, the solution has to be architectural.

The same logic applies here. Addressing opacity means investing seriously in interpretability and model auditing, not as research curiosities but as engineering requirements. Addressing data entanglement means treating training pipelines with the same security rigor applied to software supply chains: provenance tracking, anomaly detection, and cryptographic verification of dataset integrity. Addressing adaptability means building monitoring and red-teaming into post-deployment operations, not just pre-deployment evaluation.

None of this is simple. The field of Machine Learning security, as McGraw's field of software security was in 2001, is still maturing. The practices don't yet fully exist. The tooling is incomplete. The organizational structures to support it haven't been built in most companies deploying these systems. But the map is a place to start.

Thompson warned us that we cannot fully trust what we didn't build ourselves. McGraw and Hoglund warned us that the forces making software insecure are structural, not accidental. Both warnings apply, with additional force, to the Machine Learning systems we are now deploying at scale, and Machine Learning has added a second layer of structural risk on top.

The Double Trinity isn't a counsel of despair. It's a taxonomy of the problem. And you can't solve a problem you haven't named.

---

*A note on this version: the six-force table appears here as text rather than as the image used in the Medium original, and two sentences altered during copy-editing have been restored to their intended sense.*
