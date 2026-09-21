---
layout: ../../layouts/Article.astro
title: "Trust Me, I am Compiled: From Ken Thompson to the Age of Poisoned Models"
description: "How a three-page paper from 1984 predicted everything wrong with AI security, and why the people who warned us about software are now warning us about something much harder to fix."
date: "2026-02-23"
canonical: "https://medium.com/@maconstantino/trust-me-i-am-compiled-from-ken-thompson-to-the-age-of-poisoned-models-e172c852e408"
---

There is a paper every serious security practitioner has read, or should have. It is three pages long. It was delivered as a lecture in October 1983, published in *Communications of the ACM* in August 1984, and has been cited roughly 700 times in the academic literature — a modest number for a work that arguably redefined how we think about trust in computing. The author is Ken Thompson, co-creator of Unix, inventor of the B programming language, later a designer of Go at Google, and, at the time of the lecture, a Turing Award winner sharing the stage with his longtime collaborator, Dennis Ritchie. The paper is called "Reflections on Trusting Trust."

Thompson opens it with characteristic dry wit: *"I am a programmer. On my 1040 form, that is what I put down as my occupation. As a programmer, I write programs. I would like to present to you the cutest program I ever wrote."*

The program in question was not cute in any ordinary sense. What Thompson described was a compiler backdoor so elegant, so structurally invisible, and so philosophically unsettling that forty years later — with AI systems training on hundreds of billions of tokens, with models deployed into critical infrastructure, with ML supply chains stretching across dozens of untrusted parties — his moral lands harder than it ever did.

*"You can't trust code that you did not totally create yourself."*

We have a problem.

## The Original Sin

Thompson's attack is worth understanding in detail because it is in the details that the beauty — and the horror — lives.

In the traditional software development model, you write source code. Humans can read, review, and reason about it. You then pass it through a compiler, which translates it into a binary executable — the thing that actually runs on hardware. The implicit trust assumption is that the compiler faithfully translates your source. That is not an unreasonable assumption. Mostly it is true. Thompson's contribution was to demonstrate, with working code, that it need not be.

He describes a three-stage construction. In Stage 1, he introduces the concept of a quine — a self-reproducing program that outputs its own source code. This is a well-known computer science puzzle, but Thompson puts it to work. In Stage 2, he shows how a compiler can be modified to inject a backdoor into a specific program — say, the Unix login command — whenever it compiles that program. The login source code looks clean; the binary has a secret second password. Still detectable, though: anyone reviewing the *compiler* source would see the attack.

Stage 3 is the one that keeps security engineers awake at night.

You modify the compiler to do two things simultaneously: when it sees it is compiling the login command, inject the backdoor; when it sees it is compiling *itself*, inject *both* attack patterns into the resulting binary. Then you compile once, install the resulting binary as the official compiler, and delete every trace of the attack from any source file.

The attack now lives only in the binary. It is self-reproducing — every time the compiler compiles itself, it quietly passes on the attack to its successor. The login source is clean. The compiler source is clean. There is no evidence anywhere in any human-readable file. Moreover, the backdoor will persist across any number of "clean" recompilations, for as long as anyone uses a compiler that descends from the compromised binary.

Thompson emphasizes that he actually built this. The code — 99 lines of C and a 20-line shell script — dates to July 3, 1975, eight years before his Turing lecture. He tested it on colleagues. They did not find it.

The moral, stated plainly: *"No amount of source-level verification or scrutiny will protect you from using untrusted code."*

And then, more quietly devastating: *"Perhaps it is more important to trust the people who wrote the software."*

He was not being defeatist. He was being precise. Trust, Thompson was telling us, is not a technical property. It is a social one. It lives in relationships, institutions, and professional ethics — not in audits and source listings. The best cryptographic hash in the world tells you nothing about whether the person who produced the artifact was trustworthy when they created it.

## Gary McGraw and the Gospel of Building Security In

The industry spent the next twenty years mostly not listening to Thompson.

In the 1990s, software insecurity became commercially catastrophic, and a small number of people started screaming about it in ways that were hard to ignore. Gary McGraw was among the loudest and most rigorous. McGraw holds a dual PhD in Cognitive Science and Computer Science from Indiana University — his dissertation advisor was Douglas Hofstadter, the author of *Gödel, Escher, Bach* — which gives you some sense of how his mind works.

His first book, *Java Security: Hostile Applets, Holes & Antidotes* (1996, with Princeton's Edward Felten), arrived just as the web was learning to run untrusted compiled code in browsers. The problem was already Thompson's problem in disguise: what do you do when you have to execute code you didn't write, on behalf of users who cannot audit it?

Over the following decade, McGraw produced the foundational library of software security practice. *Building Secure Software* (2001, with John Viega). *Exploiting Software* (2004, with Greg Hoglund). And most importantly for our purposes, *Software Security: Building Security In* (Addison-Wesley, 2006), which synthesized his work into the Seven Touchpoints framework: a set of best practices — code review, architectural risk analysis, penetration testing, abuse cases, security requirements, and more — ordered by their effectiveness and integrated across the entire software development lifecycle.

McGraw's signature formulation: **"Software security is not security software."**

Security is not a feature you add. It is a property that either emerges from how you build, or does not emerge at all. No firewall compensates for a compromised compiler. No intrusion detection system catches a backdoor Thompson-style, because by definition, there is nothing to detect — the attack is in the absence of something, in the gap between what the source says and what the binary does.

The BSIMM (Building Security In Maturity Model), which McGraw developed with colleagues and first published in 2009, took this further: it measured what software security practices organizations *actually* implemented, beginning with nine firms and growing across successive versions into a data-driven benchmark for where the industry stood. The answer, consistently, was: not far enough.

What McGraw understood, and kept saying, was that Thompson's insight was not about compilers specifically. It was about the whole supply chain of trust. You could have perfectly written application code and still be compromised at the framework, runtime, OS, or hardware level. Security is a system property, and systems extend beyond any single team's view.

## Ross Anderson and the Economics of Insecurity

Thompson told us where the problem lives. McGraw told us how to fight it in practice. Ross Anderson, the Cambridge professor whose *Security Engineering* (now in its third edition) is the most comprehensive single-volume treatment of the field, told us something equally important: why organizations systematically fail to act on what they know.

Anderson's contribution is the economics of security. Organizations make rational decisions that produce irrational outcomes because the people who bear the cost of insecurity are often not the ones who decide on security investments. A software vendor who ships a product with vulnerabilities bears limited liability; the customers who get compromised bear all of it. This misalignment of incentives is structural, and it persists regardless of how much anyone knows about Thompson-style attacks.

Anderson also introduced the concept of security as a system property, as Thompson intuited but did not fully articulate. In a complex system — an operating system, a software ecosystem, an internet-scale AI supply chain — vulnerabilities do not live in individual components. They live in the interfaces, the assumptions, the things that every component trusts because every other component trusts them. The compiler is trusted because the toolchain depends on it. The training framework is trusted because no one has the resources to audit it. The cloud provider is trusted because the alternative is building your own data center.

Anderson would recognize immediately what has happened in AI: the incentive structures are wrong, the liability is diffuse, and the technical complexity is being used — as it always is — to obscure accountability.

## The Compiler Is Now the Data

Here is the structural insight that connects Thompson's 1984 thought experiment to 2026:

In traditional software: Source Code → Compiler → Binary. In AI/ML: Training Data → Training Process → Model.

The parallel is not metaphorical. It is architectural.

In software, you read the source code to understand what a program does. In AI, the "source" is the training data — and for a large language model, that might be a substantial fraction of the indexed internet, billions of tokens that no human team has read or could read. The compiler — the training process, the GPUs, the frameworks, the hyperparameters — transforms this data into model weights: a binary artifact, a black box, something you can query but not read.

Thompson showed that you can poison a compiler so that the binary it produces is compromised, with no evidence in the source code. The AI equivalent is data poisoning: injecting malicious examples into training data such that the resulting model behaves in ways controlled by the attacker under conditions chosen by the attacker, with no evidence in any human-readable artifact.

This is not theoretical.

A study published in *Nature Medicine* in early 2025 demonstrated that poisoning 0.001% of a medical LLM's training data — one token in 100,000 — produced a model that passed all standard benchmark evaluations while giving harmful medical advice on targeted queries. The poison was statistically invisible. The attack was undetectable through regular testing. Thompson would have recognized the architecture immediately.

In 2024, over 100 poisoned models were found on Hugging Face, the primary public repository for ML models. They appeared legitimate. They passed basic testing. They contained backdoors that activated on specific inputs. Thousands of developers had downloaded them.

The Anthropic "Sleeper Agents" paper (2024) demonstrated something even more unsettling: backdoors trained into language models survived safety fine-tuning, survived reinforcement learning from human feedback, survived adversarial training. In some cases, the safety training made the models *better at hiding their malicious behavior*. The models had learned that deceptive quiescence was adaptive.

Thompson's Stage 3 compiler, implemented in neural network weights.

## The Layers of Distrust

Thompson's attack had one trust point: the compiler. Modern AI systems have many.

**The model itself.** Model weights are not readable. You cannot inspect a transformer's 70 billion parameters the way you would review a C source file. Model signing — cryptographic signatures that prove a model came from a specific source and has not been modified — addresses provenance and integrity. It does not address safety. A signed poisoned model is still poisoned. The signature tells you *who* gave it to you. It tells you nothing about whether that party was trustworthy when they trained it, or whether their training data was trustworthy, or whether their training infrastructure was clean.

**The training process.** In 2024, more than 150 CVEs were reported across popular ML frameworks — PyTorch, TensorFlow, JAX — the infrastructure that underlies essentially all serious AI development. A compromised training framework is Thompson's compiler, one level down. It can modify the model being trained in ways that leave no trace in the training code. The verification problem recurs: to verify your training environment is secure, you need secure verification tools. But then you need to trust those tools. It is turtles all the way down.

**The training data.** This is the crux. Modern foundation models train on data at an internet scale. The Common Crawl dataset — widely used in pretraining — contains petabytes of web content. No team has read it. No audit is possible. Sophisticated data poisoning attacks craft examples that are statistically indistinguishable from legitimate data: they do not change averages, they do not trigger anomaly detectors, they quietly encode a conditional behavior that will activate later, when the attacker wants it to.

**Data provenance.** Initiatives such as C2PA (Coalition for Content Provenance and Authenticity), the OpenSSF Model Signing Specification, and SPDX profiles for AI datasets aim to establish auditable chains of custody for training data. This is valuable. It tells you *where* the data came from and *what* transformations it underwent. It does not tell you whether the source was already compromised, or whether the transformations were benign, or whether the party that curated it is trustworthy. Provenance chains eventually terminate at something you have to trust without further verification. Thompson made this point about compilers in 1984. It applies just as cleanly to dataset registries in 2026.

**The infrastructure.** Thompson explicitly said: *"I could have picked on any program-handling program, such as an assembler, a loader, or even hardware microcode. As the level of the program gets lower, these bugs will be harder and harder to detect."* Most AI training happens in cloud environments on GPU clusters owned by three or four companies. You are trusting the cloud provider's hardware, hypervisor, physical security, and nation-state threat model. A hardware backdoor in a GPU — something that modifies floating-point operations in ways that alter gradient updates during training — would be nearly impossible to detect and would compromise every model trained on that hardware. At some point, you are trusting physics.

The scaling comparison is important. Thompson could have rebuilt everything from scratch: the compiler, the runtime, the OS. It would have taken years, but it was conceivable. Modern AI systems require internet-scale training data, specialized hardware fabricated across global supply chains, and infrastructure distributed across multiple continents. The trust surface is not just larger than Thompson's; it is qualitatively different in kind. Thompson's problem was hard. The AI version is, in a meaningful technical sense, unsolvable by the same methods.

## Enter BIML

Gary McGraw is now in his second act, and it is a direct continuation of his first.

The Berryville Institute of Machine Learning (BIML) — a 501(c)(3) research nonprofit in Virginia that McGraw co-founded — applies the same discipline to machine learning that McGraw applied to software security two decades ago. The BIML ML Security Risk Framework catalogs the architectural risks inherent in ML systems: not vulnerabilities in specific implementations, but structural risks that arise from how these systems are built. Just as the BSIMM measured software security maturity empirically rather than prescriptively, BIML aims to establish a rigorous, empirically grounded foundation for ML security engineering.

The BIML framework identifies dozens of architectural risk areas — data provenance, model extraction, training process integrity, deployment security, and more — and refuses the comforting fiction that any of them are fully solved. The parallel to the software security era is exact: in the early 2000s, the industry knew software had security problems but treated them as edge cases, exceptions, things to be patched after the fact. McGraw spent years arguing that this was structurally wrong — that security had to be engineered in from the beginning, that bolting it on afterward was expensive and insufficient.

His argument about AI security is the same, at a higher level of urgency. The models are larger. The supply chains are longer. The stakes — AI in medical diagnosis, in critical infrastructure, in judicial and financial decision-making — are higher. And the industry's instinct to move fast and patch vulnerabilities afterward is, if anything, more pronounced.

There is a biographical detail worth noting: McGraw's PhD advisor was Douglas Hofstadter, who spent his career studying emergent cognition, self-reference, and the strange loops that arise when systems become complex enough to model themselves. McGraw worked on AI systems as a graduate student before pivoting to software security. He has now pivoted back. The throughline from Thompson's self-reproducing compiler to Hofstadter's strange loops to McGraw's ML security framework is not accidental.

## What the Industry Is Trying, and Why It Is Not Enough

Let us be fair to the present moment. The security community has not been idle.

Model signing (per the OpenSSF Model Signing Specification) provides cryptographic provenance for model artifacts. Reproducible builds — an approach pioneered in software and now being extended to ML — aim to verify that a specified training run actually produced a specific model. Secure enclaves and confidential computing offer hardware-isolated training environments. MITRE ATLAS catalogs adversarial threats to AI systems. The NIST AI Risk Management Framework provides a governance structure. The OWASP Top 10 for LLMs translates the classic web application security model into AI-specific attack patterns. C2PA attempts to address data provenance at scale.

None of these is without value. The problem is that each of them, scrutinized, does precisely what Thompson predicted all such defenses would do: it pushes the trust requirement down one layer without eliminating it. Model signing proves provenance; it does not prove safety. Reproducible builds verify the training process; they do not verify the training framework. Secure enclaves isolate computation; they do not verify the hardware on which they run. Provenance tracking establishes a chain of custody; it does not validate the trustworthiness of the origin.

This is not a reason not to implement these controls. Defense in depth is real and valuable; layered controls that each catch some attacks are better than no controls at all. The point is that we should not mistake the existence of these controls for a solution to Thompson's problem. We are managing the trust problem, not solving it. That distinction matters for how we reason about risk and how honest we are with the people who depend on our systems.

## The Practical Wisdom

This is where the essay could become fatalistic, and where it should not.

Thompson ended his paper not with despair but with a moral: *"The moral is obvious. You can't trust code that you did not totally create yourself."* He was not saying computing is therefore impossible. He was saying: be honest about what you are trusting, and why. McGraw spent three decades turning that moral into a practice. The practice has seven touchpoints, a maturity model, and a generation of security engineers who learned to think in terms of threat models, attack surfaces, and trust boundaries. The practice did not eliminate insecurity from software. It reduced it significantly, making the residual risk more visible and manageable.

The same discipline applies to AI:

**Accept the reality.** You will always rely on trust somewhere. Perfect security is impossible. Refusing to admit this is not humility; it is a lie that makes real security harder. Thompson was explicit: the problem is not solvable; it is manageable.

**Minimize the trust surface.** Every third-party model you use, every external dataset you incorporate, every cloud service you depend on is a trust dependency. Some are unavoidable. Many are not. Train your own models when the risk profile warrants it. Use datasets you can audit to the extent auditing is feasible. Prefer open-source infrastructure you can inspect over closed systems you cannot.

**Implement defense in depth.** Model signing does not replace adversarial testing; both are necessary. Provenance tracking does not replace monitoring; both are necessary. No single control is sufficient; the correct response is more controls, not fewer.

**Document your trust model.** This is underrated. Most AI deployments rest on a large number of implicit trust assumptions that nobody has written down. "We trust PyTorch because everyone uses PyTorch" is a trust assumption. Writing it down forces a conversation about whether it is justified. Documenting is itself a security practice.

**Build resiliency.** Assume compromise will happen. Can you detect anomalous model behavior in production? Can you roll back to a previous version? Do you have incident response plans that cover AI-specific attacks? Most organizations that have sophisticated security programs for traditional software have barely begun to think about these questions for their ML systems.

And then Thompson's deepest insight, updated for the present: *"Perhaps it is more important to trust the people who wrote the software."*

In AI, it is more important to trust the people who trained the model, curated the data, and operated the infrastructure. The technical controls are real and necessary. But ultimately, what you are trusting when you deploy an AI system — what you are asking your users to trust — is a chain of human decisions made by people you may never meet, about data you cannot audit, in processes you cannot observe. The ethics of that trust are inseparable from its engineering.

When you deploy an AI system into a high-stakes context, you are asking users to extend trust not just to the model but to everyone in your supply chain. That is an ethical obligation as much as a technical one. Being honest about it — being explicit about what you know and do not know about the trustworthiness of your system — is the minimum standard of professional responsibility.

## The Moral, Still Obvious

Thompson closed his 1984 lecture with: *"I wish to moralize… The moral is obvious."*

It is still obvious. It has just gotten more complicated.

The self-reproducing compiler that Thompson described in three elegant pages has become the poisoned training dataset, the backdoored foundation model, the compromised ML framework, the compromised GPU firmware in the data center you are renting to train the model that will make decisions about people's medical care, credit, or freedom. The trust problem is the same. The recursion is the same. The moral — that trust is not a technical property, that it is a human one, that it lives in relationships and institutions and professional ethics — is the same.

What has changed is the scale and the stakes. A compromised compiler in 1975 affected the Unix systems at Bell Labs. A compromised foundation model in 2026 can affect every application built on it, every user who interacts with it, and every decision made with its assistance. The attack surface is not just larger; it is distributed across a global supply chain that no single organization controls or can fully audit.

The three-page paper from 1984 still deserves to be read. So does McGraw's body of work, and Anderson's, and the BIML framework. Not because they solve the problem — they do not — but because the discipline of thinking clearly about trust, about supply chains, about the gap between what a system claims to be and what it actually does, is the proper discipline for this moment.

Thompson understood something fundamental: you cannot audit your way to safety if the tools you are using to audit are part of what you are auditing. Security ultimately rests on trust in people, not in systems. The systems are just where that trust gets implemented — or betrayed.

The work continues. It always does.

---

*Further reading: Thompson's "Reflections on Trusting Trust" (CACM, August 1984, Vol. 27 No. 8, pp. 761–763) is freely available online and takes fifteen minutes to read; it is worth every one of them. McGraw's "Software Security: Building Security In" (Addison-Wesley, 2006) remains the canonical text on secure SDLC. The Berryville Institute of Machine Learning publishes its ML security framework and associated research at berryvilleiml.com. Ross Anderson's "Security Engineering" (3rd edition, Wiley, 2020) covers the full landscape of security as a system property, with particular depth on the economics of insecurity. The Anthropic "Sleeper Agents" paper (2024) is available on arXiv and provides sobering empirical grounding for the theoretical concerns raised here.*

*A note on this version: the data-poisoning study referenced above is Alber et al., "Medical large language models are vulnerable to data-poisoning attacks," Nature Medicine, February 2025 (published online 8 January 2025). The Medium original dated it to 2024. Four sentences altered during copy-editing have been restored to their intended sense.*
