# Related work and positioning

VAIS should not be presented as the first deterministic prompt-injection defense. Its intended contribution is the combination of **explicit task authority, deterministic enforcement, observable security invariants and adaptive verification**.

## CaMeL and capability-based control/data separation

CaMeL places a protective system layer around a potentially vulnerable LLM, separates trusted control flow from untrusted data flow and uses capabilities to constrain unauthorized data flow. It is important prior work for VAIS's assumed-compromise model, capability boundaries and insistence that untrusted retrieved content cannot create authority.

VAIS does not claim novelty for capability-based mediation, control/data separation or deterministic containment. Its narrower research emphasis is binding explicit task authority to independently observed effect invariants and using those invariants as the terminal reward for adaptive adversarial evaluation.

Primary paper: https://arxiv.org/abs/2503.18813

## FIDES and deterministic information-flow enforcement

Microsoft Agent Framework's experimental FIDES implementation labels content along integrity and confidentiality axes, propagates those labels and enforces policy before sensitive tools run. This is strong evidence that deterministic application-layer information-flow control is becoming a practical agent-security architecture, not merely a research abstraction.

VAIS should learn from FIDES rather than claim novelty for taint labels or pre-tool enforcement. VAIS's research focus is the independent effect-level invariant oracle and defense-aware adaptive evaluation loop.

Primary documentation: https://learn.microsoft.com/en-us/agent-framework/agents/security

## SPA and cross-query persistence

SPA secures persistent agents across queries with plan-first execution: the planner runs once per query to produce a complete plan in a declarative language, and dual-lattice information-flow control tracks confidentiality and integrity across data flows and control dependencies. Execution results persist as labeled artifacts, and later planning sees only their semantic metadata, so untrusted payloads are not re-exposed to the planner. The paper reports a security-utility tradeoff introduced by strict integrity enforcement.

VAIS does not claim novelty for dual-lattice labels or label-preserving persistence. VAIS's current scenarios are single-task, so SPA's cross-query setting marks a gap in VAIS's evidence rather than a point of comparison.

Primary paper: https://arxiv.org/abs/2608.27234

## APPA and recoverable information-flow control

APPA turns agent information-flow control from blocking into recovery. It validates proposed tool calls before dispatch and realized return values before they are admitted to the context, applies gradual security typing to unannotated tools, and confines tainted data to disposable child branches, with a theorem that an abandoned child leaves the parent label unchanged. It targets the failure where monotone taint tracking over-blocks benign operations or strands downstream execution after an agent reads unvetted data.

That failure is the one VAIS records as LIM-023, where conservative model-output lineage overtaints semantically safe text. VAIS does not claim novelty for validation before and after a tool call. APPA's post-call gate checks return values entering the context; VAIS checks observed external effects against declared invariants. APPA is the natural reference for any VAIS declassification work.

Primary paper: https://arxiv.org/abs/2607.24625

## AgentDojo

AgentDojo provides a dynamic environment for evaluating attacks and defenses against tool-using LLM agents and exposes benchmark scripts that vary model, attack and defense configurations.

VAIS should interoperate with or adapt AgentDojo scenarios later instead of replacing a mature agent-task benchmark. VAIS adds value when it can express the security boundary and invariant oracle around such tasks.

Repository: https://github.com/ethz-spylab/agentdojo

## Adaptive evaluation of out-of-band defenses

A 2026 study, *Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents*, explicitly argues that deterministic defenses should be tested against defense-aware attackers rather than only static corpora. Its small independent Progent experiment found substantially lower attack success with the deterministic defense, while emphasizing that stronger optimized attacks remain open.

Paper: https://arxiv.org/abs/2606.26479

This is closely aligned with VAIS's planned RLVR integration: the important empirical question is whether an adaptive optimizer can produce **observable policy/invariant failures**, not merely jailbreak-looking text.

## Adaptive multi-round benchmarks

*Adaptive Adversaries: A Multi-Turn, Multi-LLM Benchmark for LLM Agent Security* (2026) reports materially higher success when attackers can observe prior outcomes and adapt across rounds, and it finds substantial scenario-specific differences across defender models.

Paper: https://arxiv.org/abs/2607.18063

That supports two design decisions inherited from the capstone: retain history in the attacker interface and preserve per-model/per-scenario results instead of trusting a single aggregate mean.

## Application-code output enforcement

*Evaluation of Prompt Injection Defenses in Large Language Models* (2026) reports that model-mediated defenses eventually failed under its adaptive leakage attack, while its separate application-code output filter held for the evaluated leakage condition.

Paper: https://arxiv.org/abs/2604.23887

The result is narrower than a general proof of security, but it reinforces VAIS's architectural assumption that the model should not be the final authorization/security boundary.

## Proof of Execution and runtime trace validation

Proof of Execution packages a governed agent's runtime guarantees as a single validator predicate over a contract, a cryptographically sealed causal event stream and a replay context, with five checkable invariants: authorization, path compliance, null effect on deny, history integrity and replayability. It is the closest independently derived architecture to VAIS's reference monitor and audit chain, and it is ahead of VAIS on cryptographic sealing, per-action replay envelopes and formal framing.

VAIS does not claim novelty for complete mediation, null effect on deny or hash-chained history. Proof of Execution does not model data provenance or confidentiality propagation, and its validator checks the trace the gateway produced rather than independently re-deriving effects from observed outcomes. Those are the points where VAIS's contribution sits. A term-by-term mapping is in [RELATED-ARCHITECTURES.md](RELATED-ARCHITECTURES.md).

Primary paper: https://arxiv.org/abs/2607.05397

## ARM and denial-feedback leakage

ARM (Agentic Reference Monitor) is an MCP proxy that mediates every tool call before execution. It issues capability tokens that neither the agent nor a tool can modify, keeps a SHA-256 hash-chained audit log, and tracks tool calls, returned data and denied actions in a provenance graph with an integrity lattice. Its paper names causality laundering: an adversary probes a protected action, learns from the denial, and exfiltrates the inference through a later benign call. ARM adds counterfactual edges from denied-action nodes to catch it.

VAIS does not claim novelty for proxy-based complete mediation, immutable capabilities, hash-chained audit or integrity-lattice provenance; ARM has all four. ARM evaluates policy at invocation time and records the outcome, and does not independently verify observed effects against declared invariants after execution. That is where VAIS's contribution sits. VAIS returns enforcement outcomes to the caller and does not yet model the denial-feedback channel; see [ATTACK-SURFACE.md](ATTACK-SURFACE.md), S13.

Primary paper: https://arxiv.org/abs/2604.04035

## AgentProof and static workflow verification

AgentProof statically verifies agent workflow graphs before deployment. It compiles temporal safety policies to finite automata and checks graphs extracted from LangGraph, CrewAI, AutoGen and Google ADK, including a policy that paths to sensitive operations pass through a human gate. This is pre-deployment topology verification, complementary to a runtime boundary rather than competing with it, and the natural reference if VAIS adds a conformance checker for its own integration assumptions.

Primary paper: https://arxiv.org/abs/2603.20356

## OWASP guidance and verification standards

OWASP guidance recommends layered defenses including least privilege, output validation, human approval, trust-boundary handling and monitoring. AISVS provides a useful verification-oriented standards anchor for future VAIS control/report mappings.

Prompt Injection Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html

AISVS: https://github.com/OWASP/AISVS

## VAIS hypothesis

The empirical hypothesis remains:

> A deterministic application security boundary can keep invariant-violation rate low even when a defense-aware attacker measurably changes model behavior, and adaptive RLVR-style testing will uncover failures that static attack sets miss.

That claim is falsifiable. VAIS should report negative results when the boundary fails rather than treating blocked static examples as proof of general prevention.

## Model Context Protocol

MCP standardizes how applications expose resources, prompts and tools to model-facing hosts. The official Python SDK describes tools as model-controlled functions that may take actions, while resources are application-controlled context. VAIS uses MCP as a natural complete-mediation boundary: remote content is treated as data, and consequential tool calls remain subject to application authorization.

VAIS does not claim to replace MCP authorization/OAuth. Protocol authentication answers which client or principal may access an MCP server; VAIS task authorization answers whether this particular agent action, with these arguments and this provenance, is authorized for the current task. Both layers can be required.

Specification: https://modelcontextprotocol.io/

Official Python SDK: https://github.com/modelcontextprotocol/python-sdk
