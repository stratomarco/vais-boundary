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
