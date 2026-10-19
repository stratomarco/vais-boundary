# Guardrail frameworks, and where VAIS fits

*Checked on 2026-10-19 against each project's own documentation or repository (sources at the
end). These projects change quickly; a statement here describes what the documentation said on
that date, not a test of the product. None of these frameworks has been run against VAIS's
scenarios.*

## The question each one answers

Most guardrail frameworks ask **"is this text acceptable?"**: whether an input is a jailbreak,
whether an output is toxic, leaks personal data, strays off topic or is ungrounded. They decide
with classifiers, LLM judges, word lists and regular expressions, and they trade missed attacks
against false alarms with a threshold.

VAIS asks **"is this action authorised, given where each of its arguments came from?"** It does
not read meaning. It decides deterministically from provenance labels, the task contract and the
session's history, and it cannot be argued out of a refusal. It also cannot tell whether a reply
is toxic or true. The two questions are complementary, and a deployment can need both.

## The frameworks

| Framework | Form | What it inspects | How it decides | Agent tool calls | Session state | Where an argument came from |
|---|---|---|---|---|---|---|
| **NeMo Guardrails** (NVIDIA) | Open-source library, Apache-2.0, v0.24.1 | Input, dialog, retrieval, tool calls and results, output | LLM self-check prompts, NVIDIA safety models, third-party APIs, Colang dialog flows; tool rails are deterministic | Checks that a call names a declared tool and that its arguments satisfy the tool's JSON Schema; fails closed | Dialog state through Colang flows | Not described |
| **Guardrails AI** | Open-source library, Apache-2.0; hosted inference discontinued 2026-08-25 | Input and output text; structured output | Validators from a hub: regular expressions, lists, models | Not described | Not described | Not described |
| **OpenAI Guardrails** | Open-source library, MIT; wraps the OpenAI client and Agents SDK | Input, output, tool calls and tool outputs | Moderation API, PII model, URL lists, LLM checks | An LLM judges whether each tool call or tool output fits the user's goal | The user's goal, from recent messages | Not described |
| **OpenAI Agents SDK** tool guardrails | Open-source SDK | A function tool's arguments before it runs, its output after | Functions the developer writes, deterministic or not | Skip the call, replace its output, or raise a tripwire | The run's items | Not described |
| **LlamaFirewall** (Meta) | Open-source, PurpleLlama | User input, untrusted content, agent reasoning, generated code | Classifier (PromptGuard 2), LLM auditor (AlignmentCheck), regex, static analysis (CodeShield) | AlignmentCheck audits whether the agent's reasoning and actions still serve the user's request | Conversation traces | Not described |
| **Llama Guard 4** (Meta) | Safety model, 12B, multimodal | Prompts and responses | Classifier over 14 hazard categories | Only "code interpreter abuse" as a category | None | None |
| **Granite Guardian 4.1** (IBM) | Safety model, 8B, Apache-2.0 | Prompts, responses, RAG context, tool calls | LLM judge returning yes/no per criterion | Flags tool calls with wrong argument names, values or types ("function-calling hallucination") | None | None |
| **LLM Guard** (Protect AI) | Open-source library, MIT, **archived in 2026** | 15 input and 21 output scanners | Models and regular expressions | None | None | None |
| **Invariant Guardrails** (Invariant Labs, acquired by Snyk in 2025) | Open-source, Apache-2.0; library or LLM/MCP proxy | Messages, tool calls, tool outputs, across a trace | Rules in a Python-like language, which can call detectors such as a prompt-injection score | Rules match patterns over a trace, such as a tool output followed by `send_email` | The trace | Patterns over the order of events; no labels on values described |
| **Amazon Bedrock Guardrails** | Managed service; also standalone through `ApplyGuardrail` | Input and output text, images | Content filters, denied topics, word lists, PII, grounding; Automated Reasoning checks responses against logical rules | None | None | None |
| **Amazon Bedrock AgentCore Policy** | Managed service, at the AgentCore Gateway; policies in Cedar or Dogwood (open-source language) | Every tool call through the gateway | **Deterministic**: default deny, forbid wins; optional Guardrails scores as inputs | Rules over the caller's identity, the tool and its arguments | **Temporal rules** over the session's earlier calls and their inputs and outputs: approval before an action, counts, running sums, within 24 hours | A rule can require a current argument to equal a field of an earlier event, such as the claim an earlier approval covered; no labels that follow a value through the model's text |
| **Azure AI Content Safety Prompt Shields** | Managed service; Foundry guardrails | User prompts; documents and, for agents, tool responses | Classifiers for prompt and document attacks; optional "spotlighting" that encodes documents | Scans tool responses for injected instructions (preview) | None | Microsoft states the service "doesn't independently verify the submitted content's provenance" |
| **Google Cloud Model Armor** | Managed service | Prompts, responses, documents, images | Configurable filters: safety, prompt injection, sensitive data, malicious URLs | Integrations with Agent Gateway and MCP servers listed; not described further | Stateless | None |
| **Lakera Guard** (Check Point) | Managed service | Inputs, outputs, referenced documents | Machine learning, language models and rules, with confidence thresholds | Tool allow and deny lists; a "dangerous deviation" detector for actions outside the agent's mandate | Not described | Not described |

Smaller open-source projects track the origin of values in agent tool calls directly, such as
Tessera and taintgate. They describe themselves as early or work in progress, and their results
are self-reported, so they are noted here and not assessed.

## What this shows

1. **Most of the field judges text, probabilistically.** That is the right tool for toxicity,
   personal data, topic control and grounding, which VAIS does not attempt. For prompt injection
   it carries the trade-off VAIS's Tier A v3 measured (FIND-074): the one detector there that
   approached VAIS's catch rate dropped 48% of legitimate content. OpenAI's own published numbers
   for its tool-call injection check show the same tension: at a 1% false-positive rate its
   default model, gpt-4.1-mini, detected none of the positive cases, and the best model listed,
   gpt-5, 58%. Tier A did not test any of the products above, so this is the same class of
   mechanism, not a measurement of them.
2. **Deterministic control of tool calls is now common.** NeMo validates calls against declared
   schemas, Lakera has tool allow and deny lists, the Agents SDK lets developers write checks, and
   Invariant matches rules over traces. "A deterministic check on tool calls" is not, by itself,
   distinctive.
3. **AgentCore Policy is the closest system to VAIS.** It enforces deterministic, default-deny
   rules at a gateway outside the agent's code, with session rules for approvals, counts and
   running totals, and logs every decision. Those overlap with VAIS's gateway, approvals and
   session ledger (DEC-067, DEC-069). From its documentation, the differences are:
   - **Provenance.** VAIS labels every value with its trust and confidentiality and carries the
     labels through derivation, including text the model writes after reading untrusted content.
     A rule can then refuse an argument because of where it came from, however it is phrased.
     AgentCore can match a current argument to a field of an earlier call, which covers some of
     the same cases, such as acting only on a claim an approval named. Neither AWS's nor Dogwood's
     documentation describes labels that follow a value through the model's output.
   - **Confidentiality flows.** VAIS refuses a flow of confidential data to a less trusted sink,
     and checks at startup that declared stores cannot launder labels across sessions (DEC-070).
     Nothing equivalent is described for AgentCore.
   - **Minted authority.** VAIS can make a value the application creates mid-session into an
     allowed value. AgentCore approximates this with temporal correlation.
   - **Deployment.** VAIS is an open-source library and gateway that runs anywhere. AgentCore is
     an AWS service, scoped to one account and region, and its session ID is supplied by the
     caller, so a new session resets a count. In the other direction, AgentCore is managed and
     spans services, while VAIS coordinates state only on one machine (LIM-057).
   - **Evidence.** VAIS publishes pre-registered adversarial studies against its boundary. No
     comparable public evaluation of AgentCore Policy was found.

## Consequences for VAIS

- **Scope.** VAIS should not add content moderation, topic control or grounding checks. These
  frameworks do that, and VAIS composes with them: a text guardrail on the conversation, VAIS on
  the actions.
- **Claims.** The distinctive claim is narrower than "deterministic enforcement of tool calls":
  it is **deterministic enforcement on the provenance of each argument value**, including values
  the model derived from what it read, with confidentiality flows and minted authority, in an
  open, locally run implementation with published adversarial evidence. Positioning should say
  so, and name AgentCore Policy as the nearest system.
- **A possible study, not scheduled.** Dogwood is open source, so whether VAIS's recorded attack
  scenarios can be expressed as Dogwood policies could be measured locally, without AWS. That
  would turn the comparison above from documentation into evidence.

## Sources

- NeMo Guardrails: [repository](https://github.com/NVIDIA/NeMo-Guardrails), [guardrail catalog](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog.md), [tool calling](https://docs.nvidia.com/nemo/guardrails/configure-guardrails/guardrail-catalog/tool-calling.md)
- Guardrails AI: [repository](https://github.com/guardrails-ai/guardrails)
- OpenAI Guardrails: [repository](https://github.com/openai/openai-guardrails-python), [prompt injection detection](https://openai.github.io/openai-guardrails-python/ref/checks/prompt_injection_detection/); Agents SDK: [guardrails](https://openai.github.io/openai-agents-python/guardrails/)
- LlamaFirewall: [repository](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall), [paper](https://arxiv.org/abs/2505.03574); Llama Guard 4: [model card](https://dev.meta.ai/llama/docs/model-cards-and-prompt-formats/llama-guard-4/)
- Granite Guardian: [repository](https://github.com/ibm-granite/granite-guardian)
- LLM Guard: [repository](https://github.com/protectai/llm-guard)
- Invariant Guardrails: [repository](https://github.com/invariantlabs-ai/invariant); acquisition: [Snyk](https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/)
- Amazon Bedrock Guardrails: [user guide](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
- AgentCore Policy: [overview](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html), [temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html); Dogwood: [language](https://dogwood-policy.github.io/dogwood/index.html)
- Azure Prompt Shields: [concepts](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection)
- Google Model Armor: [overview](https://docs.cloud.google.com/security-command-center/docs/model-armor-overview)
- Lakera Guard: [defenses](https://docs.lakera.ai/docs/defenses)
- Early provenance projects: [taintgate](https://github.com/rudratoshs/taintgate)
