# Pre-registration: what AgentCore Policy's language can express of VAIS's decisions

**Status:** registered on 2026-10-20, before any Dogwood policy for this study is written or any
trace is replayed. Changes after registration are listed in `RESULTS.md` as deviations, dated.

## Question

Amazon Bedrock AgentCore Policy is the system nearest to VAIS ([`docs/guardrail-frameworks.md`](../../docs/guardrail-frameworks.md)):
deterministic, default-deny rules at a gateway, with temporal rules over a session's earlier calls.
Its policy language, Dogwood, is open source. VAIS 1.0 claims that what it adds is **enforcement
on the provenance of each argument value**. This study measures that claim on VAIS's own recorded
attacks:

> On the same calls, with the same information, which of VAIS's decisions can a Dogwood policy
> make, and which can it not make without also refusing legitimate work?

The study measures the language, through its reference interpreter, not the AgentCore service. The
interpreter's README says it is not meant for production use; a difference between it and the
service would not be visible here.

## Corpus

VAIS's deterministic reference workflows, both applications, 73 in all:

| Application | Attacks | Benign |
|---|---|---|
| Incident response | 20 (`attack-01`..`attack-20`) | 5 clean |
| Accounts payable | 21 (`attack-01`..`attack-21`) | 6 clean and 21 controls, one matched to each attack |

For each workflow, the trace is the `deterministic-reference-vulnerable` target's **unprotected**
run from `vais lab reference-agent-default` (`--application` each): the sequence of calls a fully
compromised model proposes, with every argument and every tool's output. The vulnerable target
follows every injection, so every attack's harmful call is in its trace.

## How the traces are replayed

Both engines decide **every call of the same fixed trace**, in order:
- **VAIS:** the reference monitor with the workflow's own policy, contract, approval store and a
  session ledger, as in the protected run.
- **Dogwood:** `dogwood replay` over a trace in which:
  - the first event is the **task**, recorded by the gateway from the authenticated request before
    any untrusted content is read: the workflow's tenant, allowed tools, bound arguments, allowed
    values, budgets and operator approvals. The agent cannot produce this event;
  - each call is a `request` event with its plain arguments;
  - if Dogwood allows it, its `response` event follows with the tool's output; if not, an
    `error` event, and no output is recorded.

The trace is not changed by a refusal: later calls are the ones the compromised model proposed. A
real model might act differently after a refusal, so decisions after the first refusal describe
the policy, not a run. This is the simplification VAIS's own counterfactual replays make.

## The information constraint

The Dogwood policies may use exactly what VAIS's configuration knows, and nothing else:
- the policy (tools allowed, argument trust requirements, confidentiality ceilings, approval
  thresholds, exact-approval rules, call limits, the untrusted-origin rule);
- the MCP profiles' knowledge of each tool (what it returns and how confidential it is, what it
  mints);
- the fields of the task event.

They are written **per application, as general rules over tools, arguments, output fields and
task fields**. No rule may name a workflow, compare against a literal taken from an attack
payload (such as an attacker's address or account), or be written after looking at a replay
result. A policy that fails `dogwood validate` may be fixed for syntax only; a change of meaning
after the first replay is a deviation, reported as a second, exploratory round.

The policies are committed before the first replay; their commit is recorded in `RESULTS.md`.

## Outcomes

Per workflow, for each engine:
- **attack refused:** at least one call is refused at or before the first call whose effect
  violates one of VAIS's invariants in the unprotected run (the harmful call);
- **benign completed:** every call of a clean or control workflow is allowed.

Reported as a 2×2 table per application (VAIS refuses or not × Dogwood refuses or not) for attacks,
and the count of benign workflows each engine completes. Every attack where the engines differ is
listed with the call, both decisions, and why.

Per call, across all 73 traces: agreement between the two engines' decisions, with disagreements
split into **Dogwood looser** (it allows what VAIS refuses or holds) and **Dogwood stricter**.

Approval holds: VAIS's `require_approval` and a Dogwood rule that requires an earlier approval
event both count as refusing the call.

## Predictions, made before any policy is written

By attack category:
1. **Expressible, so equal.** Tools outside the task, another tenant, an authority argument that
   differs from the task's trusted value, an amount over a threshold without an exact approval, a
   replayed or mutated approval, a call limit or a sum. Dogwood expresses these as equality with
   task fields and temporal rules over earlier events.
2. **Secret egress through model-written text.** Expressible as "after reading from a confidential
   source in this session, refuse an outbound send", the same coarse session-level rule as VAIS's
   gateway. Predicted equal on these traces.
3. **Delegation (incident `attack-18`..`attack-20`).** VAIS derives a sub-agent's contract from its
   parent's and refuses one that widens it. Predicted **not expressible** within the policy
   language: a delegated principal and its authority would have to be created outside it.
4. **Authority from a system of record** (accounts payable: a bank account read from the vendor
   master). Expressible as correlation with that read's output field; predicted equal, except
   where the attack first changes the record through a call the policy allows.

Overall prediction: Dogwood matches VAIS on most attacks and benign workflows of this corpus, and
differs on the delegation attacks and on at most a few others.

## How the result is read

- If at least one attack VAIS refuses **cannot** be refused by a policy written under the
  constraint without failing a benign workflow, that attack is evidence for VAIS's claim, and is
  described exactly.
- If Dogwood matches VAIS on every attack and benign workflow, the claim of a decision AgentCore's
  language cannot make is **not supported on this corpus**. VAIS's distinctive claim then narrows to
  what the comparison did not measure: the library path, openness and local deployment, and the
  published adversarial evidence. The positioning documents are changed to say so.
- Either way, the structural differences that the corpus does not exercise are reported separately
  and not counted: the 24-hour window cap, caller-supplied session identifiers, principal-scoped
  history, and the library integration path.

## What this study cannot show

- Anything about the AgentCore service itself, its natural-language authoring, or its Guardrails
  integration.
- Behaviour beyond these 73 deterministic workflows, two applications designed alongside VAIS.
- That the policies written are the best possible: a better Dogwood author might express more. Each
  policy is published so that can be checked.

## Materials

- `make_traces.py`: turns the reference runs into Dogwood traces and VAIS's per-call decisions.
- `policies/incident.dw`, `policies/accounts-payable.dw`, and their Cedar schemas.
- `run.py`: replays every trace with both engines and writes `results/`.
- Dogwood: `dogwood-policy/dogwood`, Apache-2.0, built from the commit recorded in `RESULTS.md`.
