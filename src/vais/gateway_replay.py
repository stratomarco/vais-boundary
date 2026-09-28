"""Replay recorded library-path traces through the gateway and compare the decisions.

Every VAIS study runs the reference agent on the library path: the harness labels the model's
arguments and calls ``MCPProtectedClient`` itself. A deployment behind ``vais gateway`` decides
differently in one respect: the gateway labels every argument itself, from the contract file and
from what the session has received through it (``label_agent_action``). This module asks what
the gateway would have decided for the same agent actions.

For each recorded protected trace it builds a real ``Gateway`` with the workflow's contract as an
operator file, upstream sessions that return the recorded results, and the reference policy, and
sends the recorded calls in order, including the application's setup reads, so the gateway sees
everything the agent saw. Each step's gateway outcome is compared with the recorded decision.

Two orderings are used. A decision is ranked allow < require approval < deny. A label is
stricter when it is less trusted or more confidential. A gateway decision above the library's is
*stricter* (a utility cost); below it is *looser* (a security question). The comparison stops at
a trace's first divergent decision: after it, the two paths have observed different results, so
the recorded actions no longer describe what an agent behind the gateway would have done.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
import json
from pathlib import Path
import secrets
import tempfile
from typing import Any, Iterable, Mapping

import yaml

from .approvals import ApprovalStore
from .gateway import ContractRegistry, Gateway, GatewayOutcomeKind, exposed_name, label_agent_action, token_digest
from .mcp import MCPEffectMapping, MCPMintSpec, MCPProfile, MCPResultPolicy, MCPToolBinding
from .models import ConfidentialityLevel, TaskContract, TrustLevel, action_fingerprint
from .monitor import ReferenceMonitor
from .reference_agent import (
    REFERENCE_POLICY,
    REFERENCE_PROFILE,
    ReferenceWorkflow,
    attack_workflows,
    clean_workflows,
    control_workflows,
)

# The reference application's own tools, served by the harness rather than an MCP server on
# the library path. Behind a gateway they would be upstream tools like any other.
APPLICATION_BINDINGS = (
    # The declassifier's result is the public artifact id the senders require trusted. The
    # library binds it into the contract; behind the gateway the operator declares it a mint
    # (DEC-064). Without the mint the sends were denied (LIM-068).
    MCPToolBinding("status", "build_public_update", "status.build_public_update",
                   MCPResultPolicy(ConfidentialityLevel.PUBLIC),
                   MCPEffectMapping("public_update_built", {"incident_id": "incident_id"}),
                   mints=(MCPMintSpec(None, (("email.send_public_update", "artifact_id"),
                                             ("slack.send_public_update", "artifact_id"))),)),
    MCPToolBinding("email", "send_public_update", "email.send_public_update",
                   MCPResultPolicy(ConfidentialityLevel.PUBLIC),
                   MCPEffectMapping("email_public_update_sent", {"recipient": "recipient", "artifact_id": "artifact_id"})),
    MCPToolBinding("slack", "send_public_update", "slack.send_public_update",
                   MCPResultPolicy(ConfidentialityLevel.PUBLIC),
                   MCPEffectMapping("slack_public_update_sent", {"channel": "channel", "artifact_id": "artifact_id"})),
)
REPLAY_PROFILE = MCPProfile(tuple(REFERENCE_PROFILE.bindings) + APPLICATION_BINDINGS)

_DECISION_RANK = {"allow": 0, "require_approval": 1, "deny": 2}
_OUTCOME_DECISION = {
    GatewayOutcomeKind.ALLOWED: "allow",
    GatewayOutcomeKind.APPROVAL_REQUIRED: "require_approval",
    GatewayOutcomeKind.DENIED: "deny",
}
# Refusals the harness makes after the monitor allowed the call: the application's own
# checks, which a real upstream would make after the gateway forwarded it.
_APPLICATION_REFUSALS = ("unknown_public_artifact:",)


# The known reasons the gateway can be stricter than the library. Anything else, and every
# looser decision, is "unexplained".
MINTED_AUTHORITY = "minted_authority"  # LIM-068
CONTRACT_APPROVAL_SINGLE_USE = "contract_approval_single_use"  # DEC-060; reusable on the library path (LIM-044)
_MINTED_ARGUMENTS = {("email.send_public_update", "artifact_id"), ("slack.send_public_update", "artifact_id")}


def _fingerprint(action) -> str | None:
    try:
        return action_fingerprint(action)
    except ValueError:
        return None


class UpstreamRefused(Exception):
    """The recorded upstream refused the call after the monitor allowed it."""


class _RecordedUpstream:
    """An upstream session that returns whatever the replay has queued for the next call."""

    def __init__(self, server_id: str, feed: "_Feed") -> None:
        self.server_id = server_id
        self.feed = feed

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        return self.feed.take()


@dataclass
class _Feed:
    result: Any = None
    refuse: bool = False

    def take(self) -> Any:
        if self.refuse:
            raise UpstreamRefused()
        return self.result


def _label_key(trust: str, confidentiality: str) -> tuple[int, int]:
    """(untrusted?, confidentiality rank): larger is stricter in both places."""
    return (0 if trust == TrustLevel.TRUSTED.value else 1, ConfidentialityLevel(confidentiality).rank)


def _compare(gateway: tuple[int, int], library: tuple[int, int]) -> str:
    if gateway == library:
        return "same"
    if all(g >= l for g, l in zip(gateway, library)):
        return "gateway_stricter"
    if all(g <= l for g, l in zip(gateway, library)):
        return "gateway_looser"
    return "mixed"


@dataclass(frozen=True)
class StepComparison:
    index: int
    phase: str
    tool: str
    library_decision: str
    gateway_decision: str
    decision: str  # same | gateway_stricter | gateway_looser
    labels: Mapping[str, str]  # argument -> same | gateway_stricter | gateway_looser | mixed
    library_reasons: tuple[str, ...] = ()
    gateway_reasons: tuple[str, ...] = ()
    trust_lost: tuple[str, ...] = ()  # arguments the library trusted and the gateway did not
    cause: str | None = None  # for a divergent decision: why, or "unexplained"


@dataclass
class TraceComparison:
    workflow_id: str
    steps: list[StepComparison] = field(default_factory=list)
    not_compared: int = 0  # action steps after the first divergent decision

    @property
    def first_divergence(self) -> StepComparison | None:
        return next((s for s in self.steps if s.decision != "same"), None)


def _contract_file(path: Path, token: str, contract: TaskContract, *, session_id: str, capability_id: str) -> None:
    bound: dict[str, dict[str, Any]] = {}
    for (tool, argument), value in contract.bound_arguments.items():
        bound.setdefault(tool, {})[argument] = {"value": value.data,
                                                 "confidentiality": value.provenance.confidentiality.value}
    body = {
        "version": 1,
        "token_sha256": token_digest(token),
        "principal_id": "human:analyst",
        "session_id": session_id,
        "tenant_id": "acme",
        "capability_id": capability_id,
        "allowed_tools": sorted(contract.allowed_tools),
        "granted_scopes": sorted(contract.granted_scopes),
        "bound_arguments": bound,
        "approved_action_fingerprints": sorted(contract.approved_action_fingerprints),
    }
    path.write_text(yaml.safe_dump(body, sort_keys=True), encoding="utf-8")


def _setup_contract(workflow: ReferenceWorkflow) -> TaskContract:
    # The library fetches a delegated agent's output under a narrow application contract
    # (reference_agent._trusted_retrieval_contract); the replay gives it the same authority.
    return TaskContract(
        allowed_tools={"agent.delegate"},
        granted_scopes={"agents:delegate"},
        bound_arguments={k: v for k, v in workflow.contract.bound_arguments.items() if k[0] == "agent.delegate"},
    )


async def replay_trace(workflow: ReferenceWorkflow, trace: list[Mapping[str, Any]], workdir: Path) -> TraceComparison:
    """Replay one recorded protected trace (``ReferenceTraceStep.to_dict`` entries)."""
    contracts = workdir / "contracts"
    contracts.mkdir(parents=True, exist_ok=True)
    for old in contracts.glob("*.yaml"):
        old.unlink()
    session_id = f"replay:{workflow.id}:{secrets.token_hex(4)}"
    agent_token, setup_token = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    _contract_file(contracts / "agent.yaml", agent_token, workflow.contract, session_id=session_id, capability_id="task")
    _contract_file(contracts / "setup.yaml", setup_token, _setup_contract(workflow), session_id=session_id,
                   capability_id="application-setup")

    feed = _Feed()
    registry = ContractRegistry(contracts)
    gateway = Gateway(
        profile=REPLAY_PROFILE,
        monitor=ReferenceMonitor(REFERENCE_POLICY),
        registry=registry,
        sessions={b.server_id: _RecordedUpstream(b.server_id, feed) for b in REPLAY_PROFILE.bindings},
        approval_store=ApprovalStore(),
        pending_dir=workdir / "pending",
    )
    agent_contract = registry.lookup(agent_token)
    comparison = TraceComparison(workflow.id)
    allowed_fingerprints: set[str] = set()

    for step in trace:
        action = step.get("action")
        if not action:
            continue
        if comparison.first_divergence is not None:
            comparison.not_compared += 1
            continue
        tool = action["tool"]
        arguments = {name: value["data"] for name, value in action["arguments"].items()}
        setup = step["phase"] == "trusted_retrieval" and tool == "agent.delegate"
        token = setup_token if setup else agent_token
        contract = registry.lookup(token)

        library_reasons = tuple((step.get("decision") or {}).get("reasons") or ())
        library_decision = (step.get("decision") or {}).get("type", "deny")
        application_refused = any(r.startswith(_APPLICATION_REFUSALS) for r in library_reasons)
        if application_refused:
            library_decision = "allow"  # the monitor allowed it; the application refused it afterwards
        result = step.get("result")
        feed.result = result["data"] if result else {"status": "ok"}
        feed.refuse = application_refused

        # The labels the gateway assigns, from the session state it holds before this call.
        state = gateway._state(agent_contract)
        planned = label_agent_action(tool, arguments, contract, state.context_level, state.context_trust,
                                     state.context.minted_for(tool))
        labels, trust_lost = {}, []
        for name, value in action["arguments"].items():
            recorded = value["provenance"]
            mine = planned.arguments[name].provenance
            if recorded["trust"] == TrustLevel.TRUSTED.value and mine.trust is not TrustLevel.TRUSTED:
                trust_lost.append(name)
            labels[name] = _compare(_label_key(mine.trust.value, mine.confidentiality.value),
                                    _label_key(recorded["trust"], recorded["confidentiality"]))

        binding = REPLAY_PROFILE.by_canonical_tool(tool)
        name = exposed_name(binding) if binding else tool
        outcome = await gateway.call(token, name, arguments)
        if application_refused and outcome.kind is GatewayOutcomeKind.INDETERMINATE:
            gateway_decision = "allow"  # forwarded, and the recorded upstream refused it
        else:
            gateway_decision = _OUTCOME_DECISION.get(outcome.kind, "deny")
        rank = _DECISION_RANK[gateway_decision] - _DECISION_RANK[library_decision]
        verdict = "same" if rank == 0 else ("gateway_stricter" if rank > 0 else "gateway_looser")
        fingerprint = _fingerprint(planned)
        cause = None
        if verdict == "gateway_stricter":
            if any((tool, a) in _MINTED_ARGUMENTS for a in trust_lost):
                cause = MINTED_AUTHORITY
            elif (gateway_decision == "require_approval" and fingerprint in contract.approved_action_fingerprints
                  and fingerprint in allowed_fingerprints):
                cause = CONTRACT_APPROVAL_SINGLE_USE
            else:
                cause = "unexplained"
        elif verdict == "gateway_looser":
            cause = "unexplained"
        if gateway_decision == "allow" and fingerprint is not None:
            allowed_fingerprints.add(fingerprint)
        comparison.steps.append(StepComparison(
            step["index"], step["phase"], tool, library_decision, gateway_decision, verdict, labels,
            library_reasons, tuple(outcome.reasons), tuple(trust_lost), cause,
        ))
    return comparison


def workflows_by_id() -> dict[str, ReferenceWorkflow]:
    attacks = attack_workflows()
    return {w.id: w for w in (*attacks, *control_workflows(attacks), *clean_workflows())}


def replay_records(records: Iterable[Mapping[str, Any]], parts: tuple[str, ...] = ("protected_result", "control_result"),
                   ) -> list[tuple[str, int | None, str, TraceComparison]]:
    """Replay the protected traces of adaptive-episode records. Returns (part, episode, workflow, comparison)."""
    workflows = workflows_by_id()
    out = []
    with tempfile.TemporaryDirectory(prefix="vais-gateway-replay-") as tmp:
        for record in records:
            for part in parts:
                result = record.get(part)
                if not result or result.get("mode") != "protected":
                    continue
                workflow = workflows[result["workflow_id"]]
                comparison = asyncio.run(replay_trace(workflow, result["trace"], Path(tmp)))
                out.append((part, record.get("episode"), result["workflow_id"], comparison))
    return out


def summarize(comparisons: Iterable[TraceComparison]) -> dict[str, Any]:
    traces = steps = not_compared = 0
    decisions: Counter = Counter()
    labels: Counter = Counter()
    stricter_arguments: Counter = Counter()
    trust_lost: Counter = Counter()
    divergences: Counter = Counter()
    causes: Counter = Counter()
    looser_examples: list[dict[str, Any]] = []
    for comparison in comparisons:
        traces += 1
        not_compared += comparison.not_compared
        for step in comparison.steps:
            steps += 1
            decisions[step.decision] += 1
            labels.update(step.labels.values())
            stricter_arguments.update(f"{step.tool}.{a}" for a, v in step.labels.items() if v == "gateway_stricter")
            trust_lost.update(f"{step.tool}.{a}" for a in step.trust_lost)
            if step.decision != "same":
                changed = sorted(a for a, v in step.labels.items() if v != "same")
                divergences[(step.decision, step.tool, step.library_decision, step.gateway_decision,
                             ",".join(changed))] += 1
                causes[step.cause] += 1
                if step.decision == "gateway_looser" and len(looser_examples) < 20:
                    looser_examples.append({"workflow": comparison.workflow_id, "step": step.index, "tool": step.tool,
                                            "library": [step.library_decision, *step.library_reasons],
                                            "gateway": [step.gateway_decision, *step.gateway_reasons]})
    return {
        "traces": traces,
        "traces_identical": traces - sum(divergences.values()),
        "compared_steps": steps,
        "steps_not_compared_after_divergence": not_compared,
        "decisions": dict(decisions),
        "argument_labels": dict(labels),
        "stricter_labels_by_argument": dict(stricter_arguments.most_common()),
        "trust_lost_by_argument": dict(trust_lost.most_common()),
        "divergence_causes": dict(causes.most_common()),
        "divergences": [
            {"verdict": k[0], "tool": k[1], "library": k[2], "gateway": k[3], "labels_changed": k[4], "steps": n}
            for k, n in divergences.most_common()
        ],
        "looser_examples": looser_examples,
    }


def load_records(path: str | Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
