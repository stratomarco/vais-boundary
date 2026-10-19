"""VAIS Boundary: a deterministic reference monitor for the actions an AI agent proposes.

``vais`` publishes the boundary and nothing else: the monitor, contracts, provenance labels,
policies, approvals, the session ledger, declared stores, audit, revocation, invariants, the MCP
client and the gateway. ``__all__`` is the public interface 1.0 freezes; ``tests/test_core_boundary.py``
holds it and checks that no core module imports the benchmark and research tooling.

That tooling (reference agents, attackers, scenarios, campaign runners, rewards) stays in this
package, in its own modules, for the evidence it produced: import it from those modules, for
example ``from vais.benchmark import BenchmarkRunner``. Its names are still reachable from
``vais`` itself, with a ``DeprecationWarning``, until 1.0.
"""

from importlib import import_module
import warnings

from ._version import __version__
from .approvals import ApprovalGrant, ApprovalStore
from .audit import AuditEvent, AuditTrail
from .defaults import load_default_invariants, load_default_policy, load_example_mcp_profile
from .exceptions import PolicyValidationError
from .executor import ExecutionRecord, ProtectedExecutor
from .gateway import (
    ContractRegistry,
    Gateway,
    GatewayOutcome,
    GatewayOutcomeKind,
    MintedValue,
    grant_pending_request,
    label_agent_action,
    load_gateway_contract,
)
from .invariants import (
    DeclarativeInvariantEngine,
    InvariantDefinition,
    InvariantViolation,
    load_invariants,
)
from .ledger import LedgerEntry, SessionLedger
from .mcp import (
    MCPCallState,
    MCPEffectMapping,
    MCPExecutionRecord,
    MCPProfile,
    MCPProtectedClient,
    MCPResultPolicy,
    MCPToolBinding,
    MCPToolSession,
    MCPUnprotectedClient,
    canonical_mcp_tool,
    extract_mcp_result_data,
    label_mcp_input,
    load_mcp_profile,
)
from .models import (
    ConfidentialityLevel,
    Decision,
    DecisionType,
    PlannedAction,
    Provenance,
    TaskContract,
    TrustLevel,
    TrustedValue,
    Value,
    action_fingerprint,
)
from .monitor import ReferenceMonitor
from .policy import ApprovalPolicy, ArgumentPolicy, Policy, ToolPolicy, load_policy
from .revocation import RevocationList
from .sandbox import Effect, SandboxExecutor
from .stores import store_flow_problems
from .taint import action_origin, derive_model_output, derive_value

__all__ = [
    "__version__",
    # Provenance and decisions
    "ConfidentialityLevel",
    "Decision",
    "DecisionType",
    "PlannedAction",
    "Provenance",
    "TaskContract",
    "TrustLevel",
    "TrustedValue",
    "Value",
    "action_fingerprint",
    "action_origin",
    "derive_model_output",
    "derive_value",
    # The monitor and its policy
    "ReferenceMonitor",
    "ApprovalPolicy",
    "ArgumentPolicy",
    "Policy",
    "PolicyValidationError",
    "ToolPolicy",
    "load_default_policy",
    "load_policy",
    # Approvals, session rules, revocation, audit
    "ApprovalGrant",
    "ApprovalStore",
    "AuditEvent",
    "AuditTrail",
    "LedgerEntry",
    "RevocationList",
    "SessionLedger",
    # Invariants
    "DeclarativeInvariantEngine",
    "InvariantDefinition",
    "InvariantViolation",
    "load_default_invariants",
    "load_invariants",
    # Execution
    "Effect",
    "ExecutionRecord",
    "ProtectedExecutor",
    "SandboxExecutor",
    # MCP
    "MCPCallState",
    "MCPEffectMapping",
    "MCPExecutionRecord",
    "MCPProfile",
    "MCPProtectedClient",
    "MCPResultPolicy",
    "MCPToolBinding",
    "MCPToolSession",
    "MCPUnprotectedClient",
    "canonical_mcp_tool",
    "extract_mcp_result_data",
    "label_mcp_input",
    "load_example_mcp_profile",
    "load_mcp_profile",
    "store_flow_problems",
    # The gateway
    "ContractRegistry",
    "Gateway",
    "GatewayOutcome",
    "GatewayOutcomeKind",
    "MintedValue",
    "grant_pending_request",
    "label_agent_action",
    "load_gateway_contract",
]

# Benchmark and research names that ``vais`` used to publish, and the module that holds each.
_MOVED = {
    **dict.fromkeys((
        "AttackCandidate", "AttackObservation", "Attacker", "CorpusAttacker", "CorpusEntryAttacker",
        "DeterministicScenarioTarget", "ReplayAttacker", "ScenarioStaticAttacker", "TargetAgent",
        "corpus_entry_attackers", "load_attack_corpus"), "adaptive"),
    **dict.fromkeys((
        "AdaptiveCandidate", "AdaptiveCampaignResult", "AdaptiveEpisodeResult", "AdaptiveObservation",
        "AdaptiveReferenceVerifier", "AdaptiveVerifierConfig", "FixedMutationSearchAttacker",
        "LMStudioAdaptiveAttacker", "MutationSearchAttacker", "PatternAdaptiveReferenceTarget",
        "REFERENCE_BASELINE_VERSION", "TERMINAL_REWARD_DEFINITION", "adaptive_configuration_hash",
        "independent_adaptive_violations", "selected_attack_workflows", "summarize_adaptive_campaigns",
        "terminal_security_reward", "violated_security_invariants", "write_adaptive_results_jsonl",
        "write_rlvr_trajectories"), "adaptive_reference"),
    **dict.fromkeys(("BehavioralIntegrityGate", "DriftFinding"), "behavioral_gate"),
    **dict.fromkeys((
        "BenchmarkRunner", "EpisodeResult", "ProtectionMode", "stable_hash", "summarize_results",
        "write_results_jsonl"), "benchmark"),
    **dict.fromkeys(("EvaluationResult", "SecurityEvaluationHarness"), "harness"),
    **dict.fromkeys((
        "MCPBenchmarkRunner", "MCPDeterministicScenarioTarget", "RecordingMCPSession",
        "clean_mcp_content", "default_mcp_benchmark_profile", "mcp_ingress_value"), "mcp_benchmark"),
    **dict.fromkeys(("AttackObjectiveFinding", "AttackObjectiveSpec", "AttackObjectiveType"), "objectives"),
    **dict.fromkeys(("LMStudioTarget", "OpenAICompatibleConfig", "OpenAICompatibleTarget"), "openai_compatible"),
    **dict.fromkeys((
        "DeterministicReferenceTarget", "ReferenceAgentRunner", "ReferenceMode", "ReferencePrincipal",
        "ReferenceState", "ReferenceTraceStep", "ReferenceWorkflow", "ReferenceWorkflowResult",
        "SelectiveReferenceTarget", "TraceInvariantResult", "attack_workflows", "clean_workflows",
        "reference_workflows", "summarize_reference_results", "write_reference_results_jsonl"),
        "reference_agent"),
    "ReferenceAgentLMStudioTarget": "reference_agent_lmstudio",
    **dict.fromkeys(("DeclarativeVerifiableReward", "SecurityInvariant", "VerifiableReward"), "reward"),
    **dict.fromkeys(("ExpectedEffect", "Scenario", "default_scenarios"), "scenarios"),
    **dict.fromkeys(("GenerationMetadata", "TargetRunResult", "TargetStatus"), "targeting"),
}


def __getattr__(name: str):
    module = _MOVED.get(name)
    if module is None:
        raise AttributeError(f"module 'vais' has no attribute {name!r}")
    warnings.warn(
        f"vais.{name} is benchmark or research tooling, not part of the boundary's public interface; "
        f"import it from vais.{module}. The top-level name will be removed in 1.0.",
        DeprecationWarning,
        stacklevel=2,
    )
    return getattr(import_module(f"{__name__}.{module}"), name)
