"""VAIS Boundary: a deterministic reference monitor for the actions an AI agent proposes.

``vais`` publishes the boundary and nothing else: the monitor, contracts, provenance labels,
policies, approvals, the session ledger, declared stores, audit, revocation, invariants, the MCP
client and the gateway. ``__all__`` is the public interface 1.0 freezes; ``tests/test_core_boundary.py``
holds it and checks that no core module imports the benchmark and research tooling.

That tooling (reference agents, attackers, scenarios, campaign runners, rewards) stays in this
package, in its own modules, for the evidence it produced: import it from those modules, for
example ``from vais.benchmark import BenchmarkRunner``. Since 1.0 they are not reachable from
``vais`` itself.
"""

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
