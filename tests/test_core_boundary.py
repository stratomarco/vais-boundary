"""The boundary is the public interface; the benchmark and research tooling is not.

Decided 2026-10-19 (plan of record §1a): 1.0 freezes the core's names, and the core never
depends on the tooling that produced the evidence. A change to ``PUBLIC`` is a change to the
interface 1.0 promises, so it is made here deliberately, not as a side effect.
"""

from __future__ import annotations

import ast
from importlib import import_module
from pathlib import Path
import subprocess
import sys
import warnings

import pytest

import vais

PACKAGE = Path(vais.__file__).resolve().parent

# The modules that make up the boundary. Everything else in the package is benchmark or research
# tooling, or the command line, which may use both.
CORE = {
    "_version", "approvals", "audit", "defaults", "durable", "exceptions", "executor", "gateway",
    "gateway_server", "invariants", "ledger", "mcp", "models", "monitor", "policy", "revocation",
    "sandbox", "stores", "taint", "yaml_input",
}

PUBLIC = {
    "__version__",
    "ConfidentialityLevel", "Decision", "DecisionType", "PlannedAction", "Provenance", "TaskContract",
    "TrustLevel", "TrustedValue", "Value", "action_fingerprint", "action_origin", "derive_model_output",
    "derive_value",
    "ReferenceMonitor", "ApprovalPolicy", "ArgumentPolicy", "Policy", "PolicyValidationError",
    "ToolPolicy", "load_default_policy", "load_policy",
    "ApprovalGrant", "ApprovalStore", "AuditEvent", "AuditTrail", "LedgerEntry", "RevocationList",
    "SessionLedger",
    "DeclarativeInvariantEngine", "InvariantDefinition", "InvariantViolation", "load_default_invariants",
    "load_invariants",
    "Effect", "ExecutionRecord", "ProtectedExecutor", "SandboxExecutor",
    "MCPCallState", "MCPEffectMapping", "MCPExecutionRecord", "MCPProfile", "MCPProtectedClient",
    "MCPResultPolicy", "MCPToolBinding", "MCPToolSession", "MCPUnprotectedClient", "canonical_mcp_tool",
    "extract_mcp_result_data", "label_mcp_input", "load_example_mcp_profile", "load_mcp_profile",
    "store_flow_problems",
    "ContractRegistry", "Gateway", "GatewayOutcome", "GatewayOutcomeKind", "MintedValue",
    "grant_pending_request", "label_agent_action", "load_gateway_contract",
}


def test_the_public_interface_is_the_frozen_core():
    assert len(vais.__all__) == len(set(vais.__all__))
    assert set(vais.__all__) == PUBLIC
    for name in vais.__all__:
        assert hasattr(vais, name), name


def test_every_public_name_comes_from_a_core_module():
    for name in PUBLIC - {"__version__"}:
        module = getattr(vais, name).__module__
        assert module.startswith("vais.") and module.split(".")[1] in CORE, (name, module)


def _vais_imports(path: Path) -> set[str]:
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            if node.level == 1:
                found |= {node.module.split(".")[0]} if node.module else {a.name for a in node.names}
            elif node.module and node.module.split(".")[0] == "vais":
                parts = node.module.split(".")
                found |= {parts[1]} if len(parts) > 1 else {a.name for a in node.names}
        elif isinstance(node, ast.Import):
            found |= {a.name.split(".")[1] for a in node.names if a.name.startswith("vais.")}
    return found


def test_the_core_never_imports_the_tooling():
    modules = {p.stem for p in PACKAGE.glob("*.py")} - {"__init__", "__main__"}
    assert CORE <= modules
    problems = {m: sorted((_vais_imports(PACKAGE / f"{m}.py") & modules) - CORE) for m in sorted(CORE)}
    assert not {m: v for m, v in problems.items() if v}


def test_importing_vais_loads_no_tooling():
    code = ("import sys, vais; "
            "print(','.join(sorted(m.split('.')[1] for m in sys.modules if m.startswith('vais.'))))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         env={**__import__("os").environ, "PYTHONPATH": str(PACKAGE.parent)}).stdout.strip()
    loaded = set(out.split(",")) if out else set()
    assert loaded <= CORE, sorted(loaded - CORE)


@pytest.mark.parametrize("name,module", sorted(vais._MOVED.items()))
def test_moved_names_still_resolve_with_a_deprecation_warning(name, module):
    with pytest.warns(DeprecationWarning, match=rf"vais\.{module}"):
        obj = getattr(vais, name)
    assert obj is getattr(import_module(f"vais.{module}"), name)
    assert name not in PUBLIC and module not in CORE


def test_unknown_names_are_still_errors():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        with pytest.raises(AttributeError):
            vais.NoSuchName  # noqa: B018
