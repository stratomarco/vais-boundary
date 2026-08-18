from pathlib import Path

from vais.models import PlannedAction, TaskContract, TrustedValue, DecisionType
from vais.monitor import ReferenceMonitor
from vais.policy import load_policy


def test_policy_v3_exact_action_approval(tmp_path: Path):
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
version: 3
default_action: deny
tools:
  production.restart_service:
    allow: true
    required_scope: production:restart
    exact_approval_required: true
    arguments:
      service:
        trust_required: trusted
""".strip()
        + "\n",
        encoding="utf-8",
    )
    policy = load_policy(policy_file)
    service = TrustedValue("service-api", source="user")
    action = PlannedAction("production.restart_service", {"service": service})
    contract = TaskContract(
        allowed_tools={"production.restart_service"},
        granted_scopes={"production:restart"},
        bound_arguments={("production.restart_service", "service"): service},
    )
    monitor = ReferenceMonitor(policy)
    assert monitor.evaluate(action, contract).type == DecisionType.REQUIRE_APPROVAL
    assert monitor.evaluate(action, contract.with_approved_action(action)).type == DecisionType.ALLOW
