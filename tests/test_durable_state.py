"""State that survives a restart and holds across processes (rc14).

Until rc14 the session ledger, the revocation list and the gateway's session context lived in
one process's memory: a restart or a second worker reset call limits, forgot revocations and
let a session that had read secret data send it again (LIM-055, LIM-056, LIM-063). Each now
takes an optional file, locked and reloaded around every decision. Without one, nothing
changes, which the rest of the suite covers.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import vais.ledger as ledger_module
import vais.revocation as revocation_module
from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.approvals import ApprovalStore
from vais.cli import main
from vais.gateway import ContractRegistry, Gateway, GatewayOutcomeKind
from vais.gateway_server import build_monitor, load_gateway_config
from vais.ledger import SessionLedger
from vais.models import PlannedAction, TaskContract, TrustedValue
from vais.revocation import RevocationList

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_gateway import POLICY as GATEWAY_POLICY, PROFILE, TOKEN, FakeUpstream, _write_contract  # noqa: E402

POLICY = Policy(version=5, default_action="deny", tools={
    "send": ToolPolicy(True, {"to": ArgumentPolicy("trusted")}, max_calls=2),
    "deploy": ToolPolicy(True, exact_approval_required=True),
})


def _contract(session: str = "s-1") -> TaskContract:
    return TaskContract(allowed_tools={"send", "deploy"}, principal_id="alice", session_id=session,
                        tenant_id="acme", capability_id="root")


def _send() -> PlannedAction:
    return PlannedAction("send", {"to": TrustedValue("ops@acme.test", source="user")})


def _decide(ledger, n=1, action=None, contract=None, revocations=None):
    monitor = ReferenceMonitor(POLICY, revocations=revocations)
    return [monitor.evaluate(action or _send(), contract or _contract(), None, ledger).type.value for _ in range(n)]


# --- the ledger ---------------------------------------------------------------------------

def test_a_call_limit_survives_a_restart(tmp_path):
    path = tmp_path / "ledger.json"
    assert _decide(SessionLedger(_contract(), path), n=2) == ["allow", "allow"]
    assert _decide(SessionLedger(_contract(), path)) == ["deny"]  # a new process, same file


def test_two_ledgers_on_one_file_share_the_limit(tmp_path):
    path = tmp_path / "ledger.json"
    first, second = SessionLedger(_contract(), path), SessionLedger(_contract(), path)  # both loaded first
    assert _decide(first) + _decide(second) + _decide(first) == ["allow", "allow", "deny"]


def test_a_contract_approval_stays_spent_across_a_restart_without_a_store(tmp_path):
    deploy = PlannedAction("deploy", {"target": TrustedValue("prod", source="user")})
    contract = _contract().with_approved_action(deploy)
    path = tmp_path / "ledger.json"
    assert _decide(SessionLedger(contract, path), action=deploy, contract=contract) == ["allow"]
    assert _decide(SessionLedger(contract, path), action=deploy, contract=contract) == ["require_approval"]


_WORKER = """
import sys, time
sys.path.insert(0, {src!r})
from vais import ArgumentPolicy, Policy, ReferenceMonitor, ToolPolicy
from vais.ledger import SessionLedger
from vais.models import PlannedAction, TaskContract, TrustedValue
policy = Policy(version=5, default_action="deny", tools={{"send": ToolPolicy(True, {{"to": ArgumentPolicy("trusted")}}, max_calls=2)}})
contract = TaskContract(allowed_tools={{"send"}}, principal_id="alice", session_id="s-1", tenant_id="acme", capability_id="root")
ledger = SessionLedger(contract, {path!r})
action = PlannedAction("send", {{"to": TrustedValue("ops@acme.test", source="user")}})
while time.time() < {start!r}:
    time.sleep(0.001)
print(ReferenceMonitor(policy).evaluate(action, contract, None, ledger).type.value)
"""


def test_processes_racing_on_one_ledger_file_respect_the_limit(tmp_path):
    path = tmp_path / "ledger.json"
    script = _WORKER.format(src=str(SRC), path=str(path), start=time.time() + 3.0)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    workers = [subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True, env=env)
               for _ in range(6)]
    results = [worker.communicate(timeout=120)[0].strip() for worker in workers]
    assert sorted(results) == ["allow"] * 2 + ["deny"] * 4
    assert len(json.loads(path.read_text(encoding="utf-8"))["entries"]) == 2


def test_a_ledger_file_from_another_session_is_refused(tmp_path):
    path = tmp_path / "ledger.json"
    _decide(SessionLedger(_contract("s-1"), path))
    with pytest.raises(ValueError, match="different session"):
        SessionLedger(_contract("s-2"), path)


@pytest.mark.parametrize("body", ['{"version": 2}', '[]', '{"version": 1, "identity": ["alice", "s-1", "acme"], '
                                  '"entries": [{"tool": "send"}]}'])
def test_a_malformed_ledger_file_is_refused(tmp_path, body):
    path = tmp_path / "ledger.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        SessionLedger(_contract(), path)


def test_a_record_that_cannot_be_written_is_neither_kept_nor_returned(tmp_path, monkeypatch):
    path = tmp_path / "ledger.json"
    ledger = SessionLedger(_contract(), path)

    def fail(*_):
        raise OSError("disk full")

    monkeypatch.setattr(ledger_module, "write_json_atomic", fail)
    with pytest.raises(OSError):
        _decide(ledger)
    assert ledger.entries == ()
    assert not path.exists()


# --- revocations -----------------------------------------------------------------------------

def test_a_revocation_by_another_process_holds_at_the_next_decision_and_after_a_restart(tmp_path):
    path = tmp_path / "revocations.json"
    watching = RevocationList(path)  # the running monitor's list
    fresh = lambda session="s-1": SessionLedger(_contract(session))  # noqa: E731  (send has a call limit)
    assert _decide(fresh(), revocations=watching) == ["allow"]
    RevocationList(path).revoke_session(_contract())  # an operator's command, another process
    assert _decide(fresh(), revocations=watching) == ["deny"]
    assert _decide(fresh(), revocations=RevocationList(path)) == ["deny"]
    assert _decide(fresh("s-2"), contract=_contract("s-2"), revocations=watching) == ["allow"]


def test_revoking_one_capability_leaves_the_others(tmp_path):
    path = tmp_path / "revocations.json"
    RevocationList(path).revoke_capability(_contract())
    other = TaskContract(allowed_tools={"send"}, principal_id="alice", session_id="s-1", tenant_id="acme",
                         capability_id="mailer")
    assert RevocationList(path).is_revoked(_contract())
    assert not RevocationList(path).is_revoked(other)


def test_a_malformed_revocation_file_is_refused(tmp_path):
    path = tmp_path / "revocations.json"
    path.write_text('{"version": 1, "sessions": [["alice", "s-1"]], "capabilities": []}', encoding="utf-8")
    with pytest.raises(ValueError):
        RevocationList(path)


def test_a_revocation_that_cannot_be_written_is_not_applied(tmp_path, monkeypatch):
    revocations = RevocationList(tmp_path / "revocations.json")

    def fail(*_):
        raise OSError("disk full")

    monkeypatch.setattr(revocation_module, "write_json_atomic", fail)
    with pytest.raises(OSError):
        revocations.revoke_session(_contract())
    assert not revocations.is_revoked(_contract())


# --- the gateway -----------------------------------------------------------------------------

def _gateway(tmp_path, *, state=True, monitor=None):
    return Gateway(profile=PROFILE, monitor=monitor or ReferenceMonitor(GATEWAY_POLICY),
                   registry=ContractRegistry(tmp_path / "contracts"), sessions={"ops": FakeUpstream()},
                   approval_store=ApprovalStore(tmp_path / "approvals.json"), pending_dir=tmp_path / "pending",
                   state_dir=tmp_path / "state" if state else None)


def _call(gateway, name, arguments):
    return asyncio.run(gateway.call(TOKEN, name, arguments)).kind


@pytest.fixture
def contracts(tmp_path):
    (tmp_path / "contracts").mkdir()
    _write_contract(tmp_path / "contracts")
    return tmp_path


EMAIL = {"recipient": "ir-team@acme.test", "body": "status"}


def test_the_gateways_call_limit_survives_a_restart(contracts):
    first = _gateway(contracts)
    assert [_call(first, "ops.send_email", EMAIL) for _ in range(2)] == [GatewayOutcomeKind.ALLOWED] * 2
    assert _call(_gateway(contracts), "ops.send_email", EMAIL) is GatewayOutcomeKind.DENIED


def test_what_the_session_read_still_bounds_what_it_sends_after_a_restart(contracts):
    _call(_gateway(contracts), "ops.get_incident", {"incident_id": "INC-1"})  # secret-labelled result
    assert _call(_gateway(contracts), "ops.send_email", EMAIL) is GatewayOutcomeKind.DENIED


def test_without_a_state_directory_a_restart_starts_the_session_fresh(contracts):
    # LIM-063 in the in-memory mode, kept as documented.
    _call(_gateway(contracts, state=False), "ops.get_incident", {"incident_id": "INC-1"})
    assert _call(_gateway(contracts, state=False), "ops.send_email", EMAIL) is GatewayOutcomeKind.ALLOWED


def test_state_file_names_do_not_come_from_the_identity(contracts):
    _call(_gateway(contracts), "ops.get_incident", {"incident_id": "INC-1"})
    names = sorted(p.name for p in (contracts / "state").iterdir() if not p.name.endswith((".lock", ".tmp")))
    assert len(names) == 2 and all(len(n.split(".")[0]) == 32 for n in names)
    assert not any("alice" in n or "s-1" in n for n in names)


def _config(tmp_path) -> Path:
    path = tmp_path / "gateway.yaml"
    path.write_text("version: 1\npolicy: policy.yaml\nprofile: profile.yaml\ncontracts: contracts/\n"
                    "approvals: approvals.json\npending: pending/\naudit: audit.jsonl\nstate: state/\n"
                    "revocations: revocations.json\nupstreams: {ops: {stdio: {command: python}}}\n", encoding="utf-8")
    return path


def test_an_operator_revokes_a_gateway_session_from_the_command_line(contracts, capsys):
    config = load_gateway_config(_config(contracts))
    assert config.state == contracts / "state" and config.revocations == contracts / "revocations.json"
    gateway = _gateway(contracts, monitor=build_monitor(GATEWAY_POLICY, config))
    assert _call(gateway, "ops.send_email", EMAIL) is GatewayOutcomeKind.ALLOWED

    assert main(["gateway-revoke", "--config", str(contracts / "gateway.yaml"),
                 str(contracts / "contracts" / "alice.yaml")]) == 0
    assert "revoked session s-1" in capsys.readouterr().out
    assert _call(gateway, "ops.send_email", EMAIL) is GatewayOutcomeKind.DENIED  # the running gateway


def test_revoking_needs_a_configured_revocation_file(contracts, capsys):
    path = _config(contracts)
    path.write_text(path.read_text(encoding="utf-8").replace("revocations: revocations.json\n", ""), encoding="utf-8")
    assert main(["gateway-revoke", "--config", str(path), str(contracts / "contracts" / "alice.yaml")]) == 2
    assert "no 'revocations' file" in capsys.readouterr().out
