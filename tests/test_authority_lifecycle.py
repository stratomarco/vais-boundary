"""Authority that expires, can be withdrawn, holds across processes, and only narrows (P1b-8).

Before P1b-8 a task contract and an approval stayed valid for as long as they were used
and could not be withdrawn (LIM-047, the second external reviewer's "where does a
previously valid yes stop counting"), consume-once held only inside one store instance
(LIM-045), and there was no way to hand a sub-agent less authority than its parent.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from vais import (
    PlannedAction,
    Policy,
    ReferenceMonitor,
    RevocationList,
    SessionLedger,
    TaskContract,
    ToolPolicy,
    TrustedValue,
    action_fingerprint,
)
from vais.approvals import ApprovalStore

SRC = Path(__file__).resolve().parents[1] / "src"


class Clock:
    def __init__(self, now: float = 1000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


def _policy(max_calls=None, exact=False) -> Policy:
    return Policy(version=5, default_action="deny", tools={
        "send_email": ToolPolicy(allow=True, exact_approval_required=exact, max_calls=max_calls),
        "read_document": ToolPolicy(allow=True),
    })


def _contract(**overrides) -> TaskContract:
    fields = dict(allowed_tools={"send_email", "read_document"}, granted_scopes={"email:send", "docs:read"},
                  principal_id="p1", session_id="s1", tenant_id="t1", capability_id="root")
    fields.update(overrides)
    return TaskContract(**fields)


def _email(body="hello") -> PlannedAction:
    return PlannedAction("send_email", {"recipient": TrustedValue("alice@example.com"), "body": TrustedValue(body)})


# --- validity window ----------------------------------------------------------------

def test_a_contract_is_denied_outside_its_window():
    clock = Clock()
    contract = _contract(not_before=1000.0, not_after=2000.0)
    monitor = ReferenceMonitor(_policy(), clock=clock)

    clock.now = 999.9
    assert monitor.evaluate(_email(), contract).reasons == ("contract_not_yet_valid",)
    clock.now = 1000.0
    assert monitor.evaluate(_email(), contract).type.value == "allow"
    clock.now = 2000.0
    assert monitor.evaluate(_email(), contract).reasons == ("contract_expired",)


def test_an_expired_contract_does_not_reach_the_ledger():
    clock = Clock(5000.0)
    contract = _contract(not_after=2000.0)
    ledger = SessionLedger(contract)
    ReferenceMonitor(_policy(max_calls=1), clock=clock).evaluate(_email(), contract, None, ledger)
    assert ledger.entries == ()


@pytest.mark.parametrize("fields", [
    {"not_before": True}, {"not_after": float("inf")}, {"not_after": float("nan")}, {"not_before": "1000"},
    {"not_before": 2000.0, "not_after": 1000.0}, {"not_before": 1000.0, "not_after": 1000.0},
])
def test_invalid_windows_are_rejected(fields):
    with pytest.raises(ValueError):
        _contract(**fields)


# --- revocation ------------------------------------------------------------------------

def test_revoking_a_session_denies_every_capability_in_it():
    revocations = RevocationList()
    root = _contract()
    delegate = root.delegate(capability_id="researcher", allowed_tools={"read_document"})
    other_session = _contract(session_id="s2")
    monitor = ReferenceMonitor(_policy(), revocations=revocations)

    revocations.revoke_session(root)

    assert monitor.evaluate(_email(), root).reasons == ("contract_revoked",)
    read = PlannedAction("read_document", {"path": TrustedValue("/a")})
    assert monitor.evaluate(read, delegate).reasons == ("contract_revoked",)
    assert monitor.evaluate(_email(), other_session).type.value == "allow"


def test_revoking_a_capability_leaves_the_rest_of_the_session():
    revocations = RevocationList()
    root = _contract()
    delegate = root.delegate(capability_id="researcher")
    monitor = ReferenceMonitor(_policy(), revocations=revocations)

    revocations.revoke_capability(delegate)

    assert monitor.evaluate(_email(), delegate).reasons == ("contract_revoked",)
    assert monitor.evaluate(_email(), root).type.value == "allow"


# --- approval expiry ------------------------------------------------------------------

def test_an_expired_approval_is_not_consumed():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    store.grant(_email(), _contract(), ttl_seconds=60)

    clock.now += 60
    assert store.consume(_email(), _contract()) is False
    assert store.was_consumed(action_fingerprint(_email()), _contract()) is False


def test_an_approval_within_its_ttl_is_consumed_once():
    clock = Clock()
    store = ApprovalStore(clock=clock)
    store.grant(_email(), _contract(), ttl_seconds=60)
    clock.now += 59.9
    assert [store.consume(_email(), _contract()) for _ in range(2)] == [True, False]


@pytest.mark.parametrize("ttl", [0, -1, True, float("inf"), "60"])
def test_invalid_ttls_are_rejected(ttl):
    with pytest.raises(ValueError):
        ApprovalStore().grant(_email(), _contract(), ttl_seconds=ttl)


def test_expiry_survives_persistence_and_old_files_still_load(tmp_path):
    path = tmp_path / "approvals.json"
    clock = Clock()
    ApprovalStore(path, clock=clock).grant(_email(), _contract(), ttl_seconds=60)
    clock.now += 61
    assert ApprovalStore(path, clock=clock).consume(_email(), _contract()) is False

    legacy = tmp_path / "legacy.json"
    fingerprint = action_fingerprint(_email())
    legacy.write_text(
        f'[{{"capability_id":"root","consumed":false,"fingerprint":"{fingerprint}",'
        '"principal_id":"p1","session_id":"s1","tenant_id":"t1"}]\n', encoding="utf-8")
    assert ApprovalStore(legacy).consume(_email(), _contract()) is True


# --- consume-once across store instances and processes -------------------------------------

def test_two_store_instances_sharing_a_file_consume_once(tmp_path):
    path = tmp_path / "approvals.json"
    ApprovalStore(path).grant(_email(), _contract())
    first, second = ApprovalStore(path), ApprovalStore(path)  # both loaded before either consumes

    assert [first.consume(_email(), _contract()), second.consume(_email(), _contract())] == [True, False]


_WORKER = """
import sys
sys.path.insert(0, {src!r})
from vais import PlannedAction, TaskContract, TrustedValue
from vais.approvals import ApprovalStore
start = {start!r}
import time
while time.time() < start:
    time.sleep(0.001)
action = PlannedAction("send_email", {{"recipient": TrustedValue("alice@example.com"), "body": TrustedValue("hello")}})
contract = TaskContract(allowed_tools={{"send_email", "read_document"}}, granted_scopes={{"email:send", "docs:read"}},
                        principal_id="p1", session_id="s1", tenant_id="t1", capability_id="root")
print(ApprovalStore({path!r}).consume(action, contract))
"""


def test_processes_racing_on_one_file_consume_once(tmp_path):
    import time

    path = tmp_path / "approvals.json"
    ApprovalStore(path).grant(_email(), _contract())
    script = _WORKER.format(src=str(SRC), path=str(path), start=time.time() + 3.0)
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    workers = [subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True, env=env)
               for _ in range(6)]
    results = [worker.communicate(timeout=120)[0].strip() for worker in workers]

    assert sorted(results) == ["False"] * 5 + ["True"]


# --- delegation --------------------------------------------------------------------------

def test_a_delegate_can_only_narrow():
    root = _contract(approved_action_fingerprints={action_fingerprint(_email())}, not_after=2000.0,
                     bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com")})
    child = root.delegate(capability_id="mailer", allowed_tools={"send_email"}, granted_scopes={"email:send"})

    assert child.allowed_tools == {"send_email"}
    assert child.granted_scopes == {"email:send"}
    assert child.bound_arguments == root.bound_arguments
    assert child.not_after == 2000.0
    assert (child.principal_id, child.session_id, child.tenant_id) == ("p1", "s1", "t1")

    for widening in ({"allowed_tools": {"send_email", "shell_exec"}}, {"granted_scopes": {"admin"}},
                     {"approved_action_fingerprints": {"f" * 64}}, {"not_after": 2000.1}):
        with pytest.raises(ValueError):
            root.delegate(capability_id="mailer", **widening)
    with pytest.raises(ValueError):
        root.delegate(capability_id="root")


def test_bindings_for_dropped_tools_are_not_carried():
    root = _contract(bound_arguments={("send_email", "recipient"): TrustedValue("alice@example.com")})
    child = root.delegate(capability_id="reader", allowed_tools={"read_document"})
    assert dict(child.bound_arguments) == {}


def test_a_delegate_shares_its_parents_call_limit():
    root = _contract()
    ledger = SessionLedger(root)
    child = root.delegate(capability_id="mailer")
    monitor = ReferenceMonitor(_policy(max_calls=3))

    decisions = [monitor.evaluate(_email(), c, None, ledger).type.value for c in (root, root, child, child)]
    assert decisions == ["allow", "allow", "allow", "deny"]


def test_a_delegate_spends_its_parents_contract_approval():
    fingerprint = action_fingerprint(_email())
    root = _contract(approved_action_fingerprints={fingerprint})
    ledger = SessionLedger(root)
    child = root.delegate(capability_id="mailer")
    monitor = ReferenceMonitor(_policy(exact=True))

    assert monitor.evaluate(_email(), root, None, ledger).type.value == "allow"
    assert monitor.evaluate(_email(), child, None, ledger).type.value == "require_approval"


def test_the_ledger_is_keyed_by_session_not_capability():
    ledger = SessionLedger(_contract())
    assert ledger.matches(_contract(capability_id="other")) is True
    assert ledger.matches(_contract(session_id="s2")) is False
