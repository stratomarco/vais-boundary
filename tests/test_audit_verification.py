"""Where and how an audit chain broke (LIM-038), and verifying the file an investigator holds.

Until rc14 AuditTrail.verify returned a bare boolean and nothing checked an audit file. Now
verify_report and verify_jsonl list every failed check with its position, and
`vais audit-verify` runs them on a file. verify() keeps its answer.
"""
from __future__ import annotations

import pytest

from vais.audit import AuditBreak, AuditTrail, verify_jsonl
from vais.cli import main


def _trail(n: int = 6) -> AuditTrail:
    trail = AuditTrail()
    for i in range(n):
        trail.record("decision", tool=f"tool{i}", decision="allow", reasons=("ok",), details={"n": i})
    return trail


def _lines() -> list[str]:
    return _trail().to_jsonl().splitlines()


def test_an_intact_file_verifies_and_reads_back_identically():
    text = _trail().to_jsonl()
    assert verify_jsonl(text).ok and verify_jsonl(text).events == 6
    assert AuditTrail.from_jsonl(text).to_jsonl() == text
    assert AuditTrail.from_jsonl(text).verify()


def test_an_edit_in_place_is_one_content_break_at_that_event():
    lines = _lines()
    lines[2] = lines[2].replace('"tool2"', '"toolX"')
    assert verify_jsonl("\n".join(lines)).breaks == (AuditBreak(3, "content"),)


def test_a_removed_event_breaks_the_sequence_and_the_link_where_it_was():
    lines = _lines()
    report = verify_jsonl("\n".join(lines[:2] + lines[3:]))
    assert report.first_break == AuditBreak(3, "sequence")
    assert AuditBreak(3, "link") in report.breaks
    assert all(b.check == "sequence" for b in report.breaks if b.position > 3)


def test_a_rewritten_prefix_shows_as_one_link_break_where_it_meets_the_original():
    original = _lines()
    forged = AuditTrail()
    for i in range(3):  # an attacker rewrites events 1..3 with recomputed hashes
        forged.record("decision", tool=f"forged{i}", decision="allow", reasons=("ok",), details={"n": i})
    text = "\n".join(forged.to_jsonl().splitlines() + original[3:])
    assert verify_jsonl(text).breaks == (AuditBreak(4, "link"),)


def test_a_line_that_is_not_an_event_is_reported_not_raised():
    lines = _lines()
    lines[1] = "not json"
    report = verify_jsonl("\n".join(lines))
    assert report.breaks == (AuditBreak(2, "malformed"),)  # the next link cannot be checked
    with pytest.raises(ValueError):
        AuditTrail.from_jsonl("\n".join(lines))


def test_verify_answers_as_before():
    trail = _trail()
    assert trail.verify() and trail.verify_report().ok
    edited = AuditTrail.from_jsonl("\n".join(_lines()[:2] + _lines()[3:]))
    assert edited.verify() is False


def test_the_command_line_reports_and_exits_by_result(tmp_path, capsys):
    good, bad = tmp_path / "good.jsonl", tmp_path / "bad.jsonl"
    good.write_text(_trail().to_jsonl() + "\n", encoding="utf-8")
    lines = _lines()
    lines[4] = lines[4].replace('"tool4"', '"toolX"')
    bad.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main(["audit-verify", str(good)]) == 0
    assert "intact: 6 events" in capsys.readouterr().out
    assert main(["audit-verify", str(bad)]) == 1
    assert "event 5: content" in capsys.readouterr().out


def test_the_gateways_audit_file_verifies(tmp_path):
    import asyncio
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_gateway import POLICY, PROFILE, TOKEN, FakeUpstream, _write_contract

    from vais import ReferenceMonitor
    from vais.approvals import ApprovalStore
    from vais.gateway import ContractRegistry, Gateway

    (tmp_path / "contracts").mkdir()
    _write_contract(tmp_path / "contracts")
    gateway = Gateway(profile=PROFILE, monitor=ReferenceMonitor(POLICY), registry=ContractRegistry(tmp_path / "contracts"),
                      sessions={"ops": FakeUpstream()}, approval_store=ApprovalStore(), pending_dir=tmp_path / "pending",
                      audit_path=tmp_path / "audit.jsonl")
    for call in (("ops.get_incident", {"incident_id": "INC-1"}), ("ops.send_email", {"recipient": "x@evil.test", "body": "b"}),
                 ("ops.pay", {"payee": "vendor-9", "amount": 500})):
        asyncio.run(gateway.call(TOKEN, *call))
    report = verify_jsonl((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert report.ok and report.events == len(gateway.audit.events) >= 4
