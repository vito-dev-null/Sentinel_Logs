from pathlib import Path

import pytest

from sentinellogs.audit import AuditLog
from sentinellogs.detection import CorrelationEngine
from sentinellogs.schema import LogRecord, normalize_security_record


def test_normalized_security_fields_and_mitre_mapping() -> None:
    record = LogRecord(
        format="syslog",
        message="Failed password for root from 203.0.113.5 port 22",
        ips=["203.0.113.5"],
        timestamp="2026-08-22T10:00:00Z",
    )
    normalize_security_record(record, tenant_id="acme", agent_id="host-1", source_type="linux_auth")

    payload = record.to_dict()
    assert payload["tenant_id"] == "acme"
    assert payload["agent_id"] == "host-1"
    assert payload["source.ip"] == "203.0.113.5"
    assert payload["user.name"] == "root"
    assert payload["event.action"] == "authentication"
    assert payload["event.outcome"] == "failure"
    assert payload["threat.technique.id"] == ["T1110"]


def test_brute_force_alert_is_emitted_on_eleventh_attempt() -> None:
    engine = CorrelationEngine(threshold=10, window_seconds=60)
    alerts = []
    for second in range(11):
        record = LogRecord(
            event_action="authentication",
            event_outcome="failure",
            source_ip="203.0.113.5",
            tenant_id="acme",
            timestamp=f"2026-08-22T10:00:{second:02d}Z",
        )
        alerts.extend(engine.observe(record))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "brute-force-ssh"
    assert alerts[0].mitre_technique == "T1110"


def test_successful_authentication_from_untrusted_network_alerts_only_when_configured() -> None:
    record = LogRecord(
        event_action="authentication",
        event_outcome="success",
        source_ip="203.0.113.8",
        source_type="google_workspace_login",
        tenant_id="acme",
    )

    assert CorrelationEngine().observe(record) == []

    trusted_engine = CorrelationEngine(trusted_login_cidrs=["198.51.100.0/24"])
    alerts = trusted_engine.observe(record)
    assert len(alerts) == 1
    assert alerts[0].rule_id == "untrusted-login-source"
    assert alerts[0].source_ip == "203.0.113.8"

    trusted_record = LogRecord(
        event_action="authentication",
        event_outcome="success",
        source_ip="198.51.100.42",
        source_type="linux_auth",
        tenant_id="acme",
    )
    assert trusted_engine.observe(trusted_record) == []


def test_invalid_trusted_login_cidr_fails_configuration() -> None:
    with pytest.raises(ValueError, match="Invalid trusted login CIDR configuration"):
        CorrelationEngine(trusted_login_cidrs=["not-a-network"])


def test_sudo_user_is_normalized_from_syslog_message() -> None:
    record = LogRecord(message="sudo: alice : TTY=pts/0 ; COMMAND=/usr/bin/id")
    normalize_security_record(record, tenant_id="acme", agent_id="agent-1", source_type="linux_auth")

    assert record.user_name == "alice"
    assert record.event_action == "sudo_command"


def test_audit_log_detects_tampering(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    audit = AuditLog(path)
    audit.append({"tenant_id": "acme", "action": "login_failure"})
    audit.append({"tenant_id": "acme", "action": "login_success"})
    assert audit.verify()
    assert audit.integrity_verified

    contents = path.read_text(encoding="utf-8").replace("login_success", "changed")
    path.write_text(contents, encoding="utf-8")
    corrupted = AuditLog(path)
    assert not corrupted.verify()
    assert not corrupted.integrity_verified
    corrupted_contents = path.read_bytes()
    with pytest.raises(RuntimeError, match="integrity check failed"):
        corrupted.append({"action": "must_not_extend_corrupt_history"})
    assert path.read_bytes() == corrupted_contents


def test_missing_audit_log_is_unverified_until_first_record(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")

    assert not audit.verify()
    assert not audit.integrity_verified

    audit.append({"action": "audit_started"})

    assert audit.verify()
    assert audit.integrity_verified


def test_empty_audit_log_is_unverified(tmp_path: Path) -> None:
    path = tmp_path / "empty-audit.jsonl"
    path.touch()
    audit = AuditLog(path)

    assert not audit.verify()
    assert not audit.integrity_verified