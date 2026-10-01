from pathlib import Path

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

    contents = path.read_text(encoding="utf-8").replace("login_success", "changed")
    path.write_text(contents, encoding="utf-8")
    assert not AuditLog(path).verify()