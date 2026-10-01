import json
from pathlib import Path
from urllib.request import Request

from sentinellogs.access import AccessController, Principal
from sentinellogs.audit import AuditLog
from sentinellogs.detection import CorrelationEngine, SecurityAlert
from sentinellogs.notifications import NotificationRouter, PagerDutyConnector, SlackConnector, TeamsConnector
from sentinellogs.reporting import export_compliance_pdf
from sentinellogs.soar import Playbook, SoarEngine


class FakeGeoIP:
    locations = {"198.51.100.1": (40.7128, -74.0060), "203.0.113.5": (35.6762, 139.6503)}

    def locate(self, ip: str):
        return self.locations.get(ip)


class FakeProvider:
    def authenticate(self, credentials):
        return Principal("user-1", "acme", frozenset({"soc_analyst"}), credentials)


def test_rbac_authentication_and_tenant_isolation() -> None:
    access = AccessController({"oidc": FakeProvider()})
    principal = access.authenticate("oidc", {"sub": "user-1"})
    assert access.authorize(principal, "events:read", "acme")
    assert not access.authorize(principal, "users:manage", "acme")
    assert not access.authorize(principal, "events:read", "other")


def test_impossible_travel_uses_geoip_and_speed() -> None:
    engine = CorrelationEngine(geoip=FakeGeoIP(), impossible_speed_kmh=900)
    first = SecurityAlert("x", "x", "high", "x", "acme", "x", "x")
    from sentinellogs.schema import LogRecord
    engine.observe(LogRecord(event_action="authentication", event_outcome="success", user_name="alice", source_ip="198.51.100.1", tenant_id="acme", timestamp="2026-08-22T10:00:00Z"))
    alerts = engine.observe(LogRecord(event_action="authentication", event_outcome="success", user_name="alice", source_ip="203.0.113.5", tenant_id="acme", timestamp="2026-08-22T10:10:00Z"))
    assert len(alerts) == 1
    assert alerts[0].rule_id == "impossible-travel"
    assert alerts[0].details["speed_kmh"] > 900


def test_soar_allowlist_blocks_or_executes_action() -> None:
    executed = []
    alert = SecurityAlert("brute-force-ssh", "Brute force", "high", "attack", "acme", "203.0.113.5", "T1110")
    playbook = Playbook("block-ip", frozenset({"brute-force-ssh"}), lambda _: executed.append(True), allowed_ips=frozenset({"198.51.100.1"}))
    engine = SoarEngine([playbook])
    assert engine.execute(alert) == ["block-ip"]
    assert executed == [True]
    assert engine.execute(alert) == ["block-ip"]


def test_pdf_report_contains_audit_and_compliance_text(tmp_path: Path) -> None:
    audit = AuditLog(tmp_path / "audit.jsonl")
    audit.append({"action": "login_failure"})
    target = export_compliance_pdf(tmp_path / "report.pdf", metrics={"processed_lines": 4, "dropped_lines": 1, "alerts_generated": 1}, incidents=[], audit_log=audit)
    content = target.read_bytes()
    assert content.startswith(b"%PDF-1.4")
    assert b"ISO 27001" in content
    assert b"YES" in content


def test_native_webhook_payloads_are_validated() -> None:
    requests: list[Request] = []
    send = lambda request: requests.append(request)
    alert = SecurityAlert("brute-force-ssh", "Brute force", "high", "attack", "acme", "203.0.113.5", "T1110")
    SlackConnector("https://slack.test", send).send_alert(alert)
    TeamsConnector("https://teams.test", send).send_alert(alert)
    PagerDutyConnector("https://pager.test", "routing-key", send).send_alert(alert)
    assert len(requests) == 3
    payloads = [json.loads(request.data) for request in requests]
    assert payloads[0]["text"].startswith("[HIGH]")
    assert payloads[1]["summary"] == "Brute force"
    assert payloads[2]["routing_key"] == "routing-key"
    assert NotificationRouter([SlackConnector("https://slack.test", send)]).dispatch(alert) == 1