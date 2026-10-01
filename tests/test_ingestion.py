from pathlib import Path

from sentinellogs.ingestion import ingest_events, send_events
from sentinellogs.parsers import ParserRegistry
from sentinellogs.local_agent import LocalLogAgent, _process_name


def test_ingest_events_normalizes_multiple_source_types() -> None:
    registry = ParserRegistry.from_config(Path("src/sentinellogs/patterns.yaml"))
    received = []
    payload = {
        "events": [
            {"source_type": "linux_auth", "raw": "Aug 22 10:22:31 host sshd[1234]: Failed password for root from 203.0.113.5 port 22"},
            {"source_type": "windows_eventlog_security", "message": "Successful logon", "event.outcome": "success", "user.name": "admin"},
            {"source_type": "aws_cloudtrail", "message": "ConsoleLogin", "event.action": "ConsoleLogin", "event.outcome": "failure"},
            {"source_type": "network_syslog", "message": "firewall denied connection", "event.action": "network_connection"},
        ]
    }

    accepted = ingest_events(payload, tenant_id="acme", agent_id="agent-1", registry=registry, on_record=received.append)

    assert accepted == 4
    assert all(record.tenant_id == "acme" and record.agent_id == "agent-1" for record in received)
    assert received[0].event_outcome == "failure"
    assert received[1].source_type == "windows_eventlog_security"


def test_ingest_events_rejects_unknown_source_type() -> None:
    registry = ParserRegistry.from_config(Path("src/sentinellogs/patterns.yaml"))
    try:
        ingest_events({"event": {"source_type": "invented", "message": "event"}}, tenant_id="acme", agent_id="agent-1", registry=registry, on_record=lambda _: None)
    except ValueError as exc:
        assert "unsupported source_type" in str(exc)
    else:
        raise AssertionError("unknown source type was accepted")


def test_local_agent_builds_real_log_event(monkeypatch, tmp_path: Path) -> None:
    sent = []
    monkeypatch.setattr("sentinellogs.local_agent.post_events", lambda *args, **kwargs: sent.append((args, kwargs)) or 1)
    agent = LocalLogAgent([tmp_path / "missing.log"], hostname="test-host", username="test-user", source_ip="203.0.113.10")
    assert agent.forward_line("raw auth line\n", "/var/log/auth.log") == 1
    assert sent[0][0][0] == "http://localhost:9090"
    payload = sent[0][0][2][0]
    assert payload == {
        "source_type": "linux_auth",
        "source": "/var/log/auth.log",
        "raw": "raw auth line",
        "message": "raw auth line",
        "process": "unknown",
        "source.ip": "203.0.113.10",
        "host.hostname": "test-host",
        "user.name": "test-user",
        "host": {"hostname": agent.hostname},
        "user": {"name": agent.username},
    }
    assert payload["message"] == "raw auth line"
    assert payload["source.ip"] == "203.0.113.10"
    assert payload["host.hostname"] == "test-host"
    assert payload["user.name"] == "test-user"


def test_local_agent_uses_invoking_user_and_rejects_generic_users(monkeypatch) -> None:
    monkeypatch.setenv("SUDO_USER", "test-user")
    monkeypatch.setattr("sentinellogs.local_agent.os.getlogin", lambda: "root")
    assert LocalLogAgent._current_username() == "test-user"

    monkeypatch.delenv("SUDO_USER")
    monkeypatch.setattr("sentinellogs.local_agent.getpass.getuser", lambda: "user")
    assert LocalLogAgent._current_username() == "unknown"


def test_local_agent_can_disable_initial_replay(tmp_path: Path) -> None:
    agent = LocalLogAgent([tmp_path / "missing.log"], from_start=False)
    assert agent.from_start is False


def test_pam_event_maps_actor_and_target() -> None:
    registry = ParserRegistry.from_config(Path("src/sentinellogs/patterns.yaml"))
    received = []
    ingest_events(
        {"event": {"source_type": "linux_auth", "message": "pam_unix(sudo:session): session opened for user root by test-user", "host": {"hostname": "test-host"}, "user": {"name": "test-user"}}},
        tenant_id="local",
        agent_id="agent",
        registry=registry,
        on_record=received.append,
    )
    assert received[0].user_name == "test-user"
    assert received[0].user_target == "root"
    assert received[0].host_hostname == "test-host"


def test_local_agent_extracts_service_name() -> None:
    assert _process_name("2026-08-20T22:30:04+02:00 test-host sshd[123]: Accepted password for user") == "sshd"
    assert _process_name("Aug 20 22:30:04 test-host sudo: test-user : COMMAND=/usr/bin/id") == "sudo"


def test_agent_prints_compact_http_status(monkeypatch, capsys) -> None:
    import requests
    request_options = {}

    class Response:
        status_code = 202
        ok = True
        text = ""

        def raise_for_status(self):
            return None

        def json(self):
            return {"accepted": 1}

    def fake_post(*args, **kwargs):
        request_options.update(kwargs)
        return Response()

    monkeypatch.setattr(requests, "post", fake_post)
    from sentinellogs.local_agent import post_events

    monkeypatch.setenv("SENTINELLOGS_BASIC_AUTH", "test-user:a-strong-test-password-1234")
    post_events("http://localhost:9090", "local-agent", [{
        "message": "pam_unix(sudo:session): session opened for user root by test-user",
        "source.ip": "203.0.113.10",
        "user.name": "test-user",
        "host.hostname": "test-host",
        "process": "sudo",
    }])
    output = capsys.readouterr().out
    assert "[OK 202]" in output
    assert request_options["auth"] == ("test-user", "a-strong-test-password-1234")
    assert "IP:" not in output
    assert "test-user" not in output
    assert "test-host" not in output
    assert "pam_unix" not in output


def test_local_agent_refuses_to_send_without_auth(monkeypatch) -> None:
    import requests

    monkeypatch.delenv("SENTINELLOGS_BASIC_AUTH", raising=False)
    monkeypatch.setattr(requests, "post", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("request must not be sent")))

    from sentinellogs.local_agent import post_events

    try:
        post_events("http://127.0.0.1:9090", "local-agent", [])
    except RuntimeError as error:
        assert "SENTINELLOGS_BASIC_AUTH" in str(error)
    else:
        raise AssertionError("local agent sent an unauthenticated request")


def test_local_agent_falls_back_to_journal_on_permission_error(monkeypatch, tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text("", encoding="utf-8")
    forwarded = []

    class DeniedTailer:
        def __init__(self, path, from_start=False):
            raise PermissionError("denied")

    monkeypatch.setattr("sentinellogs.local_agent.LogTailer", DeniedTailer)
    monkeypatch.setattr("sentinellogs.local_agent.journal_lines", lambda: iter(["journal event\n"]))
    agent = __import__("sentinellogs.local_agent", fromlist=["LocalLogAgent"]).LocalLogAgent([log_path], sender=lambda endpoint, agent_id, events: forwarded.append(events) or 1)
    agent._follow(log_path)

    assert forwarded[0][0]["source"] == "journald"