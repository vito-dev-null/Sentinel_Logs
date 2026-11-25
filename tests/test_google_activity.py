import json
from pathlib import Path

from sentinellogs.cli import build_alert_engine
from sentinellogs.google_activity import (
    GoogleActivityWatcher,
    parse_google_activity_document,
    parse_google_activity_file,
)
from sentinellogs.ingestion import ingest_events
from sentinellogs.parsers import ParserRegistry
from sentinellogs.schema import LogRecord


def test_workspace_login_export_normalizes_security_fields() -> None:
    document = {
        "items": [
            {
                "id": {"time": "2026-11-25T06:00:00Z", "uniqueQualifier": "safe-fixture"},
                "actor": {"email": "analyst@example.invalid"},
                "ipAddress": "203.0.113.25",
                "events": [
                    {"name": "login_success"},
                    {"name": "login_failure"},
                    {"name": "suspicious_login"},
                ],
            }
        ]
    }

    parsed = parse_google_activity_document(document)
    received = []
    registry = ParserRegistry.from_config(Path("src/sentinellogs/patterns.yaml"))
    accepted = ingest_events(
        {"events": [item.event for item in parsed]},
        tenant_id="test-tenant",
        agent_id="test-agent",
        registry=registry,
        on_record=received.append,
    )

    assert accepted == 3
    assert [record.event_outcome for record in received] == ["success", "failure", "unknown"]
    assert [record.event_action for record in received] == [
        "authentication",
        "authentication",
        "google_suspicious_login",
    ]
    assert all(record.source_ip == "203.0.113.25" for record in received)
    assert all(record.user_name == "analyst@example.invalid" for record in received)
    assert "google-suspicious-login" in build_alert_engine().matching_rules(received[2])


def test_takeout_activity_is_not_mislabeled_as_a_login() -> None:
    private_title = "Synthetic private activity title"
    parsed = parse_google_activity_document(
        [
            {
                "header": "Google Search",
                "title": private_title,
                "time": "2026-11-25T06:05:00Z",
            }
        ]
    )

    assert len(parsed) == 1
    event = parsed[0].event
    assert event["source_type"] == "google_account_activity"
    assert event["event.action"] == "google_account_activity"
    assert event["event.outcome"] == "unknown"
    assert "source.ip" not in event
    assert private_title not in event["message"]
    assert build_alert_engine().matching_rules(
        LogRecord(
            event_action=event["event.action"],
            event_outcome=event["event.outcome"],
            message=event["message"],
        )
    ) == []


def test_google_activity_watcher_deduplicates_exports_across_restarts(tmp_path: Path) -> None:
    directory = tmp_path / "google-activity"
    export = directory / "workspace-export.json"
    export.parent.mkdir()
    export.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "id": {"time": "2026-11-25T06:10:00Z"},
                        "actor": {"email": "analyst@example.invalid"},
                        "ipAddress": "203.0.113.25",
                        "events": [{"name": "login_success"}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sent = []

    def sender(endpoint: str, agent_id: str, events: list[dict]) -> int:
        sent.append((endpoint, agent_id, events))
        return len(events)

    watcher = GoogleActivityWatcher(directory, "https://example.invalid", "test-agent", sender)
    assert watcher.scan_once() == 1
    assert watcher.scan_once() == 0

    restarted_watcher = GoogleActivityWatcher(directory, "https://example.invalid", "test-agent", sender)
    assert restarted_watcher.scan_once() == 0
    assert len(sent) == 1

    state = json.loads((directory / ".sentinellogs-seen.json").read_text(encoding="utf-8"))
    assert len(state) == 1
    assert len(state[0]) == 64
    assert "analyst@example.invalid" not in json.dumps(state)


def test_jsonl_google_workspace_export_is_supported(tmp_path: Path) -> None:
    path = tmp_path / "workspace-export.ndjson"
    path.write_text(
        json.dumps(
            {
                "id": {"time": "2026-11-25T06:15:00Z"},
                "actor": {"email": "analyst@example.invalid"},
                "events": [{"name": "logout"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    parsed = parse_google_activity_file(path)

    assert len(parsed) == 1
    assert parsed[0].event["event.action"] == "google_session_end"
