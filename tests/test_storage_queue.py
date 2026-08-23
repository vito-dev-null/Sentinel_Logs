from pathlib import Path

from sentinellogs.detection import SecurityAlert
from sentinellogs.persistence import JsonlStore, create_store
from sentinellogs.queue import InMemoryQueue, record_from_payload
from sentinellogs.schema import LogRecord


def test_jsonl_store_is_compatible_fallback(tmp_path: Path) -> None:
    store = JsonlStore(tmp_path)
    record = LogRecord(format="syslog", message="Accepted password", tenant_id="acme", source_ip="198.51.100.1")
    store.save_log(record)
    store.save_alert(SecurityAlert("r", "title", "high", "message", "acme", "198.51.100.1", "T1078"))
    store.save_audit({"hash": "a" * 64, "previous_hash": "0" * 64, "event": {"tenant_id": "acme"}})
    assert (tmp_path / "logs.jsonl").read_text(encoding="utf-8").count("\n") == 1
    assert (tmp_path / "alerts.jsonl").exists()
    assert (tmp_path / "audit_records.jsonl").exists()


def test_queue_round_trip_preserves_normalized_fields() -> None:
    queue = InMemoryQueue()
    record = LogRecord(format="syslog", message="login", tenant_id="acme", source_ip="198.51.100.1", event_outcome="success")
    queue.publish(record)
    received = []
    queue.consume_once(received.append)
    assert received[0].tenant_id == "acme"
    assert received[0].source_ip == "198.51.100.1"
    assert received[0].event_outcome == "success"


def test_storage_backend_selection_defaults_to_jsonl(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("STORAGE_BACKEND", raising=False)
    monkeypatch.setenv("STORAGE_PATH", str(tmp_path))
    assert create_store().__class__ is JsonlStore