from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol

from .audit import AuditLog
from .detection import SecurityAlert
from .schema import LogRecord

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL REFERENCES tenants(id), subject TEXT NOT NULL, role TEXT NOT NULL, UNIQUE (tenant_id, subject));
CREATE TABLE IF NOT EXISTS logs (id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, agent_id TEXT, source_type TEXT, event_time TIMESTAMPTZ, source_ip INET, user_name TEXT, event_action TEXT, event_outcome TEXT, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS logs_tenant_event_time_idx ON logs (tenant_id, event_time);
CREATE INDEX IF NOT EXISTS logs_source_ip_idx ON logs (tenant_id, source_ip);
CREATE TABLE IF NOT EXISTS alerts (id BIGSERIAL PRIMARY KEY, tenant_id TEXT NOT NULL, rule_id TEXT NOT NULL, severity TEXT NOT NULL, source_ip INET, message TEXT NOT NULL, mitre_technique TEXT, details JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS audit_records (id BIGSERIAL PRIMARY KEY, tenant_id TEXT, record_hash CHAR(64) NOT NULL, previous_hash CHAR(64) NOT NULL, payload JSONB NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
"""


class EventStore(Protocol):
    def save_log(self, record: LogRecord) -> None: ...
    def save_alert(self, alert: SecurityAlert) -> None: ...
    def save_audit(self, entry: dict[str, Any]) -> None: ...
    def close(self) -> None: ...


class JsonlStore:
    def __init__(self, directory: str | Path = "output") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _append(self, name: str, value: dict[str, Any]) -> None:
        with (self.directory / name).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")

    def save_log(self, record: LogRecord) -> None:
        self._append("logs.jsonl", record.to_dict())

    def save_alert(self, alert: SecurityAlert) -> None:
        self._append("alerts.jsonl", {"rule_id": alert.rule_id, "title": alert.title, "severity": alert.severity, "message": alert.message, "tenant_id": alert.tenant_id, "source_ip": alert.source_ip, "mitre_technique": alert.mitre_technique, "details": alert.details})

    def save_audit(self, entry: dict[str, Any]) -> None:
        self._append("audit_records.jsonl", entry)

    def close(self) -> None:
        return None


class PostgresStore:
    def __init__(self, dsn: str) -> None:
        try:
            import psycopg  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError("Install the postgres optional dependency to use PostgreSQL storage") from exc
        self.connection = psycopg.connect(dsn)
        self.connection.execute(SCHEMA_SQL)
        self.connection.commit()

    def save_log(self, record: LogRecord) -> None:
        payload = record.to_dict()
        self.connection.execute("INSERT INTO logs (tenant_id, agent_id, source_type, event_time, source_ip, user_name, event_action, event_outcome, payload) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)", (record.tenant_id or "unknown", record.agent_id, record.source_type, record.event_time or record.timestamp, record.source_ip, record.user_name, record.event_action, record.event_outcome, json.dumps(payload)))
        self.connection.commit()

    def save_alert(self, alert: SecurityAlert) -> None:
        self.connection.execute("INSERT INTO alerts (tenant_id, rule_id, severity, source_ip, message, mitre_technique, details) VALUES (%s,%s,%s,%s,%s,%s,%s)", (alert.tenant_id or "unknown", alert.rule_id, alert.severity, alert.source_ip, alert.message, alert.mitre_technique, json.dumps(alert.details or {})))
        self.connection.commit()

    def save_audit(self, entry: dict[str, Any]) -> None:
        self.connection.execute("INSERT INTO audit_records (tenant_id, record_hash, previous_hash, payload) VALUES (%s,%s,%s,%s)", (entry.get("event", {}).get("tenant_id"), entry["hash"], entry["previous_hash"], json.dumps(entry)))
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()


def create_store() -> EventStore:
    backend = os.environ.get("STORAGE_BACKEND", "jsonl").lower()
    if backend == "postgres":
        dsn = os.environ.get("DATABASE_URL")
        if not dsn:
            raise RuntimeError("DATABASE_URL is required when STORAGE_BACKEND=postgres")
        return PostgresStore(dsn)
    if backend == "jsonl":
        return JsonlStore(os.environ.get("STORAGE_PATH", "output"))
    raise ValueError(f"unsupported STORAGE_BACKEND: {backend}")