from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Sequence

DEFAULT_REDACTION_PATTERNS = [
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    r"\b(?:\d[ -]?){13,19}\b",
]


def normalize_security_record(
    record: "LogRecord",
    *,
    tenant_id: str,
    agent_id: str,
    source_type: str,
) -> "LogRecord":
    message = record.message or ""
    lowered = message.lower()
    if not record.source_ip and record.ips:
        record.source_ip = record.ips[0]
    if not record.user_name:
        user_match = None
        pam_match = re.search(r"session\s+(?:opened|closed)\s+for\s+user\s+([A-Za-z0-9._@-]+)\s+by\s+([A-Za-z0-9._@-]+)", message, re.IGNORECASE)
        if pam_match:
            record.user_target = record.user_target or pam_match.group(1)
            user_match = pam_match
            record.user_name = pam_match.group(2)
        else:
            user_match = re.search(r"(?:for|user[= ])\s+([A-Za-z0-9._@-]+)", message, re.IGNORECASE)
        if not user_match and "sudo:" in lowered:
            user_match = re.search(r"sudo:\s*([A-Za-z0-9._@-]+)\s*:", message, re.IGNORECASE)
        if user_match and not record.user_name:
            record.user_name = user_match.group(1)
    if record.user_target is None:
        target_match = re.search(r"session\s+(?:opened|closed)\s+for\s+user\s+([A-Za-z0-9._@-]+)", message, re.IGNORECASE)
        if target_match:
            record.user_target = target_match.group(1)
    if not record.event_action:
        if "sudo:" in lowered and "command=" in lowered:
            record.event_action = "sudo_command"
        elif any(token in lowered for token in ("failed password for", "invalid user", "failed publickey", "authentication failure", "auth failure")):
            record.event_action = "authentication"
        elif any(token in lowered for token in ("accepted password for", "accepted publickey for", "session opened for user")):
            record.event_action = "authentication"
    if not record.event_outcome and record.event_action == "authentication":
        record.event_outcome = "failure" if any(token in lowered for token in ("failed ", "invalid user", "authentication failure", "auth failure")) else "success"
    if not record.event_category and record.event_action:
        record.event_category = "authentication" if record.event_action == "authentication" else "iam"
    record.tenant_id = tenant_id
    record.agent_id = agent_id
    record.source_type = source_type
    if record.event_action == "authentication" and record.event_outcome == "failure":
        record.mitre_techniques = sorted(set(record.mitre_techniques) | {"T1110"})
    if record.event_action == "sudo_command":
        record.mitre_techniques = sorted(set(record.mitre_techniques) | {"T1548.003"})
    return record


@dataclass
class LogRecord:
    """Typed, JSON-serializable log record used by the parser and CLI."""

    format: str = "unknown"
    timestamp: str | None = None
    host: str | None = None
    process: str | None = None
    pid: str | None = None
    level: str | None = None
    message: str | None = None
    ips: list[str] = field(default_factory=list)
    parsed_at: str | None = None
    raw: str | None = None
    # Normalized event time (UTC) and delta to parsed_at
    event_time: str | None = None
    delta_seconds: float | None = None
    # New fields for diagnostics and UI
    raw_line: str | None = None
    matched_parser: str | None = None
    parse_duration_ms: float | None = None
    source: str | None = None
    tenant_id: str | None = None
    agent_id: str | None = None
    source_type: str | None = None
    source_ip: str | None = None
    user_name: str | None = None
    user_target: str | None = None
    host_hostname: str | None = None
    event_action: str | None = None
    event_outcome: str | None = None
    event_category: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "format": self.format,
            "timestamp": self.timestamp,
            "event_time": self.event_time,
            "delta_seconds": self.delta_seconds,
            "host": self.host,
            "process": self.process,
            "pid": self.pid,
            "level": self.level,
            "message": self.message,
            "ips": list(self.ips),
            "parsed_at": self.parsed_at,
            "raw": self.raw,
            "raw_line": self.raw_line,
            "matched_parser": self.matched_parser,
            "parse_duration_ms": self.parse_duration_ms,
            "source": self.source,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
            "source_type": self.source_type,
            "source.ip": self.source_ip or (self.ips[0] if self.ips else None),
            "user.name": self.user_name,
            "user.target": self.user_target,
            "host.hostname": self.host_hostname or self.host,
            "event.action": self.event_action,
            "event.outcome": self.event_outcome,
            "event.category": self.event_category,
            "threat.technique.id": list(self.mitre_techniques),
        }
        cleaned = {k: v for k, v in payload.items() if v is not None}
        if not cleaned.get("ips"):
            cleaned.pop("ips", None)
        if not cleaned.get("threat.technique.id"):
            cleaned.pop("threat.technique.id", None)
        if self.format == "unknown" and "raw" in cleaned:
            cleaned["raw"] = self.raw
        return cleaned

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    def redact(self, patterns: Sequence[str] | None = None) -> "LogRecord":
        patterns = list(patterns or DEFAULT_REDACTION_PATTERNS)
        if not self.message:
            return self

        redacted_message = self.message
        for pattern in patterns:
            redacted_message = re.sub(pattern, "[REDACTED]", redacted_message)

        clone = LogRecord(
            format=self.format,
            timestamp=self.timestamp,
            event_time=self.event_time,
            delta_seconds=self.delta_seconds,
            host=self.host,
            process=self.process,
            pid=self.pid,
            level=self.level,
            message=redacted_message,
            ips=list(self.ips),
            parsed_at=self.parsed_at,
            raw=self.raw,
            raw_line=self.raw_line,
            matched_parser=self.matched_parser,
            parse_duration_ms=self.parse_duration_ms,
            source=self.source,
            tenant_id=self.tenant_id,
            agent_id=self.agent_id,
            source_type=self.source_type,
            source_ip=self.source_ip,
            user_name=self.user_name,
            user_target=self.user_target,
            host_hostname=self.host_hostname,
            event_action=self.event_action,
            event_outcome=self.event_outcome,
            event_category=self.event_category,
            mitre_techniques=list(self.mitre_techniques),
        )
        return clone

    @classmethod
    def unknown(cls, raw: str, parsed_at: str) -> "LogRecord":
        return cls(format="unknown", raw=raw, raw_line=raw, parsed_at=parsed_at, matched_parser="unknown", parse_duration_ms=0.0)
