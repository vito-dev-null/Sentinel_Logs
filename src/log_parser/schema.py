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
        }
        cleaned = {k: v for k, v in payload.items() if v is not None}
        if not cleaned.get("ips"):
            cleaned.pop("ips", None)
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
        )
        return clone

    @classmethod
    def unknown(cls, raw: str, parsed_at: str) -> "LogRecord":
        return cls(format="unknown", raw=raw, raw_line=raw, parsed_at=parsed_at, matched_parser="unknown", parse_duration_ms=0.0)
