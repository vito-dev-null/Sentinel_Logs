from __future__ import annotations

import time

from log_parser.parsers import BaseLogParser, ParserRegistry
from log_parser.schema import LogRecord


class SlowParser(BaseLogParser):
    def __init__(self) -> None:
        super().__init__("slow", r".*", [])

    def parse(self, line: str) -> LogRecord | None:
        time.sleep(0.2)
        return LogRecord(format="slow", message=line)


def test_parse_timeout_discards_slow_line() -> None:
    registry = ParserRegistry([SlowParser()], max_line_length=10_000, parse_timeout_ms=10)
    record = registry.parse_line("payload")
    assert record is not None
    assert record.format == "unknown"
    assert record.raw == "payload"


def test_max_line_length_discards_overlong_line() -> None:
    registry = ParserRegistry(max_line_length=16)
    assert registry.parse_line("x" * 100) is None


def test_redact_masks_sensitive_values() -> None:
    record = LogRecord(
        format="app",
        message="User alice@example.com logged in from 10.0.0.5 using 4111111111111111",
        parsed_at="2026-01-01T00:00:00Z",
    )
    redacted = record.redact([
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        r"\b(?:\d[ -]?){13,19}\b",
    ])
    assert "[REDACTED]" in redacted.message
    assert "alice" not in redacted.message
