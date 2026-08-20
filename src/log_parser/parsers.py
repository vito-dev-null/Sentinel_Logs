from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import re
import signal
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Sequence

from .schema import LogRecord

logger = logging.getLogger(__name__)

DEFAULT_MAX_LINE_LENGTH = 100_000
DEFAULT_PARSE_TIMEOUT_MS = 500


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_timestamp_to_iso(ts: str | None) -> str | None:
    """Try to parse common timestamp formats and return ISO 8601 UTC string.

    Interprets naive timestamps as local time (system timezone) and converts
    them to UTC. If parsing fails, returns the original string unchanged.
    """
    if not ts:
        return None
    ts = str(ts).strip()
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z",
        "%b %d %H:%M:%S",
    ]
    local_tz = datetime.now().astimezone().tzinfo
    for fmt in formats:
        try:
            # special handling for syslog without year (e.g., 'Aug 20 07:00:00')
            if fmt == "%b %d %H:%M:%S":
                dt = datetime.strptime(ts, fmt)
                dt = dt.replace(year=datetime.now().year, tzinfo=local_tz).astimezone(timezone.utc)
            else:
                dt = datetime.strptime(ts, fmt)
                # naive -> treat as local time
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=local_tz).astimezone(timezone.utc)
            return dt.isoformat().replace("+00:00", "Z")
        except Exception:
            continue
    # fallback: return original
    return ts


def extract_ips(message: str) -> list[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_config(path: Path) -> str:
    digest = sha256_file(path)
    logger.info("Loaded config %s with SHA-256 %s", path, digest)
    return digest


class BaseLogParser(ABC):
    """Base interface for parser implementations."""

    def __init__(self, name: str, pattern: str | re.Pattern[str], fields: Sequence[str]) -> None:
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
        self.fields = list(fields)

    @abstractmethod
    def parse(self, line: str) -> LogRecord | None:
        """Parse a single line and return a typed LogRecord or None."""

    def _build_record(self, match: re.Match[str]) -> LogRecord:
        data = match.groupdict()
        ts_raw = data.get("timestamp")
        ts_iso = normalize_timestamp_to_iso(ts_raw)
        record = LogRecord(
            format=self.name,
            timestamp=ts_iso or ts_raw,
            host=data.get("host"),
            process=data.get("process"),
            pid=data.get("pid"),
            level=data.get("level"),
            message=data.get("message"),
            parsed_at=utc_now_iso(),
        )
        # If we successfully normalized a timestamp, expose it as event_time
        if ts_iso:
            record.event_time = ts_iso
            try:
                parsed_dt = datetime.fromisoformat(record.parsed_at.replace("Z", "+00:00"))
                event_dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
                record.delta_seconds = (parsed_dt - event_dt).total_seconds()
            except Exception:
                # ignore delta computation failures
                pass

        message = record.message or ""
        ips = extract_ips(message)
        if ips:
            record.ips = ips
        return record


class SyslogParser(BaseLogParser):
    def parse(self, line: str) -> LogRecord | None:
        raw_line = line.rstrip("\r\n")
        start = perf_counter()
        match = self.pattern.match(raw_line)
        duration_ms = (perf_counter() - start) * 1000.0
        if match is None:
            return None
        record = self._build_record(match)
        record.parse_duration_ms = round(duration_ms, 3)
        record.raw_line = raw_line
        record.matched_parser = self.name
        return record


class AppLogParser(BaseLogParser):
    def parse(self, line: str) -> LogRecord | None:
        raw_line = line.rstrip("\r\n")
        start = perf_counter()
        match = self.pattern.match(raw_line)
        duration_ms = (perf_counter() - start) * 1000.0
        if match is None:
            return None
        record = self._build_record(match)
        record.parse_duration_ms = round(duration_ms, 3)
        record.raw_line = raw_line
        record.matched_parser = self.name
        return record


class ParserRegistry:
    def __init__(
        self,
        parsers: Sequence[BaseLogParser] | None = None,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
        parse_timeout_ms: int = DEFAULT_PARSE_TIMEOUT_MS,
    ) -> None:
        self.parsers = list(parsers or [])
        self.max_line_length = max_line_length
        self.parse_timeout_ms = parse_timeout_ms

    @classmethod
    def from_config(
        cls,
        config_path: Path | None = None,
        max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
        parse_timeout_ms: int = DEFAULT_PARSE_TIMEOUT_MS,
    ) -> "ParserRegistry":
        config_file = config_path or Path(__file__).with_name("patterns.yaml")
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")

        config = load_pattern_config(config_file)
        audit_config(config_file)
        registry_parsers: list[BaseLogParser] = []
        for format_name, spec in config.items():
            if not isinstance(spec, dict):
                logger.warning("Skipping invalid config for %s", format_name)
                continue
            pattern = spec.get("pattern")
            fields = spec.get("fields", [])
            if not isinstance(pattern, str):
                logger.warning("Skipping parser %s because pattern missing", format_name)
                continue
            parser_name = "SyslogParser" if format_name == "syslog" else "AppLogParser"
            registry_parsers.append(build_parser_from_name(parser_name, format_name, pattern, fields))
        return cls(registry_parsers, max_line_length=max_line_length, parse_timeout_ms=parse_timeout_ms)

    def _safe_parse(self, parser: BaseLogParser, line: str) -> LogRecord | None:
        if os.name != "nt" and hasattr(signal, "SIGALRM"):
            return self._safe_parse_with_signal(parser, line)
        return self._safe_parse_with_thread(parser, line)

    def _safe_parse_with_signal(self, parser: BaseLogParser, line: str) -> LogRecord | None:
        previous_handler = signal.getsignal(signal.SIGALRM)

        def _handle_timeout(_signum: int, _frame: Any) -> None:
            raise TimeoutError(f"Parsing timed out after {self.parse_timeout_ms} ms")

        signal.signal(signal.SIGALRM, _handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, self.parse_timeout_ms / 1000.0)
        try:
            return parser.parse(line)
        except TimeoutError:
            logger.warning("Discarding log line because parser timed out after %sms: %s", self.parse_timeout_ms, line[:120])
            return None
        except Exception:
            logger.exception("Parser %s raised an exception while parsing: %s", parser.name, line[:120])
            return None
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)

    def _safe_parse_with_thread(self, parser: BaseLogParser, line: str) -> LogRecord | None:
        results: queue.Queue[tuple[str, Any]] = queue.Queue()

        def _worker() -> None:
            try:
                results.put(("ok", parser.parse(line)))
            except Exception as exc:  # pragma: no cover - defensive path
                results.put(("error", exc))

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=self.parse_timeout_ms / 1000.0)
        if thread.is_alive():
            logger.warning("Discarding log line because parser timed out after %sms: %s", self.parse_timeout_ms, line[:120])
            return None
        if results.empty():
            logger.warning("Parser %s produced no result for line: %s", parser.name, line[:120])
            return None
        status, payload = results.get()
        if status == "error":
            logger.exception("Parser %s raised an exception while parsing: %s", parser.name, payload)
            return None
        return payload

    def parse_line(self, line: str) -> LogRecord | None:
        clean_line = line.rstrip("\r\n")
        if len(clean_line) > self.max_line_length:
            logger.warning(
                "Discarding log line longer than %s bytes (%s bytes): %s",
                self.max_line_length,
                len(clean_line),
                clean_line[:120],
            )
            return None

        for parser in self.parsers:
            parsed = self._safe_parse(parser, clean_line)
            if parsed is not None:
                return parsed

        logger.debug("No parser matched line: %s", clean_line[:120])
        return LogRecord.unknown(clean_line, utc_now_iso())


def build_parser_from_name(parser_name: str, format_name: str, pattern: str, fields: Sequence[str]) -> BaseLogParser:
    if parser_name == "SyslogParser":
        return SyslogParser(format_name, pattern, fields)
    if parser_name == "AppLogParser":
        return AppLogParser(format_name, pattern, fields)
    raise ValueError(f"Unsupported parser class: {parser_name}")


def load_pattern_config(config_path: Path) -> dict[str, dict[str, Any]]:
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    suffix = config_path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError(
                "PyYAML is required to read YAML patterns. Install dependencies with pip install -r requirements-dev.txt or pip install PyYAML."
            ) from exc

        try:
            with config_path.open("r", encoding="utf-8") as handle:
                payload = yaml.safe_load(handle) or {}
        except yaml.YAMLError as exc:  # type: ignore[attr-defined]
            raise ValueError(f"Malformed YAML configuration in {config_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"YAML config root must be a mapping: {config_path}")
        return payload

    if suffix == ".json":
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed JSON configuration in {config_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"JSON config root must be a mapping: {config_path}")
        return payload

    raise ValueError(f"Unsupported config format for {config_path}. Use .yaml, .yml, or .json")
