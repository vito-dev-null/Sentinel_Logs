from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_timestamp_to_utc(ts: str) -> datetime | None:
    """Try to parse a variety of timestamp formats and return a UTC
    aware datetime. Returns None if parsing fails.

    Supported formats (best-effort):
    - ISO8601 with timezone or Z (e.g. 2026-08-20T07:30:00Z)
    - YYYY-MM-DD HH:MM:SS (assumed local timezone)
    - Syslog "Mon DD HH:MM:SS" (assumes current year and local timezone)
    """
    try:
        # ISO-like with timezone (handles trailing Z by replacing it)
        if "T" in ts or "Z" in ts or ("+" in ts and ":" in ts):
            try:
                # datetime.fromisoformat understands offsets like +00:00
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    # treat naive ISO as UTC
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass

        # Try YYYY-MM-DD HH:MM:SS (common app_plain/app formats)
        try:
            dt_naive = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
            local_tz = datetime.now().astimezone().tzinfo
            return dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
        except Exception:
            pass

        # Try syslog month day format (e.g. "Aug 20 07:00:00")
        try:
            dt_naive = datetime.strptime(ts, "%b %d %H:%M:%S")
            year = datetime.now().year
            dt_naive = dt_naive.replace(year=year)
            local_tz = datetime.now().astimezone().tzinfo
            return dt_naive.replace(tzinfo=local_tz).astimezone(timezone.utc)
        except Exception:
            pass

    except Exception:
        return None

    return None


def extract_ips(message: str) -> list[str]:
    """Extract IPv4-like addresses from a message."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)


class BaseLogParser(ABC):
    """Base interface for log-specific parsers."""

    def __init__(self, name: str, pattern: str | re.Pattern[str], fields: Sequence[str]) -> None:
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
        self.fields = list(fields)

    @abstractmethod
    def parse(self, line: str) -> dict[str, Any] | None:
        """Parse a single log line and return a dictionary or None."""

    def _normalize_record(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize a parsed record, add parsed_at (UTC), extract ips and
        if possible convert the original event timestamp into UTC (event_time)
        and compute the delta in seconds between parsing time and event time.
        """
        data["format"] = self.name
        data["parsed_at"] = utc_now_iso()

        message = data.get("message", "")
        ips = extract_ips(str(message))
        if ips:
            data["ips"] = ips

        # Try to parse an original timestamp if the parser captured one.
        ts = data.get("timestamp")
        if isinstance(ts, str) and ts:
            event_dt_utc = _parse_timestamp_to_utc(ts)
            if event_dt_utc is not None:
                # store canonical event time in ISO8601 Z format
                data["event_time"] = event_dt_utc.isoformat().replace("+00:00", "Z")
                try:
                    parsed_dt = datetime.fromisoformat(data["parsed_at"].replace("Z", "+00:00"))
                    data["delta_seconds"] = (parsed_dt - event_dt_utc).total_seconds()
                except Exception:
                    # if anything goes wrong, skip delta_seconds
                    pass

        for field in ("level", "host", "process", "pid"):
            if field not in data:
                data[field] = None

        return data


class SyslogParser(BaseLogParser):
    """Parser for standard syslog format."""

    def parse(self, line: str) -> dict[str, Any] | None:
        clean_line = line.rstrip("\r\n")
        match = self.pattern.match(clean_line)
        if not match:
            return None

        data = match.groupdict()
        data["format"] = self.name
        data["parsed_at"] = utc_now_iso()
        message = data.get("message", "")
        ips = extract_ips(str(message))
        if ips:
            data["ips"] = ips
        data.setdefault("level", None)
        data.setdefault("host", None)
        data.setdefault("process", None)
        data.setdefault("pid", None)
        return data


class AppLogParser(BaseLogParser):
    """Parser for application logs with severity level markers like [ERROR]."""

    def parse(self, line: str) -> dict[str, Any] | None:
        clean_line = line.rstrip("\r\n")
        match = self.pattern.match(clean_line)
        if not match:
            return None

        data = match.groupdict()
        data["format"] = self.name
        data["parsed_at"] = utc_now_iso()
        message = data.get("message", "")
        ips = extract_ips(str(message))
        if ips:
            data["ips"] = ips
        data.setdefault("level", None)
        data.setdefault("host", None)
        data.setdefault("process", None)
        data.setdefault("pid", None)
        return data


class ParserRegistry:
    """Ordered registry for parser instances."""

    def __init__(self, parsers: Sequence[BaseLogParser] | None = None) -> None:
        self.parsers = list(parsers or [])

    @classmethod
    def from_config(cls, config_path: Path) -> "ParserRegistry":
        logger.info("Loading parser configuration from %s", config_path)
        config = load_pattern_config(config_path)

        built_parsers: list[BaseLogParser] = []
        for format_name, spec in config.items():
            if not isinstance(spec, Mapping):
                logger.warning("Skipping invalid parser config for %s: expected mapping", format_name)
                continue

            pattern = spec.get("pattern")
            fields = spec.get("fields", [])
            if not isinstance(pattern, str):
                logger.warning("Skipping parser %s because pattern is missing or invalid", format_name)
                continue

            cls_name = "SyslogParser" if format_name == "syslog" else "AppLogParser"
            parser = build_parser_from_name(cls_name, format_name, pattern, list(fields))
            built_parsers.append(parser)

        return cls(built_parsers)

    def parse_line(self, line: str) -> dict[str, Any]:
        clean_line = line.rstrip("\r\n")
        for parser in self.parsers:
            try:
                parsed = parser.parse(clean_line)
            except re.error as exc:
                logger.exception("Regex error in parser %s: %s", parser.name, exc)
                continue
            if parsed is not None:
                return parsed

        logger.debug("No parser matched line: %s", clean_line)
        return {"format": "unknown", "raw": clean_line, "parsed_at": utc_now_iso()}


def build_parser_from_name(
    parser_name: str,
    format_name: str,
    pattern: str,
    fields: Sequence[str],
) -> BaseLogParser:
    """Construct a concrete parser class instance from its name."""
    if parser_name == "SyslogParser":
        return SyslogParser(format_name, pattern, fields)
    if parser_name == "AppLogParser":
        return AppLogParser(format_name, pattern, fields)
    raise ValueError(f"Unsupported parser class: {parser_name}")


def load_pattern_config(config_path: Path) -> dict[str, dict[str, Any]]:
    """Load pattern configuration from YAML or JSON with clear validation errors."""
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    suffix = config_path.suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore
            except ModuleNotFoundError as exc:
                raise ModuleNotFoundError(
                    "PyYAML is required to read YAML configuration files. "
                    "Install it with `pip install PyYAML` or use a JSON config file."
                ) from exc

            with config_path.open("r", encoding="utf-8") as handle:
                try:
                    payload = yaml.safe_load(handle) or {}
                except yaml.YAMLError as exc:  # type: ignore[attr-defined]
                    raise ValueError(f"Malformed YAML configuration in {config_path}: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"YAML config root must be a mapping: {config_path}")
            return payload

        if suffix == ".json":
            with config_path.open("r", encoding="utf-8") as handle:
                try:
                    payload = json.load(handle)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Malformed JSON configuration in {config_path}: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"JSON config root must be a mapping: {config_path}")
            return payload
    except ModuleNotFoundError:
        logger.warning("PyYAML not installed; attempting to load JSON fallback.")

    fallback_json = config_path.with_suffix(".json")
    if fallback_json.exists():
        with fallback_json.open("r", encoding="utf-8") as handle:
            try:
                payload = json.load(handle)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON fallback configuration in {fallback_json}: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"JSON fallback root must be a mapping: {fallback_json}")
        return payload

    raise FileNotFoundError(f"No valid parser config found at {config_path} or {fallback_json}")
