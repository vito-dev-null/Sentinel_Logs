from __future__ import annotations

import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from logging.handlers import SysLogHandler
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .schema import LogRecord
from .secrets import EnvSecretProvider, SecretProvider

logger = logging.getLogger(__name__)
USER_AGENT = "sentinellogs/0.2.0"


class BaseSink(ABC):
    """Base interface for output backends."""

    @abstractmethod
    def emit(self, record: LogRecord) -> None:
        """Deliver a parsed record to the sink."""

    def close(self) -> None:
        """Optional cleanup hook for sink implementations."""


class StdoutSink(BaseSink):
    def emit(self, record: LogRecord) -> None:
        print(record.to_json(), flush=True)


class FileSink(BaseSink):
    def __init__(
        self,
        path: str | os.PathLike[str],
        max_file_size_bytes: int | None = None,
        retention_days: int | None = None,
        max_files: int | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_file_size_bytes = max_file_size_bytes
        self.retention_days = retention_days
        self.max_files = max_files
        self.handle = self.path.open("a", encoding="utf-8")
        self._enforce_retention()

    def _rotate_if_needed(self) -> None:
        if self.max_file_size_bytes is None:
            return
        if self.path.exists() and self.path.stat().st_size >= self.max_file_size_bytes:
            logger.info("Rotating output file %s due to size limit %s bytes", self.path, self.max_file_size_bytes)
            rotated = self.path.with_name(f"{self.path.stem}.1{self.path.suffix}")
            if rotated.exists():
                for idx in range(9, 0, -1):
                    previous = self.path.with_name(f"{self.path.stem}.{idx}{self.path.suffix}")
                    next_path = self.path.with_name(f"{self.path.stem}.{idx + 1}{self.path.suffix}")
                    if previous.exists():
                        previous.rename(next_path)
            if self.path.exists():
                self.handle.close()
                self.path.rename(rotated)
                self.handle = self.path.open("a", encoding="utf-8")

    def _enforce_retention(self) -> None:
        if self.retention_days is not None and self.retention_days > 0:
            cutoff = datetime.now() - timedelta(days=self.retention_days)
            for candidate in self.path.parent.glob(f"{self.path.stem}*{self.path.suffix}"):
                try:
                    if candidate.stat().st_mtime < cutoff.timestamp():
                        candidate.unlink()
                except OSError:
                    logger.warning("Unable to remove old file %s during retention cleanup", candidate)

        if self.max_files is not None and self.max_files > 0:
            matches = sorted(
                self.path.parent.glob(f"{self.path.stem}*{self.path.suffix}"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for old in matches[self.max_files :]:
                try:
                    old.unlink()
                except OSError:
                    logger.warning("Unable to remove old rotated file %s", old)

    def emit(self, record: LogRecord) -> None:
        self._rotate_if_needed()
        self._enforce_retention()
        self.handle.write(record.to_json() + "\n")
        self.handle.flush()

    def close(self) -> None:
        if not self.handle.closed:
            self.handle.close()


class WebhookSink(BaseSink):
    def __init__(
        self,
        url: str | None = None,
        timeout: int = 5,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        secret_provider: SecretProvider | None = None,
        secret_name: str = "WEBHOOK_URL",
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.secret_provider = secret_provider or EnvSecretProvider()
        self.secret_name = secret_name
        self.url = url or self._resolve_url()

    def _resolve_url(self) -> str:
        try:
            return self.secret_provider.get_secret(self.secret_name)
        except KeyError:
            raise ValueError(f"Missing secret '{self.secret_name}' for webhook sink")

    def emit(self, record: LogRecord) -> None:
        payload = json.dumps(record.to_dict(), ensure_ascii=False).encode("utf-8")
        request = Request(
            self.url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    response.read()
                return
            except (HTTPError, URLError, OSError) as exc:
                last_error = exc
                if attempt == self.max_retries:
                    break
                sleep_for = self.backoff_seconds * (2 ** (attempt - 1))
                logger.warning(
                    "Webhook delivery failed for %s (attempt %s/%s): %s; retrying in %.1fs",
                    self.url,
                    attempt,
                    self.max_retries,
                    exc,
                    sleep_for,
                )
                time.sleep(sleep_for)

        logger.error("Webhook delivery failed permanently for %s: %s", self.url, last_error)


class SyslogSink(BaseSink):
    def __init__(
        self,
        host: str = "localhost",
        port: int = 514,
        username: str | None = None,
        password: str | None = None,
        secret_provider: SecretProvider | None = None,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.username = username
        self.password = password
        self.secret_provider = secret_provider or EnvSecretProvider()
        self.logger = logging.getLogger(f"sentinellogs.syslog.{host}:{port}")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        for existing_handler in list(self.logger.handlers):
            self.logger.removeHandler(existing_handler)
        handler = SysLogHandler((host, self.port))
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)

    def emit(self, record: LogRecord) -> None:
        self.logger.info(record.to_json())


class SentinelLogsSink(BaseSink):
    """Sink for sending records to SentinelLogs HTTP ingest endpoint.

    Usage in CLI: --sink sentinellogs:https://sentinel.example.com/api/logs
    The target URL can be provided via environment secret reference like ${SENTINEL_URL}.
    """
    def __init__(self, endpoint: str, api_key: str | None = None, timeout: int = 5, max_retries: int = 3, backoff_seconds: float = 1.0) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds

    def emit(self, record: LogRecord) -> None:
        payload = json.dumps(record.to_dict(), ensure_ascii=False).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
        # if api_key provided, prefer that; otherwise check environment variable SENTINEL_API_KEY
        api_key = self.api_key or os.environ.get("SENTINEL_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        request = Request(
            self.endpoint,
            data=payload,
            headers=headers,
            method="POST",
        )

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    response.read()
                return
            except (HTTPError, URLError, OSError) as exc:
                last_error = exc
                if attempt == self.max_retries:
                    break
                sleep_for = self.backoff_seconds * (2 ** (attempt - 1))
                logger.warning(
                    "SentinelLogs delivery failed for %s (attempt %s/%s): %s; retrying in %.1fs",
                    self.endpoint,
                    attempt,
                    self.max_retries,
                    exc,
                    sleep_for,
                )
                time.sleep(sleep_for)

        logger.error("SentinelLogs delivery failed permanently for %s: %s", self.endpoint, last_error)


@dataclass(init=False)
class AlertRule:
    name: str
    field: str | None
    equals: str | None
    regex: str | None
    sinks: list[str]

    def __init__(
        self,
        name: str,
        field: str | None = None,
        equals: str | None = None,
        regex: str | None = None,
        sinks: list[str] | None = None,
    ) -> None:
        self.name = name
        self.field = field
        self.equals = equals
        self.regex = regex
        self.sinks = list(sinks or [])

    def matches(self, record: LogRecord) -> bool:
        value: Any = None
        if self.field is not None:
            value = getattr(record, self.field, None)
        if self.equals is not None:
            return str(value) == self.equals
        if self.regex is not None:
            return value is not None and re.search(self.regex, str(value)) is not None
        return False


class AlertEngine:
    def __init__(self, rules: Iterable[AlertRule] | None = None) -> None:
        self.rules = list(rules or [])

    @classmethod
    def from_yaml(cls, path: str | os.PathLike[str] | None) -> "AlertEngine":
        if path is None:
            return cls()

        config_path = Path(path)
        if not config_path.exists():
            return cls()

        try:
            import yaml  # type: ignore
        except ModuleNotFoundError as exc:
            raise ModuleNotFoundError("PyYAML is required to load alert rules.") from exc

        with config_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}

        raw_rules = payload.get("alert_rules") or payload.get("rules") or []
        rules: list[AlertRule] = []
        for index, item in enumerate(raw_rules):
            if not isinstance(item, dict):
                continue
            rules.append(
                AlertRule(
                    name=item.get("name", f"rule-{index + 1}"),
                    field=item.get("field"),
                    equals=item.get("equals"),
                    regex=item.get("regex") or item.get("pattern"),
                    sinks=list(item.get("sinks", [])),
                )
            )
        return cls(rules)

    def matching_sinks(self, record: LogRecord, sink_factory: Any) -> list[BaseSink]:
        matched: list[BaseSink] = []
        seen: set[str] = set()
        for rule in self.rules:
            if not rule.matches(record):
                continue
            for sink_spec in rule.sinks:
                sink_key = sink_spec
                if sink_key in seen:
                    continue
                try:
                    sink = sink_factory(sink_spec)
                except ValueError as exc:
                    logger.warning("Skipping invalid alert sink %s: %s", sink_spec, exc)
                    continue
                matched.append(sink)
                seen.add(sink_key)
        return matched

    def matching_rules(self, record: LogRecord) -> list[str]:
        """Return list of rule names that match the given record."""
        names: list[str] = []
        for rule in self.rules:
            if rule.matches(record):
                names.append(rule.name)
        return names

    def matching_sink_specs(self, record: LogRecord) -> list[str]:
        """Return list of sink specification strings for rules that match the record."""
        specs: list[str] = []
        seen: set[str] = set()
        for rule in self.rules:
            if not rule.matches(record):
                continue
            for sink_spec in rule.sinks:
                if sink_spec in seen:
                    continue
                specs.append(sink_spec)
                seen.add(sink_spec)
        return specs


def _resolve_secret_reference(reference: str) -> str:
    value = reference.strip()
    if value.startswith("${") and value.endswith("}"):
        name = value[2:-1]
        provider = EnvSecretProvider()
        return provider.get_secret(name)
    return value


def create_sink(sink_spec: str) -> BaseSink:
    sink_spec = sink_spec.strip()
    if not sink_spec:
        raise ValueError("Empty sink specification")

    if sink_spec == "stdout":
        return StdoutSink()

    if sink_spec.startswith("file:"):
        target = sink_spec.split(":", 1)[1]
        return FileSink(target, max_file_size_bytes=None, retention_days=None, max_files=None)

    if sink_spec.startswith("webhook:"):
        target = sink_spec.split(":", 1)[1]
        target = _resolve_secret_reference(target)
        if not target.startswith("http"):
            raise ValueError(f"Invalid webhook URL in sink specification: {sink_spec}")
        return WebhookSink(url=target)

    if sink_spec.startswith("sentinellogs:"):
        remainder = sink_spec.split(":", 1)[1]
        # allow optional params after '|' like sentinellogs:https://...|apikey:${SENTINEL_API_KEY}
        parts = remainder.split("|")
        endpoint_raw = parts[0]
        endpoint = _resolve_secret_reference(endpoint_raw)
        if not endpoint.startswith("http"):
            raise ValueError(f"Invalid SentinelLogs endpoint in sink specification: {sink_spec}")
        api_key = None
        for part in parts[1:]:
            for prefix in ("apikey=", "apikey:"):
                if part.startswith(prefix):
                    api_key = _resolve_secret_reference(part[len(prefix):])
                    break
        return SentinelLogsSink(endpoint=endpoint, api_key=api_key)

    if sink_spec.startswith("syslog:"):
        remainder = sink_spec.split(":", 1)[1]
        if not remainder:
            return SyslogSink()
        if ":" in remainder:
            host, port = remainder.rsplit(":", 1)
            return SyslogSink(host=host, port=port)
        return SyslogSink(host=remainder, port=514)

    raise ValueError(f"Unsupported sink: {sink_spec}")
