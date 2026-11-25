from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

SUPPORTED_EXPORT_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson"})
MAX_BATCH_SIZE = 100
STATE_FILENAME = ".sentinellogs-seen.json"


@dataclass(frozen=True)
class ParsedGoogleEvent:
    event: dict[str, Any]
    fingerprint: str


def _fingerprint(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _activities(document: Any) -> list[Any]:
    if isinstance(document, list):
        return document
    if isinstance(document, dict):
        for key in ("items", "activities"):
            entries = document.get(key)
            if isinstance(entries, list):
                return entries
        return [document]
    raise ValueError("Google activity export must contain an object or array")


def _event_name(event: dict[str, Any]) -> str:
    raw_name = event.get("name") or event.get("eventName") or event.get("type") or "unknown"
    return re.sub(r"[^a-z0-9]+", "_", str(raw_name).lower()).strip("_")[:80] or "unknown"


def _event_action(name: str) -> tuple[str, str, str]:
    if any(token in name for token in ("suspicious", "risky", "hijacked")):
        return "google_suspicious_login", "unknown", "authentication"
    if name in {"login_success", "login_successful", "successful_login"}:
        return "authentication", "success", "authentication"
    if name in {"login_failure", "login_failed", "failed_login"}:
        return "authentication", "failure", "authentication"
    if name in {"logout", "user_logout", "session_end"}:
        return "google_session_end", "success", "authentication"
    return "google_workspace_activity", "unknown", "iam"


def _parameter(event: dict[str, Any], names: frozenset[str]) -> Any:
    parameters = event.get("parameters")
    if not isinstance(parameters, list):
        return None
    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "").lower().replace("-", "_")
        if name in names:
            return parameter.get("value")
    return None


def _source_ip(activity: dict[str, Any], event: dict[str, Any]) -> str | None:
    candidates = (
        activity.get("ipAddress"),
        event.get("ipAddress"),
        _parameter(event, frozenset({"ip_address", "ipaddress", "login_ip"})),
    )
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            return ipaddress.ip_address(candidate.strip()).compressed
        except ValueError:
            continue
    return None


def _workspace_events(activity: dict[str, Any]) -> list[ParsedGoogleEvent]:
    nested_events = activity.get("events")
    if not isinstance(nested_events, list):
        raise ValueError("Workspace activity is missing its events array")

    activity_id = activity.get("id")
    timestamp = (
        activity_id.get("time")
        if isinstance(activity_id, dict)
        else None
    ) or activity.get("timestamp") or activity.get("time")
    actor = activity.get("actor")
    user_email = actor.get("email") if isinstance(actor, dict) else activity.get("userEmail")
    output: list[ParsedGoogleEvent] = []
    for event in nested_events:
        if not isinstance(event, dict):
            continue
        name = _event_name(event)
        action, outcome, category = _event_action(name)
        normalized: dict[str, Any] = {
            "source_type": "google_workspace_login",
            "source": "google-workspace-export",
            "message": f"Google Workspace audit event: {name}",
            "timestamp": timestamp,
            "event.action": action,
            "event.outcome": outcome,
            "event.category": category,
            "host.hostname": "google-workspace",
        }
        source_ip = _source_ip(activity, event)
        if source_ip:
            normalized["source.ip"] = source_ip
        if isinstance(user_email, str) and user_email.strip():
            normalized["user.name"] = user_email.strip()
        output.append(ParsedGoogleEvent(normalized, _fingerprint({"activity": activity, "event": event})))
    return output


def _takeout_event(activity: dict[str, Any]) -> ParsedGoogleEvent:
    timestamp = activity.get("time") or activity.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError("Google Takeout activity is missing its timestamp")
    header = activity.get("header")
    product = re.sub(r"[^A-Za-z0-9 ._-]", "", str(header or "account activity"))[:80]
    normalized = {
        "source_type": "google_account_activity",
        "source": "google-account-activity-export",
        "message": f"Google account activity export: {product}",
        "timestamp": timestamp,
        "event.action": "google_account_activity",
        "event.outcome": "unknown",
        "event.category": "web",
        "host.hostname": "google-account",
    }
    return ParsedGoogleEvent(normalized, _fingerprint(activity))


def parse_google_activity_document(document: Any) -> list[ParsedGoogleEvent]:
    parsed: list[ParsedGoogleEvent] = []
    for activity in _activities(document):
        if not isinstance(activity, dict):
            continue
        if "events" in activity:
            parsed.extend(_workspace_events(activity))
        elif "header" in activity and ("time" in activity or "timestamp" in activity):
            parsed.append(_takeout_event(activity))
        else:
            raise ValueError("Unsupported Google activity record shape")
    return parsed


def parse_google_activity_file(path: Path) -> list[ParsedGoogleEvent]:
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_EXPORT_SUFFIXES:
        raise ValueError("Unsupported Google activity export extension")
    if suffix == ".json":
        return parse_google_activity_document(json.loads(path.read_text(encoding="utf-8")))

    parsed: list[ParsedGoogleEvent] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                document = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON Lines record at line {line_number}") from exc
            parsed.extend(parse_google_activity_document(document))
    return parsed


class GoogleActivityWatcher:
    def __init__(
        self,
        directory: str | Path,
        endpoint: str,
        agent_id: str,
        sender: Callable[[str, str, list[dict[str, Any]]], int],
        *,
        poll_interval: float = 30.0,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.endpoint = endpoint
        self.agent_id = agent_id
        self.sender = sender
        self.poll_interval = poll_interval
        self.state_path = self.directory / STATE_FILENAME
        self._seen = self._load_seen()
        self._reported_parse_errors: set[tuple[int, int]] = set()

    def _load_seen(self) -> set[str]:
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return set()
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Google activity deduplication state cannot be read") from exc
        if not isinstance(payload, list) or any(
            not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None
            for value in payload
        ):
            raise RuntimeError("Google activity deduplication state is invalid")
        return set(payload)

    def _save_seen(self, values: set[str]) -> None:
        fd, temporary_name = tempfile.mkstemp(prefix=".sentinellogs-state-", dir=self.directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(sorted(values), handle, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.state_path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    def scan_once(self) -> int:
        pending: dict[str, dict[str, Any]] = {}
        for path in sorted(self.directory.rglob("*")):
            if not path.is_file() or path.name.startswith(".") or path.suffix.lower() not in SUPPORTED_EXPORT_SUFFIXES:
                continue
            try:
                parsed_events = parse_google_activity_file(path)
            except (OSError, UnicodeError, ValueError) as exc:
                try:
                    stats = path.stat()
                    signature = (stats.st_mtime_ns, stats.st_size)
                except OSError:
                    signature = (0, 0)
                if signature not in self._reported_parse_errors:
                    logger.warning("Google activity export could not be parsed (%s)", type(exc).__name__)
                    self._reported_parse_errors.add(signature)
                continue
            for parsed in parsed_events:
                if parsed.fingerprint not in self._seen:
                    pending.setdefault(parsed.fingerprint, parsed.event)

        pending_items = list(pending.items())
        accepted_total = 0
        for start in range(0, len(pending_items), MAX_BATCH_SIZE):
            batch = pending_items[start : start + MAX_BATCH_SIZE]
            try:
                accepted = self.sender(self.endpoint, self.agent_id, [event for _, event in batch])
            except (RequestException, OSError, RuntimeError) as exc:
                raise RuntimeError("Google activity event delivery failed") from exc
            if accepted != len(batch):
                raise RuntimeError("Google activity endpoint accepted an incomplete batch")
            updated_seen = self._seen | {fingerprint for fingerprint, _ in batch}
            self._save_seen(updated_seen)
            self._seen = updated_seen
            accepted_total += accepted
        return accepted_total

    def run(self) -> None:
        logger.info("Google activity export watcher started")
        while True:
            try:
                imported = self.scan_once()
                if imported:
                    logger.info("Imported %s Google activity records", imported)
            except (OSError, RuntimeError) as exc:
                logger.error("Google activity watcher cycle failed (%s)", type(exc).__name__)
            time.sleep(self.poll_interval)
