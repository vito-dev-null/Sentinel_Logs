from __future__ import annotations

import logging
import getpass
import os
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread
from typing import Any, Callable

from .tailer import LogTailer, journal_lines

logger = logging.getLogger(__name__)

AUTHORIZED_USER = "local-user"
AUTHORIZED_HOST = "PC"
GENERIC_LOCAL_USERS = frozenset({"", "user", "root", "unknown", "n/a", "none"})

ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"


def _terminal(text: str, color: str | None = None) -> None:
    if color and sys.stdout.isatty():
        print(f"{color}{text}{ANSI_RESET}", flush=True)
    else:
        print(text, flush=True)


def _process_name(line: str) -> str:
    match = re.search(r"^(?:\S+\s+\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+)\s+(\S+?)(?:\[\d+\])?:\s", line)
    return match.group(1) if match else "unknown"


def _local_ip() -> str:
    try:
        import psutil  # type: ignore
        for addresses in psutil.net_if_addrs().values():
            for address in addresses:
                if address.family == socket.AF_INET and not address.address.startswith("127."):
                    return address.address
    except (ImportError, OSError):
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.connect(("192.0.2.1", 80))
            return connection.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def post_events(endpoint: str, agent_id: str, events: list[dict[str, Any]]) -> int:
    try:
        import requests  # type: ignore
    except ImportError as exc:
        raise RuntimeError("requests is required; run ./run-local-agent.sh to install dependencies") from exc
    try:
        response = requests.post(
            endpoint.rstrip("/") + "/v1/ingest",
            json={"events": events},
            headers={"Content-Type": "application/json", "X-Sentinel-Agent": agent_id},
            timeout=10,
        )
        event = events[0] if events else {}
        message = str(event.get("message", "")).replace("\r", " ").replace("\n", " ")[:60]
        output = (
            f"[{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"[{'OK' if response.ok else 'ERR'} {response.status_code}] "
            f"IP: {event.get('source.ip', 'n/d')} | User: {event.get('user.name', 'n/d')} | "
            f"Host: {event.get('host.hostname', 'n/d')} | Service: {event.get('process', 'unknown')} | Msg: \"{message}\""
        )
        _terminal(output, ANSI_GREEN if response.ok else ANSI_RED)
        response.raise_for_status()
        body = response.json()
        return int(body.get("accepted", 0))
    except requests.RequestException as exc:
        response = getattr(exc, "response", None)
        detail = response.text[:200] if response is not None and response.text else str(exc)
        _terminal(
            f"[{datetime.now(timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S')}] [ERROR] "
            f"Backend {endpoint}: {detail}",
            ANSI_RED,
        )
        raise


class LocalLogAgent:
    """Forward real local authentication lines to the local ingestion endpoint."""

    def __init__(self, paths: list[str | Path], endpoint: str = "http://localhost:9090", agent_id: str = "local-agent", hostname: str | None = None, username: str | None = None, source_ip: str | None = None, sender: Callable[[str, str, list[dict[str, Any]]], int] | None = None, from_start: bool = True) -> None:
        self.paths = [Path(path) for path in paths if Path(path).is_file() and os.access(path, os.R_OK)]
        self.endpoint = endpoint
        self.agent_id = agent_id
        self.hostname = hostname or socket.gethostname()
        self.username = username or self._current_username()
        self.source_ip = source_ip or _local_ip()
        self.sender = sender or post_events
        self.from_start = from_start
        print(f"SentinelLogs agent: user={self.username} host={self.hostname} ip={self.source_ip} backend={self.endpoint}", flush=True)

    @staticmethod
    def _current_username() -> str:
        candidates = [os.environ.get("SUDO_USER")]
        try:
            candidates.append(os.getlogin())
        except OSError:
            pass
        candidates.append(getpass.getuser())
        for candidate in candidates:
            username = str(candidate or "").strip()
            if username.lower() not in GENERIC_LOCAL_USERS:
                return username
        return AUTHORIZED_USER

    def forward_line(self, line: str, source: str) -> int:
        return self.sender(self.endpoint, self.agent_id, [{
                "source_type": "linux_auth",
                "source": source,
                "raw": line.rstrip("\r\n"),
                "message": line.rstrip("\r\n"),
                "process": _process_name(line),
                "source.ip": self.source_ip,
                "host.hostname": self.hostname,
                "user.name": self.username,
                "host": {"hostname": self.hostname},
                "user": {"name": self.username},
            }])

    def run(self) -> None:
        if not self.paths:
            logger.warning("No readable auth.log/syslog found; trying journald. Run with sudo for complete authentication visibility.")
            try:
                for line in journal_lines():
                    self.forward_line(line, "journald")
            except RuntimeError:
                logger.exception("journalctl unavailable; run with sudo ./run-local-agent.sh for complete authentication visibility")
            return
        workers = [Thread(target=self._follow, args=(path,), daemon=True) for path in self.paths]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()

    def _follow(self, path: Path) -> None:
        try:
            for line in LogTailer(path, from_start=self.from_start):
                try:
                    self.forward_line(line, str(path))
                except Exception:
                    logger.exception("Unable to forward local log line from %s", path)
        except PermissionError:
            logger.warning("Permission denied for %s; falling back to journald. Run with sudo for complete authentication visibility.", path)
            try:
                for line in journal_lines():
                    self.forward_line(line, "journald")
            except RuntimeError:
                logger.exception("journalctl unavailable after permission failure for %s", path)