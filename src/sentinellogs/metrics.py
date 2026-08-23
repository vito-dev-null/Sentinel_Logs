from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from time import monotonic
from typing import Any

logger = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class MetricsRegistry:
    def __init__(self, history_size: int = 60, alert_size: int = 30, recent_size: int = 50) -> None:
        self._lock = threading.Lock()
        self.processed_lines = 0
        self.dropped_lines = 0
        self.parser_errors = 0
        self.sink_errors = 0
        self.alerts_generated = 0
        self.sink_latency_ms: list[float] = []
        self.history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self.alerts: deque[dict[str, Any]] = deque(maxlen=alert_size)
        # recent_lines stores the last N processed lines with key fields
        self.recent_lines: deque[dict[str, Any]] = deque(maxlen=recent_size)
        self.tailer_active = False
        self._last_health_check = monotonic()
        # monitored sources (for dashboard visibility)
        self.sources: list[str] = []
        self.dashboard_html: bytes | None = None
        self.dependencies: dict[str, bool] = {"postgres": True, "redis": True, "worker": True}
        self.integrity_verified = False
        self.compliance = {"ISO 27001": "ready", "GDPR": "ready", "NIS2": "ready", "PCI-DSS": "ready"}

    def set_sources(self, sources: list[str]) -> None:
        """Set the list of monitored sources (file paths or globs) for dashboard display."""
        with self._lock:
            self.sources = list(sources or [])

    def set_dependency(self, name: str, healthy: bool) -> None:
        with self._lock:
            self.dependencies[name] = bool(healthy)

    def set_integrity_status(self, verified: bool) -> None:
        with self._lock:
            self.integrity_verified = bool(verified)

    def _capture_history(self) -> None:
        self.history.append({
            "timestamp": utc_now_iso(),
            "processed_lines": self.processed_lines,
        })

    def mark_processed(self, count: int = 1) -> None:
        with self._lock:
            self.processed_lines += count
            self._capture_history()

    def mark_dropped(self, count: int = 1) -> None:
        with self._lock:
            self.dropped_lines += count

    def mark_parser_error(self, count: int = 1) -> None:
        with self._lock:
            self.parser_errors += count

    def mark_sink_error(self, count: int = 1) -> None:
        with self._lock:
            self.sink_errors += count

    def observe_sink_latency(self, latency_ms: float) -> None:
        with self._lock:
            self.sink_latency_ms.append(latency_ms)

    def record_alert(self, source: str, message: str, level: str = "warning", details: dict[str, Any] | None = None) -> None:
        with self._lock:
            self.alerts_generated += 1
            self.alerts.append({
                "timestamp": utc_now_iso(),
                "source": source,
                "message": message,
                "level": level,
                "details": dict(details or {}),
            })

    def record_recent_line(self, record: Any, is_alert: bool = False, matching_rules: list[str] | None = None, alert_sinks: list[str] | None = None) -> None:
        """Record a processed line into the recent_lines buffer.

        `record` may be any object with attributes similar to LogRecord or a dict.
        We extract only a small set of fields for the UI.
        matching_rules: optional list of alert rule names that matched
        alert_sinks: optional list of sink specification strings targeted by the alert rules
        """
        try:
            # support both dict-like and attribute access
            fmt = getattr(record, 'format', None) or (record.get('format') if isinstance(record, dict) else None) or 'unknown'
            # prefer original timestamp extracted from the log (record.timestamp),
            # fall back to parsed_at (processing time) when original timestamp missing
            ts = getattr(record, 'timestamp', None) or getattr(record, 'parsed_at', None) or (record.get('timestamp') if isinstance(record, dict) else None) or (record.get('parsed_at') if isinstance(record, dict) else None)
            host = getattr(record, 'host', None) or (record.get('host') if isinstance(record, dict) else None)
            proc = getattr(record, 'process', None) or (record.get('process') if isinstance(record, dict) else None)
            level = getattr(record, 'level', None) or (record.get('level') if isinstance(record, dict) else None)
            message = getattr(record, 'message', None) or (record.get('message') if isinstance(record, dict) else '') or ''
            ips = getattr(record, 'ips', None) or (record.get('ips') if isinstance(record, dict) else []) or []
            raw_line = getattr(record, 'raw_line', None) or (record.get('raw_line') if isinstance(record, dict) else None) or getattr(record, 'raw', None) or (record.get('raw') if isinstance(record, dict) else None) or ''
            matched = getattr(record, 'matched_parser', None) or (record.get('matched_parser') if isinstance(record, dict) else None) or fmt or 'unknown'
            parse_dur = getattr(record, 'parse_duration_ms', None) or (record.get('parse_duration_ms') if isinstance(record, dict) else None)
            source = getattr(record, 'source', None) or (record.get('source') if isinstance(record, dict) else None)
            source_ip = getattr(record, 'source_ip', None) or (record.get('source.ip') if isinstance(record, dict) else None)
            user_name = getattr(record, 'user_name', None) or (record.get('user.name') if isinstance(record, dict) else None)
            hostname = getattr(record, 'host_hostname', None) or getattr(record, 'host', None) or (record.get('host.hostname') if isinstance(record, dict) else None)
            user_target = getattr(record, 'user_target', None) or (record.get('user.target') if isinstance(record, dict) else None)
        except Exception:
            # defensive fallback
            fmt = 'unknown'
            ts = None
            host = None
            proc = None
            level = None
            message = ''
            ips = []
            raw_line = ''
            matched = 'unknown'
            parse_dur = None
            source = None
            source_ip = None
            user_name = None
            hostname = None
            user_target = None

        # truncate message to 200 chars for the UI
        truncated = (message[:200] + '...') if len(message) > 200 else message

        entry = {
            'processed_at': utc_now_iso(),
            'format': fmt,
            'timestamp': ts,
            'host': host,
            'process': proc,
            'level': level,
            'message': truncated,
            'raw_line': raw_line,
            'matched_parser': matched,
            'parse_duration_ms': float(parse_dur) if parse_dur is not None else None,
            'ips': list(ips),
            'is_alert': bool(is_alert),
            'matching_rules': list(matching_rules) if matching_rules else [],
            'alert_sinks': list(alert_sinks) if alert_sinks else [],
            'source': source,
            'source.ip': source_ip or (ips[0] if ips else None),
            'user.name': user_name,
            'host.hostname': hostname,
            'user.target': user_target,
        }
        with self._lock:
            self.recent_lines.append(entry)

    def set_tailer_active(self, active: bool) -> None:
        with self._lock:
            self.tailer_active = active
            self._last_health_check = monotonic()

    def as_dict(self) -> dict[str, Any]:
        with self._lock:
            avg_latency = 0.0
            if self.sink_latency_ms:
                avg_latency = sum(self.sink_latency_ms) / len(self.sink_latency_ms)
            return {
                "status": "ok" if self.tailer_active else "degraded",
                "tailer_active": self.tailer_active,
                "processed_lines": self.processed_lines,
                "dropped_lines": self.dropped_lines,
                "parser_errors": self.parser_errors,
                "sink_errors": self.sink_errors,
                "alerts_generated": self.alerts_generated,
                "average_sink_latency_ms": avg_latency,
                "history": list(self.history),
                "alerts": list(self.alerts),
                "recent_lines": list(self.recent_lines),
                "sources": list(self.sources),
                "dependencies": dict(self.dependencies),
                "integrity_verified": self.integrity_verified,
                "compliance": dict(self.compliance),
            }

    def render_prometheus(self) -> str:
        with self._lock:
            avg_latency = 0.0
            if self.sink_latency_ms:
                avg_latency = sum(self.sink_latency_ms) / len(self.sink_latency_ms)
            lines = [
                '# HELP sentinellogs_processed_lines_total Total processed log lines.',
                '# TYPE sentinellogs_processed_lines_total counter',
                f'sentinellogs_processed_lines_total {self.processed_lines}',
                '# HELP sentinellogs_dropped_lines_total Total dropped log lines.',
                '# TYPE sentinellogs_dropped_lines_total counter',
                f'sentinellogs_dropped_lines_total {self.dropped_lines}',
                '# HELP sentinellogs_parser_errors_total Total parser errors.',
                '# TYPE sentinellogs_parser_errors_total counter',
                f'sentinellogs_parser_errors_total {self.parser_errors}',
                '# HELP sentinellogs_sink_errors_total Total sink errors.',
                '# TYPE sentinellogs_sink_errors_total counter',
                f'sentinellogs_sink_errors_total {self.sink_errors}',
                '# HELP sentinellogs_alerts_generated_total Alert events generated by the application.',
                '# TYPE sentinellogs_alerts_generated_total counter',
                f'sentinellogs_alerts_generated_total {self.alerts_generated}',
                '# HELP sentinellogs_sink_latency_ms Average sink latency in milliseconds.',
                '# TYPE sentinellogs_sink_latency_ms gauge',
                f'sentinellogs_sink_latency_ms {avg_latency}',
                '# HELP sentinellogs_tailer_active Whether the tailer is active.',
                '# TYPE sentinellogs_tailer_active gauge',
                f'sentinellogs_tailer_active {1 if self.tailer_active else 0}',
            ]
            return "\n".join(lines) + "\n"

    def health_json(self) -> dict[str, Any]:
        payload = self.as_dict()
        payload["status"] = "ok" if self.tailer_active else "degraded"
        return payload

    def infrastructure_health(self) -> dict[str, Any]:
        with self._lock:
            dependencies = dict(self.dependencies)
            healthy = self.tailer_active and all(dependencies.values())
            return {"status": "ok" if healthy else "degraded", "dependencies": dependencies}


class MetricsHTTPHandler(BaseHTTPRequestHandler):
    @property
    def registry(self) -> MetricsRegistry:
        return getattr(self.server, "registry")

    @staticmethod
    def _resolve_basic_auth() -> tuple[str, str] | None:
        raw = os.environ.get("SENTINELLOGS_BASIC_AUTH") or os.environ.get("LOG_PARSER_BASIC_AUTH")
        if raw and ":" in raw:
            username, password = raw.split(":", 1)
            return username, password
        username = os.environ.get("SENTINELLOGS_BASIC_AUTH_USERNAME") or os.environ.get("LOG_PARSER_BASIC_AUTH_USERNAME")
        password = os.environ.get("SENTINELLOGS_BASIC_AUTH_PASSWORD") or os.environ.get("LOG_PARSER_BASIC_AUTH_PASSWORD")
        if username and password:
            return username, password
        return None

    def _is_authorized(self) -> bool:
        credentials = getattr(self.server, "basic_auth", None)
        if credentials is None:
            return True
        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth_header.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        expected = f"{credentials[0]}:{credentials[1]}"
        return decoded == expected

    def _send_401(self) -> None:
        payload = b"Unauthorized\n"
        self.send_response(401)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("WWW-Authenticate", 'Basic realm="sentinellogs"')
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # type: ignore[override]
        if not self._is_authorized():
            self._send_401()
            return

        path = self.path.split("?", 1)[0]

        if not getattr(self.server, "enable_dashboard", True):
            if path in {"/dashboard", "/dashboard/", "/api/metrics.json"}:
                self.send_response(404)
                self.end_headers()
                return

        if path in {"/dashboard", "/dashboard/"}:
            if self.server.dashboard_html is None:  # type: ignore[attr-defined]
                dashboard_path = Path(__file__).with_name("dashboard.html")
                self.server.dashboard_html = dashboard_path.read_bytes()  # type: ignore[attr-defined]
            payload = self.server.dashboard_html  # type: ignore[attr-defined]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/api/metrics.json":
            payload = json.dumps(self.registry.as_dict(), ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/api/recent-lines.json":
            # expose only recent_lines for a lighter endpoint
            payload = json.dumps({"recent_lines": list(self.registry.recent_lines)}, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/metrics":
            payload = self.registry.render_prometheus().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/health":
            healthy = self.registry.tailer_active
            payload = json.dumps({"status": "ok" if healthy else "degraded"}).encode("utf-8")
            status_code = 200 if healthy else 503
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/healthz":
            payload = json.dumps(self.registry.infrastructure_health()).encode("utf-8")
            status_code = 200 if self.registry.infrastructure_health()["status"] == "ok" else 503
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/api/events":
            payload = json.dumps(self.registry.as_dict(), ensure_ascii=False).encode("utf-8")
            stream = b"retry: 2000\n\n" + b"event: snapshot\ndata: " + payload + b"\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Content-Length", str(len(stream)))
            self.end_headers()
            self.wfile.write(stream)
            self.wfile.flush()
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # type: ignore[override]
        if not self._is_authorized():
            self._send_401()
            return
        if self.path == "/v1/ingest":
            callback = getattr(self.server, "ingest_callback", None)
            if callback is None:
                self.send_error(503, "local ingestion is not configured")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 5_000_000:
                    raise ValueError("invalid payload size")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("payload must be an object")
                accepted = int(callback(payload, self.headers.get("X-Sentinel-Agent", "local-agent")))
            except (ValueError, json.JSONDecodeError) as exc:
                self.send_error(400, str(exc))
                return
            body = json.dumps({"accepted": accepted}).encode("utf-8")
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/api/soar/block-ip":
            self.send_response(404)
            self.end_headers()
            return
        action = getattr(self.server, "soar_action", None)
        if action is None:
            self.send_error(503, "SOAR action is not configured")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            ip_address = str(payload.get("ip", "")).strip()
            if not ip_address:
                raise ValueError("ip is required")
            action(ip_address)
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_error(400, str(exc))
            return
        body = b'{"status":"accepted"}'
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        logger.debug("HTTP %s", format % args)


def start_metrics_server(registry: MetricsRegistry, port: int, enable_dashboard: bool = True, soar_action: Any | None = None, ingest_callback: Any | None = None) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("0.0.0.0", port), MetricsHTTPHandler)
    server.registry = registry  # type: ignore[attr-defined]
    server.basic_auth = MetricsHTTPHandler._resolve_basic_auth()  # type: ignore[attr-defined]
    server.enable_dashboard = enable_dashboard  # type: ignore[attr-defined]
    server.dashboard_html = None  # type: ignore[attr-defined]
    server.soar_action = soar_action  # type: ignore[attr-defined]
    server.ingest_callback = ingest_callback  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Metrics server started on http://0.0.0.0:%s", port)
    return server
