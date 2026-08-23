from __future__ import annotations

import hmac
import json
import logging
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, Callable
from urllib.request import Request, urlopen

from .parsers import ParserRegistry
from .schema import LogRecord, normalize_security_record

logger = logging.getLogger(__name__)

SUPPORTED_SOURCE_TYPES = frozenset({
    "linux_auth",
    "journald",
    "windows_eventlog_security",
    "windows_sysmon",
    "aws_cloudtrail",
    "azure_monitor",
    "network_syslog",
    "generic",
})


def send_events(endpoint: str, token: str, agent_id: str, events: list[dict[str, Any]], *, timeout: float = 10.0, context: ssl.SSLContext | None = None) -> int:
    payload = json.dumps({"events": events}, ensure_ascii=False).encode("utf-8")
    request = Request(
        endpoint.rstrip("/") + "/v1/ingest",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Sentinel-Agent": agent_id,
        },
        method="POST",
    )
    with urlopen(request, timeout=timeout, context=context) as response:
        result = json.loads(response.read().decode("utf-8"))
    return int(result.get("accepted", 0))


def _record_from_event(event: dict[str, Any], registry: ParserRegistry) -> LogRecord | None:
    raw = event.get("raw") or event.get("message")
    record: LogRecord | None = None
    if isinstance(raw, str):
        record = registry.parse_line(raw)
        if record is not None and record.format == "unknown":
            record = None
    if record is None and isinstance(event.get("message"), str):
        record = LogRecord(
            format=str(event.get("format") or event.get("source_type") or "structured"),
            timestamp=event.get("timestamp"),
            message=event["message"],
            raw=event.get("raw"),
            raw_line=event.get("raw"),
        )
    if record is None:
        return None
    record.source = event.get("source") or event.get("source_name")
    host = event.get("host")
    if isinstance(host, dict):
        record.host_hostname = host.get("hostname")
    elif isinstance(host, str):
        record.host_hostname = host
    user = event.get("user")
    if isinstance(user, dict):
        record.user_name = user.get("name") or record.user_name
    record.user_target = event.get("user_target") or event.get("user.target")
    record.source_ip = event.get("source_ip") or event.get("source.ip")
    record.user_name = event.get("user_name") or event.get("user.name")
    record.event_action = event.get("event_action") or event.get("event.action")
    record.event_outcome = event.get("event_outcome") or event.get("event.outcome")
    record.event_category = event.get("event_category") or event.get("event.category")
    record.host_hostname = event.get("host.hostname") or record.host_hostname
    return record


def ingest_events(
    payload: dict[str, Any],
    *,
    tenant_id: str,
    agent_id: str,
    registry: ParserRegistry,
    on_record: Callable[[LogRecord], None],
) -> int:
    events = payload.get("events")
    if events is None:
        events = [payload.get("event", payload)]
    if not isinstance(events, list):
        raise ValueError("events must be a list")
    accepted = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        source_type = str(event.get("source_type") or "generic")
        if source_type not in SUPPORTED_SOURCE_TYPES:
            raise ValueError(f"unsupported source_type: {source_type}")
        record = _record_from_event(event, registry)
        if record is None:
            continue
        on_record(normalize_security_record(record, tenant_id=tenant_id, agent_id=agent_id, source_type=source_type))
        accepted += 1
    return accepted


class IngestionHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # type: ignore[override]
        if self.path != "/v1/ingest":
            self.send_error(404)
            return
        token = self.headers.get("Authorization", "")
        if not token.startswith("Bearer "):
            self.send_error(401)
            return
        supplied = token[7:].strip()
        tenant_id = next((tenant for tenant, expected in self.server.tenant_tokens.items() if hmac.compare_digest(supplied, expected)), None)  # type: ignore[attr-defined]
        if tenant_id is None:
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > self.server.max_payload_bytes:  # type: ignore[attr-defined]
                raise ValueError("invalid payload size")
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("payload must be an object")
            agent_id = self.headers.get("X-Sentinel-Agent", "unknown-agent")
            accepted = self.server.ingest(payload, tenant_id=tenant_id, agent_id=agent_id)  # type: ignore[attr-defined]
        except (ValueError, json.JSONDecodeError) as exc:
            self.send_error(400, str(exc))
            return
        body = json.dumps({"accepted": accepted}).encode("utf-8")
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        logger.debug("Ingestion HTTP %s", format % args)


def start_ingestion_server(
    registry: ParserRegistry,
    on_record: Callable[[LogRecord], None],
    *,
    host: str = "0.0.0.0",
    port: int = 9443,
    tenant_tokens: dict[str, str],
    certfile: str,
    keyfile: str,
    max_payload_bytes: int = 5_000_000,
) -> ThreadingHTTPServer:
    if not tenant_tokens:
        raise ValueError("At least one tenant token is required")
    server = ThreadingHTTPServer((host, port), IngestionHandler)
    server.tenant_tokens = dict(tenant_tokens)  # type: ignore[attr-defined]
    server.max_payload_bytes = max_payload_bytes  # type: ignore[attr-defined]
    server.ingest = lambda payload, tenant_id, agent_id: ingest_events(  # type: ignore[attr-defined]
        payload, tenant_id=tenant_id, agent_id=agent_id, registry=registry, on_record=on_record
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    Thread(target=server.serve_forever, daemon=True).start()
    logger.info("HTTPS ingestion server started on https://%s:%s/v1/ingest", host, port)
    return server