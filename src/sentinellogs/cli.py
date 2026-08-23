from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from threading import Thread
from typing import Sequence, TextIO

from .metrics import MetricsRegistry, start_metrics_server
from .multi_source import MultiSourceTailer
from .parsers import DEFAULT_MAX_LINE_LENGTH, DEFAULT_PARSE_TIMEOUT_MS, ParserRegistry
from .audit import AuditLog
from .detection import CorrelationEngine
from .ingestion import ingest_events, start_ingestion_server
from .notifications import NotificationRouter
from .persistence import EventStore, create_store
from .queue import RedisQueue
from .schema import LogRecord, normalize_security_record
from .sinks import AlertEngine, BaseSink, create_sink
from .tailer import LogTailer, journal_lines
from .telemetry import invia_ping

logger = logging.getLogger(__name__)

DEMO_NAME_TOKENS = ("sample", "demo", "parsed_preview", "live_output", "output.jsonl")
DEMO_DIR_TOKENS = ("examples", "fixtures", "demo")


def configure_logging(level_name: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level_name.upper(), logging.INFO),
        format='{"ts": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "msg": "%(message)s"}',
        stream=sys.stderr,
        force=True,
    )


def _get_package_version() -> str:
    try:
        return version("sentinellogs")
    except PackageNotFoundError:
        return "0.2.0"


def emit_record(record: object, output_handle: TextIO | None = None) -> None:
    payload = record.to_json() if hasattr(record, "to_json") else json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    print(payload, flush=True)
    if output_handle is not None:
        output_handle.write(payload + "\n")
        output_handle.flush()


def looks_like_demo_path(file_path: Path) -> bool:
    is_demo_name = any(token in file_path.name.lower() for token in DEMO_NAME_TOKENS)
    is_examples_dir = any(part.lower() in DEMO_DIR_TOKENS for part in file_path.parts)
    return is_demo_name or is_examples_dir


def _record_from_json_line(line: str) -> LogRecord | None:
    if not line.lstrip().startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or "raw" not in obj:
        return None
    return LogRecord(
        format=obj.get("format", "unknown"),
        timestamp=obj.get("timestamp"),
        host=obj.get("host"),
        process=obj.get("process"),
        pid=obj.get("pid"),
        level=obj.get("level"),
        message=obj.get("message"),
        ips=obj.get("ips") or [],
        parsed_at=obj.get("parsed_at"),
        raw=obj.get("raw"),
        source=obj.get("source"),
    )


def dispatch_record(
    record: LogRecord,
    *,
    sinks: list[BaseSink],
    output_handle: TextIO | None,
    redaction_patterns: Sequence[str] | None,
    metrics_registry: MetricsRegistry | None,
    alert_engine: AlertEngine | None,
    source: str | None = None,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    source_type: str | None = None,
    correlation_engine: CorrelationEngine | None = None,
    audit_log: AuditLog | None = None,
    notification_router: NotificationRouter | None = None,
    event_store: EventStore | None = None,
    measure_sink_latency: bool = False,
) -> None:
    if source and not record.source:
        record.source = source
    if tenant_id and agent_id and source_type:
        normalize_security_record(record, tenant_id=tenant_id, agent_id=agent_id, source_type=source_type)
    if redaction_patterns:
        record = record.redact(redaction_patterns)

    is_alert = False
    matching_rules: list[str] = []
    alert_sink_specs: list[str] = []
    alert_sinks: list[BaseSink] = []
    if alert_engine is not None:
        try:
            alert_sinks = list(alert_engine.matching_sinks(record, create_sink))
            matching_rules = alert_engine.matching_rules(record)
            alert_sink_specs = alert_engine.matching_sink_specs(record)
            is_alert = bool(matching_rules)
        except Exception:
            logger.exception("Alert evaluation failed")
    if correlation_engine is not None:
        for alert in correlation_engine.observe(record):
            if metrics_registry is not None:
                metrics_registry.record_alert(alert.source_ip or "unknown", alert.message, alert.severity, alert.details)
            if event_store is not None:
                event_store.save_alert(alert)
            if notification_router is not None:
                notification_router.dispatch(alert)

    if audit_log is not None:
        audit_entry = audit_log.append(record.to_dict())
        if event_store is not None:
            event_store.save_audit(audit_entry)
    if event_store is not None:
        event_store.save_log(record)
    if metrics_registry is not None:
        metrics_registry.mark_processed()
        try:
            metrics_registry.record_recent_line(
                record,
                is_alert=is_alert,
                matching_rules=matching_rules,
                alert_sinks=alert_sink_specs,
            )
        except Exception:
            logger.debug("Unable to record recent line for metrics", exc_info=True)

    for sink in sinks:
        start = time.perf_counter()
        try:
            sink.emit(record)
        except Exception as exc:  # pragma: no cover - defensive path
            logger.exception("Sink failed while emitting record: %s", exc)
            if metrics_registry is not None:
                metrics_registry.mark_sink_error()
        finally:
            if measure_sink_latency and metrics_registry is not None:
                metrics_registry.observe_sink_latency((time.perf_counter() - start) * 1000)

    for alert_sink in alert_sinks:
        try:
            alert_sink.emit(record)
        except Exception as exc:  # pragma: no cover - defensive path
            logger.exception("Alert sink failed while emitting record: %s", exc)
            if metrics_registry is not None:
                metrics_registry.mark_sink_error()

    if not sinks:
        emit_record(record, output_handle)


def parse_existing_lines(
    file_path: Path,
    registry: ParserRegistry,
    output_handle: TextIO | None = None,
    sinks: list[BaseSink] | None = None,
    redaction_patterns: Sequence[str] | None = None,
    metrics_registry: MetricsRegistry | None = None,
    alert_engine: AlertEngine | None = None,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    source_type: str | None = None,
    correlation_engine: CorrelationEngine | None = None,
    audit_log: AuditLog | None = None,
    event_store: EventStore | None = None,
) -> None:
    sinks = sinks or []
    with file_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            record = _record_from_json_line(line)
            if record is None:
                record = registry.parse_line(line)
            if record is None or record.format == "unknown":
                if metrics_registry is not None:
                    metrics_registry.mark_dropped()
                continue
            dispatch_record(
                record,
                sinks=sinks,
                output_handle=output_handle,
                redaction_patterns=redaction_patterns,
                metrics_registry=metrics_registry,
                alert_engine=alert_engine,
                source=str(file_path),
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            source_type=source_type,
                            correlation_engine=correlation_engine,
                            audit_log=audit_log,
                            event_store=event_store,
            )


def build_registry(
    config_path: Path | None = None,
    max_line_length: int = DEFAULT_MAX_LINE_LENGTH,
    parse_timeout_ms: int = DEFAULT_PARSE_TIMEOUT_MS,
) -> ParserRegistry:
    if config_path is None:
        config_path = Path(__file__).with_name("patterns.yaml")
    return ParserRegistry.from_config(config_path, max_line_length=max_line_length, parse_timeout_ms=parse_timeout_ms)


def build_alert_engine(alert_config: Path | None = None) -> AlertEngine:
    if alert_config is None:
        alert_config = Path(__file__).with_name("alerts.yaml")
    if not alert_config.exists():
        return AlertEngine()
    return AlertEngine.from_yaml(alert_config)


def _build_sink_specs(args: argparse.Namespace) -> list[str]:
    specs = list(args.sink or [])
    if args.output and not any(spec.startswith("file:") for spec in specs):
        specs.append(f"file:{args.output}")
    return specs if specs else ["stdout"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinellogs",
        description="SentinelLogs: real-time log parser with JSONL output, pluggable sinks, and alerting.",
        epilog=(
            "Examples:\n"
            "  sentinellogs --file /var/log/syslog\n"
            "  sentinellogs --file /var/log/auth.log --sink stdout --sink file:parsed.jsonl\n"
            "  sentinellogs --file /var/log/app.log --metrics-port 9090\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--file", nargs="+", help="Log file path(s) to monitor. Globs are supported.")
    parser.add_argument(
        "--confirm-demo",
        action="store_true",
        help="Allow sample/demo files under examples/ or similarly named paths.",
    )
    parser.add_argument("--output", help="Optional JSONL file path. Equivalent to --sink file:<path>.")
    parser.add_argument("--from-start", action="store_true", help="Parse existing lines before following new appends.")
    parser.add_argument("--log-level", default="INFO", help="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL.")
    parser.add_argument("--version", action="store_true", help="Print the package version and exit.")
    parser.add_argument(
        "--sink",
        action="append",
        default=[],
        help="Output sink. Repeatable. Examples: stdout, file:/path.jsonl, webhook:https://..., syslog:host:port, sentinellogs:https://...",
    )
    parser.add_argument("--patterns", help="Path to a YAML/JSON parser pattern file. Defaults to the bundled patterns.")
    parser.add_argument("--alert-config", help="Path to a YAML alert-rules file.")
    parser.add_argument("--metrics-port", type=int, default=None, help="Expose /metrics, /health, and the dashboard on this port.")
    parser.add_argument(
        "--dashboard",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Serve the HTML dashboard at /dashboard when metrics are enabled.",
    )
    parser.add_argument("--redact", nargs="+", default=None, help="Regex patterns used to redact sensitive message fields.")
    parser.add_argument("--max-line-length", type=int, default=DEFAULT_MAX_LINE_LENGTH, help="Drop lines longer than this many bytes.")
    parser.add_argument("--parse-timeout-ms", type=int, default=DEFAULT_PARSE_TIMEOUT_MS, help="Per-line parse timeout in milliseconds.")
    parser.add_argument("--tenant-id", default="local", help="Tenant identifier attached to normalized events.")
    parser.add_argument("--agent-id", default="local-agent", help="Agent identifier attached to normalized events.")
    parser.add_argument("--source-type", default="linux_auth", help="Source type: linux_auth, journald, Windows, cloud, or network.")
    parser.add_argument("--audit-log", help="Append accepted events to a tamper-evident hash-chain JSONL file.")
    parser.add_argument("--admin-user", action="append", default=[], help="Administrator allowed to use sudo. Repeatable.")
    parser.add_argument("--ingestion-port", type=int, default=None, help="Enable the HTTPS remote ingestion listener.")
    parser.add_argument("--ingestion-certfile", help="TLS certificate for the ingestion listener.")
    parser.add_argument("--ingestion-keyfile", help="TLS private key for the ingestion listener.")
    parser.add_argument("--journal", action="store_true", help="Follow authentication events from journald when log files are unavailable.")
    return parser


def _process_live_line(
    line: str,
    registry: ParserRegistry,
    sinks: list[BaseSink],
    output_handle: TextIO | None,
    redact: Sequence[str] | None,
    metrics_registry: MetricsRegistry,
    alert_engine: AlertEngine,
    source: str | None = None,
    tenant_id: str | None = None,
    agent_id: str | None = None,
    source_type: str | None = None,
    correlation_engine: CorrelationEngine | None = None,
    audit_log: AuditLog | None = None,
    event_store: EventStore | None = None,
) -> None:
    record = registry.parse_line(line)
    if record is None or record.format == "unknown":
        metrics_registry.mark_dropped()
        return
    dispatch_record(
        record,
        sinks=sinks,
        output_handle=output_handle,
        redaction_patterns=redact,
        metrics_registry=metrics_registry,
        alert_engine=alert_engine,
        source=source,
        tenant_id=tenant_id,
        agent_id=agent_id,
        source_type=source_type,
        correlation_engine=correlation_engine,
        audit_log=audit_log,
        event_store=event_store,
        measure_sink_latency=True,
    )


def main(argv: list[str] | None = None) -> int:
    invia_ping()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(_get_package_version())
        return 0

    if not args.file:
        parser.error("No log file specified. Use --file <path> to select the file to monitor.")

    configure_logging(args.log_level)

    metrics_registry = MetricsRegistry()
    metrics_server = None
    ingestion_server = None
    event_store: EventStore | None = None
    redis_queue: RedisQueue | None = None
    worker_thread: Thread | None = None
    metrics_registry.set_sources(args.file if args.file else [])
    if args.metrics_port is not None:
        metrics_server = start_metrics_server(metrics_registry, args.metrics_port, enable_dashboard=args.dashboard)
    metrics_registry.set_tailer_active(True)

    sink_specs = _build_sink_specs(args)
    sinks: list[BaseSink] = []
    for sink_spec in sink_specs:
        try:
            sinks.append(create_sink(sink_spec))
        except ValueError as exc:
            logger.error("Invalid sink configuration '%s': %s", sink_spec, exc)
            if metrics_server is not None:
                metrics_server.shutdown()
            return 1

    output_handle: TextIO | None = None
    if args.output and not any(spec.startswith("file:") for spec in sink_specs):
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_handle = output_path.open("a", encoding="utf-8")
        except OSError as exc:
            logger.error("Unable to open output file '%s': %s", args.output, exc)
            if metrics_server is not None:
                metrics_server.shutdown()
            return 1

    try:
        registry = build_registry(
            Path(args.patterns) if args.patterns else None,
            max_line_length=args.max_line_length,
            parse_timeout_ms=args.parse_timeout_ms,
        )
        alert_engine = build_alert_engine(Path(args.alert_config) if args.alert_config else None)
        correlation_engine = CorrelationEngine(admin_users=set(args.admin_user))
        audit_log = AuditLog(args.audit_log) if args.audit_log else None
        event_store = create_store()
        metrics_registry.set_dependency("postgres", os.environ.get("STORAGE_BACKEND", "jsonl").lower() == "jsonl" or event_store.__class__.__name__ == "PostgresStore")
        if os.environ.get("QUEUE_BACKEND", "off").lower() == "redis":
            redis_queue = RedisQueue()
            metrics_registry.set_dependency("redis", redis_queue.ping())
        if args.ingestion_port is not None:
            if not args.ingestion_certfile or not args.ingestion_keyfile:
                parser.error("--ingestion-port requires --ingestion-certfile and --ingestion-keyfile")
            raw_tokens = os.environ.get("SENTINELLOGS_TENANT_TOKENS", "")
            tenant_tokens = dict(item.split(":", 1) for item in raw_tokens.split(",") if ":" in item)
            ingestion_server = start_ingestion_server(
                registry,
                lambda record: redis_queue.publish(record) if redis_queue is not None else dispatch_record(record, sinks=sinks, output_handle=output_handle, redaction_patterns=args.redact, metrics_registry=metrics_registry, alert_engine=alert_engine, source="remote-ingestion", correlation_engine=correlation_engine, audit_log=audit_log, event_store=event_store),
                port=args.ingestion_port,
                tenant_tokens=tenant_tokens,
                certfile=args.ingestion_certfile,
                keyfile=args.ingestion_keyfile,
            )
            if redis_queue is not None:
                worker_thread = Thread(target=redis_queue.consume, args=(lambda record: dispatch_record(record, sinks=sinks, output_handle=output_handle, redaction_patterns=args.redact, metrics_registry=metrics_registry, alert_engine=alert_engine, source="redis-worker", correlation_engine=correlation_engine, audit_log=audit_log, event_store=event_store),), daemon=True)
                worker_thread.start()
                metrics_registry.set_dependency("worker", worker_thread.is_alive())

        if args.metrics_port is not None:
            metrics_server.ingest_callback = lambda payload, agent_id: ingest_events(  # type: ignore[attr-defined]
                payload,
                tenant_id=args.tenant_id,
                agent_id=agent_id,
                registry=registry,
                on_record=(redis_queue.publish if redis_queue is not None else lambda record: dispatch_record(record, sinks=sinks, output_handle=output_handle, redaction_patterns=args.redact, metrics_registry=metrics_registry, alert_engine=alert_engine, source="local-ingestion", correlation_engine=correlation_engine, audit_log=audit_log, event_store=event_store)),
            )

        if args.journal:
            for line in journal_lines():
                _process_live_line(line, registry, sinks, output_handle, args.redact, metrics_registry, alert_engine, source="journald", tenant_id=args.tenant_id, agent_id=args.agent_id, source_type="journald", correlation_engine=correlation_engine, audit_log=audit_log, event_store=event_store)
        elif len(args.file) == 1 and all(ch not in args.file[0] for ch in "*?["):
            file_path = Path(args.file[0])
            if not file_path.exists():
                logger.error("File not found: %s", file_path)
                return 1

            if looks_like_demo_path(file_path) and not args.confirm_demo:
                logger.error(
                    "Refusing to monitor %s because it looks like a sample/demo file. "
                    "Pass --confirm-demo if that is intentional.",
                    file_path,
                )
                return 2
            if args.from_start:
                parse_existing_lines(
                    file_path,
                    registry,
                    output_handle,
                    sinks=sinks,
                    redaction_patterns=args.redact,
                    metrics_registry=metrics_registry,
                    alert_engine=alert_engine,
                    tenant_id=args.tenant_id,
                    agent_id=args.agent_id,
                    source_type=args.source_type,
                    correlation_engine=correlation_engine,
                    audit_log=audit_log,
                    event_store=event_store,
                )
            tailer = LogTailer(file_path)
            for line in tailer:
                _process_live_line(line, registry, sinks, output_handle, args.redact, metrics_registry, alert_engine, source=str(file_path), tenant_id=args.tenant_id, agent_id=args.agent_id, source_type=args.source_type, correlation_engine=correlation_engine, audit_log=audit_log, event_store=event_store)
        else:
            collector = MultiSourceTailer(args.file)
            collector.start()
            for line in collector.iter_lines():
                _process_live_line(line, registry, sinks, output_handle, args.redact, metrics_registry, alert_engine, tenant_id=args.tenant_id, agent_id=args.agent_id, source_type=args.source_type, correlation_engine=correlation_engine, audit_log=audit_log, event_store=event_store)

    except KeyboardInterrupt:
        logger.info("Interrupted by user (Ctrl+C).")
        return 0
    except FileNotFoundError as exc:
        logger.error("File not found while monitoring: %s", exc)
        return 1
    except OSError as exc:
        logger.error("I/O error during log monitoring: %s", exc)
        return 1
    finally:
        metrics_registry.set_tailer_active(False)
        for sink in sinks:
            try:
                sink.close()
            except Exception:
                logger.debug("Error while closing sink", exc_info=True)
        if output_handle is not None:
            output_handle.close()
        if metrics_server is not None:
            metrics_server.shutdown()
            metrics_server.server_close()
        if ingestion_server is not None:
            ingestion_server.shutdown()
            ingestion_server.server_close()
        if event_store is not None:
            event_store.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
