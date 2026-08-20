from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Sequence, TextIO

from .metrics import MetricsRegistry, start_metrics_server
from .multi_source import MultiSourceTailer
from .parsers import DEFAULT_MAX_LINE_LENGTH, DEFAULT_PARSE_TIMEOUT_MS, ParserRegistry
from .sinks import AlertEngine, BaseSink, create_sink
from .tailer import LogTailer
from .schema import LogRecord

logger = logging.getLogger(__name__)


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
        try:
            return version("sentinellogs")
        except PackageNotFoundError:
            return "0.1.0"


def emit_record(record: object, output_handle: TextIO | None = None) -> None:
    payload = record.to_json() if hasattr(record, "to_json") else json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    print(payload, flush=True)
    if output_handle is not None:
        output_handle.write(payload + "\n")
        output_handle.flush()


def parse_existing_lines(
    file_path: Path,
    registry: ParserRegistry,
    output_handle: TextIO | None = None,
    sinks: list[BaseSink] | None = None,
    redaction_patterns: Sequence[str] | None = None,
    metrics_registry: MetricsRegistry | None = None,
    alert_engine: AlertEngine | None = None,
) -> None:
    with file_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        for line in handle:
            line = line.rstrip("\r\n")
            # If the line looks like JSON (already parsed output), re-emit it instead of reparsing
            record = None
            if line.lstrip().startswith("{"):
                try:
                    obj = json.loads(line)
                except Exception:
                    obj = None
                if isinstance(obj, dict) and "raw" in obj:
                    # Reconstruct a LogRecord from the JSON object when possible
                    record = LogRecord(
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
                    )
            # If not JSON or couldn't reconstruct, attempt to parse as raw log line
            if record is None:
                record = registry.parse_line(line)
            if record is None:
                if metrics_registry is not None:
                    metrics_registry.mark_dropped()
                continue
            if redaction_patterns:
                record = record.redact(redaction_patterns)

            # detect whether this record would trigger alerts
            is_alert = False
            matching_rules = []
            alert_sink_specs = []
            try:
                if alert_engine is not None:
                    matches = list(alert_engine.matching_sinks(record, create_sink))
                    is_alert = len(matches) > 0
                    matching_rules = alert_engine.matching_rules(record)
                    alert_sink_specs = alert_engine.matching_sink_specs(record)
            except Exception:
                is_alert = False

            if metrics_registry is not None:
                metrics_registry.mark_processed()
                # record into recent_lines buffer
                try:
                    metrics_registry.record_recent_line(record, is_alert=is_alert, matching_rules=matching_rules, alert_sinks=alert_sink_specs)
                except Exception:
                    pass

            for sink in sinks or []:
                try:
                    sink.emit(record)
                except Exception as exc:  # pragma: no cover - defensive path
                    logger.exception("Sink failed while processing backlog record: %s", exc)
                    if metrics_registry is not None:
                        metrics_registry.mark_sink_error()
            if not sinks:
                emit_record(record, output_handle)


def build_registry(config_path: Path | None = None, max_line_length: int = DEFAULT_MAX_LINE_LENGTH, parse_timeout_ms: int = DEFAULT_PARSE_TIMEOUT_MS) -> ParserRegistry:
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SentinelLogs - real-time log parser in tempo reale con output JSONL")
    parser.add_argument("--file", nargs="+", help="Path del file di log da monitorare, anche con wildcard")
    parser.add_argument("--confirm-demo", action="store_true", help="Conferma esplicita per usare file che sembrano demo/sample (se usato, l'app accetta file d'esempio)")
    parser.add_argument("--output", help="Path del file JSONL dove salvare l'output (opzionale)")
    parser.add_argument("--from-start", action="store_true", help="Processa anche le righe già presenti prima del tail live")
    parser.add_argument("--log-level", default="INFO", help="Livello di logging: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    parser.add_argument("--version", action="store_true", help="Mostra la versione del pacchetto e termina")
    parser.add_argument("--sink", action="append", default=[], help="Sink di output: stdout, file:/path/file.jsonl, webhook:https://..., syslog:host:port")
    parser.add_argument("--alert-config", help="Path del file di regole di alerting YAML")
    parser.add_argument("--metrics-port", type=int, default=None, help="Se specificato, avvia un endpoint HTTP /metrics e /health sulla porta indicata")
    parser.add_argument("--dashboard", action=argparse.BooleanOptionalAction, default=True, help="Abilita la dashboard HTML in /dashboard e la API JSON in /api/metrics.json quando i metrics sono attivi")
    parser.add_argument("--redact", nargs="+", default=None, help="Lista di pattern regex da usare per mascherare i campi sensibili del messaggio")
    parser.add_argument("--max-line-length", type=int, default=DEFAULT_MAX_LINE_LENGTH, help="Massima lunghezza in byte di una riga prima di essere scartata")
    parser.add_argument("--parse-timeout-ms", type=int, default=DEFAULT_PARSE_TIMEOUT_MS, help="Timeout massimo di parsing per riga in millisecondi")
    args = parser.parse_args(argv)

    if args.version:
        print(_get_package_version())
        return 0

    if not args.file:
        parser.error("Nessun file di log specificato. Usa --file <percorso> per indicare il file da monitorare")

    configure_logging(args.log_level)

    metrics_registry = MetricsRegistry()
    metrics_server = None
    # record the configured sources (files/globs) so the dashboard can display them
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
        registry = build_registry(max_line_length=args.max_line_length, parse_timeout_ms=args.parse_timeout_ms)
        alert_engine = build_alert_engine(Path(args.alert_config) if args.alert_config else None)

        # If a single literal path is passed, validate it and guard against accidental demo files
        if len(args.file) == 1 and all(ch not in args.file[0] for ch in "*?[" ):
            file_path = Path(args.file[0])
            if not file_path.exists():
                logger.error("File not found: %s", file_path)
                return 1

            # guard: prevent accidentally using repository example/demo files as production data
            demo_indicators = ("sample", "demo", "parsed_preview", "live_output", "output.jsonl")
            is_demo_name = any(tok in file_path.name.lower() for tok in demo_indicators)
            is_examples_dir = any(part.lower() in ("examples", "fixtures", "demo") for part in file_path.parts)
            if (is_demo_name or is_examples_dir) and not args.confirm_demo:
                logger.error("Il file indicato (%s) sembra essere un file di test/demo. Se intendi usarlo esplicitamente, ripeti con --confirm-demo.", file_path)
                return 2
            if args.from_start:
                parse_existing_lines(file_path, registry, output_handle, sinks=sinks, redaction_patterns=args.redact, metrics_registry=metrics_registry, alert_engine=alert_engine)
            tailer = LogTailer(file_path)
            for line in tailer:
                record = registry.parse_line(line)
                if record is None:
                    metrics_registry.mark_dropped()
                    continue
                if args.redact:
                    record = record.redact(args.redact)

                # detect alerts for this record before emitting so we can annotate recent_lines
                is_alert = False
                try:
                    matches = list(alert_engine.matching_sinks(record, create_sink)) if alert_engine is not None else []
                    is_alert = len(matches) > 0
                except Exception:
                    is_alert = False

                metrics_registry.mark_processed()
                try:
                    metrics_registry.record_recent_line(record, is_alert=is_alert)
                except Exception:
                    pass

                for sink in sinks:
                    start = time.perf_counter()
                    try:
                        sink.emit(record)
                    except Exception as exc:  # pragma: no cover - defensive path
                        logger.exception("Sink failed while emitting record: %s", exc)
                        metrics_registry.mark_sink_error()
                    finally:
                        metrics_registry.observe_sink_latency((time.perf_counter() - start) * 1000)
                for alert_sink in (matches if 'matches' in locals() else alert_engine.matching_sinks(record, create_sink)):
                    try:
                        alert_sink.emit(record)
                    except Exception as exc:  # pragma: no cover - defensive path
                        logger.exception("Alert sink failed while emitting record: %s", exc)
                        metrics_registry.mark_sink_error()
                if not sinks:
                    emit_record(record, output_handle)
        else:
            collector = MultiSourceTailer(args.file)
            collector.start()
            for line in collector.iter_lines():
                record = registry.parse_line(line)
                if record is None:
                    metrics_registry.mark_dropped()
                    continue
                if args.redact:
                    record = record.redact(args.redact)

                # detect alerts for this record before emitting so we can annotate recent_lines
                is_alert = False
                try:
                    matches = list(alert_engine.matching_sinks(record, create_sink)) if alert_engine is not None else []
                    is_alert = len(matches) > 0
                except Exception:
                    is_alert = False

                metrics_registry.mark_processed()
                try:
                    metrics_registry.record_recent_line(record, is_alert=is_alert)
                except Exception:
                    pass

                for sink in sinks:
                    start = time.perf_counter()
                    try:
                        sink.emit(record)
                    except Exception as exc:  # pragma: no cover - defensive path
                        logger.exception("Sink failed while emitting record: %s", exc)
                        metrics_registry.mark_sink_error()
                    finally:
                        metrics_registry.observe_sink_latency((time.perf_counter() - start) * 1000)
                for alert_sink in (matches if 'matches' in locals() else alert_engine.matching_sinks(record, create_sink)):
                    try:
                        alert_sink.emit(record)
                    except Exception as exc:  # pragma: no cover - defensive path
                        logger.exception("Alert sink failed while emitting record: %s", exc)
                        metrics_registry.mark_sink_error()
                if not sinks:
                    emit_record(record, output_handle)

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
                pass
        if output_handle is not None:
            output_handle.close()
        if metrics_server is not None:
            metrics_server.shutdown()
            metrics_server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
