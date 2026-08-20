from __future__ import annotations

import json
import urllib.request

from log_parser.metrics import MetricsRegistry, start_metrics_server


def test_metrics_registry_tracks_data() -> None:
    registry = MetricsRegistry()
    registry.mark_processed(3)
    registry.mark_dropped(2)
    registry.mark_parser_error(1)
    registry.mark_sink_error(1)
    registry.observe_sink_latency(42.0)

    prom = registry.render_prometheus()
    assert 'log_parser_processed_lines_total 3' in prom
    assert 'log_parser_dropped_lines_total 2' in prom
    assert 'log_parser_parser_errors_total 1' in prom
    assert 'log_parser_sink_errors_total 1' in prom
    assert 'log_parser_sink_latency_ms 42.0' in prom

    health = registry.health_json()
    assert health['processed_lines'] == 3
    assert health['dropped_lines'] == 2


def test_dashboard_and_metrics_api() -> None:
    registry = MetricsRegistry()
    registry.mark_processed(5)
    registry.mark_dropped(2)
    registry.record_alert('auth.log', 'Failed password for root', 'warning')
    server = start_metrics_server(registry, 0, enable_dashboard=True)
    port = server.server_address[1]

    try:
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/dashboard', timeout=5) as response:
            body = response.read().decode('utf-8')
            assert response.status == 200
            assert 'log-parser monitoring' in body

        with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/metrics.json', timeout=5) as response:
            payload = json.loads(response.read().decode('utf-8'))
            assert response.status == 200
            assert payload['processed_lines'] == 5
            assert payload['dropped_lines'] == 2
            assert payload['alerts_generated'] >= 1
            assert isinstance(payload['history'], list)
            assert isinstance(payload['alerts'], list)
            assert payload['alerts'][0]['message'] == 'Failed password for root'
            # recent_lines endpoint / field should be present (may be empty)
            assert 'recent_lines' in payload
    finally:
        server.shutdown()
        server.server_close()


def test_history_buffer_updates_after_events() -> None:
    registry = MetricsRegistry(history_size=10, alert_size=5)
    registry.mark_processed(1)
    registry.mark_processed(2)
    payload = registry.as_dict()
    assert len(payload['history']) >= 2
    assert payload['history'][-1]['processed_lines'] == 3
    registry.record_alert('syslog', 'Permission denied', 'error')
    assert payload['alerts_generated'] == 0
    refreshed = registry.as_dict()
    assert refreshed['alerts_generated'] == 1
    assert refreshed['alerts'][0]['source'] == 'syslog'


def test_recent_lines_buffer() -> None:
    registry = MetricsRegistry(history_size=5, alert_size=5, recent_size=3)
    # simulate three processed records
    registry.record_recent_line({'format': 'app', 'timestamp': '2026-01-01T00:00:00', 'process': 'p1', 'message': 'one', 'raw_line': 'one'}, is_alert=False)
    registry.record_recent_line({'format': 'app', 'timestamp': '2026-01-01T00:00:01', 'process': 'p2', 'message': 'two', 'raw_line': 'two'}, is_alert=True)
    registry.record_recent_line({'format': 'syslog', 'timestamp': '2026-01-01T00:00:02', 'process': 'p3', 'message': 'three', 'raw_line': 'three'}, is_alert=False)
    payload = registry.as_dict()
    assert 'recent_lines' in payload
    assert len(payload['recent_lines']) == 3
    # add one more, verify truncation to recent_size
    registry.record_recent_line({'format': 'app', 'timestamp': '2026-01-01T00:00:03', 'process': 'p4', 'message': 'four', 'raw_line': 'four'}, is_alert=True)
    payload2 = registry.as_dict()
    assert len(payload2['recent_lines']) == 3
    # most recent entry should be the last one recorded
    assert payload2['recent_lines'][-1]['process'] == 'p4'
    # check is_alert preserved
    assert any(e['is_alert'] for e in payload2['recent_lines'])


def test_parsers_measure_duration_and_raw_line() -> None:
    # ensure ParserRegistry returns parse_duration_ms, matched_parser and raw_line on parsed records
    from log_parser.parsers import ParserRegistry
    from pathlib import Path
    reg = ParserRegistry.from_config(Path('src/log_parser/patterns.yaml'))
    line = '2026-08-20 07:00:00 INFO myapp Started processing id=123 user=alice'
    rec = reg.parse_line(line)
    assert rec is not None
    assert hasattr(rec, 'parse_duration_ms')
    assert getattr(rec, 'parse_duration_ms') is not None
    assert getattr(rec, 'matched_parser') in ('app_plain', 'app', 'app_iso', 'syslog')
    assert getattr(rec, 'raw_line') == line
    # malformed line should return unknown with matched_parser == 'unknown'
    line2 = 'not a valid log line'
    rec2 = reg.parse_line(line2)
    assert rec2 is not None
    assert getattr(rec2, 'matched_parser') == 'unknown'
    assert getattr(rec2, 'raw_line') == line2
