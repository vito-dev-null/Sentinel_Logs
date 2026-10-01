from __future__ import annotations

import json
import urllib.request
from urllib.error import HTTPError

from sentinellogs.metrics import MetricsRegistry, start_metrics_server


def test_metrics_registry_tracks_data() -> None:
    registry = MetricsRegistry()
    registry.mark_processed(3)
    registry.mark_dropped(2)
    registry.mark_parser_error(1)
    registry.mark_sink_error(1)
    registry.observe_sink_latency(42.0)

    prom = registry.render_prometheus()
    assert 'sentinellogs_processed_lines_total 3' in prom
    assert 'sentinellogs_dropped_lines_total 2' in prom
    assert 'sentinellogs_parser_errors_total 1' in prom
    assert 'sentinellogs_sink_errors_total 1' in prom
    assert 'sentinellogs_sink_latency_ms 42.0' in prom

    health = registry.health_json()
    assert health['processed_lines'] == 3
    assert health['dropped_lines'] == 2


def test_metrics_server_requires_authentication(monkeypatch) -> None:
    for name in (
        "SENTINELLOGS_BASIC_AUTH",
    ):
        monkeypatch.delenv(name, raising=False)

    try:
        start_metrics_server(MetricsRegistry(), 0)
    except RuntimeError as error:
        assert "SENTINELLOGS_BASIC_AUTH" in str(error)
    else:
        raise AssertionError("metrics server started without credentials")


def test_metrics_server_rejects_weak_password(monkeypatch) -> None:
    monkeypatch.setenv("SENTINELLOGS_BASIC_AUTH", "test-user:short")

    try:
        start_metrics_server(MetricsRegistry(), 0)
    except RuntimeError as error:
        assert "at least 24 characters" in str(error)
    else:
        raise AssertionError("metrics server started with a weak password")


def test_dashboard_and_metrics_api(monkeypatch) -> None:
    monkeypatch.setenv("SENTINELLOGS_BASIC_AUTH", "test-user:a-strong-test-password-1234")
    registry = MetricsRegistry()
    registry.mark_processed(5)
    registry.mark_dropped(2)
    registry.record_alert('auth.log', 'Failed password for root', 'warning')
    server = start_metrics_server(registry, 0, enable_dashboard=True)
    port = server.server_address[1]
    password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    password_manager.add_password(None, f"http://127.0.0.1:{port}/", "test-user", "a-strong-test-password-1234")
    opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(password_manager))

    try:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/dashboard', timeout=5)
        except HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError("anonymous dashboard request was accepted")

        for path in ("/metrics", "/api/metrics.json", "/api/recent-lines.json", "/api/events", "/health", "/healthz"):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)
            except HTTPError as error:
                assert error.code == 401
            else:
                raise AssertionError(f"anonymous request was accepted for {path}")

        with opener.open(f'http://127.0.0.1:{port}/dashboard', timeout=5) as response:
            body = response.read().decode('utf-8')
            assert response.status == 200
            assert 'SentinelLogs monitoring' in body

        registry.set_tailer_active(False)
        try:
            opener.open(f'http://127.0.0.1:{port}/healthz', timeout=5)
        except HTTPError as error:
            assert error.code == 503

        received = []
        server.ingest_callback = lambda payload, agent_id: received.append((payload, agent_id)) or 1
        request = urllib.request.Request(
            f'http://127.0.0.1:{port}/v1/ingest',
            data=json.dumps({'events': []}).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'X-Sentinel-Agent': 'local-test'},
            method='POST',
        )
        with opener.open(request, timeout=5) as response:
            assert response.status == 202
        assert received[0][1] == 'local-test'

        with opener.open(f'http://127.0.0.1:{port}/api/metrics.json', timeout=5) as response:
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
            assert 'dependencies' in payload
            assert isinstance(payload['compliance'], dict)

        with opener.open(f'http://127.0.0.1:{port}/api/events', timeout=5) as response:
            stream = response.read().decode('utf-8')
            assert response.headers['Content-Type'].startswith('text/event-stream')
            assert 'event: snapshot' in stream

        registry.set_tailer_active(True)
        with opener.open(f'http://127.0.0.1:{port}/healthz', timeout=5) as response:
            assert response.status == 200
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
    registry.record_recent_line({'format': 'app', 'timestamp': '2026-01-01T00:00:00', 'process': 'p1', 'message': 'one', 'raw_line': 'one', 'source': '/var/log/app.log'}, is_alert=False)
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
    assert payload['recent_lines'][0]['source'] == '/var/log/app.log'
    # check is_alert preserved
    assert any(e['is_alert'] for e in payload2['recent_lines'])


def test_recent_line_exposes_identity_fallbacks() -> None:
    registry = MetricsRegistry()
    registry.record_recent_line({
        'format': 'syslog',
        'message': 'session opened for user root by test-user',
        'source.ip': '203.0.113.5',
        'user.name': 'test-user',
        'host.hostname': 'test-host',
    })
    entry = registry.as_dict()['recent_lines'][0]
    assert entry['source.ip'] == '203.0.113.5'
    assert entry['user.name'] == 'test-user'
    assert entry['host.hostname'] == 'test-host'


def test_parsers_measure_duration_and_raw_line() -> None:
    # ensure ParserRegistry returns parse_duration_ms, matched_parser and raw_line on parsed records
    from sentinellogs.parsers import ParserRegistry
    from pathlib import Path
    reg = ParserRegistry.from_config(Path('src/sentinellogs/patterns.yaml'))
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
