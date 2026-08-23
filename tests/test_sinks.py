from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinellogs.schema import LogRecord
from sentinellogs.sinks import AlertEngine, AlertRule, FileSink, StdoutSink, SyslogSink, WebhookSink, create_sink


def test_stdout_sink_emits_json() -> None:
    record = LogRecord(format='app', level='ERROR', message='service down', parsed_at='2026-01-01T00:00:00Z')
    with patch('builtins.print') as mock_print:
        StdoutSink().emit(record)
    mock_print.assert_called_once()
    payload = mock_print.call_args.args[0]
    assert '"message":"service down"' in payload


def test_file_sink_writes_json(tmp_path: Path) -> None:
    path = tmp_path / 'out.jsonl'
    sink = FileSink(path)
    record = LogRecord(format='app', level='INFO', message='started', parsed_at='2026-01-01T00:00:00Z')
    sink.emit(record)
    sink.close()
    contents = path.read_text(encoding='utf-8')
    assert '"message":"started"' in contents


def test_webhook_sink_retries_and_posts() -> None:
    record = LogRecord(format='syslog', message='Failed password', level='ERROR', parsed_at='2026-01-01T00:00:00Z')
    fake_response = MagicMock()
    fake_response.__enter__.return_value = fake_response
    fake_response.read.return_value = b'ok'

    with patch('sentinellogs.sinks.urlopen', side_effect=[OSError('temporary fail'), fake_response]) as mock_urlopen:
        sink = WebhookSink('https://example.com/hook', max_retries=2, backoff_seconds=0)
        sink.emit(record)

    assert mock_urlopen.call_count == 2


def test_syslog_sink_triggers_handler() -> None:
    record = LogRecord(format='app', level='ERROR', message='disk full', parsed_at='2026-01-01T00:00:00Z')
    fake_logger = MagicMock()
    fake_logger.handlers = []
    fake_logger.propagate = False
    fake_handler = MagicMock()
    fake_handler.level = logging.INFO

    with patch('sentinellogs.sinks.logging.getLogger', return_value=fake_logger), patch('sentinellogs.sinks.SysLogHandler', return_value=fake_handler) as mock_syslog:
        sink = SyslogSink('localhost', 514)
        sink.emit(record)

    assert mock_syslog.called
    fake_logger.info.assert_called_once()


def test_alert_engine_matches_rule() -> None:
    record = LogRecord(format='syslog', message='Failed password for root', level='ERROR', parsed_at='2026-01-01T00:00:00Z')
    rule = AlertRule(name='ssh-fail', field='message', regex='Failed password', sinks=['stdout'])
    engine = AlertEngine([rule])
    sinks = engine.matching_sinks(record, create_sink)
    assert len(sinks) == 1
    assert isinstance(sinks[0], StdoutSink)


def test_create_sink_from_file_spec() -> None:
    sink = create_sink('file:/tmp/example.jsonl')
    assert sink.__class__.__name__ == 'FileSink'


def test_sentinellogs_sink_retries_and_posts() -> None:
    record = LogRecord(format='syslog', message='Failed password', level='ERROR', parsed_at='2026-01-01T00:00:00Z')
    fake_response = MagicMock()
    fake_response.__enter__.return_value = fake_response
    fake_response.read.return_value = b'ok'

    with patch('sentinellogs.sinks.urlopen', side_effect=[OSError('temporary fail'), fake_response]) as mock_urlopen:
        sink = create_sink('sentinellogs:https://sentinel.example.com/ingest')
        sink.emit(record)

    assert mock_urlopen.call_count == 2


def test_sentinellogs_sink_accepts_apikey_colon_syntax(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_KEY_NAME", "secret-token")
    sink = create_sink("sentinellogs:https://sentinel.example.com/ingest|apikey:${SENTINEL_KEY_NAME}")
    assert sink.api_key == "secret-token"
    assert sink.endpoint == "https://sentinel.example.com/ingest"
