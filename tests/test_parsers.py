from __future__ import annotations

from pathlib import Path

import pytest

from sentinellogs.parsers import AppLogParser, ParserRegistry, SyslogParser, normalize_timestamp_to_iso


@pytest.fixture
def parser_specs() -> dict[str, str]:
    config = ParserRegistry.from_config(Path(__file__).resolve().parents[1] / 'src' / 'sentinellogs' / 'patterns.yaml')
    return {
        'syslog': config.parsers[0].pattern.pattern,
        'app': config.parsers[1].pattern.pattern,
    }


def test_syslog_parser_valid_record(parser_specs: dict[str, str]) -> None:
    parser = SyslogParser('syslog', parser_specs['syslog'], ['timestamp', 'host', 'process', 'pid', 'message'])
    line = 'Jan  5 10:22:31 host sshd[1234]: Failed password for root from 1.2.3.4 port 22'
    record = parser.parse(line)

    assert record is not None
    assert record.format == 'syslog'
    assert record.timestamp == normalize_timestamp_to_iso('Jan  5 10:22:31')
    assert record.host == 'host'
    assert record.process == 'sshd'
    assert record.pid == '1234'
    assert record.message == 'Failed password for root from 1.2.3.4 port 22'
    assert record.ips == ['1.2.3.4']


def test_app_parser_valid_record(parser_specs: dict[str, str]) -> None:
    parser = AppLogParser('app', parser_specs['app'], ['timestamp', 'level', 'message'])
    line = '2026-08-20 10:22:31 [ERROR] Connection refused from 10.0.0.5'
    record = parser.parse(line)

    assert record is not None
    assert record.format == 'app'
    assert record.timestamp == normalize_timestamp_to_iso('2026-08-20 10:22:31')
    assert record.level == 'ERROR'
    assert record.message == 'Connection refused from 10.0.0.5'
    assert record.ips == ['10.0.0.5']


def test_plain_app_parser_valid_record() -> None:
    parser = AppLogParser(
        'app_plain',
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<level>[A-Z]+)\s+(?P<process>\S+)\s+(?P<message>.*)$',
        ['timestamp', 'level', 'process', 'message'],
    )
    line = '2026-08-20 07:00:00 INFO myapp Started processing id=123 user=alice'
    record = parser.parse(line)

    assert record is not None
    assert record.format == 'app_plain'
    assert record.timestamp == normalize_timestamp_to_iso('2026-08-20 07:00:00')
    assert record.level == 'INFO'
    assert record.process == 'myapp'
    assert record.message == 'Started processing id=123 user=alice'


def test_invalid_line_returns_none(parser_specs: dict[str, str]) -> None:
    parser = SyslogParser('syslog', parser_specs['syslog'], ['timestamp', 'host', 'process', 'pid', 'message'])
    assert parser.parse('nota un log valido') is None

    app_parser = AppLogParser('app', parser_specs['app'], ['timestamp', 'level', 'message'])
    assert app_parser.parse('questa riga non combacia') is None


def test_ip_extraction_absent() -> None:
    parser = AppLogParser(
        'app',
        r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>[A-Za-z]+)\]\s+(?P<message>.*)$',
        ['timestamp', 'level', 'message'],
    )
    record = parser.parse('2026-08-20 10:22:31 [INFO] service started successfully')

    assert record is not None
    assert record.ips == []


def test_registry_selects_correct_parser() -> None:
    registry = ParserRegistry.from_config(Path(__file__).resolve().parents[1] / 'src' / 'sentinellogs' / 'patterns.yaml')

    syslog_record = registry.parse_line('Jan  5 10:22:31 host sshd[1234]: Failed password for root from 1.2.3.4 port 22')
    app_record = registry.parse_line('2026-08-20 10:22:31 [ERROR] Connection refused from 10.0.0.5')
    unknown_record = registry.parse_line('riga senza pattern riconoscibile')

    assert syslog_record.format == 'syslog'
    assert app_record.format == 'app'
    assert unknown_record.format == 'unknown'
    assert unknown_record.raw == 'riga senza pattern riconoscibile'


def test_registry_parses_iso_syslog_line() -> None:
    registry = ParserRegistry.from_config(Path(__file__).resolve().parents[1] / 'src' / 'sentinellogs' / 'patterns.yaml')

    record = registry.parse_line(
        '2026-08-21T22:55:21.705320+02:00 PC vsce-sign: SignatureIntegrityPolicy for primary package'
    )

    assert record is not None
    assert record.format == 'syslog_iso'
    assert record.host == 'PC'
    assert record.process == 'vsce-sign'
    assert record.message == 'SignatureIntegrityPolicy for primary package'


def test_registry_ignores_configured_noisy_processes() -> None:
    registry = ParserRegistry.from_config(Path(__file__).resolve().parents[1] / 'src' / 'sentinellogs' / 'patterns.yaml')

    noisy = registry.parse_line('Aug 22 10:22:31 host chrome[1234]: routine browser event')
    security_event = registry.parse_line('Aug 22 10:22:31 host sshd[1235]: Failed password for root from 203.0.113.5 port 22')

    assert noisy is None
    assert security_event is not None
    assert security_event.process == 'sshd'
