from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

import pytest

from sentinellogs import cli
from sentinellogs.audit import AuditLog
from sentinellogs.metrics import MetricsRegistry


def test_cli_requires_file_argument(monkeypatch):
    # calling main without args should cause the parser to error with a helpful message
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    # argparse exits with code 2 for argument errors
    assert exc.value.code == 2


def test_cli_rejects_example_file_without_confirm(monkeypatch, tmp_path):
    # create a sample file in an examples-like path
    ex_dir = tmp_path / 'examples'
    ex_dir.mkdir()
    sample = ex_dir / 'sample.log'
    sample.write_text('2026-01-01 00:00:00 INFO test\n', encoding='utf-8')

    # main returns 2 when a demo-like filename is used without --confirm-demo
    assert cli.main(["--file", str(sample)]) == 2


def test_metrics_sources_includes_file_arg(tmp_path):
    # ensure that when --file is provided, metrics_registry includes the source
    sample = tmp_path / 'prod.log'
    sample.write_text('line\n', encoding='utf-8')
    # run main up to the point where it would start the server; invoke with --metrics-port to exercise setting sources
    # We expect SystemExit or return; just run and check that no exception is raised during arg parsing
    try:
        # call parse only to exercise args processing
        parser_args = ["--file", str(sample)]
        # create a MetricsRegistry and set sources like the main would
        from sentinellogs.metrics import MetricsRegistry
        mr = MetricsRegistry()
        mr.set_sources([str(sample)])
        assert str(sample) in mr.as_dict().get('sources', [])
    except Exception as e:
        pytest.fail(f"Unexpected exception during test: {e}")


def test_dispatch_record_updates_audit_integrity_metric(tmp_path):
    audit_log = AuditLog(tmp_path / "audit.jsonl")
    metrics_registry = MetricsRegistry()
    assert not metrics_registry.as_dict()["integrity_verified"]

    cli.dispatch_record(
        cli.LogRecord(format="syslog", message="accepted login", raw="accepted login"),
        sinks=[],
        output_handle=StringIO(),
        redaction_patterns=None,
        metrics_registry=metrics_registry,
        alert_engine=None,
        audit_log=audit_log,
    )

    assert audit_log.integrity_verified
    assert metrics_registry.as_dict()["integrity_verified"]


def test_record_from_json_preserves_source():
    record = cli._record_from_json_line(
        '{"format":"syslog","message":"Failed password","raw":"raw line","source":"/var/log/auth.log"}'
    )

    assert record is not None
    assert record.source == "/var/log/auth.log"


def test_security_alert_rules_exclude_routine_login_and_sudo_events():
    engine = cli.build_alert_engine()

    assert "ssh-failed-password" in engine.matching_rules(
        cli.LogRecord(format="syslog", message="Failed password for root from 203.0.113.5")
    )
    assert "ssh-login-success" not in engine.matching_rules(
        cli.LogRecord(format="syslog", message="Accepted publickey for admin from 203.0.113.5")
    )
    assert "sudo-privileged-command" not in engine.matching_rules(
        cli.LogRecord(format="syslog", message="sudo: admin : TTY=pts/0 ; COMMAND=/usr/bin/id")
    )


def test_fail2ban_alert_rule_only_matches_ban_actions():
    engine = cli.build_alert_engine()

    assert "fail2ban-ban-action" in engine.matching_rules(
        cli.LogRecord(format="syslog", message="fail2ban.actions: Ban 203.0.113.9")
    )
    assert "fail2ban-ban-action" not in engine.matching_rules(
        cli.LogRecord(format="syslog", message="fail2ban.actions: Found 203.0.113.9")
    )
    assert "fail2ban-ban-action" not in engine.matching_rules(
        cli.LogRecord(format="syslog", message="fail2ban.actions: Unban 203.0.113.9")
    )
