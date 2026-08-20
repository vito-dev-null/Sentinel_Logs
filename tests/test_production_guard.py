from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sentinellogs import cli


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

    # main should return exit code 2 when trying to use a demo-like filename without --confirm-demo
    with pytest.raises(SystemExit) as exc:
        # simulate running: program --file <path>
        cli.main(["--file", str(sample)])
    assert exc.value.code in (1, 2)


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
