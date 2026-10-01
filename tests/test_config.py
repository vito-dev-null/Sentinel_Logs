from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinellogs.parsers import load_pattern_config


def test_load_yaml_config(tmp_path: Path) -> None:
    config_path = tmp_path / 'patterns.yaml'
    config_path.write_text(
        "syslog:\n  pattern: '^(?P<timestamp>.*)$'\n  fields: [timestamp]\n",
        encoding='utf-8',
    )

    payload = load_pattern_config(config_path)
    assert payload['syslog']['pattern'] == '^(?P<timestamp>.*)$'


def test_load_json_config(tmp_path: Path) -> None:
    config_path = tmp_path / 'patterns.json'
    config_path.write_text(
        json.dumps({'app': {'pattern': '^(?P<message>.*)$', 'fields': ['message']}}),
        encoding='utf-8',
    )

    payload = load_pattern_config(config_path)
    assert payload['app']['fields'] == ['message']


def test_missing_config_file_raises_clear_error(tmp_path: Path) -> None:
    missing = tmp_path / 'missing.yaml'

    with pytest.raises(FileNotFoundError, match='Configuration file not found'):
        load_pattern_config(missing)


def test_malformed_yaml_raises_value_error(tmp_path: Path) -> None:
    config_path = tmp_path / 'broken.yaml'
    config_path.write_text('syslog: [broken\n', encoding='utf-8')

    with pytest.raises(ValueError, match='Malformed YAML configuration'):
        load_pattern_config(config_path)


def test_malformed_json_raises_value_error(tmp_path: Path) -> None:
    config_path = tmp_path / 'broken.json'
    config_path.write_text('{not valid json}', encoding='utf-8')

    with pytest.raises(ValueError, match='Malformed JSON configuration'):
        load_pattern_config(config_path)


def test_local_secret_bootstrap_is_offline_and_idempotent(tmp_path: Path, monkeypatch) -> None:
    from sentinellogs.bootstrap import ensure_local_secrets

    monkeypatch.setenv("SENTINELLOGS_CONFIG_DIR", str(tmp_path / ".sentinellogs"))
    monkeypatch.delenv("SENTINELLOGS_BASIC_AUTH", raising=False)
    monkeypatch.delenv("SENTINELLOGS_TENANT_TOKENS", raising=False)

    secret_path = ensure_local_secrets()
    first = secret_path.read_text(encoding="utf-8")
    assert secret_path.stat().st_mode & 0o777 == 0o600
    assert "SENTINELLOGS_BASIC_AUTH=sentinellogs:" in first
    assert "SENTINELLOGS_TENANT_TOKENS=local:" in first

    secret_path.unlink()
    ensure_local_secrets()
    second = secret_path.read_text(encoding="utf-8")
    assert first != second
