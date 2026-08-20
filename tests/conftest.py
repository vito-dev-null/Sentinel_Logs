from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    path = tmp_path / 'test.log'
    path.write_text('', encoding='utf-8')
    return path
