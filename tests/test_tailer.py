from __future__ import annotations

import threading
import time
from pathlib import Path

from log_parser.tailer import LogTailer


def test_tailer_reads_incremental_lines(log_file: Path) -> None:
    result: list[str] = []
    tailer = LogTailer(log_file)
    iterator = iter(tailer)

    def worker() -> None:
        for _ in range(2):
            result.append(next(iterator))

    thread = threading.Thread(target=worker)
    thread.start()
    time.sleep(0.2)
    with log_file.open('a', encoding='utf-8') as handle:
        handle.write('alpha\n')
        handle.flush()
    time.sleep(0.2)
    with log_file.open('a', encoding='utf-8') as handle:
        handle.write('beta\n')
        handle.flush()
    thread.join(timeout=5)

    assert result == ['alpha\n', 'beta\n']


def test_tailer_detects_rotation(log_file: Path) -> None:
    result: list[str] = []
    tailer = LogTailer(log_file)
    iterator = iter(tailer)

    def worker() -> None:
        for _ in range(2):
            result.append(next(iterator))

    thread = threading.Thread(target=worker)
    thread.start()
    time.sleep(0.2)

    rotated_path = log_file.with_suffix('.rotated')
    log_file.rename(rotated_path)
    new_file = log_file
    new_file.write_text('new-one\n', encoding='utf-8')

    time.sleep(0.3)
    with new_file.open('a', encoding='utf-8') as handle:
        handle.write('new-two\n')
        handle.flush()

    thread.join(timeout=5)
    assert result == ['new-one\n', 'new-two\n']

    if rotated_path.exists():
        rotated_path.unlink()


def test_tailer_detects_truncation(log_file: Path) -> None:
    log_file.write_text('before\nsecond\n', encoding='utf-8')
    result: list[str] = []
    tailer = LogTailer(log_file)
    iterator = iter(tailer)

    def worker() -> None:
        result.append(next(iterator))

    thread = threading.Thread(target=worker)
    thread.start()
    time.sleep(0.2)
    log_file.write_text('fresh\n', encoding='utf-8')
    time.sleep(0.3)
    thread.join(timeout=5)

    assert result == ['fresh\n']
