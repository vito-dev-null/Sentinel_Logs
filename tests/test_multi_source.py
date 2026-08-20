from __future__ import annotations

import time
from pathlib import Path
from queue import Empty

from sentinellogs.multi_source import InMemoryQueueBackend, MultiSourceTailer


def test_multi_source_collector_reads_multiple_files(tmp_path: Path) -> None:
    first = tmp_path / 'one.log'
    second = tmp_path / 'two.log'
    first.write_text('', encoding='utf-8')
    second.write_text('', encoding='utf-8')

    backend = InMemoryQueueBackend()
    collector = MultiSourceTailer([first, second], backend=backend)
    collector.start()

    time.sleep(0.3)
    with first.open('a', encoding='utf-8') as fh:
        fh.write('first\n')
    with second.open('a', encoding='utf-8') as fh:
        fh.write('second\n')

    seen: list[str] = []
    deadline = time.time() + 5.0
    while time.time() < deadline and len(seen) < 2:
        try:
            seen.append(backend.get(timeout=0.25))
        except Empty:
            continue

    assert 'first\n' in seen
    assert 'second\n' in seen
