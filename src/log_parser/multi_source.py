from __future__ import annotations

import glob
import logging
import queue
import threading
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .tailer import LogTailer

logger = logging.getLogger(__name__)


class QueueBackend:
    """Abstract backend for ingesting many log streams into a shared queue."""

    def put(self, item: str) -> None:
        raise NotImplementedError

    def get(self, block: bool = True, timeout: float | None = None) -> str:
        raise NotImplementedError


class InMemoryQueueBackend(QueueBackend):
    def __init__(self) -> None:
        self._queue: queue.Queue[str] = queue.Queue()

    def put(self, item: str) -> None:
        self._queue.put(item)

    def get(self, block: bool = True, timeout: float | None = None) -> str:
        return self._queue.get(block=block, timeout=timeout)


class MultiSourceTailer:
    def __init__(self, patterns: Sequence[str | Path], backend: QueueBackend | None = None) -> None:
        self.patterns = [str(p) for p in patterns]
        self.backend = backend or InMemoryQueueBackend()
        self._threads: list[threading.Thread] = []

    def expand_paths(self) -> list[Path]:
        expanded: list[Path] = []
        seen: set[Path] = set()
        for pattern in self.patterns:
            matches = glob.glob(pattern, recursive=True)
            if not matches:
                candidate = Path(pattern)
                if candidate.exists():
                    matches = [str(candidate)]
            for match in matches:
                path = Path(match)
                if path not in seen:
                    expanded.append(path)
                    seen.add(path)
        return expanded

    def start(self) -> None:
        paths = self.expand_paths()
        if not paths:
            logger.warning("No log files matched the requested patterns: %s", self.patterns)
            return
        for path in paths:
            thread = threading.Thread(target=self._read_stream, args=(path,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _read_stream(self, path: Path) -> None:
        tailer = LogTailer(path)
        for line in tailer:
            self.backend.put(line)

    def iter_lines(self) -> Iterator[str]:
        while True:
            yield self.backend.get(timeout=0.5)
