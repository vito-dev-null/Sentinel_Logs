from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Iterator, TextIO

logger = logging.getLogger(__name__)


class LogTailer:
    """Tail a log file while handling rotation, truncation, and temporary unavailability."""

    def __init__(self, file_path: str | Path, from_start: bool = False, poll_interval: float = 0.5) -> None:
        self.file_path = Path(file_path)
        self.from_start = from_start
        self.poll_interval = poll_interval
        self._handle: TextIO | None = None
        self._last_inode: int | None = None
        self._last_size = 0

    def _close_file(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    def _open_file(self, start_at_end: bool = True) -> None:
        self._close_file()
        if not self.file_path.exists():
            logger.info("Log file %s is temporarily unavailable; waiting for it to reappear.", self.file_path)
            self._handle = None
            self._last_inode = None
            self._last_size = 0
            return

        try:
            handle = self.file_path.open("r", encoding="utf-8", errors="replace", newline="")
        except FileNotFoundError:
            logger.info("Log file %s is temporarily unavailable; waiting for it to reappear.", self.file_path)
            self._handle = None
            self._last_inode = None
            self._last_size = 0
            return

        self._handle = handle
        self._last_size = 0
        try:
            stats = os.stat(self.file_path)
        except FileNotFoundError:
            self._last_inode = None
            return

        self._last_inode = getattr(stats, "st_ino", None)
        if start_at_end:
            handle.seek(0, 2)
        else:
            handle.seek(0)
        self._last_size = handle.tell()

    def _check_rotation_or_truncate(self) -> bool:
        if not self.file_path.exists():
            return False

        try:
            stats = os.stat(self.file_path)
        except FileNotFoundError:
            return False

        current_inode = getattr(stats, "st_ino", None)
        current_size = stats.st_size

        if self._last_inode is not None and current_inode is not None and current_inode != self._last_inode:
            logger.info(
                "Detected log rotation for %s: inode changed from %s to %s",
                self.file_path,
                self._last_inode,
                current_inode,
            )
            return True

        if current_size < self._last_size:
            logger.info("Detected log truncation for %s: size decreased from %s to %s", self.file_path, self._last_size, current_size)
            return True

        return False

    def _ensure_handle(self) -> None:
        if self._handle is None:
            self._open_file(start_at_end=not self.from_start)

    def __iter__(self) -> Iterator[str]:
        if self.from_start:
            if self.file_path.exists():
                with self.file_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                    for line in handle:
                        yield line

        self._open_file(start_at_end=not self.from_start)

        while True:
            self._ensure_handle()
            if self._handle is None:
                time.sleep(self.poll_interval)
                continue

            try:
                line = self._handle.readline()
            except OSError as exc:
                logger.warning("Error reading log file %s: %s", self.file_path, exc)
                time.sleep(self.poll_interval)
                continue

            if line:
                self._last_size = self._handle.tell()
                yield line
                continue

            if self._check_rotation_or_truncate():
                logger.info("Reopening rotated/truncated file %s from the beginning.", self.file_path)
                self._open_file(start_at_end=False)
                continue

            if not self.file_path.exists():
                logger.info("Log file %s temporarily unavailable; retrying.", self.file_path)
                time.sleep(self.poll_interval)
                continue

            time.sleep(self.poll_interval)
