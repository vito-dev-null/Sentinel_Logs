"""Compatibility package that exposes the src/log_parser implementation."""

from __future__ import annotations

from pathlib import Path

_repo_root = Path(__file__).resolve().parent.parent
_src_pkg = _repo_root / "src" / "log_parser"
if str(_src_pkg) not in __path__:
    __path__.append(str(_src_pkg))

from .cli import main  # noqa: F401

__all__ = [
    "main",
]
