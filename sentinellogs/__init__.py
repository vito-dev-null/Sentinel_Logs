"""Compatibility package that exposes the src/sentinellogs implementation for local development."""

from __future__ import annotations

from pathlib import Path

_repo_root = Path(__file__).resolve().parent
_src_pkg = _repo_root.parent / "src" / "sentinellogs"
if str(_src_pkg) not in __path__:
    __path__.append(str(_src_pkg))

from .cli import main  # noqa: F401

__all__ = [
    "main",
]
