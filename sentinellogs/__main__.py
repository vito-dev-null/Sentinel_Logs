"""Compatibility wrapper to run sentinellogs in-place during development."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
