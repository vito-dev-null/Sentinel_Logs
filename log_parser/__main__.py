#!/usr/bin/env python3
"""Compatibility wrapper for the packaged log_parser module."""

from __future__ import annotations

from sentinellogs.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
