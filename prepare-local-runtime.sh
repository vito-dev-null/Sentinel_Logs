#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON="$PROJECT_DIR/.venv/bin/python"

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "Python 3 non trovato. Installare Python 3 e riprovare." >&2
    exit 1
fi

if [ ! -x "$PYTHON" ]; then
    python3 -m venv "$PROJECT_DIR/.venv"
fi

if ! "$PYTHON" -c 'import sentinellogs' >/dev/null 2>&1; then
    "$PYTHON" -m pip install --disable-pip-version-check -e "$PROJECT_DIR"
fi

cd "$PROJECT_DIR"
"$PYTHON" -c 'from sentinellogs.bootstrap import ensure_local_secrets; ensure_local_secrets()'
