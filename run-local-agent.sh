#!/bin/sh
set -eu

if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ]; then
	printf '%s\n' "Impostare SENTINELLOGS_BASIC_AUTH prima di avviare il local agent." >&2
	exit 1
fi

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v python3 >/dev/null 2>&1; then
	printf '%s\n' "Python 3 non trovato. Installare python3 e riprovare." >&2
	exit 1
fi
if ! command -v pip3 >/dev/null 2>&1; then
	printf '%s\n' "pip3 non trovato. Installare python3-pip e riprovare." >&2
	exit 1
fi
if [ ! -x "$PROJECT_DIR/.venv/bin/python" ]; then
	python3 -m venv "$PROJECT_DIR/.venv"
fi
PYTHON="$PROJECT_DIR/.venv/bin/python"
"$PYTHON" -c 'from sentinellogs.bootstrap import ensure_local_secrets; ensure_local_secrets()'
set -a
. "$PROJECT_DIR/.sentinellogs/secrets.env"
set +a
if ! "$PYTHON" -c 'import requests, psutil' >/dev/null 2>&1; then
	"$PYTHON" -m pip install --disable-pip-version-check requests psutil
fi
if ! "$PYTHON" -c 'import sentinellogs' >/dev/null 2>&1; then
	"$PYTHON" -m pip install --disable-pip-version-check -e "$PROJECT_DIR"
fi
exec "$PYTHON" -c 'from sentinellogs.local_agent import LocalLogAgent; LocalLogAgent(["/var/log/auth.log", "/var/log/syslog"], from_start=True).run()'