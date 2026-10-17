#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$PROJECT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
	printf '%s\n' "Python 3 non trovato. Installare python3 e riprovare." >&2
	exit 1
fi

"$PROJECT_DIR/prepare-local-runtime.sh"
PYTHON="$PROJECT_DIR/.venv/bin/python"
if ! "$PYTHON" -c 'import psutil' >/dev/null 2>&1; then
	"$PYTHON" -m pip install --disable-pip-version-check psutil
fi
set -a
. "$PROJECT_DIR/.sentinellogs/secrets.env"
set +a
if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ]; then
	printf '%s\n' "Credenziali locali non disponibili in .sentinellogs/secrets.env." >&2
	exit 1
fi
exec "$PYTHON" -c 'from sentinellogs.local_agent import LocalLogAgent; LocalLogAgent(["/var/log/auth.log", "/var/log/syslog"], from_start=True).run()'