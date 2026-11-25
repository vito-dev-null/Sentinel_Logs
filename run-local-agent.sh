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
if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ] && [ -z "${SENTINELLOGS_INGEST_TOKEN:-}" ]; then
	printf '%s\n' "Configure Basic Auth or a Bearer token in the agent environment." >&2
	exit 1
fi
exec "$PYTHON" -c 'import os; from sentinellogs.local_agent import LocalLogAgent; LocalLogAgent(["/var/log/auth.log", "/var/log/syslog"], endpoint=os.environ.get("SENTINELLOGS_AGENT_ENDPOINT", "http://localhost:9090"), agent_id=os.environ.get("SENTINELLOGS_AGENT_ID", "local-agent"), from_start=os.environ.get("SENTINELLOGS_AGENT_FROM_START", "").lower() in {"1", "true", "yes"}, google_activity_dir=os.environ.get("SENTINELLOGS_GOOGLE_ACTIVITY_DIR") or os.path.join(os.getcwd(), "google-activity")).run()'