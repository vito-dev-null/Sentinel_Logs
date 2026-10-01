#!/bin/sh
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="$PROJECT_DIR/.venv/bin/python"

mkdir -p "$PROJECT_DIR/logs"
LOG_FILE="${SENTINELLOGS_LOG_FILE:-}"

if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ]; then
    printf '%s\n' "Impostare SENTINELLOGS_BASIC_AUTH (utente:password di almeno 24 caratteri) prima di avviare SentinelLogs." >&2
    exit 1
fi

if [ ! -x "$PYTHON" ]; then
    printf '%s\n' "SentinelLogs non e installato. Esegui: $PYTHON -m pip install -e ." >&2
    exit 1
fi

"$PYTHON" -c 'from sentinellogs.bootstrap import ensure_local_secrets; ensure_local_secrets()'
set -a
. "$PROJECT_DIR/.sentinellogs/secrets.env"
set +a

if [ -n "$LOG_FILE" ] && [ -r "$LOG_FILE" ]; then
    set -- --file "$LOG_FILE"
elif [ -r /var/log/auth.log ] || [ -r /var/log/syslog ]; then
    set -- --file
    [ ! -r /var/log/auth.log ] || set -- "$@" /var/log/auth.log
    [ ! -r /var/log/syslog ] || set -- "$@" /var/log/syslog
else
    set -- --journal --file /var/log/auth.log
fi

if [ "${SENTINELLOGS_NO_BROWSER:-0}" != "1" ]; then
    (
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            if "$PYTHON" -c 'import base64, os, urllib.request; credentials=os.environ["SENTINELLOGS_BASIC_AUTH"].encode(); request=urllib.request.Request("http://127.0.0.1:9090/health", headers={"Authorization": "Basic "+base64.b64encode(credentials).decode()}); urllib.request.urlopen(request, timeout=1)' >/dev/null 2>&1; then
                xdg-open "http://localhost:9090/dashboard" >/dev/null 2>&1 || true
                exit 0
            fi
            sleep 1
        done
    ) &
fi

exec "$PYTHON" -m sentinellogs \
    "$@" \
    --sink "file:$PROJECT_DIR/logs/parsed.jsonl" \
    --metrics-port 9090
