#!/bin/sh
set -eu

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON="$PROJECT_DIR/.venv/bin/python"
cd "$PROJECT_DIR"

mkdir -p "$PROJECT_DIR/logs"
LOG_FILE="${SENTINELLOGS_LOG_FILE:-}"
AUDIT_LOG="${SENTINELLOGS_AUDIT_LOG:-$PROJECT_DIR/logs/audit.jsonl}"

"$PROJECT_DIR/prepare-local-runtime.sh"
set -a
. "$PROJECT_DIR/.sentinellogs/secrets.env"
set +a

if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ]; then
    printf '%s\n' "Credenziali locali non disponibili in .sentinellogs/secrets.env." >&2
    exit 1
fi

if [ -n "$LOG_FILE" ] && [ -r "$LOG_FILE" ]; then
    set -- --file "$LOG_FILE"
elif [ -r /var/log/auth.log ] || [ -r /var/log/syslog ]; then
    set -- --file
    [ ! -r /var/log/auth.log ] || set -- "$@" /var/log/auth.log
    [ ! -r /var/log/syslog ] || set -- "$@" /var/log/syslog
else
    set -- --journal --file /var/log/auth.log
fi

if [ -n "${SENTINELLOGS_INGESTION_PORT:-}" ]; then
    if [ -z "${SENTINELLOGS_INGESTION_HOST:-}" ] ||
        [ -z "${SENTINELLOGS_INGESTION_CERTFILE:-}" ] ||
        [ -z "${SENTINELLOGS_INGESTION_KEYFILE:-}" ]; then
        printf '%s\n' "Set the ingestion host, certificate and key when remote ingestion is enabled." >&2
        exit 1
    fi
    if [ -z "${SENTINELLOGS_TENANT_TOKENS:-}" ]; then
        printf '%s\n' "SENTINELLOGS_TENANT_TOKENS must be set when remote ingestion is enabled." >&2
        exit 1
    fi
    if [ ! -r "$SENTINELLOGS_INGESTION_CERTFILE" ] || [ ! -r "$SENTINELLOGS_INGESTION_KEYFILE" ]; then
        printf '%s\n' "The configured SentinelLogs ingestion certificate or key is not readable." >&2
        exit 1
    fi
    set -- "$@" \
        --ingestion-host "$SENTINELLOGS_INGESTION_HOST" \
        --ingestion-port "$SENTINELLOGS_INGESTION_PORT" \
        --ingestion-certfile "$SENTINELLOGS_INGESTION_CERTFILE" \
        --ingestion-keyfile "$SENTINELLOGS_INGESTION_KEYFILE"
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
    --audit-log "$AUDIT_LOG" \
    --metrics-port 9090
