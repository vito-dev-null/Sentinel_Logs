#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON="$PROJECT_DIR/.venv/bin/python"
LOG_DIR="$PROJECT_DIR/output"
BACKEND_LOG="$LOG_DIR/backend.log"
AGENT_LOG="$LOG_DIR/agent.log"
URL="http://127.0.0.1:9090/dashboard"
PROXY_PORT=${SENTINELLOGS_DASHBOARD_PROXY_PORT:-19090}
PROXY_URL="http://127.0.0.1:$PROXY_PORT/dashboard"
CENTRAL_PROXY_PORT=19090
CENTRAL_PROXY_URL="http://127.0.0.1:$CENTRAL_PROXY_PORT/dashboard"
CENTRAL_METRICS_URL="http://127.0.0.1:$CENTRAL_PROXY_PORT/api/metrics.json"

health_check() {
    "$PYTHON" -c 'import base64, os, urllib.request; credentials=os.environ["SENTINELLOGS_BASIC_AUTH"].encode(); request=urllib.request.Request("http://127.0.0.1:9090/health", headers={"Authorization": "Basic "+base64.b64encode(credentials).decode()}); urllib.request.urlopen(request, timeout=1)' >/dev/null 2>&1
}

open_dashboard() {
    if command -v google-chrome >/dev/null 2>&1; then
        exec google-chrome --new-window "$1"
    fi
    if command -v chromium >/dev/null 2>&1; then
        exec chromium --new-window "$1"
    fi

    printf '%s\n' "Nessun browser disponibile; apro la dashboard nel browser predefinito." >&2
    exec xdg-open "$1"
}

mkdir -p "$LOG_DIR"

if ! "$PROJECT_DIR/prepare-local-runtime.sh" >>"$BACKEND_LOG" 2>&1; then
    printf '%s\n' "Preparazione SentinelLogs non riuscita. Consultare $BACKEND_LOG" >&2
    exit 1
fi

cd "$PROJECT_DIR"
set -a
. "$PROJECT_DIR/.sentinellogs/secrets.env"
set +a
if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ]; then
    printf '%s\n' "Credenziali locali non disponibili in .sentinellogs/secrets.env." >&2
    exit 1
fi

if ! health_check; then
    SENTINELLOGS_NO_BROWSER=1 nohup "$PROJECT_DIR/start-sentinellogs.sh" >>"$BACKEND_LOG" 2>&1 &
fi

ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if health_check; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    printf '%s\n' "Backend non disponibile. Consultare $BACKEND_LOG" >&2
    exit 1
fi

if ! pgrep -f '[s]entinellogs.local_agent' >/dev/null 2>&1; then
    nohup "$PROJECT_DIR/run-local-agent.sh" >>"$AGENT_LOG" 2>&1 &
fi

unset SENTINELLOGS_BASIC_AUTH SENTINELLOGS_TENANT_TOKENS

if [ -f "$PROJECT_DIR/.sentinellogs/central-dashboard-mode" ]; then
    if ! systemctl --user start sentinellogs-central-dashboard-tunnel.service \
        >>"$LOG_DIR/central-dashboard-tunnel.log" 2>&1; then
        printf '%s\n' "Tunnel della dashboard centrale non avviabile. Consultare $LOG_DIR/central-dashboard-tunnel.log" >&2
        exit 1
    fi

    central_ready=0
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if "$PYTHON" -c 'import json, sys, urllib.request; data=json.load(urllib.request.urlopen(sys.argv[1], timeout=1)); raise SystemExit(0 if data.get("history_index_enabled") is True else 1)' "$CENTRAL_METRICS_URL" >/dev/null 2>&1; then
            central_ready=1
            break
        fi
        sleep 1
    done
    if [ "$central_ready" -ne 1 ]; then
        printf '%s\n' "Dashboard centrale non disponibile o senza indice storico; consultare il servizio tunnel." >&2
        exit 1
    fi

    open_dashboard "$CENTRAL_PROXY_URL"
fi

dashboard_proxy_ready() {
    "$PYTHON" -c 'import sys, urllib.request; urllib.request.urlopen(sys.argv[1], timeout=1).close()' \
        "http://127.0.0.1:$PROXY_PORT/dashboard" >/dev/null 2>&1
}

if ! dashboard_proxy_ready; then
    nohup "$PYTHON" -m sentinellogs.dashboard_proxy \
        --port "$PROXY_PORT" \
        --secrets-file "$PROJECT_DIR/.sentinellogs/secrets.env" \
        >>"$LOG_DIR/dashboard-proxy.log" 2>&1 </dev/null &
fi

proxy_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if dashboard_proxy_ready; then
        proxy_ready=1
        break
    fi
    sleep 1
done
if [ "$proxy_ready" -ne 1 ]; then
    printf '%s\n' "Dashboard proxy non disponibile. Consultare $LOG_DIR/dashboard-proxy.log" >&2
    exit 1
fi

open_dashboard "$PROXY_URL"
