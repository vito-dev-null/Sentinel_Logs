#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON="$PROJECT_DIR/.venv/bin/python"
LOG_DIR="$PROJECT_DIR/output"
BACKEND_LOG="$LOG_DIR/backend.log"
AGENT_LOG="$LOG_DIR/agent.log"
URL="http://127.0.0.1:9090/dashboard"

if [ -z "${SENTINELLOGS_BASIC_AUTH:-}" ]; then
    printf '%s\n' "Impostare SENTINELLOGS_BASIC_AUTH prima di avviare la dashboard." >&2
    exit 1
fi

health_check() {
    "$PYTHON" -c 'import base64, os, urllib.request; credentials=os.environ["SENTINELLOGS_BASIC_AUTH"].encode(); request=urllib.request.Request("http://127.0.0.1:9090/health", headers={"Authorization": "Basic "+base64.b64encode(credentials).decode()}); urllib.request.urlopen(request, timeout=1)' >/dev/null 2>&1
}

mkdir -p "$LOG_DIR"

if ! command -v python3 >/dev/null 2>&1 || [ ! -x "$PYTHON" ]; then
    printf '%s\n' "SentinelLogs non installato: eseguire prima ./run-local-agent.sh" >&2
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

if command -v google-chrome >/dev/null 2>&1; then
    exec google-chrome --app="$URL" --class=SentinelLogsSecurity --name=SentinelLogsSecurity
fi
if command -v chromium >/dev/null 2>&1; then
    exec chromium --app="$URL" --class=SentinelLogsSecurity --name=SentinelLogsSecurity
fi

printf '%s\n' "Nessun browser app-mode disponibile; apro la dashboard nel browser predefinito." >&2
exec xdg-open "$URL"
