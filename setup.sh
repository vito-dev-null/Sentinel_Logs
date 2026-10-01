#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$PROJECT_DIR"

if ! command -v docker >/dev/null 2>&1; then
    printf '%s\n' "Docker non trovato. Installare Docker Engine e Docker Compose Plugin." >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    printf '%s\n' "Docker Compose Plugin non trovato." >&2
    exit 1
fi

if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    printf '%s\n' "Creato .env da .env.example: inserire i segreti prima del deploy." >&2
fi

mkdir -p tls geoip logs output
if [ "$#" -ge 2 ]; then
    [ -f "$1" ] || { printf '%s\n' "Certificato non trovato: $1" >&2; exit 1; }
    [ -f "$2" ] || { printf '%s\n' "Chiave TLS non trovata: $2" >&2; exit 1; }
    [ -e tls/tls.crt ] || cp "$1" tls/tls.crt
    [ -e tls/tls.key ] || cp "$2" tls/tls.key
    chmod 600 tls/tls.key
fi

docker compose pull postgres redis nginx
docker compose build sentinellogs
chmod +x "$PROJECT_DIR/launch-dashboard.sh"
mkdir -p "$HOME/.local/share/applications"
escaped_project_dir=$(printf '%s\n' "$PROJECT_DIR" | sed 's/[\\&|]/\\&/g')
sed "s|@PROJECT_DIR@|$escaped_project_dir|g" "$PROJECT_DIR/sentinellogs.desktop" > "$HOME/.local/share/applications/sentinellogs.desktop"
chmod 644 "$HOME/.local/share/applications/sentinellogs.desktop"
printf '%s\n' "Bootstrap completato. Verificare .env e tls/tls.crt + tls/tls.key, quindi eseguire: docker compose up -d"
printf '%s\n' "Launcher installato nel menu applicazioni: SentinelLogs Security Dashboard"