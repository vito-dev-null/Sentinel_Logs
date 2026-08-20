# SentinelLogs

`log-parser` is a real-time log parser designed for tail-like monitoring, regex extraction, JSONL output, and integration with alerting and SIEM pipelines.

## Features

- Tail-like monitoring of appended log lines
- Regex-based parsing for syslog and app logs
- Automatic IP extraction from log messages
- JSONL output to stdout and optional file sink
- Logrotate-safe file handling and truncation detection
- Modular sink architecture for stdout, file, HTTP webhook and syslog
- Alert rule engine driven by YAML configuration
- Container-ready packaging with Docker and docker-compose

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## CLI usage

```bash
log-parser --file /var/log/syslog
log-parser --file /var/log/auth.log --output parsed.jsonl --from-start
log-parser --file /var/log/app.log --log-level DEBUG --version
log-parser --file /var/log/app.log --sink stdout --sink file:out.jsonl
log-parser --file /var/log/app.log --sink webhook:https://example.com/hook --sink syslog:localhost:514
log-parser --file /var/log/app.log --metrics-port 9090 --dashboard
log-parser --file /var/log/app.log --metrics-port 9090 --no-dashboard
```

## Docker

Build the image:

```bash
docker build -t log-parser .
```

Run the container:

```bash
docker run --rm -it -v "$PWD/logs:/var/log/app:ro" -v "$PWD/output:/var/log/output" log-parser --file /var/log/app/app.log --sink stdout --sink file:/var/log/output/parsed.jsonl
```

Compose example:

```bash
docker compose up --build
```

The included `docker-compose.yml` mounts:
- `./logs:/var/log/app:ro`
- `./output:/var/log/output`

## Observability dashboard

When `--metrics-port` is enabled, the project exposes:
- `/metrics` in Prometheus format
- `/health` with a simple active/degraded status
- `/dashboard` with a lightweight live monitoring page
- `/api/metrics.json` for polling by the frontend

Example:

```bash
log-parser --file /var/log/auth.log --metrics-port 9090
```

Then open:

```text
http://localhost:9090/dashboard
```

The dashboard is designed for internal/demo use. It is intentionally simple, responsive, and updates every ~4 seconds via `fetch()` without reloading the page. The page includes metric cards, a realtime line chart, and the most recent alert table.

A minimal security layer is available via basic auth environment variables before exposing the dashboard on any shared network:

```bash
export LOG_PARSER_BASIC_AUTH="admin:change-me"
# or
export LOG_PARSER_BASIC_AUTH_USERNAME="admin"
export LOG_PARSER_BASIC_AUTH_PASSWORD="change-me"
```

This is not a substitute for a proper reverse proxy or SSO layer in production.

## Alerting

The project supports pluggable sinks and alert rules. You can configure alerts in `src/log_parser/alerts.yaml` or pass a custom file with `--alert-config`.

Example `alerts.yaml`:

```yaml
alert_rules:
  - name: ssh-failed-password
    field: message
    regex: "Failed password|Permission denied"
    sinks:
      - webhook:${WEBHOOK_URL}
  - name: app-errors
    field: level
    equals: ERROR
    sinks:
      - syslog:localhost:514
```

Sinks are configured through the CLI with repeated `--sink` flags:

```bash
log-parser --file /var/log/auth.log \
  --sink stdout \
  --sink file:parsed.jsonl \
  --sink webhook:https://example.com/hook \
  --sink syslog:localhost:514
```

For webhook secrets, prefer environment variables such as:

```bash
export WEBHOOK_URL="https://hooks.example.com/abc123"
log-parser --file /var/log/auth.log --sink webhook:${WEBHOOK_URL}
```

This pattern is useful for sending Slack/Teams notifications for SSH failures or `ERROR` events without hardcoding credentials.

## Adding a new log format

Edit the configuration file in `src/log_parser/patterns.yaml` and add a new section like:

```yaml
nginx:
  pattern: '^(?P<timestamp>...) ...$'
  fields: [timestamp, host, message]
```

The parser registry loads the file on startup and tries each parser in order until one matches.

## Running tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest tests/ -v
```

## Produzione

ATTENZIONE: in ambiente aziendale è fondamentale che la dashboard mostri SOLO dati reali e non file di esempio o dati fittizi.

- Non avviare l'app senza specificare il file di log con `--file /percorso/del/log`.
- Se il file è protetto (es. `/var/log/auth.log`), eseguire il processo con i permessi adeguati (es. `sudo`) o fornire accesso di sola lettura al servizio.
- I file di esempio/dimostrazione sono collocati sotto `examples/` e non vengono usati automaticamente. Se si intende usare un file di esempio, è necessario passare esplicitamente `--confirm-demo`.
- Per inviare i log a SentinelLogs usare il sink `sentinellogs:`. Esempi:

    # usare variabile d'ambiente per la chiave API (Authorization: Bearer)
    export SENTINEL_API_KEY="REDACTED_SECRET"
    log-parser --file /var/log/app.log --sink sentinellogs:https://sentinel.example.com/ingest

    # oppure specificare chiave per sink tramite riferimento a segreto
    export SENTINEL_KEY_NAME="REDACTED_SECRET"
    log-parser --file /var/log/app.log --sink "sentinellogs:https://sentinel.example.com/ingest|apikey:${SENTINEL_KEY_NAME}"
- La dashboard mostra un badge "Sorgente" con il percorso/espressione dei file monitorati per evitare confusioni: controllare sempre quel campo prima di interpretare i dati.
- Prima del deploy in produzione verificare che gli host siano sincronizzati via NTP (es. `timedatectl status`, `chronyc tracking`).

Esempio d'avvio in produzione:

```bash
sudo log-parser --file /var/log/auth.log --metrics-port 9090
```

Queste precauzioni garantiscono che ogni riga visualizzata nella dashboard corrisponda a un evento reale del sistema monitorato.