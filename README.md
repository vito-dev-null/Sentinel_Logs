# SentinelLogs

SentinelLogs is a real-time log parser for tail-style monitoring, regex extraction, JSONL output, and SIEM or alerting pipelines.

The CLI is available as `sentinellogs` (alias: `log-parser`).

For a local Linux workstation, `start-sentinellogs.sh` monitors the explicitly configured
file, otherwise both readable `/var/log/auth.log` and `/var/log/syslog`; when neither is
available it follows the real authentication stream from journald. To use the local
agent mode, start the dashboard/backend on port `9090` and run `./run-local-agent.sh`.
The agent sends each real line to `POST http://localhost:9090/v1/ingest`; no sample or
synthetic line is produced.

The security-themed desktop launcher is `sentinellogs.desktop` and uses
`assets/sentinellogs-security.svg`. Run `./setup.sh` to install it in the current user's
application menu; double-clicking it starts the backend and opens the dashboard only
after the health endpoint is ready.
The launcher opens the dashboard through a loopback-only proxy, which supplies the
backend's Basic Auth credentials without showing a browser login prompt. The metrics
backend remains authenticated and bound to `127.0.0.1`; the proxy is not for remote access.

For a workstation that should display a central SentinelLogs instance, an operator can
enable central-dashboard mode with the ignored local marker
`.sentinellogs/central-dashboard-mode` and a user-level systemd tunnel named
`sentinellogs-central-dashboard-tunnel.service`. The tunnel must forward loopback port
`19090` to the central host's loopback port `19090`; use an SSH host alias from the
operator's SSH configuration rather than placing host-specific values or credentials
in this repository. In this mode the launcher verifies that the remote history index is
available before opening the dashboard and fails closed instead of silently showing
the local, incomplete view.

## Features

- Follow appended log lines with logrotate-safe truncation handling
- Regex parsers for syslog and application logs
- Validated IPv4 and IPv6 extraction from parsed and structured messages
- JSONL output to stdout, files, HTTP webhooks, syslog, or a SentinelLogs ingest endpoint
- YAML-driven alert rules
- Prometheus metrics, health checks, and an optional live dashboard
- Docker image and Compose example
- Multi-tenant HTTPS ingestion for remote agents
- ECS-style normalized security fields and MITRE ATT&CK mappings
- Brute-force correlation and tamper-evident audit hash chain
- Offline-first JSONL persistence with optional remote integrations disabled by default

## Storage and queue configuration

The default runtime uses `STORAGE_BACKEND=jsonl`, writes local records below
`STORAGE_PATH`, and sets `QUEUE_BACKEND=off`. The JSONL event store appends to its
log, alert, and audit files without automatic expiry; plan disk capacity, backups,
and any archival or deletion policy explicitly. A separate `file:` sink uses
`SENTINELLOGS_LOG_MAX_BYTES`, `SENTINELLOGS_LOG_RETENTION_DAYS`, and
`SENTINELLOGS_LOG_MAX_FILES`. The file-count limit is an additional cap and can
shorten the age-based retention window if it is too low for the event volume. Docker
Compose examples default to 7 days and 5 files; configure both values for the target
retention period and measured rotation rate. Remote queues, webhooks, and external
notification providers are opt-in and must be configured explicitly by the operator.

## Remote ingestion

Remote collectors such as Fluent Bit, Winlogbeat, AWS CloudTrail forwarders, Azure
Monitor exporters, or a proprietary agent can send an authenticated JSON envelope to
`POST /v1/ingest`. The backend requires TLS, a tenant-scoped Bearer token, and an
`X-Sentinel-Agent` header. Supported `source_type` values are `linux_auth`, `journald`,
`windows_eventlog_security`, `windows_sysmon`, `aws_cloudtrail`, `azure_monitor`,
`network_syslog`, `google_workspace_login`, `google_account_activity`, and `generic`.

## Google activity exports

The existing local agent also watches the ignored `google-activity/` folder, or the
directory configured by `SENTINELLOGS_GOOGLE_ACTIVITY_DIR`. It scans every 30 seconds
and sends normalized events through the same authenticated ingestion endpoint as node
logs. Supported inputs are Google Workspace Admin Reports API activity JSON responses
(`items` with `actor`, `id`, and `events`), Google Takeout My Activity JSON arrays, and
newline-delimited JSON/JSONL containing those records. A private hash-only checkpoint
prevents already imported export records from being sent again after restart.

Workspace login events are normalized with timestamp, account, outcome, and source IP
when the export provides them. Explicit suspicious-login events alert immediately;
failed logins are correlated to avoid alerting on every typo. Successful logins from
outside expected networks alert only when the backend has
`SENTINELLOGS_TRUSTED_LOGIN_CIDRS` configured as a comma-separated list of trusted
CIDRs. Leave it unset until the expected networks are known. General Takeout activity
is recorded as account activity, not mislabeled as a successful login, and does not
generate authentication alerts.

This is file-based collection, not a live Google connector. Workspace login audit
events must first be exported by an operator or an authorized Reports API collector.
For consumer Google accounts, Takeout My Activity can describe product activity but
does not provide a complete login/session audit; those account-security events remain
unavailable unless Google provides an explicit export for them.

The Python client can be used by a lightweight agent:

```python
import os
from sentinellogs.ingestion import send_events

send_events(
  "https://sentinellogs.example.com",
  token=os.environ["SENTINELLOGS_TENANT_TOKEN"],
  agent_id="server-001",
  events=[{"source_type": "windows_eventlog_security", "message": "..."}],
)
```

Start the HTTPS listener from Python with `start_ingestion_server(...)`, providing a
certificate, private key, and a mapping of tenant IDs to tokens. Tokens are compared
in constant time; never place them in source control. Structured events retain their
original fields and are not accepted when they contain neither a raw line nor a message.
When `source.ip` is omitted, SentinelLogs uses the first valid IP address found in the
event message; if no address is present, it leaves `source.ip` unset rather than
substituting the collector's own address. The local agent follows this rule; its
optional `source_ip` override is only for deployments that explicitly need a fixed
source address. Supply `source.ip` explicitly when an event contains multiple
addresses and the source must be unambiguous.

Remote ingestion is disabled by default and binds to `127.0.0.1` unless an address is
explicitly configured. For a private Tailscale deployment, bind the HTTPS listener to
the server's Tailscale IP, use a certificate valid for its MagicDNS name, and restrict
tailnet access with ACLs. Do not expose the dashboard's port `9090` to remote agents.
The native launcher enables the listener only when `SENTINELLOGS_INGESTION_PORT`,
`SENTINELLOGS_INGESTION_HOST`, `SENTINELLOGS_INGESTION_CERTFILE`, and
`SENTINELLOGS_INGESTION_KEYFILE` are set and `SENTINELLOGS_TENANT_TOKENS` contains
at least one tenant-scoped Bearer token.

`LocalLogAgent` can send to that listener with `SENTINELLOGS_INGEST_TOKEN` and
`SENTINELLOGS_AGENT_ENDPOINT=https://<server>:9443`. Bearer credentials are refused
over HTTP. For a private CA or pinned certificate, set
`SENTINELLOGS_INGEST_CA_FILE` to the trusted certificate path on the agent.
The agent starts at the end of each log file and forwards only new lines; historical
replay is opt-in with `SENTINELLOGS_AGENT_FROM_START=true`.

## Normalization and detection

Accepted events expose ECS-style fields including `source.ip`, `user.name`,
`event.action`, and `event.outcome`, together with `tenant_id`, `agent_id`, and
`source_type`. Failed authentication is mapped to MITRE ATT&CK `T1110`; unexpected
sudo usage can be mapped to `T1548.003`. `CorrelationEngine` raises a brute-force alert when failures exceed the configured
threshold. Protect the dashboard with mandatory HTTP Basic Auth; the service refuses
to start without a password of at least 24 characters.
The default fail2ban rule matches the `Ban` action only; discovery (`Found`) and
unban (`Unban`) records are not treated as bans.

Accepted events are appended to a SHA-256 hash chain. The native launcher writes the
chain to `logs/audit.jsonl` by default; override the location with
`SENTINELLOGS_AUDIT_LOG`. The dashboard reports integrity as verified only after the
chain contains a valid record. Missing, empty, or corrupted history remains
unverified and is never repaired automatically; use `AuditLog.verify()` to check
the chain.

## Enterprise access, response and notifications

`AccessController` accepts adapters for OIDC/OAuth2, SAML 2.0, LDAP, or Active
Directory and enforces both role permissions and tenant isolation. The application
does not implement an identity protocol itself: production adapters must validate
issuer, signature, audience, certificate rotation, and LDAP TLS settings before
returning a `Principal`.

`SoarEngine` executes only explicitly registered high/critical playbooks. A playbook
receives a typed alert and can call a firewall or host-isolation API; IP and tenant
allowlists are checked before the callback. No shell command is executed implicitly.

Use `SlackConnector`, `TeamsConnector`, and `PagerDutyConnector` with
`NotificationRouter` to dispatch detection alerts. URLs and PagerDuty routing keys
must come from a secret manager or environment variables, not from source files.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

For tests:

```bash
pip install -e ".[dev]"
```

## CLI usage

```bash
sentinellogs --file /var/log/syslog
sentinellogs --file /var/log/auth.log --output parsed.jsonl --from-start
sentinellogs --file /var/log/app.log --log-level DEBUG --version
sentinellogs --file /var/log/app.log --sink stdout --sink file:out.jsonl
sentinellogs --file /var/log/app.log --sink webhook:https://example.com/hook --sink syslog:localhost:514
sentinellogs --file /var/log/app.log --metrics-port 9090
sentinellogs --file /var/log/app.log --metrics-port 9090 --no-dashboard
```

## Docker

```bash
docker build -t sentinellogs .
docker run --rm -it \
  -v "$PWD/logs:/var/log/app:ro" \
  -v "$PWD/output:/var/log/output" \
  sentinellogs --file /var/log/app/app.log --sink stdout --sink file:/var/log/output/parsed.jsonl
```

Compose:

```bash
cp .env.example .env
# Edit .env with a non-overlapping IPv4 subnet and distinct container addresses.
docker compose up --build
```

The included `docker-compose.yml` mounts:

- `./logs:/var/log/app:ro`
- `./output:/var/log/output`

and exposes the authenticated dashboard and ingestion service through Nginx. It uses
an explicitly configured bridge subnet and fixed backend/Nginx container addresses;
the application and proxy bind only to those addresses. Published host ports are fixed
to loopback. The ignored `.env` file must contain `SENTINELLOGS_DOCKER_SUBNET`,
`SENTINELLOGS_BACKEND_CONTAINER_ADDRESS`, and
`SENTINELLOGS_NGINX_CONTAINER_ADDRESS`, with non-overlapping, distinct addresses
assigned from the selected subnet. Never commit the local `.env` file.

The commands above copy the public configuration template and start the bridge stack;
edit `.env` first to replace all placeholders with an unused subnet and addresses
assigned to the two containers. The setup script creates ignored local secrets,
generates a local TLS certificate in a Docker volume, and keeps logs and storage
isolated from the host filesystem:

```bash
./setup.sh
docker compose up --build -d
```

The stack contains SentinelLogs and Nginx. Nginx redirects port 80 to 443 and proxies
`/v1/ingest` to the backend's TLS listener. The first-run bootstrap creates a unique
Basic Auth credential and tenant token locally; neither is committed or sent externally.

### Production provider setup

Install the optional GeoIP dependency in the image or virtual environment:

```bash
pip install -e '.[geoip]'
```

Download GeoLite2-City or GeoIP2 from MaxMind under the applicable license and place the
database at the path in `MAXMIND_DB_PATH`. Construct `MaxMindGeoIP` from that path and
pass it to `CorrelationEngine`; private/reserved IPs without a database location are
ignored rather than guessed. Set OIDC/LDAP and webhook variables from the enterprise
secret store; `.env.example` contains names only.

### Lab smoke test

From a lab agent, send real, approved test records over the public HTTPS endpoint:

```python
import os
from sentinellogs.ingestion import send_events
send_events(
  "https://sentinellogs.example.com",
  token=os.environ["SENTINELLOGS_TENANT_TOKEN"],
  agent_id="lab-server-001",
  events=[{"source_type": "linux_auth", "raw": "...approved lab log..."}],
)
```

Use `CorrelationEngine` tests for brute force and impossible travel; SentinelLogs
does not enable live SOAR actions. The dashboard's IP-block request is wired to a
dry-run handler: it validates the address and records that a simulation was
requested, but never changes firewall or network state. Successful SSH logins,
generic `sudo` commands, and an external source address alone are informational and
do not trigger dashboard alerts; explicit security rules such as failed logins and
fail2ban actions remain visible. Real firewall isolation is not implemented by the
dashboard. Webhook delivery, certificate issuance, and lab-agent deployment require
access to an organization's network and credentials and are intentionally not run
by this repository's tests.

## Observability

When `--metrics-port` is set, SentinelLogs serves:

| Path | Purpose |
| --- | --- |
| `/metrics` | Prometheus text format |
| `/health` | `ok` / `degraded` status |
| `/healthz` | Infrastructure readiness: database, Redis, and worker |
| `/dashboard` | Lightweight live monitoring page |
| `/api/metrics.json` | JSON snapshot for the dashboard |
| `/api/events` | Server-Sent Events live snapshot stream |

The recent-events table displays the normalized `source.ip`, `user.name`, and
`host.hostname` fields when the source provides them. Missing values are shown as
`(n/d)` rather than inferred.

Example:

```bash
read -rsp 'SentinelLogs password: ' SENTINELLOGS_PASSWORD
printf '\n'
export SENTINELLOGS_BASIC_AUTH="sentinellogs:${SENTINELLOGS_PASSWORD}"
unset SENTINELLOGS_PASSWORD
sentinellogs --file /var/log/auth.log --metrics-port 9090
```

Then open `http://localhost:9090/dashboard`.

Basic authentication is mandatory for the dashboard, APIs, and metrics. The server
binds to `127.0.0.1` by default. Bind addresses are validated and unspecified
addresses are rejected unless `--allow-wildcard-bind` is explicitly supplied; use
that opt-in only behind an enforced network boundary. Use a unique password of at
least 24 characters:

Protect it with HTTP basic auth before exposing it on a shared network:

```bash
read -rsp 'SentinelLogs password: ' SENTINELLOGS_PASSWORD
printf '\n'
export SENTINELLOGS_BASIC_AUTH="sentinellogs:${SENTINELLOGS_PASSWORD}"
unset SENTINELLOGS_PASSWORD
```

The local-agent process must receive the same `SENTINELLOGS_BASIC_AUTH` value in its
environment.

Telemetry and crash reporting are not implemented. SentinelLogs makes no telemetry
requests; external sinks are explicit operator actions, not background services.

## Alerting

Alert rules live in `src/sentinellogs/alerts.yaml`, or in a file passed with `--alert-config`.

For Linux authentication monitoring, use the real authentication source, for example
`/var/log/auth.log` on Ubuntu/Debian:

```bash
sudo sentinellogs --file /var/log/auth.log --metrics-port 9090
```

The built-in rules classify these real messages as security events:

- `Failed password for`, `Invalid user`, `Failed publickey`: failed SSH login
- `Accepted password for`, `Accepted publickey for`: successful SSH login
- `authentication failure` and `auth failure`: PAM authentication failure
- `sudo: ... COMMAND=...`: privileged command execution

On systems using only journald, export or forward the journal authentication stream to a
real file before monitoring it. Useful discovery commands are:

```bash
journalctl -f _COMM=sshd
journalctl -f _COMM=pam
```

No sample data is generated by the application. Files under `examples/` are rejected by
the CLI unless `--confirm-demo` is explicitly supplied.

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

Output sinks are configured with repeated `--sink` flags:

```bash
sentinellogs --file /var/log/auth.log \
  --sink stdout \
  --sink file:parsed.jsonl \
  --sink webhook:https://example.com/hook \
  --sink syslog:localhost:514
```

Keep webhook URLs in the environment:

```bash
export WEBHOOK_URL="https://hooks.example.com/abc123"
sentinellogs --file /var/log/auth.log --sink "webhook:${WEBHOOK_URL}"
```

## SentinelLogs ingest sink

```bash
SENTINEL_API_KEY"REDACTED_SECRET"
sentinellogs --file /var/log/app.log --sink sentinellogs:https://sentinel.example.com/ingest
```

Or attach a per-sink secret:

```bash
export SENTINEL_KEY_NAME="REDACTED_SECRET"
sentinellogs --file /var/log/app.log \
  --sink "sentinellogs:https://sentinel.example.com/ingest|apikey:${SENTINEL_KEY_NAME}"
```

## Adding a log format

Edit `src/sentinellogs/patterns.yaml` or pass a custom file with `--patterns`:

```yaml
nginx:
  pattern: '^(?P<timestamp>...) ...$'
  fields: [timestamp, host, message]
```

The parser registry loads that file at startup and tries each parser in order until one matches.

The bundled parser also filters known desktop noise before an event reaches the dashboard.
The list is in `src/sentinellogs/patterns.yaml` under `ignore_processes`; edit it only for
processes confirmed to be non-security noise. SSH, sudo, PAM and other unlisted services
remain visible.

## Tests

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Production notes

The dashboard should reflect live system logs, not repository samples.

- Always pass the log path with `--file`.
- Grant the process read access to protected files such as `/var/log/auth.log`.
- Files under `examples/` and similarly named demo logs are rejected unless you pass `--confirm-demo`.
- Confirm host clocks are NTP-synced (`timedatectl status` or `chronyc tracking`) before relying on event timestamps.

Production start:

```bash
sudo sentinellogs --file /var/log/auth.log --metrics-port 9090
```

## License

MIT. See [LICENSE](LICENSE).
