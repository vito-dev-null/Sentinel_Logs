from __future__ import annotations

import argparse
import base64
import http.client
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

READ_PATHS = frozenset({
    "/dashboard",
    "/dashboard/",
    "/api/metrics.json",
    "/api/recent-lines.json",
    "/api/events",
})
ACTION_PATHS = frozenset({"/api/soar/block-ip"})
MAX_ACTION_BODY_BYTES = 64 * 1024


def read_basic_auth(secrets_file: Path) -> str:
    raw = ""
    for line in secrets_file.read_text(encoding="utf-8").splitlines():
        if line.startswith("SENTINELLOGS_BASIC_AUTH="):
            raw = line.partition("=")[2].strip()
            break
    username, separator, password = raw.partition(":")
    if not separator or not username.strip() or len(password) < 24:
        raise ValueError("SENTINELLOGS_BASIC_AUTH is missing or invalid")
    if any(ord(char) < 32 for char in username + password):
        raise ValueError("SENTINELLOGS_BASIC_AUTH contains control characters")
    return "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")


class DashboardProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, port: int, upstream_port: int, authorization: str) -> None:
        super().__init__(("127.0.0.1", port), DashboardProxyHandler)
        self.upstream_port = upstream_port
        self.authorization = authorization


class DashboardProxyHandler(BaseHTTPRequestHandler):
    server: DashboardProxyServer

    def do_GET(self) -> None:
        self._proxy()

    def do_HEAD(self) -> None:
        self._proxy()

    def do_POST(self) -> None:
        self._proxy()

    def _proxy(self) -> None:
        expected_host = f"127.0.0.1:{self.server.server_port}"
        if self.headers.get("Host") != expected_host:
            self.send_error(403, "Invalid dashboard host")
            return

        fetch_site = self.headers.get("Sec-Fetch-Site", "")
        origin = self.headers.get("Origin", "")
        expected_origin = f"http://{expected_host}"
        if fetch_site and fetch_site not in {"same-origin", "none"}:
            self.send_error(403, "Cross-site dashboard request rejected")
            return
        if origin and origin != expected_origin:
            self.send_error(403, "Cross-site dashboard request rejected")
            return

        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
            self.send_error(400, "Invalid dashboard path")
            return

        if self.command in {"GET", "HEAD"}:
            if parsed.path == "/__proxy_health":
                self._send_body(200, b"ok\n", "text/plain; charset=utf-8")
                return
            if parsed.path not in READ_PATHS:
                self.send_error(404)
                return
            body = None
        elif self.command == "POST":
            if parsed.path not in ACTION_PATHS:
                self.send_error(404)
                return
            if origin != expected_origin:
                self.send_error(403, "Dashboard action requires a same-origin request")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400, "Invalid content length")
                return
            if length <= 0 or length > MAX_ACTION_BODY_BYTES:
                self.send_error(413, "Dashboard action body is too large or empty")
                return
            body = self.rfile.read(length)
        else:
            self.send_error(405, "Method not allowed")
            return

        request_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        headers = {
            "Authorization": self.server.authorization,
            "Host": "127.0.0.1:9090",
            "Connection": "close",
        }
        for name in ("Accept", "Content-Type", "If-None-Match", "If-Modified-Since", "User-Agent"):
            value = self.headers.get(name)
            if value:
                headers[name] = value
        if body is not None:
            headers["Content-Length"] = str(len(body))

        connection = http.client.HTTPConnection("127.0.0.1", self.server.upstream_port, timeout=5)
        try:
            connection.request(self.command, request_path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read()
            content_type = response.getheader("Content-Type", "application/octet-stream")
            self.send_response(response.status)
            self.send_header("Content-Type", content_type)
            for name in ("Cache-Control", "ETag", "Last-Modified", "Retry-After", "WWW-Authenticate"):
                value = response.getheader(name)
                if value:
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)
        except (http.client.HTTPException, OSError) as exc:
            logger.warning("Sentinel Logs dashboard upstream unavailable (%s)", type(exc).__name__)
            self.send_error(502, "Sentinel Logs backend unavailable")
        finally:
            connection.close()

    def _send_body(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        logger.debug("Sentinel Logs dashboard proxy request handled")


def main() -> None:
    parser = argparse.ArgumentParser(description="Loopback-only authenticated Sentinel Logs dashboard proxy")
    parser.add_argument("--port", type=int, default=19090)
    parser.add_argument("--upstream-port", type=int, default=9090)
    parser.add_argument("--secrets-file", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.upstream_port <= 65535:
        parser.error("ports must be between 1 and 65535")

    server = DashboardProxyServer(args.port, args.upstream_port, read_basic_auth(args.secrets_file))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
