from __future__ import annotations

import base64
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError

from sentinellogs.dashboard_proxy import DashboardProxyServer, read_basic_auth


def test_proxy_adds_backend_auth_without_challenging_dashboard_client(tmp_path) -> None:
    credentials = "sentinellogs:" + "x" * 24
    observed = {}

    class UpstreamHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            observed["authorization"] = self.headers.get("Authorization")
            observed["path"] = self.path
            body = b"dashboard"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    secrets = tmp_path / "secrets.env"
    secrets.write_text(f"SENTINELLOGS_BASIC_AUTH={credentials}\n", encoding="utf-8")
    proxy = DashboardProxyServer(0, upstream.server_address[1], read_basic_auth(secrets))
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (upstream, proxy)
    ]
    for thread in threads:
        thread.start()
    try:
        url = f"http://127.0.0.1:{proxy.server_port}/dashboard?tab=events"
        with urllib.request.urlopen(url, timeout=3) as response:
            assert response.status == 200
            assert response.read() == b"dashboard"
            assert response.headers.get("WWW-Authenticate") is None
        assert observed["authorization"] == "Basic " + base64.b64encode(credentials.encode()).decode()
        assert observed["path"] == "/dashboard?tab=events"
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_rejects_cross_site_action_and_non_dashboard_routes(tmp_path) -> None:
    class UpstreamHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.dumps({"ip": "192.0.2.1"}).encode()
            self.send_response(202)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            pass

    credentials = "sentinellogs:" + "x" * 24
    secrets = tmp_path / "secrets.env"
    secrets.write_text(f"SENTINELLOGS_BASIC_AUTH={credentials}\n", encoding="utf-8")
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), UpstreamHandler)
    proxy = DashboardProxyServer(0, upstream.server_address[1], read_basic_auth(secrets))
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (upstream, proxy)
    ]
    for thread in threads:
        thread.start()
    try:
        origin = f"http://127.0.0.1:{proxy.server_port}"
        action = urllib.request.Request(
            origin + "/api/soar/block-ip",
            data=b'{"ip":"192.0.2.1"}',
            headers={"Content-Type": "application/json", "Origin": "https://example.invalid"},
            method="POST",
        )
        try:
            urllib.request.urlopen(action, timeout=3)
        except HTTPError as error:
            assert error.code == 403
        else:
            raise AssertionError("cross-site action was accepted")

        try:
            urllib.request.urlopen(origin + "/v1/ingest", timeout=3)
        except HTTPError as error:
            assert error.code == 404
        else:
            raise AssertionError("non-dashboard route was proxied")
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()
