#!/usr/bin/env python3
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class _QuietHandler(BaseHTTPRequestHandler):
    server_version = "AdminDashboardE2E/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PrometheusHandler(_QuietHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/api/v1/query":
            self._json({"error": "not found"}, status=404)
            return
        query = urllib.parse.parse_qs(parsed.query).get("query", [""])[0]
        value = "300000"
        if "xdp_bytes" in query:
            value = "3000000000"
        elif 'tcp_syn="1"' in query:
            value = "30000"
        elif 'action="1"' in query:
            value = "30000"
        elif "anti_ddos_redirected_packets_total" in query:
            value = "5"
        elif "anti_ddos_not_allowed_service_total" in query:
            value = "3"
        self._json({
            "status": "success",
            "data": {
                "resultType": "vector",
                "result": [{"value": [1.0, value]}],
            },
        })


class TelegramHandler(_QuietHandler):
    calls: list[dict[str, Any]]

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        self.server.calls.append({"path": self.path, "body": raw})  # type: ignore[attr-defined]
        if "/sendMessage" not in self.path:
            self._json({"ok": False, "description": "unexpected telegram path"}, status=404)
            return
        self._json({"ok": True, "result": {"message_id": len(self.server.calls)}})  # type: ignore[attr-defined]


class FeedHandler(_QuietHandler):
    def do_GET(self) -> None:
        self._json({
            "entries": [
                {
                    "cidr": "192.0.2.0/25",
                    "score": 95,
                    "action": "drop",
                    "ttl_seconds": 3600,
                    "reason": "automation whitelist conflict fixture",
                },
                {
                    "cidr": "198.51.100.128/25",
                    "score": 90,
                    "action": "drop",
                    "ttl_seconds": 3600,
                    "reason": "automation valid reputation fixture",
                },
                {"cidr": "2001:db8::/32", "score": 80, "action": "drop"},
            ],
        })


class SupportServer:
    def __init__(self, handler: type[_QuietHandler]):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.calls = []  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address
        return f"http://{host}:{port}"

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.httpd.calls  # type: ignore[attr-defined]

    def start(self) -> "SupportServer":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)


class SupportServers:
    def __init__(self) -> None:
        self.prometheus = SupportServer(PrometheusHandler)
        self.telegram = SupportServer(TelegramHandler)
        self.feed = SupportServer(FeedHandler)

    def start(self) -> "SupportServers":
        self.prometheus.start()
        self.telegram.start()
        self.feed.start()
        return self

    def stop(self) -> None:
        for server in (self.prometheus, self.telegram, self.feed):
            server.stop()

