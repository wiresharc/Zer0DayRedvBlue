import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from datetime import datetime, timezone

PORT = int(os.environ.get("PORT", "5000"))
START = datetime.now(timezone.utc)

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "assets", "agent-bundle.zip"), "rb") as fh:
    AGENT_ZIP = fh.read()

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def render(pathname, severity, note):
    return f"2026-09-25T09:1{severity:02d}Z  {pathname:<24} {note}\n"


LOG = [
    render("POST /api/event", 2, "503 upstream retry"),
    render("GET  /api/diagnostics", 4, "200 ok"),
    render("GET  /api/token", 9, "200 handoff alarm_fallback"),
    render("GET  /api/health", 11, "200 ok"),
    render("GET  /api/agent-install", 15, "200 archive served"),
    render("auditor health claim", 11, "ZD{api_trail_62-9b}"),
    render("GET  /api/agent-install", 20, "200 archive served"),
    render("POST /api/event", 24, "200 ingested"),
    render("GET  /api/status", 25, "200 ok"),
    render("handoff matched expected shape", 28, "ZD{relay_sector_05@c}"),
    render("breaker tape review", 30, "no drift"),
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _headers(self, content_type, length, extra=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, status, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _text(self, status, body):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _route(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/api" or path == "/api/":
            self._json(200, {
                "endpoints": ["health", "status", "token", "diagnostics", "logs", "agent-install"],
                "note": "all unauthenticated by design",
            })
            return

        if path == "/api/health":
            uptime = int((datetime.now(timezone.utc) - START).total_seconds())
            self._json(200, {
                "status": "ok",
                "service": "allsafe-api",
                "build": "9.1.0",
                "runtime": "python",
                "uptime_seconds": uptime,
            })
            return

        if path == "/api/status":
            self._json(200, {
                "components": {"waf": "up", "collector": "up", "diagnostics": "up", "audit": "up"},
                "precision": params.get("precision", ["0"])[0],
                "badge_gate": "skippable",
            })
            return

        if path == "/api/token":
            self._json(200, {
                "service": "sentinel-collector",
                "audience": "internal only",
                "issued_to": "trial-account",
                "rotation": "disabled for trial keys",
                "alarm_fallback": "ZD{broken_handoff_45#k}",
            })
            return

        if path == "/api/diagnostics":
            self._json(200, {
                "ok": True,
                "engine": "sentryscan",
                "region": "ap-south",
                "memory_mb": 128,
                "latency_ms": 41,
                "declared_capabilities": ["ZD{diag_core_50%x}"],
            })
            return

        if path == "/api/logs":
            self._text(200, "".join(LOG))
            return

        if path == "/api/agent-install":
            self._headers(
                "application/zip",
                len(AGENT_ZIP),
                {"Content-Disposition": 'attachment; filename="agent-bundle.zip"'},
            )
            if self.command != "HEAD":
                self.wfile.write(AGENT_ZIP)
            return

        self._json(404, {"error": "route not found"})

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route()


if __name__ == "__main__":
    print("allsafe-api listening on " + str(PORT), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
