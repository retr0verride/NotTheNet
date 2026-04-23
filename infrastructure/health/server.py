"""HealthServer — lightweight HTTP health-check and admin endpoint.

Runs on a separate daemon thread so it never blocks the main service loop.
Uses only stdlib ``http.server``; no third-party framework is required.

Endpoints
─────────
GET /health/live    → 200 {"status":"ok"}           (liveness probe)
GET /health/ready   → 200/503 {"status":"ready"|"degraded"}  (readiness probe)
GET /health/status  → 200 full status JSON            (requires X-Admin-Token)
GET /metrics        → 200 Prometheus text format      (scraped by OTel collector)

Security
────────
- Binds to 127.0.0.1 by default (never 0.0.0.0 in production without a firewall).
- /health/status requires the ``X-Admin-Token`` header to match NTN_HEALTH_TOKEN.
- Rate limiting: max 60 requests / 60 s per IP (token bucket).
- CORS: configurable allowed origins via NTN_HEALTH_CORS_ORIGINS (comma-separated).
- No request body is ever read (DoS mitigation: avoids slow-body attacks).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlsplit

from infrastructure.logging.setup import get_trace_id, set_trace_id

logger = logging.getLogger(__name__)


# ── Rate limiting (token bucket) ─────────────────────────────────────────────

class _TokenBucket:
    """Per-IP token bucket for simple rate limiting."""

    def __init__(self, capacity: int = 60, refill_rate: float = 1.0) -> None:
        # capacity: max burst; refill_rate: tokens added per second
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._buckets: dict[str, tuple[float, float]] = {}  # ip → (tokens, last_time)
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(ip, (float(self._capacity), now))
            elapsed = now - last
            tokens = min(self._capacity, tokens + elapsed * self._refill_rate)
            if tokens < 1.0:
                self._buckets[ip] = (tokens, now)
                return False
            self._buckets[ip] = (tokens - 1.0, now)
            return True


_rate_limiter = _TokenBucket(capacity=60, refill_rate=1.0)


# ── CORS helpers ──────────────────────────────────────────────────────────────

def _cors_headers(origin: str) -> dict[str, str]:
    allowed = os.environ.get("NTN_HEALTH_CORS_ORIGINS", "")
    origins = {o.strip() for o in allowed.split(",") if o.strip()}
    if not origins or origin in origins or "*" in origins:
        return {"Access-Control-Allow-Origin": origin or "*"}
    return {}


def _error_body(code: str, message: str) -> str:
    """Return a structured JSON error envelope.

    Format: ``{"error": {"code": "ERR_CODE", "message": "...", "trace_id": "..."}}
    """
    return json.dumps(
        {"error": {"code": code, "message": message, "trace_id": get_trace_id()}}
    )


# ── Request handler ───────────────────────────────────────────────────────────

class _HealthHandler(BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler; all business logic delegated to HealthServer."""

    # Injected by HealthServer.start()
    health_server_ref: HealthServer

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug("health: " + fmt, *args)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, "", headers=_cors_headers(self._origin()))

    def do_GET(self) -> None:  # noqa: N802
        set_trace_id()  # fresh trace ID per request
        client_ip = self.client_address[0]
        if not _rate_limiter.allow(client_ip):
            self._send(429, _error_body("ERR_RATE_LIMIT", "Too many requests"))
            return

        path = urlsplit(self.path).path.rstrip("/")
        handler = self.health_server_ref._routes.get(path)
        if handler is None:
            self._send(404, _error_body("ERR_NOT_FOUND", f"Path '{path}' not found"))
            return

        body, status = handler(self)
        cors = _cors_headers(self._origin())
        self._send(status, body, headers={"Content-Type": "application/json", **cors})

    def _origin(self) -> str:
        return self.headers.get("Origin", "")

    def _send(
        self,
        status: int,
        body: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)


# ── HealthServer ──────────────────────────────────────────────────────────────

class HealthServer:
    """Standalone HTTP health-check server that runs on a daemon thread.

    Args:
        health_svc: An ``application.health.HealthCheckService`` instance.
        orchestrator: An ``application.orchestrator.ServiceOrchestrator`` instance.
        bind_ip:  IP address to bind. Defaults to NTN_HEALTH_BIND or 127.0.0.1.
        port:     TCP port.         Defaults to NTN_HEALTH_PORT or 8080.
    """

    def __init__(
        self,
        health_svc: Any,       # application.health.HealthCheckService
        orchestrator: Any,     # application.orchestrator.ServiceOrchestrator
        bind_ip: str = "127.0.0.1",
        port: int = 8080,
    ) -> None:
        self._health_svc = health_svc
        self._orchestrator = orchestrator
        self._bind_ip = os.environ.get("NTN_HEALTH_BIND", bind_ip)
        self._port = int(os.environ.get("NTN_HEALTH_PORT", port))
        self._admin_token = os.environ.get("NTN_HEALTH_TOKEN", "")
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        self._routes: dict[str, Callable[..., tuple[str, int]]] = {
            "/health/live":    self._handle_live,
            "/health/ready":   self._handle_ready,
            "/health/status":  self._handle_status,
            "/metrics":        self._handle_metrics,
        }

    def start(self) -> None:
        """Start the health server on a daemon thread."""
        handler_class = type(
            "_BoundHandler",
            (_HealthHandler,),
            {"health_server_ref": self},
        )
        try:
            self._server = HTTPServer((self._bind_ip, self._port), handler_class)
        except OSError as exc:
            logger.warning(
                "Health server could not bind %s:%d — %s",
                self._bind_ip, self._port, exc,
            )
            return

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="health-server",
            daemon=True,
        )
        self._thread.start()
        logger.info("Health server listening on http://%s:%d", self._bind_ip, self._port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.debug("Health server stopped")

    # ── Route handlers ────────────────────────────────────────────────────────

    def _handle_live(self, req: _HealthHandler) -> tuple[str, int]:
        payload = self._health_svc.liveness()
        return json.dumps(payload), 200

    def _handle_ready(self, req: _HealthHandler) -> tuple[str, int]:
        is_ready, payload = self._health_svc.readiness()
        return json.dumps(payload), 200 if is_ready else 503

    def _handle_status(self, req: _HealthHandler) -> tuple[str, int]:
        # Require admin token when one is configured.
        if self._admin_token:
            provided = req.headers.get("X-Admin-Token", "")
            if not _constant_time_compare(provided, self._admin_token):
                return _error_body("ERR_UNAUTHORIZED", "Invalid or missing X-Admin-Token"), 401
        payload = self._orchestrator.summary()
        return json.dumps(payload), 200

    def _handle_metrics(self, req: _HealthHandler) -> tuple[str, int]:
        """Prometheus text format — minimal exposition for scraping."""
        summary = self._orchestrator.summary()
        lines = [
            "# HELP notthenet_services_running Number of services currently running",
            "# TYPE notthenet_services_running gauge",
            f"notthenet_services_running {summary['services_running']}",
            "# HELP notthenet_services_total Total registered services",
            "# TYPE notthenet_services_total gauge",
            f"notthenet_services_total {summary['services_total']}",
            "# HELP notthenet_services_failed Services in FAILED state",
            "# TYPE notthenet_services_failed gauge",
            f"notthenet_services_failed {summary['services_failed']}",
        ]
        if summary.get("uptime_seconds") is not None:
            lines += [
                "# HELP notthenet_uptime_seconds Seconds since last start",
                "# TYPE notthenet_uptime_seconds counter",
                f"notthenet_uptime_seconds {summary['uptime_seconds']}",
            ]
        return "\n".join(lines) + "\n", 200


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())
