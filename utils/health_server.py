"""Health and metrics HTTP endpoint for headless mode (opt-in, used by Docker).

Endpoints (spec: openapi.yaml):
  GET /health/live    200 while the process is alive. Open.
  GET /health/ready   200 when dns, http and https are running, else 503. Open.
  GET /health/status  Per-service state. Needs the admin token.
  GET /metrics        Prometheus text format. Needs the admin token.

Admin token: ``X-Admin-Token: <t>`` or ``Authorization: Bearer <t>``. With no
token configured, the two protected endpoints are served only on a loopback
bind and return 403 anywhere else (fail closed).

Hardening: per-IP rate limit (60 burst, 1/s refill), request bodies are never
read, CORS only for allowlisted origins, nosniff/DENY/no-store on every reply.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from utils.validators import validate_ip, validate_port

if TYPE_CHECKING:
    from service_manager import ServiceManager

logger = logging.getLogger(__name__)

CORE_SERVICES = ("dns", "http", "https")
MIN_TOKEN_LENGTH = 16
_TRUTHY = ("1", "true", "yes")


@dataclass(frozen=True)
class HealthSettings:
    """Health endpoint settings, read once from ``NTN_*`` environment variables."""

    enabled: bool = False
    bind_ip: str = "127.0.0.1"
    port: int = 8080
    admin_token: str = ""
    cors_origins: frozenset[str] = frozenset()

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> HealthSettings:
        """Parse and validate. Raises ValueError with an operator-facing message."""
        enabled = env.get("NTN_HEALTH_ENABLED", "").strip().lower() in _TRUTHY

        bind_raw = env.get("NTN_HEALTH_BIND", cls.bind_ip).strip()
        ok, bind_ip = validate_ip(bind_raw)
        if not ok or bind_ip is None:
            raise ValueError(f"NTN_HEALTH_BIND={bind_raw!r} is not a valid IP address")

        port_raw = env.get("NTN_HEALTH_PORT", str(cls.port)).strip()
        ok, port = validate_port(port_raw)
        if not ok or port is None:
            raise ValueError(f"NTN_HEALTH_PORT={port_raw!r} must be an integer 1-65535")

        token = env.get("NTN_ADMIN_TOKEN", "").strip()
        if token and len(token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"NTN_ADMIN_TOKEN must be at least {MIN_TOKEN_LENGTH} characters")

        origins = frozenset(
            o.strip() for o in env.get("NTN_HEALTH_CORS_ORIGINS", "").split(",") if o.strip()
        )
        return cls(enabled, bind_ip, port, token, origins)


class _TokenBucket:
    """Per-IP token bucket rate limiter."""

    def __init__(self, capacity: int = 60, refill_per_sec: float = 1.0) -> None:
        self._capacity = float(capacity)
        self._refill = refill_per_sec
        self._buckets: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_seen)
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(ip, (self._capacity, now))
            tokens = min(self._capacity, tokens + (now - last) * self._refill)
            allowed = tokens >= 1.0
            self._buckets[ip] = (tokens - 1.0 if allowed else tokens, now)
            return allowed


def _error_body(code: str, message: str) -> str:
    return json.dumps({"error": {"code": code, "message": message}})


def _presented_token(headers: Mapping[str, str]) -> str:
    """Token from ``X-Admin-Token``, else from ``Authorization: Bearer`` (what Prometheus sends)."""
    header = headers.get("X-Admin-Token", "")
    if header:
        return header
    scheme, _, credentials = headers.get("Authorization", "").partition(" ")
    return credentials.strip() if scheme.lower() == "bearer" else ""


class _Handler(BaseHTTPRequestHandler):
    server_ref: HealthServer  # set on the subclass built in HealthServer.start()

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 (stdlib signature)
        logger.debug("health: " + format, *args)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(204, "", self.server_ref.cors_headers(self.headers.get("Origin", "")))

    def do_GET(self) -> None:  # noqa: N802
        srv = self.server_ref
        if not srv.rate_limiter.allow(self.client_address[0]):
            self._send(429, _error_body("ERR_RATE_LIMIT", "Too many requests"))
            return
        path = urlsplit(self.path).path.rstrip("/")
        route = srv.routes.get(path)
        if route is None:
            self._send(404, _error_body("ERR_NOT_FOUND", f"Path '{path}' not found"))
            return
        body, status, content_type = route(self.headers)
        headers = {"Content-Type": content_type, **srv.cors_headers(self.headers.get("Origin", ""))}
        self._send(status, body, headers)

    def _send(self, status: int, body: str, headers: Mapping[str, str] | None = None) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)


_Route = Callable[[Mapping[str, str]], tuple[str, int, str]]
_JSON = "application/json"


class HealthServer:
    """Serves the health endpoints for one ServiceManager on a daemon thread."""

    def __init__(self, manager: ServiceManager, settings: HealthSettings) -> None:
        self._manager = manager
        self._settings = settings
        self._loopback_bind = ipaddress.ip_address(settings.bind_ip).is_loopback
        self._started = time.monotonic()
        self._server: HTTPServer | None = None
        self.rate_limiter = _TokenBucket()
        self.routes: dict[str, _Route] = {
            "/health/live": self._live,
            "/health/ready": self._ready,
            "/health/status": self._status,
            "/metrics": self._metrics,
        }

    def start(self) -> None:
        """Bind and serve. Raises OSError if the port cannot be bound."""
        handler = type("_BoundHandler", (_Handler,), {"server_ref": self})
        self._server = HTTPServer((self._settings.bind_ip, self._settings.port), handler)
        threading.Thread(
            target=self._server.serve_forever, name="health-server", daemon=True,
        ).start()
        logger.info("Health server listening on %s:%d", self._settings.bind_ip, self._settings.port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def cors_headers(self, origin: str) -> dict[str, str]:
        allowed = self._settings.cors_origins
        if origin and ("*" in allowed or origin in allowed):
            return {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
        return {}

    def check_auth(self, headers: Mapping[str, str]) -> tuple[str, int, str] | None:
        """Return an error response for a protected endpoint, or None if allowed."""
        token = self._settings.admin_token
        if token:
            if hmac.compare_digest(_presented_token(headers).encode(), token.encode()):
                return None
            return _error_body("ERR_UNAUTHORIZED", "Invalid or missing admin token"), 401, _JSON
        if self._loopback_bind:
            return None
        message = "Set NTN_ADMIN_TOKEN to expose this endpoint off-loopback"
        return _error_body("ERR_FORBIDDEN", message), 403, _JSON

    # ── Routes ────────────────────────────────────────────────────────────────

    def _uptime(self) -> float:
        return round(time.monotonic() - self._started, 1)

    def _readiness(self) -> tuple[bool, dict[str, Any]]:
        running = {s["name"] for s in self._manager.service_report() if s["state"] == "running"}
        missing = [name for name in CORE_SERVICES if name not in running]
        return not missing, {
            "status": "degraded" if missing else "ready",
            "core_services_required": list(CORE_SERVICES),
            "core_services_missing": missing,
            "uptime_seconds": self._uptime(),
        }

    def _live(self, _headers: Mapping[str, str]) -> tuple[str, int, str]:
        return json.dumps({"status": "ok", "uptime_seconds": self._uptime()}), 200, _JSON

    def _ready(self, _headers: Mapping[str, str]) -> tuple[str, int, str]:
        ready, payload = self._readiness()
        return json.dumps(payload), 200 if ready else 503, _JSON

    def _summary(self) -> dict[str, Any]:
        services = self._manager.service_report()
        _, readiness = self._readiness()
        return {
            "status": readiness["status"],
            "uptime_seconds": self._uptime(),
            "services_total": len(services),
            "services_running": sum(s["state"] == "running" for s in services),
            "services_failed": sum(s["state"] == "failed" for s in services),
            "services": services,
        }

    def _status(self, headers: Mapping[str, str]) -> tuple[str, int, str]:
        denied = self.check_auth(headers)
        if denied is not None:
            return denied
        return json.dumps(self._summary()), 200, _JSON

    def _metrics(self, headers: Mapping[str, str]) -> tuple[str, int, str]:
        denied = self.check_auth(headers)
        if denied is not None:
            return denied
        s = self._summary()
        lines = [
            "# HELP notthenet_services_running Number of services currently running",
            "# TYPE notthenet_services_running gauge",
            f"notthenet_services_running {s['services_running']}",
            "# HELP notthenet_services_total Total registered services",
            "# TYPE notthenet_services_total gauge",
            f"notthenet_services_total {s['services_total']}",
            "# HELP notthenet_services_failed Enabled services that failed to start",
            "# TYPE notthenet_services_failed gauge",
            f"notthenet_services_failed {s['services_failed']}",
            "# HELP notthenet_uptime_seconds Seconds since the health server started",
            "# TYPE notthenet_uptime_seconds counter",
            f"notthenet_uptime_seconds {s['uptime_seconds']}",
        ]
        return "\n".join(lines) + "\n", 200, "text/plain; version=0.0.4"
