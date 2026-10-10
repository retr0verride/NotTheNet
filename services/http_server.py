"""NotTheNet - HTTP / HTTPS Fake Server
Returns configurable responses to all HTTP(S) requests.

Security notes (OpenSSF):
- TLS: minimum TLSv1.2, OP_NO_SSLv2/SSLv3/TLSv1/TLSv1_1 set explicitly
- Only safe cipher suites (ECDHE + AES-GCM / CHACHA20)
- Request path sanitized before logging (path traversal / log-injection)
- Request body never written to disk unless explicitly configured
- No eval/exec of any request data
- Thread-per-connection model with a bounded ThreadPoolExecutor
"""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import ipaddress
import logging
import os
import random
import socket
import socketserver
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from services.cloud_exfil_routes import (
    route_aws_s3,
    route_azure_blob,
    route_dropbox,
    route_gdrive_upload,
    route_graph_onedrive,
)
from services.doh_websocket import is_doh_request, is_websocket_upgrade
from services.dynamic_response import (
    CompiledRule,
    compile_custom_rules,
    resolve_dynamic_response,
)
from services.http_catalog import (
    _AWS_S3_RE,
    _AZURE_BLOB_RE,
    _CAPTIVE_PORTAL_HOSTS,
    _CT_HTML,
    _CT_JSON,
    _CT_PLAIN,
    _DISCORD_HOSTS,
    _DROPBOX_HOSTS,
    _FILE_HOSTING_HOSTS,
    _GITHUB_RAW_HOSTS,
    _GOOGLE_CONTENT_HOSTS,
    _GRAPH_HOST,
    _IP_CHECK_FORMATTERS,
    _IP_CHECK_HOSTS,
    _NCSI_HOSTS,
    _NCSI_RESPONSES,
    _PASTE_HOSTS,
    _PKI_HOSTS,
    _SLACK_HOST,
    _TEAMS_HOSTS,
    _TEAMS_WEBHOOK_RE,
    _TELEGRAM_HOST,
    _resolve_pki_response,
)
from services.http_routes import (
    route_dead_drop_ip,
    route_discord,
    route_doh,
    route_file_hosting,
    route_google_content,
    route_simple_text,
    route_telegram,
    route_websocket_upgrade,
)
from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string
from utils.validators import sanitize_path

logger = logging.getLogger(__name__)


# Thread pool sized to match the connection cap of other services.
# HTTP/1.1 keep-alive means threads can be held by idle connections;
# 50 workers ensures new connections aren't starved even under concurrent load.
_MAX_WORKER_THREADS = 50

_DEFAULT_SERVER_HEADER = "Apache/2.4.51"

# Cipher suites: ECDHE forward secrecy + AEAD — no RC4, 3DES, CBC
_SECURE_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!3DES"
)

_DEFAULT_BODY = "<html><body><h1>200 OK</h1></body></html>"


_MAX_BODY_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Stable "last content modification" timestamp for Last-Modified response headers.
# Computed once at module load to approximate a deployed server whose content was
# last updated ~60 days before startup — prevents absence-of-header fingerprinting.
# Time component is fixed at noon UTC (HTTP-date format, RFC 7231 §7.1.1.1) so the
# header value stays stable for cache/conditional-GET fingerprint consistency.
_LAST_MODIFIED_TIME_OF_DAY = "12:00:00 GMT"
_LAST_MODIFIED_AGE_DAYS = 60
_SERVER_LAST_MODIFIED = (
    datetime.now(timezone.utc) - timedelta(days=_LAST_MODIFIED_AGE_DAYS)
).strftime(f"%a, %d %b %Y {_LAST_MODIFIED_TIME_OF_DAY}")

# RFC 1918 private address ranges — returning one of these as a "public" IP
# would let sandbox-aware malware detect the private network.
_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def _validate_spoof_ip(raw: str, context: str = "") -> str:
    """Validate spoof_public_ip from config.

    Returns the IP string if valid and globally routable.
    Logs a warning on RFC1918 addresses (still allowed but suspicious).
    Returns '' and logs an error on parse failures.
    """
    if not raw:
        return ""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        logger.error(
            "Invalid spoof_public_ip '%s' in %s config — must be a valid IPv4/IPv6 address; "
            "IP spoofing disabled.", raw, context or "http"
        )
        return ""
    if any(addr in net for net in _RFC1918_NETWORKS):
        logger.warning(
            "spoof_public_ip '%s' (%s) is a private/loopback address — "
            "sandbox detection tools may still flag this as non-internet traffic.",
            raw, context or "http"
        )
    return raw


def _load_response_body(config: dict[str, Any]) -> str:
    """
    Resolve the HTTP response body from config.
    If 'response_body_file' is set, load the file contents (relative to the
    project root).  Falls back to the 'response_body' string if the file is
    missing or unreadable.
    """
    file_path = config.get("response_body_file", "").strip()
    if file_path:
        # Resolve relative to project root (directory of this file's parent)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        abs_path = sanitize_path(project_root, file_path)
        if abs_path is None:
            logger.error(
                "response_body_file '%s' rejected (path traversal attempt); "
                "falling back to response_body string.",
                file_path,
            )
            return str(config.get("response_body", _DEFAULT_BODY))
        try:
            size = os.path.getsize(abs_path)
            if size > _MAX_BODY_FILE_SIZE:
                logger.error(
                    "response_body_file '%s' is %d bytes (max %d); "
                    "falling back to response_body string.",
                    abs_path, size, _MAX_BODY_FILE_SIZE,
                )
            else:
                with open(abs_path, encoding="utf-8") as fh:
                    return fh.read()
        except OSError as exc:
            logger.warning("response_body_file '%s' could not be read: %s; "
                           "falling back to response_body string.", abs_path, exc)
    return str(config.get("response_body", _DEFAULT_BODY))


@dataclass(frozen=True)
class _HandlerConfig:
    """Immutable configuration bundle for FakeHTTPHandler."""
    response_code: int = 200
    response_body: bytes = b""
    server_header: str = _DEFAULT_SERVER_HEADER
    log_requests: bool = True
    spoof_ip: str = ""
    delay_ms: int = 0
    delay_jitter_ms: int = 0
    dynamic_responses: bool = False
    custom_rules: list[CompiledRule] = field(default_factory=list)
    doh_enabled: bool = False
    doh_redirect_ip: str = "127.0.0.1"
    websocket_intercept: bool = False
    pool_ips: frozenset[str] = field(default_factory=frozenset)
    exfil_log_dir: str = "logs/exfil"


def _build_handler_config(
    response_code: int, response_body: str, server_header: str,
    log_requests: bool, spoof_ip: str = "", delay_ms: int = 0,
    delay_jitter_ms: int = 0,
    dynamic_responses: bool = False, custom_rules: list[dict[str, Any]] | None = None,
    doh_enabled: bool = False, doh_redirect_ip: str = "127.0.0.1",
    websocket_intercept: bool = False,
    pool_ips: frozenset[str] = frozenset(),
    exfil_log_dir: str = "logs/exfil",
) -> _HandlerConfig:
    """Build an immutable handler configuration bundle."""
    return _HandlerConfig(
        response_code=response_code,
        response_body=response_body.encode("utf-8", errors="replace"),
        server_header=server_header,
        log_requests=log_requests,
        spoof_ip=spoof_ip,
        delay_ms=delay_ms,
        delay_jitter_ms=delay_jitter_ms,
        dynamic_responses=dynamic_responses,
        custom_rules=compile_custom_rules(custom_rules or []),
        doh_enabled=doh_enabled,
        doh_redirect_ip=doh_redirect_ip,
        websocket_intercept=websocket_intercept,
        pool_ips=pool_ips,
        exfil_log_dir=exfil_log_dir,
    )


# (handler, host) -> bool. Predicates decide; route handlers return True if they responded.
_RouteFn = Callable[["FakeHTTPHandler", str], bool]

class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler — reads config from the owning server instance."""

    @property
    def _cfg(self) -> _HandlerConfig:
        return getattr(self.server, '_handler_cfg', _HandlerConfig())

    protocol_version = "HTTP/1.1"
    server_version = ""

    def send_response(self, code: int, message: str | None = None) -> None:
        """Override to suppress Python's auto-injected Server header."""
        if message is None:
            message = self.responses[code][0] if code in self.responses else ""
        if self.request_version != "HTTP/0.9":
            if not hasattr(self, "_headers_buffer"):
                self._headers_buffer = []
            self._headers_buffer.append(
                f"{self.protocol_version} {code} {message}\r\n"
                .encode("latin-1", "strict")
            )
        self.log_request(code)
        self.send_header("Date", self.date_time_string())

    def log_message(self, _format: str, *_args: Any) -> None:
        pass  # suppress default stderr logging

    def _send_ip_check_response(self, host: str) -> None:
        """Return the spoofed public IP for known IP-check services."""
        path = self.path or "/"
        ip = self._cfg.spoof_ip or "203.0.113.1"

        formatter = _IP_CHECK_FORMATTERS.get(host)
        if formatter:
            body, content_type, extra_headers = formatter(ip, path)
        elif "format=json" in path or path.rstrip("/").endswith("/json"):
            body = f'{{"ip":"{ip}"}}\n'.encode()
            content_type = _CT_JSON
            extra_headers = None
        else:
            body = f"{ip}\n".encode()
            content_type = _CT_PLAIN
            extra_headers = None

        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  IP-CHECK %s%s from %s \u2192 spoofed %s",
                sanitize_log_string(host),
                sanitize_log_string(path, 128),
                safe_addr,
                ip,
            )
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            if not extra_headers or "Server" not in extra_headers:
                self.send_header("Server", self._cfg.server_header)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def _handle_generate_204(self) -> None:
        """Google / Android / ChromeOS connectivity probe: 204 No Content."""
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info("HTTP  CAPTIVE generate_204 from %s", safe_addr)
        try:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Server", "GFE/2.0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
        except OSError:
            pass

    def _handle_apple_captive(self, path: str) -> bool:
        """Apple captive portal / hotspot detection; returns True if handled."""
        if "/hotspot-detect.html" not in path and "/library/test/success.html" not in path:
            return False
        body = b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  CAPTIVE apple %s from %s",
                sanitize_log_string(path, 64), safe_addr,
            )
        try:
            self.send_response(200)
            self.send_header("Content-Type", _CT_HTML)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "AkamaiGHost")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    def _send_captive_portal_response(self, host: str) -> bool:
        """Handle OS-level captive portal and connectivity checks.

        Returns True if the request was handled, False to fall through.
        """
        path = (self.path or "/").split("?")[0]

        if path == "/generate_204":
            self._handle_generate_204()
            return True

        if host in ("captive.apple.com", "www.apple.com"):
            return self._handle_apple_captive(path)

        return False
    def _send_ncsi_response(self, host: str) -> None:
        """Return the exact response Windows NCSI expects.

        Windows polls these hosts to determine whether to show the
        'Internet access' indicator. When the response body matches
        exactly, Windows reports full connectivity — which prevents
        certain malware from stalling in a 'no network' idle loop.
        """
        path = (self.path or "/").split("?")[0]
        # www.msftconnecttest.com/redirect should return HTTP 302 → HTTPS.
        # Returning 200+body here triggers mismatches in NCSI validator
        # tools and is a detectable fingerprint for savvy malware.
        if path == "/redirect":
            if self._cfg.log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    "HTTP  NCSI %s/redirect from %s \u2192 302",
                    sanitize_log_string(host),
                    safe_addr,
                )
            try:
                self.send_response(302)
                self.send_header("Location", f"https://{host}/redirect")
                self.send_header("Content-Length", "0")
                self.send_header("Server", self._cfg.server_header)
                self.send_header("Connection", "close")
                self.end_headers()
            except OSError:
                pass
            return
        body = _NCSI_RESPONSES.get(host, b"Microsoft Connect Test")
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  NCSI %s from %s \u2192 %s",
                sanitize_log_string(host),
                safe_addr,
                body.decode(),
            )
        try:
            self.send_response(200)
            self.send_header("Content-Type", _CT_PLAIN)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self._cfg.server_header)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def _send_pki_response(self, host: str) -> None:
        """Return stub CRL/OCSP/CTL binary responses for Windows PKI hosts."""
        path = self.path or "/"
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  PKI %s%s from %s",
                sanitize_log_string(host),
                sanitize_log_string(path, 128),
                safe_addr,
            )
        status, body, content_type = _resolve_pki_response(host, path)
        try:
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self._cfg.server_header)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except OSError:
            pass

    def _handle_doh_request(self) -> None:
        """Handle a DNS-over-HTTPS (DoH) request and return a DNS response."""
        if not route_doh(self, _MAX_BODY_FILE_SIZE):
            # Couldn't parse DoH — fall through to normal response
            self._send_normal_response()

    def _handle_websocket_upgrade(self) -> None:
        """Complete a WebSocket handshake then send a close frame."""
        if not route_websocket_upgrade(self):
            self._send_normal_response()

    # ── Route registry ────────────────────────────────────────────────
    # Each entry: (predicate(self, host) -> bool, handler(self, host) -> bool|None).
    # Handler returns True (or None) if it consumed the request, False to
    # fall through. Evaluated in priority order; first match wins.
    _ROUTES: list[tuple[_RouteFn, _RouteFn]] = []  # populated after class body

    def _route_doh(self, _host: str) -> bool:
        ct = self.headers.get("Content-Type", "")
        if is_doh_request(ct, self.path):
            self._handle_doh_request()
            return True
        return False

    def _route_websocket(self, _host: str) -> bool:
        hdrs = {k: self.headers.get(k, "") for k in ("Connection", "Upgrade", "Sec-WebSocket-Key")}
        if is_websocket_upgrade(hdrs):
            self._handle_websocket_upgrade()
            return True
        return False

    def _route_ncsi(self, host: str) -> bool:
        self._send_ncsi_response(host)
        return True

    def _route_captive(self, host: str) -> bool:
        return self._send_captive_portal_response(host)

    def _route_pki(self, host: str) -> bool:
        self._send_pki_response(host)
        return True

    def _route_ip_check(self, host: str) -> bool:
        self._send_ip_check_response(host)
        return True

    def _route_telegram(self, _host: str) -> bool:
        return route_telegram(self, _MAX_BODY_FILE_SIZE, _CT_JSON)

    # ── Discord webhook route ─────────────────────────────────────────────
    def _route_discord(self, _host: str) -> bool:
        return route_discord(self, _MAX_BODY_FILE_SIZE, _CT_JSON)

    # ── Pastebin / paste dead-drop route ──────────────────────────────────
    def _route_paste(self, host: str) -> bool:
        return route_dead_drop_ip(self, "paste_dead_drop", host, "nginx")

    # ── Slack webhook route ───────────────────────────────────────────────
    def _route_slack(self, _host: str) -> bool:
        return route_simple_text(
            self,
            event_name="slack_c2",
            body=b"ok",
            content_type=_CT_HTML,
            server="Apache",
            status=200,
        )

    # ── Teams webhook route ───────────────────────────────────────────────
    def _route_teams(self, _host: str) -> bool:
        return route_simple_text(
            self,
            event_name="teams_c2",
            body=b"1",
            content_type=_CT_PLAIN,
            server="Microsoft-IIS/10.0",
            status=202,
        )

    # ── GitHub raw content route ──────────────────────────────────────────
    def _route_github_raw(self, host: str) -> bool:
        return route_dead_drop_ip(self, "github_dead_drop", host, "github.com")

    # ── File-hosting / payload-staging route ───────────────────────────────
    def _route_file_hosting(self, host: str) -> bool:
        return route_file_hosting(self, host)

    # ── Google Docs/Drive route ───────────────────────────────────────────
    def _route_google_content(self, host: str) -> bool:
        return route_google_content(self, host)

    # ── Cloud exfiltration routes ─────────────────────────────────────────
    def _route_aws_s3(self, host: str) -> bool:
        return route_aws_s3(self, host)

    def _route_azure_blob(self, host: str) -> bool:
        return route_azure_blob(self, host)

    def _route_graph_onedrive(self, _host: str) -> bool:
        return route_graph_onedrive(self)

    def _route_dropbox(self, _host: str) -> bool:
        return route_dropbox(self)

    def _route_gdrive_upload(self, host: str) -> bool:
        return route_gdrive_upload(self)

    def _send_fake_response(self) -> None:
        host = self.headers.get("Host", "").split(":")[0].strip().lower()

        # Skip artificial delay for OS connectivity probes.
        _probe_host = host in _NCSI_HOSTS or host in _PKI_HOSTS or host in _CAPTIVE_PORTAL_HOSTS
        if self._cfg.delay_ms > 0 and not _probe_host:
            jitter = self._cfg.delay_jitter_ms
            actual = (
                self._cfg.delay_ms + random.randint(-jitter, jitter)  # noqa: S311  # nosec B311
                if jitter > 0
                else self._cfg.delay_ms
            )
            time.sleep(max(0, actual) / 1000.0)

        # Iterate the route registry; first matching handler wins.
        for predicate, handler in self._ROUTES:
            if predicate(self, host) and handler(self, host):
                return
        self._send_normal_response()

    def _send_normal_response(self) -> None:
        if self._cfg.log_requests:
            safe_path = sanitize_log_string(self.path, max_length=256)
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  %s %s from %s",
                sanitize_log_string(self.command), safe_path, safe_addr,
            )

        # Structured JSON logging
        jl = get_json_logger()
        if jl:
            jl.log("http_request",
                   method=self.command or "",
                   path=self.path or "/",
                   src_ip=self.client_address[0],
                   host=self.headers.get("Host", ""),
                   user_agent=self.headers.get("User-Agent", ""),
                   content_type=self.headers.get("Content-Type", ""))

        # --- Dynamic response: match path to MIME type + stub body ---
        if self._cfg.dynamic_responses:
            content_type, body = resolve_dynamic_response(
                self.path or "/",
                custom_rules=self._cfg.custom_rules,
                fallback_body=self._cfg.response_body,
            )
        else:
            content_type = "text/html; charset=utf-8"
            body = self._cfg.response_body

        try:
            self.send_response(self._cfg.response_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self._cfg.server_header)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Vary", "Accept-Encoding")
            # ETag varies per path — a single static value for every URL is
            # a detectable fingerprint (real servers use inode/mtime/size).
            _path_etag = hashlib.md5(  # noqa: S324  # nosec B324 — not crypto
                (self.path or "/").encode(), usedforsecurity=False
            ).hexdigest()[:13]
            self.send_header("ETag", f'"3a4b1c-{_path_etag}"')
            self.send_header("Last-Modified", _SERVER_LAST_MODIFIED)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            # HEAD requests MUST NOT include a message body (RFC 7231 §4.3.2).
            # send_response() / send_header() still ran, so headers are correct.
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass  # Client disconnected — normal for malware scanners

    def _send_connect_response(self) -> None:
        """Handle HTTP CONNECT tunnel request.

        Malware configured to route traffic via an HTTP proxy sends
        CONNECT to tunnel to its C2 (typically port 443).  Returning
        a proper 200 response — rather than an HTML page — lets the
        malware believe the tunnel was established; the subsequent TLS
        handshake fails (no real upstream), but the connection is logged
        and the client closes cleanly instead of seeing garbled HTML.
        """
        safe_addr = sanitize_ip(self.client_address[0])
        target = sanitize_log_string(self.path or "", 256)
        if self._cfg.log_requests:
            logger.info("HTTP  CONNECT %s from %s", target, safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("http_connect", src_ip=self.client_address[0],
                   target=self.path or "")
        try:
            self.wfile.write(
                f"{self.protocol_version} 200 Connection established\r\n\r\n".encode()
            )
            self.wfile.flush()
            # Drain the incoming stream (TLS handshake bytes, app data, etc.)
            # until the client closes the connection.
            self.request.settimeout(30)
            while self.request.recv(4096):
                pass  # drain until client closes
        except OSError:
            pass  # client disconnected during CONNECT tunnel drain

    # Respond identically to most methods; CONNECT is special-cased because
    # it must not return headers/body in the normal HTTP sense.
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = \
        do_OPTIONS = do_PATCH = do_TRACE = _send_fake_response
    do_CONNECT = _send_connect_response

    # First line of the HTTP/2 client connection preface (RFC 7540 §3.5).
    _HTTP2_PREFACE_LINE = b"PRI * HTTP/2.0"

    def _handle_http2_goaway(self) -> None:
        """
        Respond to an HTTP/2 connection preface with a server SETTINGS
        frame followed by GOAWAY(HTTP_1_1_REQUIRED).

        RFC 7540 §3.5  — the server sends its own connection preface
                         (a SETTINGS frame) before any other frame.
        RFC 7540 §6.8  — GOAWAY carries the last processed stream ID
                         and an error code.
        Error 0x0D (HTTP_1_1_REQUIRED) tells the client to retry the
        request using HTTP/1.1 rather than h2.  Well-behaved HTTP/2
        clients will reconnect and fall back to http/1.1 via ALPN.
        """
        try:
            # The first readline() consumed "PRI * HTTP/2.0\r\n" (16 bytes).
            # The remaining preface bytes are "\r\nSM\r\n\r\n" = 8 bytes.
            self.rfile.read(8)
        except OSError:
            return
        try:
            # Empty SETTINGS frame — server connection preface (RFC 7540 §6.5)
            settings_frame = (
                b"\x00\x00\x00"       # payload length: 0
                b"\x04"               # frame type: SETTINGS
                b"\x00"               # no flags
                b"\x00\x00\x00\x00"  # stream ID: 0
            )
            # GOAWAY: last_stream_id=0, error=HTTP_1_1_REQUIRED (0x0D)
            goaway_frame = (
                b"\x00\x00\x08"       # payload length: 8
                b"\x07"               # frame type: GOAWAY
                b"\x00"               # no flags
                b"\x00\x00\x00\x00"  # stream ID: 0
                b"\x00\x00\x00\x00"  # last stream ID: 0
                b"\x00\x00\x00\x0d"  # error code 0x0D (HTTP_1_1_REQUIRED)
            )
            self.wfile.write(settings_frame + goaway_frame)
            self.wfile.flush()
        except OSError:
            pass

    def handle_one_request(self) -> None:
        try:
            # Read the request line ourselves so we can inspect it before
            # parse_request() sees it — needed for HTTP/2 preface detection.
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = True
                return
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                self.close_connection = True
                return
            # HTTP/2 connection preface (RFC 7540 §3.5): respond with
            # SETTINGS + GOAWAY(HTTP_1_1_REQUIRED) and close.
            if self.raw_requestline.startswith(self._HTTP2_PREFACE_LINE):
                safe_addr = sanitize_ip(self.client_address[0])
                logger.debug("HTTP2 preface from %s -> GOAWAY(HTTP_1_1_REQUIRED)", safe_addr)
                self._handle_http2_goaway()
                self.close_connection = True
                return
            if not self.parse_request():
                return
            # Explicit allowlist prevents do___init__ style attribute probing
            # and gives a clean 501 for genuinely unknown HTTP methods.
            _known_methods = frozenset({
                "GET", "POST", "PUT", "DELETE", "HEAD",
                "OPTIONS", "PATCH", "TRACE", "CONNECT",
            })
            if self.command not in _known_methods:
                self.send_error(501, f"Unsupported method ({self.command!r})")
                return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(501, f"Unsupported method ({self.command!r})")
                return
            getattr(self, mname)()
            self.wfile.flush()
        except Exception as e:  # noqa: BLE001
            logger.debug("HTTP handler error (benign): %s", e)
            self.close_connection = True


# Populate route registry after class body so method refs are valid.
# noqa comments suppress SLF001 (intra-module access to own class members).
FakeHTTPHandler._ROUTES = [  # noqa: SLF001
    (lambda s, h: s._cfg.doh_enabled,                           FakeHTTPHandler._route_doh),           # noqa: SLF001
    (lambda s, h: s._cfg.websocket_intercept,                   FakeHTTPHandler._route_websocket),      # noqa: SLF001
    (lambda s, h: h in _NCSI_HOSTS,                             FakeHTTPHandler._route_ncsi),           # noqa: SLF001
    (lambda s, h: h in _CAPTIVE_PORTAL_HOSTS,                   FakeHTTPHandler._route_captive),        # noqa: SLF001
    (lambda s, h: h in _PKI_HOSTS,                              FakeHTTPHandler._route_pki),            # noqa: SLF001
    (lambda s, h: h in _IP_CHECK_HOSTS or h in s._cfg.pool_ips, FakeHTTPHandler._route_ip_check),      # noqa: SLF001
    (lambda s, h: h == _TELEGRAM_HOST,                          FakeHTTPHandler._route_telegram),       # noqa: SLF001
    (lambda s, h: h in _DISCORD_HOSTS,                          FakeHTTPHandler._route_discord),        # noqa: SLF001
    (lambda s, h: h in _PASTE_HOSTS,                            FakeHTTPHandler._route_paste),          # noqa: SLF001
    (lambda s, h: h == _SLACK_HOST,                             FakeHTTPHandler._route_slack),          # noqa: SLF001
    (lambda s, h: h in _TEAMS_HOSTS or bool(_TEAMS_WEBHOOK_RE.search(h)),
                                                                FakeHTTPHandler._route_teams),          # noqa: SLF001
    (lambda s, h: h in _GITHUB_RAW_HOSTS,                       FakeHTTPHandler._route_github_raw),     # noqa: SLF001
    (lambda s, h: h in _FILE_HOSTING_HOSTS,                     FakeHTTPHandler._route_file_hosting),   # noqa: SLF001
    (lambda s, h: h in _GOOGLE_CONTENT_HOSTS,                   FakeHTTPHandler._route_google_content), # noqa: SLF001
    # Cloud exfil: placed after google content so non-upload googleapis paths
    # are handled by the dead-drop route; gdrive_upload returns False for those.
    (lambda s, h: bool(_AWS_S3_RE.search(h)),                    FakeHTTPHandler._route_aws_s3),          # noqa: SLF001
    (lambda s, h: bool(_AZURE_BLOB_RE.search(h)),                FakeHTTPHandler._route_azure_blob),      # noqa: SLF001
    (lambda s, h: h == _GRAPH_HOST,                              FakeHTTPHandler._route_graph_onedrive),  # noqa: SLF001
    (lambda s, h: h in _DROPBOX_HOSTS,                           FakeHTTPHandler._route_dropbox),         # noqa: SLF001
    (lambda s, h: h == "www.googleapis.com",                     FakeHTTPHandler._route_gdrive_upload),   # noqa: SLF001
]


class _ThreadedServer(socketserver.ThreadingTCPServer):
    """TCP server using a bounded thread pool."""
    allow_reuse_address = True
    daemon_threads = True
    _handler_cfg: _HandlerConfig = _HandlerConfig()

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._pool = ThreadPoolExecutor(max_workers=_MAX_WORKER_THREADS)
        super().__init__(*args, **kwargs)

    # TCP-only server: request is always a socket, narrower than the stdlib stub.
    def process_request(  # type: ignore[override]
        self, request: socket.socket, client_address: tuple[str, int],
    ) -> None:
        self._pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(  # type: ignore[override]
        self, request: socket.socket, client_address: tuple[str, int],
    ) -> None:
        # Set a read timeout before handing the socket to the handler.
        # Without this, a client that negotiates h2 via ALPN but never sends
        # the connection preface holds a pool worker indefinitely.
        with contextlib.suppress(OSError):
            request.settimeout(30)
        super().process_request_thread(request, client_address)

    def server_close(self) -> None:
        self._pool.shutdown(wait=False)
        super().server_close()


class HTTPService:
    """Fake HTTP server that returns a canned response to everything."""

    def __init__(self, config: dict[str, Any], bind_ip: str = "0.0.0.0") -> None:
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 80))
        self.bind_ip = bind_ip
        self.response_code = int(config.get("response_code", 200))
        self.response_body = _load_response_body(config)
        self.server_header = config.get("server_header", _DEFAULT_SERVER_HEADER)
        self.log_requests = config.get("log_requests", True)
        raw_spoof = str(config.get("spoof_public_ip", "") or "").strip()
        self.spoof_ip = _validate_spoof_ip(raw_spoof, "http")
        self.delay_ms = int(config.get("response_delay_ms", 0) or 0)
        self.delay_jitter_ms = int(config.get("response_delay_jitter_ms", 0) or 0)
        self.dynamic_responses = config.get("dynamic_responses", False)
        self.custom_rules = config.get("dynamic_response_rules", [])
        self.doh_enabled = config.get("doh_intercept", False)
        self.doh_redirect_ip = config.get("doh_redirect_ip", "127.0.0.1")
        self.websocket_intercept = config.get("websocket_intercept", False)
        self.exfil_log_dir = config.get("exfil_log_dir", "logs/exfil")
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        cfg = _build_handler_config(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
            delay_jitter_ms=self.delay_jitter_ms,
            dynamic_responses=self.dynamic_responses,
            custom_rules=self.custom_rules,
            doh_enabled=self.doh_enabled,
            doh_redirect_ip=self.doh_redirect_ip,
            websocket_intercept=self.websocket_intercept,
            exfil_log_dir=self.exfil_log_dir,
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), FakeHTTPHandler)
            self._server._handler_cfg = cfg  # noqa: SLF001
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("HTTP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("HTTP service failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            with contextlib.suppress(OSError):
                self._server.socket.shutdown(socket.SHUT_RDWR)
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class HTTPSService:
    """Fake HTTPS server with hardened TLS configuration."""

    def __init__(self, config: dict[str, Any], bind_ip: str = "0.0.0.0") -> None:
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 443))
        self.bind_ip = bind_ip
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
        self.response_code = int(config.get("response_code", 200))
        self.response_body = _load_response_body(config)
        self.server_header = config.get("server_header", _DEFAULT_SERVER_HEADER)
        self.log_requests = config.get("log_requests", True)
        raw_spoof = str(config.get("spoof_public_ip", "") or "").strip()
        self.spoof_ip = _validate_spoof_ip(raw_spoof, "https")
        self.delay_ms = int(config.get("response_delay_ms", 0) or 0)
        self.delay_jitter_ms = int(config.get("response_delay_jitter_ms", 0) or 0)
        self.dynamic_responses = config.get("dynamic_responses", False)
        self.custom_rules = config.get("dynamic_response_rules", [])
        self.dynamic_certs = config.get("dynamic_certs", False)
        self.doh_enabled = config.get("doh_intercept", False)
        self.doh_redirect_ip = config.get("doh_redirect_ip", "127.0.0.1")
        self.websocket_intercept = config.get("websocket_intercept", False)
        self.exfil_log_dir = config.get("exfil_log_dir", "logs/exfil")
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """
        Build a hardened SSLContext.
        - TLSv1.2 minimum
        - OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_TLSv1, OP_NO_TLSv1_1
        - Strong cipher list, no export / null / anonymous
        - ALPN: h2 + http/1.1 (matches real Apache 2.4 behaviour)
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= (
            ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_CIPHER_SERVER_PREFERENCE
            | ssl.OP_SINGLE_DH_USE
            | ssl.OP_SINGLE_ECDH_USE
        )
        ctx.set_ciphers(_SECURE_CIPHERS)
        # Advertise h2 + http/1.1 via ALPN — matches real Apache 2.4.x ServerHello.
        # When h2 is negotiated the handler detects the connection preface and
        # sends GOAWAY(HTTP_1_1_REQUIRED) so the client retries on HTTP/1.1.
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def start(self) -> bool:
        if not self.enabled:
            return False

        # Auto-generate certs if missing
        ensure_certs(self.cert_file, self.key_file)

        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.error(
                "HTTPS cert/key not found: %s / %s", self.cert_file, self.key_file
            )
            return False

        cfg = _build_handler_config(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
            delay_jitter_ms=self.delay_jitter_ms,
            dynamic_responses=self.dynamic_responses,
            custom_rules=self.custom_rules,
            doh_enabled=self.doh_enabled,
            doh_redirect_ip=self.doh_redirect_ip,
            websocket_intercept=self.websocket_intercept,
            exfil_log_dir=self.exfil_log_dir,
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), FakeHTTPHandler)
            self._server._handler_cfg = cfg  # noqa: SLF001
            ssl_ctx = self._build_ssl_context()
            if self.dynamic_certs:
                from utils.cert_utils import DynamicCertCache
                self._cert_cache = DynamicCertCache(
                    self.cert_file, self.key_file
                )
                ssl_ctx.sni_callback = self._cert_cache.sni_callback
            self._server.socket = ssl_ctx.wrap_socket(
                self._server.socket, server_side=True
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "HTTPS service started on %s:%s (TLS 1.2+ enforced)",
                self.bind_ip, self.port,
            )
            return True
        except ssl.SSLError as e:
            logger.error("HTTPS TLS setup error: %s", e)
            return False
        except OSError as e:
            logger.error("HTTPS service failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            with contextlib.suppress(OSError):
                self._server.socket.shutdown(socket.SHUT_RDWR)
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
