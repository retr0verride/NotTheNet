"""
NotTheNet - HTTP / HTTPS Fake Server
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

import http.server
import logging
import os
import select
import socketserver
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from services.doh_websocket import (
    DOH_CONTENT_TYPE,
    build_websocket_close_frame,
    build_websocket_handshake_response,
    handle_doh_get,
    handle_doh_post,
    is_doh_request,
    is_websocket_upgrade,
)
from services.dynamic_response import compile_custom_rules, resolve_dynamic_response
from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

# Bounded thread pool — prevents resource exhaustion from flooded connections
_MAX_WORKER_THREADS = 50

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

# Well-known public-IP-check services. When spoof_public_ip is set and a
# request Host header matches one of these, the handler returns the spoofed
# IP instead of the normal response body. This defeats the most common
# sandbox-evasion technique of checking "am I on the real internet?".
_IP_CHECK_HOSTS = frozenset({
    "api.ipify.org", "api4.ipify.org", "api6.ipify.org",
    "icanhazip.com", "ipv4.icanhazip.com",
    "checkip.amazonaws.com",
    "ifconfig.me", "ifconfig.io",
    "ip.me",
    "wtfismyip.com",
    "ipecho.net",
    "ident.me", "v4.ident.me",
    "ipinfo.io",
    "api.my-ip.io",
    "checkip.dyndns.org", "checkip.dyndns.com",
    "eth0.me",
    "ip4.seeip.org",
    "myexternalip.com",
    "httpbin.org",
    "ip-api.com",
})

# Windows Network Connectivity Status Indicator (NCSI) endpoints.
# Windows queries these to determine whether the "Internet access" indicator
# is shown in the system tray.  Some malware waits for NCSI to report
# connectivity before detonating.  The responses MUST be exact byte-for-byte
# matches of what a real Microsoft server returns.
_NCSI_HOSTS = frozenset({
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
})
_NCSI_RESPONSES: dict[str, bytes] = {
    "msftconnecttest.com":      b"Microsoft Connect Test",
    "ipv6.msftconnecttest.com": b"Microsoft Connect Test",
    "www.msftncsi.com":         b"Microsoft NCSI",
}


_MAX_BODY_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def _load_response_body(config: dict) -> str:
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
        abs_path = os.path.join(project_root, file_path)
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
            logger.warning(f"response_body_file '{abs_path}' could not be read: {exc}; "
                           "falling back to response_body string.")
    return config.get("response_body", _DEFAULT_BODY)


def _make_handler(response_code: int, response_body: str, server_header: str,
                  log_requests: bool, spoof_ip: str = "", delay_ms: int = 0,
                  dynamic_responses: bool = False, custom_rules: list | None = None,
                  doh_enabled: bool = False, doh_redirect_ip: str = "127.0.0.1",
                  websocket_sinkhole: bool = False):
    """Factory: create a BaseHTTPRequestHandler subclass with captured config."""

    class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
        _response_code = response_code
        _response_body = response_body.encode("utf-8", errors="replace")
        _server_header = server_header
        _log_requests = log_requests
        _spoof_ip = spoof_ip
        _delay_ms = delay_ms
        _dynamic_responses = dynamic_responses
        _custom_rules = compile_custom_rules(custom_rules or [])
        _doh_enabled = doh_enabled
        _doh_redirect_ip = doh_redirect_ip
        _websocket_sinkhole = websocket_sinkhole

        # Prevent send_response() from prepending its own
        # "Server: BaseHTTP/0.6 Python/3.x" header before ours.  Without
        # this, every response carries two Server headers — an obvious
        # fingerprint that sandbox-detection tools check for.
        server_version = ""

        def send_response(self, code, message=None):
            """Override to suppress Python's auto-injected Server header.

            Python's BaseHTTPRequestHandler.send_response() unconditionally
            calls send_header('Server', self.version_string()), which emits
            'Server:  Python/3.x.y' even when server_version is set to "".
            This would create two Server headers in every response — the
            Python one and the spoofed 'Apache/...' one we add explicitly.
            We reproduce the same status-line + Date logic without the Server
            header so only our explicit Server declaration is transmitted.
            """
            if message is None:
                if code in self.responses:
                    message = self.responses[code][0]
                else:
                    message = ""
            if self.request_version != "HTTP/0.9":
                if not hasattr(self, "_headers_buffer"):
                    self._headers_buffer = []
                self._headers_buffer.append(
                    f"{self.protocol_version} {code} {message}\r\n"
                    .encode("latin-1", "strict")
                )
            self.log_request(code)
            # Add Date (required by HTTP/1.1) but NOT the Python Server header.
            self.send_header("Date", self.date_time_string())

        # Suppress default BaseHTTPServer stderr logging (we do our own)
        def log_message(self, fmt, *args):
            pass

        def _send_ip_check_response(self, host: str):
            """Return the spoofed public IP for known IP-check services."""
            path = self.path or "/"
            ip = self._spoof_ip

            # ipinfo.io — returns detailed JSON including ISP/org.
            # Malware often checks the 'org' field for datacenter/hosting ASNs
            # to detect sandboxes; we return a realistic residential ISP.
            if host == "ipinfo.io":
                body = (
                    f'{{"ip":"{ip}",'
                    f'"city":"Columbus","region":"Ohio","country":"US",'
                    f'"loc":"39.9612,-82.9988",'
                    f'"org":"AS7922 Comcast Cable Communications, LLC",'
                    f'"postal":"43215","timezone":"America/New_York"}}\n'
                ).encode()
                content_type = "application/json"
            # ip-api.com — its /json endpoint returns an expanded object.
            elif host == "ip-api.com":
                body = (
                    f'{{"status":"success","country":"United States",'
                    f'"countryCode":"US","region":"OH","regionName":"Ohio",'
                    f'"city":"Columbus","zip":"43215",'
                    f'"lat":39.9612,"lon":-82.9988,'
                    f'"timezone":"America/New_York",'
                    f'"isp":"Comcast Cable Communications",'
                    f'"org":"Comcast Cable Communications",'
                    f'"as":"AS7922 Comcast Cable Communications, LLC",'
                    f'"query":"{ip}"}}\n'
                ).encode()
                content_type = "application/json"
            # httpbin.org/ip uses {"origin": "..."}
            elif host == "httpbin.org":
                body = f'{{"origin":"{ip}"}}\n'.encode()
                content_type = "application/json"
            # ipify ?format=json or URL ending in /json
            elif "format=json" in path or path.rstrip("/").endswith("/json"):
                body = f'{{"ip":"{ip}"}}\n'.encode()
                content_type = "application/json"
            else:
                body = f"{ip}\n".encode()
                content_type = "text/plain"
            if self._log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  IP-CHECK {sanitize_log_string(host)}"
                    f"{sanitize_log_string(path, 128)} "
                    f"from {safe_addr} \u2192 spoofed {ip}"
                )
            try:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_ncsi_response(self, host: str):
            """Return the exact response Windows NCSI expects.

            Windows polls these hosts to determine whether to show the
            'Internet access' indicator. When the response body matches
            exactly, Windows reports full connectivity — which prevents
            certain malware from stalling in a 'no network' idle loop.
            """
            body = _NCSI_RESPONSES.get(host, b"Microsoft Connect Test")
            if self._log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  NCSI {sanitize_log_string(host)} "
                    f"from {safe_addr} \u2192 {body.decode()}"
                )
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _handle_doh_request(self):
            """Handle a DNS-over-HTTPS (DoH) request and return a DNS response."""
            safe_addr = sanitize_ip(self.client_address[0])
            path = self.path or "/"
            if self.command == "GET":
                response_data = handle_doh_get(path, self._doh_redirect_ip)
            else:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else b""
                response_data = handle_doh_post(body, self._doh_redirect_ip)

            if response_data:
                if self._log_requests:
                    logger.info(f"DoH   request from {safe_addr} -> sinkholed")
                jl = get_json_logger()
                if jl:
                    jl.log("doh_request", src_ip=self.client_address[0],
                           method=self.command or "", path=self.path or "/")
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", DOH_CONTENT_TYPE)
                    self.send_header("Content-Length", str(len(response_data)))
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Server", self._server_header)
                    self.end_headers()
                    self.wfile.write(response_data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                # Couldn't parse DoH — fall through to normal response
                self._send_normal_response()

        def _handle_websocket_upgrade(self):
            """Complete a WebSocket handshake then send a close frame."""
            safe_addr = sanitize_ip(self.client_address[0])
            ws_key = self.headers.get("Sec-WebSocket-Key", "")
            if not ws_key:
                self._send_normal_response()
                return

            if self._log_requests:
                safe_path = sanitize_log_string(self.path or "/", 256)
                logger.info(
                    f"WS    WebSocket upgrade from {safe_addr} "
                    f"path={safe_path} -> sinkholed"
                )
            jl = get_json_logger()
            if jl:
                jl.log("websocket_upgrade", src_ip=self.client_address[0],
                       path=self.path or "/")

            try:
                # Send 101 Switching Protocols
                handshake = build_websocket_handshake_response(ws_key)
                self.wfile.write(handshake)
                self.wfile.flush()

                # Drain up to 4KB of incoming WebSocket frames (log preview)
                readable, _, _ = select.select([self.rfile], [], [], 2.0)
                if readable:
                    try:
                        data = self.rfile.read1(4096) if hasattr(self.rfile, 'read1') else self.rfile.read(4096)
                        if data and self._log_requests:
                            preview = sanitize_log_string(
                                data[:64].hex(), 128
                            )
                            logger.debug(f"WS    received frame preview: {preview}")
                    except Exception:
                        pass

                # Send close frame
                close_frame = build_websocket_close_frame(1000, "sinkholed")
                self.wfile.write(close_frame)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def _send_fake_response(self):
            # Optional artificial delay (simulates realistic network latency,
            # defeats timing-based sandbox detection)
            if self._delay_ms > 0:
                time.sleep(self._delay_ms / 1000.0)

            # --- DNS over HTTPS (DoH) interception ---
            if self._doh_enabled:
                ct = self.headers.get("Content-Type", "")
                if is_doh_request(ct, self.path):
                    self._handle_doh_request()
                    return

            # --- WebSocket sinkhole ---
            if self._websocket_sinkhole:
                hdrs = {k: self.headers.get(k, "") for k in ("Connection", "Upgrade", "Sec-WebSocket-Key")}
                if is_websocket_upgrade(hdrs):
                    self._handle_websocket_upgrade()
                    return

            host = self.headers.get("Host", "").split(":")[0].strip().lower()

            # Windows NCSI: must respond correctly regardless of spoof_ip setting
            if host in _NCSI_HOSTS:
                self._send_ncsi_response(host)
                return

            # Public IP spoof: intercept well-known IP-check hostnames
            if self._spoof_ip and host in _IP_CHECK_HOSTS:
                self._send_ip_check_response(host)
                return
            self._send_normal_response()

        def _send_normal_response(self):
            if self._log_requests:
                safe_path = sanitize_log_string(self.path, max_length=256)
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  {sanitize_log_string(self.command)} {safe_path} "
                    f"from {safe_addr}"
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
            if self._dynamic_responses:
                content_type, body = resolve_dynamic_response(
                    self.path or "/",
                    custom_rules=self._custom_rules,
                    fallback_body=self._response_body,
                )
            else:
                content_type = "text/html; charset=utf-8"
                body = self._response_body

            try:
                self.send_response(self._response_code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "close")
                self.end_headers()
                # HEAD requests MUST NOT include a message body (RFC 7231 §4.3.2).
                # send_response() / send_header() still ran, so headers are correct.
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Client disconnected — normal for malware scanners

        def _send_connect_response(self):
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
            if self._log_requests:
                logger.info(f"HTTP  CONNECT {target} from {safe_addr} \u2192 tunnelled")
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
                    pass
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        # Respond identically to most methods; CONNECT is special-cased because
        # it must not return headers/body in the normal HTTP sense.
        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = \
            do_OPTIONS = do_PATCH = do_TRACE = _send_fake_response
        do_CONNECT = _send_connect_response

        def handle_one_request(self):
            try:
                super().handle_one_request()
            except Exception as e:
                logger.debug(f"HTTP handler error (benign): {e}")

    return FakeHTTPHandler


class _ThreadedServer(socketserver.ThreadingTCPServer):
    """TCP server using a bounded thread pool."""
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._pool = ThreadPoolExecutor(max_workers=_MAX_WORKER_THREADS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        self._pool.submit(self.process_request_thread, request, client_address)

    def server_close(self):
        self._pool.shutdown(wait=False)
        super().server_close()


class HTTPService:
    """Fake HTTP server that returns a canned response to everything."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 80))
        self.bind_ip = bind_ip
        self.response_code = int(config.get("response_code", 200))
        self.response_body = _load_response_body(config)
        self.server_header = config.get("server_header", "Apache/2.4.51")
        self.log_requests = config.get("log_requests", True)
        self.spoof_ip = str(config.get("spoof_public_ip", "") or "").strip()
        self.delay_ms = int(config.get("response_delay_ms", 0) or 0)
        self.dynamic_responses = config.get("dynamic_responses", False)
        self.custom_rules = config.get("dynamic_response_rules", [])
        self.doh_enabled = config.get("doh_sinkhole", False)
        self.doh_redirect_ip = config.get("doh_redirect_ip", "127.0.0.1")
        self.websocket_sinkhole = config.get("websocket_sinkhole", False)
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        handler = _make_handler(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
            dynamic_responses=self.dynamic_responses,
            custom_rules=self.custom_rules,
            doh_enabled=self.doh_enabled,
            doh_redirect_ip=self.doh_redirect_ip,
            websocket_sinkhole=self.websocket_sinkhole,
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"HTTP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"HTTP service failed to bind {self.bind_ip}:{self.port}: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class HTTPSService:
    """Fake HTTPS server with hardened TLS configuration."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 443))
        self.bind_ip = bind_ip
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
        self.response_code = int(config.get("response_code", 200))
        self.response_body = _load_response_body(config)
        self.server_header = config.get("server_header", "Apache/2.4.51")
        self.log_requests = config.get("log_requests", True)
        self.spoof_ip = str(config.get("spoof_public_ip", "") or "").strip()
        self.delay_ms = int(config.get("response_delay_ms", 0) or 0)
        self.dynamic_responses = config.get("dynamic_responses", False)
        self.custom_rules = config.get("dynamic_response_rules", [])
        self.dynamic_certs = config.get("dynamic_certs", False)
        self.doh_enabled = config.get("doh_sinkhole", False)
        self.doh_redirect_ip = config.get("doh_redirect_ip", "127.0.0.1")
        self.websocket_sinkhole = config.get("websocket_sinkhole", False)
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """
        Build a hardened SSLContext.
        - TLSv1.2 minimum
        - OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_TLSv1, OP_NO_TLSv1_1
        - Strong cipher list, no export / null / anonymous
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
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def start(self) -> bool:
        if not self.enabled:
            return False

        # Auto-generate certs if missing
        ensure_certs(self.cert_file, self.key_file)

        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.error(
                f"HTTPS cert/key not found: {self.cert_file} / {self.key_file}"
            )
            return False

        handler = _make_handler(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
            dynamic_responses=self.dynamic_responses,
            custom_rules=self.custom_rules,
            doh_enabled=self.doh_enabled,
            doh_redirect_ip=self.doh_redirect_ip,
            websocket_sinkhole=self.websocket_sinkhole,
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), handler)
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
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(
                f"HTTPS service started on {self.bind_ip}:{self.port} "
                f"(TLS 1.2+ enforced)"
            )
            return True
        except OSError as e:
            logger.error(f"HTTPS service failed to bind {self.bind_ip}:{self.port}: {e}")
            return False
        except ssl.SSLError as e:
            logger.error(f"HTTPS TLS setup error: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
