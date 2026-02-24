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

import http.server
import logging
import os
import socketserver
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from utils.cert_utils import ensure_certs
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
            with open(abs_path, encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            logger.warning(f"response_body_file '{abs_path}' could not be read: {exc}; "
                           "falling back to response_body string.")
    return config.get("response_body", _DEFAULT_BODY)


def _make_handler(response_code: int, response_body: str, server_header: str,
                  log_requests: bool, spoof_ip: str = "", delay_ms: int = 0):
    """Factory: create a BaseHTTPRequestHandler subclass with captured config."""

    class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
        _response_code = response_code
        _response_body = response_body.encode("utf-8", errors="replace")
        _server_header = server_header
        _log_requests = log_requests
        _spoof_ip = spoof_ip
        _delay_ms = delay_ms

        # Suppress default BaseHTTPServer stderr logging (we do our own)
        def log_message(self, fmt, *args):
            pass

        def _send_ip_check_response(self, host: str):
            """Return the spoofed public IP for known IP-check services."""
            path = self.path or "/"
            # httpbin.org/ip uses {"origin": "..."}
            if host == "httpbin.org":
                body = f'{{"origin":"{self._spoof_ip}"}}\n'.encode()
                content_type = "application/json"
            # ipify ?format=json or URL ending in /json
            elif "format=json" in path or path.rstrip("/").endswith("/json"):
                body = f'{{"ip":"{self._spoof_ip}"}}\n'.encode()
                content_type = "application/json"
            else:
                body = f"{self._spoof_ip}\n".encode()
                content_type = "text/plain"
            if self._log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  IP-CHECK {sanitize_log_string(host)}"
                    f"{sanitize_log_string(path, 128)} "
                    f"from {safe_addr} \u2192 spoofed {self._spoof_ip}"
                )
            try:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_fake_response(self):
            # Optional artificial delay (simulates realistic network latency,
            # defeats timing-based sandbox detection)
            if self._delay_ms > 0:
                time.sleep(self._delay_ms / 1000.0)
            # Public IP spoof: intercept well-known IP-check hostnames
            if self._spoof_ip:
                host = self.headers.get("Host", "").split(":")[0].strip().lower()
                if host in _IP_CHECK_HOSTS:
                    self._send_ip_check_response(host)
                    return
            if self._log_requests:
                safe_path = sanitize_log_string(self.path, max_length=256)
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  {sanitize_log_string(self.command)} {safe_path} "
                    f"from {safe_addr}"
                )
            try:
                self.send_response(self._response_code)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(self._response_body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(self._response_body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Client disconnected — normal for malware scanners

        # Respond identically to all methods
        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = \
            do_OPTIONS = do_PATCH = do_CONNECT = do_TRACE = _send_fake_response

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
        self._server: Optional[_ThreadedServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        handler = _make_handler(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
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
        self._server: Optional[_ThreadedServer] = None
        self._thread: Optional[threading.Thread] = None

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
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), handler)
            self._server.socket = self._build_ssl_context().wrap_socket(
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
