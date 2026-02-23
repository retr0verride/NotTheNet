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
import json
import logging
import os
import ssl
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from utils.logging_utils import sanitize_log_string, sanitize_ip
from utils.cert_utils import ensure_certs

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


def _make_handler(response_code: int, response_body: str, server_header: str, log_requests: bool):
    """Factory: create a BaseHTTPRequestHandler subclass with captured config."""

    class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
        _response_code = response_code
        _response_body = response_body.encode("utf-8", errors="replace")
        _server_header = server_header
        _log_requests = log_requests

        # Suppress default BaseHTTPServer stderr logging (we do our own)
        def log_message(self, fmt, *args):
            pass

        def _send_fake_response(self):
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
        self.response_body = config.get(
            "response_body", "<html><body><h1>200 OK</h1></body></html>"
        )
        self.server_header = config.get("server_header", "Apache/2.4.51")
        self.log_requests = config.get("log_requests", True)
        self._server: Optional[_ThreadedServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        handler = _make_handler(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
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
        self.response_body = config.get(
            "response_body", "<html><body><h1>200 OK</h1></body></html>"
        )
        self.server_header = config.get("server_header", "Apache/2.4.51")
        self.log_requests = config.get("log_requests", True)
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
