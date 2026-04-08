"""
NotTheNet - TCP/UDP Catch-All Service
Accepts connections on a catch-all port (redirected via iptables) and
responds with a protocol-aware response to keep malware engaged and
capture as much of its communication as possible.

Protocol detection (first-byte inspection):
  - HTTP  â†’ proper HTTP/1.1 200 OK response
  - TLS   â†’ complete TLS handshake using existing certs, then HTTP 200
  - Other â†’ generic "200 OK" banner

Security notes (OpenSSF):
- Accepts at most MAX_CONNECTIONS simultaneous TCP connections
- Each TCP session is limited to SESSION_TIMEOUT seconds
- Received data is logged sanitized (max LOG_PREVIEW bytes shown)
- UDP socket recvfrom is bounded to 4096 bytes
- Runs in daemon threads so it can't block process exit
- TLS wrap enforces TLSv1.2 minimum; no SSLv2/3/TLSv1/TLSv1.1
"""

import logging
import os
import select
import socket
import socketserver
import ssl
import threading
from collections import defaultdict
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_CONNECTIONS = 200
MAX_PER_IP     = 20    # max simultaneous connections from a single IP
SESSION_TIMEOUT = 10   # seconds — max lifetime of a single catch-all session
PEEK_TIMEOUT    = 0.5  # seconds to wait for initial bytes before sending banner
LOG_PREVIEW     = 256  # max bytes logged per received chunk (sanitized)

# HTTP request method prefixes â€” first 4 bytes of a plain-text HTTP request
_HTTP_PREFIXES = (
    b"GET ", b"POST", b"PUT ", b"HEAD",
    b"OPTI", b"DELE", b"PATC", b"TRAC", b"CONN",
)

# Realistic-looking HTTP 200 response â€” satisfies malware that checks the body
_HTTP_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.57\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)

# For unknown protocols, echo nothing protocol-specific â€” just close.
# Sending "200 OK" to a non-HTTP protocol is a detectable anomaly.
_GENERIC_BANNER = b""


def _detect_protocol(peek: bytes) -> str:
    """Return 'http', 'tls', or 'unknown' from the first few bytes of a stream."""
    if not peek:
        return "unknown"
    if peek[:4] in _HTTP_PREFIXES:
        return "http"
    # TLS ClientHello: content_type=0x16 (handshake), legacy_version=0x03xx
    if len(peek) >= 2 and peek[0] == 0x16 and peek[1] == 0x03:
        return "tls"
    return "unknown"


def _build_tls_context(cert_path: str, key_path: str) -> "Optional[ssl.SSLContext]":
    """
    Build a reusable TLS server context.  Returns None if certs are missing.
    TLSv1.2 minimum is enforced; older versions are rejected.
    """
    if not cert_path or not key_path:
        return None
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= (
            ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_CIPHER_SERVER_PREFERENCE
        )
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        return ctx
    except Exception as e:
        logger.error("Failed to build catch-all TLS context: %s", e)
        return None


def _try_tls_wrap_ctx(
    sock: socket.socket, ctx: ssl.SSLContext
) -> "Optional[ssl.SSLSocket]":
    """Wrap *sock* using a pre-built SSLContext.  Returns None on failure."""
    try:
        return ctx.wrap_socket(sock, server_side=True)
    except ssl.SSLError as e:
        logger.debug("Catch-all TLS handshake failed: %s", e)
        return None
    except OSError as e:
        logger.debug("Catch-all TLS wrap OS error: %s", e)
        return None


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address and per-server connection limit."""
    allow_reuse_address = True
    daemon_threads = True
    _sem = None  # BoundedSemaphore injected by CatchAllTCPService.start()
    _per_ip: defaultdict  # {ip: int} — active connection count per IP
    _per_ip_lock: threading.Lock

    def process_request(self, request, client_address):
        """Drop the connection when global or per-IP limits are exceeded."""
        ip = client_address[0]

        # Global capacity check
        if self._sem is not None and not self._sem.acquire(blocking=False):
            logger.debug(
                "Catch-all TCP at capacity, dropping %s",
                sanitize_ip(ip),
            )
            self.shutdown_request(request)
            return

        # Per-IP limit check
        with self._per_ip_lock:
            if self._per_ip[ip] >= MAX_PER_IP:
                logger.debug(
                    "Catch-all TCP per-IP limit (%d) hit for %s",
                    MAX_PER_IP, sanitize_ip(ip),
                )
                if self._sem is not None:
                    self._sem.release()
                self.shutdown_request(request)
                return
            self._per_ip[ip] += 1

        super().process_request(request, client_address)

    def process_request_thread(self, request, client_address):
        """Release the semaphore slot and per-IP counter after the handler finishes."""
        try:
            super().process_request_thread(request, client_address)
        finally:
            ip = client_address[0]
            with self._per_ip_lock:
                self._per_ip[ip] -= 1
                if self._per_ip[ip] <= 0:
                    del self._per_ip[ip]
            if self._sem is not None:
                self._sem.release()


class _CatchAllTCPHandler(socketserver.BaseRequestHandler):
    # Class-level cert paths and cached TLS context; set by CatchAllTCPService before server start
    cert_path: str = ""
    key_path:  str = ""
    _tls_ctx: "Optional[ssl.SSLContext]" = None

    def _upgrade_tls(
        self, sock: socket.socket, safe_addr: str, src_port: int,
    ) -> "Optional[socket.socket]":
        """Attempt TLS handshake; return upgraded socket, original, or None."""
        if self._tls_ctx is None:
            logger.debug(
                "Catch-all no TLS context for %s:%s; raw fallback",
                safe_addr, src_port,
            )
            return sock
        tls_sock = _try_tls_wrap_ctx(sock, self._tls_ctx)
        if tls_sock:
            logger.debug(
                "Catch-all TLS handshake complete: %s:%s",
                safe_addr, src_port,
            )
            return tls_sock
        logger.debug(
            "Catch-all TLS handshake failed for %s:%s; closing",
            safe_addr, src_port,
        )
        return None

    def handle(self):
        safe_addr = sanitize_ip(self.client_address[0])
        src_port  = self.client_address[1]
        sock      = self.request

        try:
            # â”€â”€ 1. Peek at first bytes to detect protocol â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            sock.settimeout(PEEK_TIMEOUT)
            try:
                peek = sock.recv(8, socket.MSG_PEEK)
            except OSError:
                peek = b""

            protocol = _detect_protocol(peek)

            # â”€â”€ 2. Complete TLS handshake if the client is speaking TLS â”€â”€â”€â”€
            if protocol == "tls":
                sock = self._upgrade_tls(sock, safe_addr, src_port)
                if sock is None:
                    return

            logger.info(
                "CATCH-ALL TCP from %s:%s [%s]",
                safe_addr, src_port, protocol.upper(),
            )

            sock.settimeout(SESSION_TIMEOUT)

            # â”€â”€ 3. Read the first request payload â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            #    For plain sockets, MSG_PEEK left the data in the buffer so
            #    recv() here returns those same bytes plus whatever follows.
            #    For TLS sockets, recv() returns decrypted plaintext.
            first_data = b""
            try:
                first_data = sock.recv(4096)
                if first_data:
                    preview = sanitize_log_string(
                        first_data[:LOG_PREVIEW].decode("utf-8", errors="replace")
                    )
                    logger.debug(
                        "CATCH-ALL [%s] %s:%s "
                        "\u2014 %sB: %s",
                        protocol.upper(), safe_addr, src_port,
                        min(len(first_data), LOG_PREVIEW), preview,
                    )
            except Exception:
                logger.debug("Catch-all TCP initial recv failed", exc_info=True)

            # â”€â”€ 4. Send protocol-appropriate response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            response = (
                _HTTP_200 if protocol in ("http", "tls") else _GENERIC_BANNER
            )
            try:
                sock.sendall(response)
            except Exception as e:
                logger.debug("Catch-all send failed for %s:%s: %s", safe_addr, src_port, e)
                return

            # â”€â”€ 5. Log to structured JSON events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            jl = get_json_logger()
            if jl:
                jl.log(
                    "catch_all_tcp",
                    src_ip=self.client_address[0],
                    src_port=src_port,
                    protocol=protocol,
                    payload_bytes=len(first_data),
                )

            # â”€â”€ 6. Keep reading to capture follow-on messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    preview = sanitize_log_string(
                        chunk[:LOG_PREVIEW].decode("utf-8", errors="replace")
                    )
                    logger.debug(
                        "CATCH-ALL [%s] %s:%s "
                        "follow-on %sB: %s",
                        protocol.upper(), safe_addr, src_port,
                        len(chunk), preview,
                    )
            except Exception:
                logger.debug("Catch-all TCP follow-on drain failed", exc_info=True)
        except Exception:
            logger.debug(
                "Catch-all TCP session error for %s:%s",
                safe_addr, src_port,
                exc_info=True,
            )


class CatchAllTCPService:
    """Listens on a TCP port. iptables redirects unknown ports here."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled  = config.get("redirect_tcp", True)
        self.port     = int(config.get("tcp_port", 9999))
        self.bind_ip  = bind_ip
        self.cert_path = str(config.get("cert_file", "certs/server.crt"))
        self.key_path  = str(config.get("key_file",  "certs/server.key"))
        self._server  = None
        self._thread  = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            # Build a reusable TLS context once instead of per-connection
            tls_ctx = _build_tls_context(self.cert_path, self.key_path)
            # Inject cert paths and cached context into the handler class
            _CatchAllTCPHandler.cert_path = self.cert_path
            _CatchAllTCPHandler.key_path  = self.key_path
            _CatchAllTCPHandler._tls_ctx  = tls_ctx
            self._server = _ReuseServer((self.bind_ip, self.port), _CatchAllTCPHandler)
            self._server._sem = threading.BoundedSemaphore(MAX_CONNECTIONS)
            self._server._per_ip = defaultdict(int)
            self._server._per_ip_lock = threading.Lock()
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            tls_note = (
                " (TLS ready)" if (
                    os.path.exists(self.cert_path)
                    and os.path.exists(self.key_path)
                ) else " (no certs â€” TLS fallback disabled)"
            )
            logger.info(
                "Catch-all TCP service started on %s:%s%s",
                self.bind_ip, self.port, tls_note,
            )
            return True
        except OSError as e:
            logger.error("Catch-all TCP failed to bind: %s", e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server = None
        logger.info("Catch-all TCP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class CatchAllUDPService:
    """Listens on a UDP port, echoes a short acknowledgement."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("redirect_udp", False)
        self.port = int(config.get("udp_port", 9998))
        self.bind_ip = bind_ip
        self._sock: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._thread = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()
            logger.info("Catch-all UDP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("Catch-all UDP failed to bind: %s", e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            ready = select.select([self._sock], [], [], 1.0)
            if not ready[0]:
                continue
            try:
                data, addr = self._sock.recvfrom(4096)
                safe_addr = sanitize_ip(addr[0])
                logger.info("CATCH-ALL UDP from %s:%s (%d bytes)", safe_addr, addr[1], len(data))
                jl = get_json_logger()
                if jl:
                    jl.log("catch_all_udp", src_ip=addr[0], src_port=addr[1],
                           data_len=len(data))
                # Don't respond to unknown UDP â€” no real service echoes "OK".
                # Silently logging is more realistic than replying.
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.debug("Catch-all UDP error: %s", e)

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock:
            self._sock.close()
            self._sock = None
        logger.info("Catch-all UDP service stopped.")

    @property
    def running(self) -> bool:
        return self._sock is not None
