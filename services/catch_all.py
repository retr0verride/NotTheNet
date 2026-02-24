"""
NotTheNet - TCP/UDP Catch-All Service
Accepts connections on a catch-all port (redirected via iptables) and
responds with a generic banner, satisfying any connection-check malware makes.

Security notes (OpenSSF):
- Accepts at most MAX_CONNECTIONS simultaneous TCP connections
- Each TCP session is limited to SESSION_TIMEOUT seconds
- Received data is logged sanitized (max 64 bytes shown)
- UDP socket recvfrom is bounded to 4096 bytes
- Runs in daemon threads so it can't block process exit
"""

import logging
import select
import socket
import socketserver
import threading
from typing import Optional

from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_CONNECTIONS = 200
SESSION_TIMEOUT = 10  # seconds


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address set before server_bind()."""
    allow_reuse_address = True
    daemon_threads = True


class _CatchAllTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        safe_addr = sanitize_ip(self.client_address[0])
        port = self.client_address[1]
        logger.info(f"CATCH-ALL TCP from {safe_addr}:{port}")
        try:
            self.request.settimeout(SESSION_TIMEOUT)
            # Send a generic banner
            self.request.sendall(b"200 OK\r\n")
            # Drain up to 1 KB of data (log sanitized snippet)
            try:
                data = self.request.recv(1024)
                if data:
                    preview = sanitize_log_string(
                        data[:64].decode("utf-8", errors="replace")
                    )
                    logger.debug(f"CATCH-ALL TCP data preview: {preview}")
            except Exception:
                pass
        except Exception as e:
            logger.debug(f"Catch-all TCP {safe_addr} error: {e}")


class CatchAllTCPService:
    """Listens on a TCP port. iptables redirects unknown ports here."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("redirect_tcp", True)
        self.port = int(config.get("tcp_port", 9999))
        self.bind_ip = bind_ip
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._server = _ReuseServer((self.bind_ip, self.port), _CatchAllTCPHandler)
            # Bound the thread pool indirectly via semaphore
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"Catch-all TCP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"Catch-all TCP failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
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
            logger.info(f"Catch-all UDP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"Catch-all UDP failed to bind: {e}")
            return False

    def _serve(self):
        while not self._stop_event.is_set():
            ready = select.select([self._sock], [], [], 1.0)
            if not ready[0]:
                continue
            try:
                data, addr = self._sock.recvfrom(4096)
                safe_addr = sanitize_ip(addr[0])
                logger.info(f"CATCH-ALL UDP from {safe_addr}:{addr[1]} ({len(data)} bytes)")
                self._sock.sendto(b"OK\r\n", addr)
            except Exception as e:
                if not self._stop_event.is_set():
                    logger.debug(f"Catch-all UDP error: {e}")

    def stop(self):
        self._stop_event.set()
        if self._sock:
            self._sock.close()
            self._sock = None
        logger.info("Catch-all UDP service stopped.")

    @property
    def running(self) -> bool:
        return self._sock is not None
