"""
NotTheNet - DNS-over-TLS (DoT) Server
RFC 7858: DNS queries over TLS on port 853.

Shares the same _FakeResolver as the plain DNS server, so DGA entropy
detection, FCrDNS, NCSI overrides, Windows NCSI overrides, and the
public IP pool all apply identically.

Each DNS message is framed with a 2-byte big-endian length prefix,
exactly as specified for DNS-over-TCP (RFC 1035 §4.2.2).
"""

from __future__ import annotations

import logging
import socket
import ssl
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

_DOT_MAX_WORKERS = 50

from utils.logging_utils import sanitize_ip

logger = logging.getLogger(__name__)

try:
    from dnslib import DNSRecord
    from services.dns_server import _DNSLIB_AVAILABLE, _FakeResolver
except ImportError:
    _DNSLIB_AVAILABLE = False
    logger.warning("dnslib not installed; DoT service unavailable.")


class _FakeClientHandler:
    """Minimal handler shim — provides attributes _FakeResolver.resolve() accesses."""

    def __init__(self, addr: tuple):
        self.client_address = addr
        self.tcp = True  # DoT is always TCP


class DoTService:
    """
    DNS-over-TLS server (RFC 7858) on port 853.

    Shares all resolver logic with the plain DNS service (DGA detection,
    FCrDNS, NCSI exact-match responses, public IP pool, custom records).
    Uses the HTTPS server certificate; install the CA into the analysis
    VM trust store to make DoT lookups appear fully validated.
    """

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 853))
        self.bind_ip = config.get("bind_ip", "0.0.0.0")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
        # Resolver settings — inherited from DNS config by service_manager
        self.redirect_ip = config.get("resolve_to", "127.0.0.1")
        self.ttl = int(config.get("ttl", 300))
        self.handle_ptr = bool(config.get("handle_ptr", True))
        self.custom_records: dict = config.get("custom_records", {})
        self.nxdomain_entropy_threshold = float(
            config.get("nxdomain_entropy_threshold", 0.0) or 0.0
        )
        self.nxdomain_label_min_length = int(
            config.get("nxdomain_label_min_length", 12) or 12
        )
        self.public_response_ips: list[str] = list(
            config.get("public_response_ips", []) or []
        )
        self._server_sock: Optional[socket.socket] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None
        self._thread: Optional[threading.Thread] = None
        self._pool: Optional[ThreadPoolExecutor] = None
        self.running = False

    def start(self) -> bool:
        if not self.enabled:
            logger.info("DoT service disabled in config.")
            return False

        if not _DNSLIB_AVAILABLE:
            logger.error("DoT service cannot start: dnslib not installed.")
            return False

        # Build TLS context — minimum TLSv1.2, ALPN "dot" per RFC 7858
        try:
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self._ssl_ctx.set_alpn_protocols(["dot"])
            self._ssl_ctx.load_cert_chain(
                certfile=self.cert_file, keyfile=self.key_file
            )
        except (ssl.SSLError, OSError) as e:
            logger.error("DoT TLS context setup failed: %s", e)
            return False

        # Build resolver (shared with plain DNS service)
        self._resolver = _FakeResolver(
            self.redirect_ip,
            self.custom_records,
            self.ttl,
            self.handle_ptr,
            nxdomain_entropy_threshold=self.nxdomain_entropy_threshold,
            nxdomain_label_min_length=self.nxdomain_label_min_length,
            public_response_ips=self.public_response_ips or None,
        )

        # Bind raw TCP socket (TLS is applied per-client in accept loop)
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw.bind((self.bind_ip, self.port))
            raw.listen(64)
            self._server_sock = raw
        except OSError as e:
            logger.error(
                "DoT service failed to bind %s:%d: %s", self.bind_ip, self.port, e
            )
            return False

        self._pool = ThreadPoolExecutor(max_workers=_DOT_MAX_WORKERS)
        self.running = True
        self._thread = threading.Thread(
            target=self._accept_loop, daemon=True, name="dot-accept"
        )
        self._thread.start()
        logger.info(
            "DoT service started on %s:%d (TLS) -> all queries resolve to %s",
            self.bind_ip, self.port, sanitize_ip(self.redirect_ip),
        )
        return True

    def _accept_loop(self):
        while self.running:
            try:
                client_sock, addr = self._server_sock.accept()
            except OSError:
                break  # server socket was closed via stop()
            # Perform TLS handshake before submitting to thread pool.
            # Catch both ssl.SSLError and OSError (e.g. connection reset during
            # handshake) — an unhandled exception here would kill the accept loop.
            try:
                tls_sock = self._ssl_ctx.wrap_socket(client_sock, server_side=True)
            except (ssl.SSLError, OSError) as e:
                logger.debug(
                    "DoT TLS handshake failed from %s: %s", sanitize_ip(addr[0]), e
                )
                try:
                    client_sock.close()
                except OSError:
                    pass
                continue
            self._pool.submit(self._handle_client, tls_sock, addr)

    def _handle_client(self, sock: ssl.SSLSocket, addr: tuple):
        handler = _FakeClientHandler(addr)
        try:
            sock.settimeout(10.0)
            while True:
                # RFC 1035 §4.2.2: 2-byte big-endian message length prefix
                length_bytes = self._recv_exact(sock, 2)
                if not length_bytes:
                    break
                msg_len = struct.unpack("!H", length_bytes)[0]
                # Sanity-check: reject zero-length or oversized messages
                if msg_len == 0 or msg_len > 4096:
                    break
                data = self._recv_exact(sock, msg_len)
                if len(data) < msg_len:
                    break
                try:
                    request = DNSRecord.parse(data)
                except Exception:
                    break  # malformed DNS message — silently close
                reply = self._resolver.resolve(request, handler)
                reply_bytes = reply.pack()
                sock.sendall(struct.pack("!H", len(reply_bytes)) + reply_bytes)
        except (OSError, ssl.SSLError, TimeoutError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
        """Read exactly *n* bytes from sock; return b'' on EOF or error."""
        buf = b""
        while len(buf) < n:
            try:
                chunk = sock.recv(n - len(buf))
            except (OSError, ssl.SSLError):
                return b""
            if not chunk:
                return b""
            buf += chunk
        return buf

    def stop(self):
        self.running = False
        if self._pool:
            self._pool.shutdown(wait=False)
            self._pool = None
        if self._server_sock:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
