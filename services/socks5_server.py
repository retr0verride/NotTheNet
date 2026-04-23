"""
NotTheNet - Fake SOCKS5 Proxy Server (port 1080)

Why this matters:
    A large proportion of modern malware does NOT connect directly to its C2.
    Instead, it routes all C2 traffic through a SOCKS5 proxy â€” typically another
    infected host or a rented proxy service.  Families that do this include:

      SystemBC     â€” uses SOCKS5 exclusively for all C2 tunnelling
      QakBot       â€” SOCKS5 proxy module embedded in the loader
      Cobalt Strike â€” systemwide SOCKS5 proxy for post-exploit tunnelling
      Emotet        â€” proxy module chains infections together
      DarkComet/RATs â€” proxied C2 to hide operator's real IP

    Key intelligence captured here:
      - The *real* destination host:port the malware is trying to reach
        (visible inside the SOCKS5 CONNECT request, even if the outer DNS
        query is fake).  This gives you the true C2 address.
      - The protocol the malware speaks after the proxy is established
        (HTTP beacon, TLS, custom binary â€” all logged).

    This server:
      1. Completes the SOCKS5 RFC 1928 handshake (no-auth)
      2. Accepts CONNECT requests for IPv4, IPv6, and domain targets
      3. Logs the requested destination (the critical intel)
      4. Replies with a success response so the malware continues
      5. Snoops the tunnelled traffic using the same protocol-aware
         logic as the catch-all: TLS wrap if TLS ClientHello detected,
         HTTP 200 for HTTP requests, generic banner otherwise

Security notes (OpenSSF):
- BIND and UDP ASSOCIATE commands are refused (SSRF / amplification vectors)
- Destination host from CONNECT is sanitized before logging (log injection)
- Received tunnel data is log-sanitized (max LOG_PREVIEW bytes shown)
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT
"""

import logging
import os
import socket
import ssl
import struct
import threading

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 30   # seconds
LOG_PREVIEW     = 256  # max bytes logged per tunnel chunk (sanitized)

# â”€â”€â”€ SOCKS5 constants (RFC 1928) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_VER    = 0x05
_CMD_CONNECT  = 0x01
_CMD_BIND     = 0x02
_CMD_UDP      = 0x03
_ATYP_IPV4    = 0x01
_ATYP_DOMAIN  = 0x03
_ATYP_IPV6    = 0x04
_REP_OK       = 0x00
_REP_REFUSED  = 0x05

# Response: success, bind IP 0.0.0.0, bind port 0
_CONNECT_OK   = struct.pack("!BBBBIH", _VER, _REP_OK, 0, _ATYP_IPV4, 0, 0)
_CONNECT_FAIL = struct.pack("!BBBBIH", _VER, _REP_REFUSED, 0, _ATYP_IPV4, 0, 0)

# â”€â”€â”€ Protocol detection / response (mirrors catch_all.py logic) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_HTTP_PREFIXES = (b"GET ", b"POST", b"PUT ", b"HEAD", b"OPTI", b"DELE", b"PATC")

_HTTP_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.57\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)
_GENERIC_BANNER = b"200 OK\r\n"


def _detect_protocol(peek: bytes) -> str:
    if not peek:
        return "unknown"
    if peek[:4] in _HTTP_PREFIXES:
        return "http"
    if len(peek) >= 2 and peek[0] == 0x16 and peek[1] == 0x03:
        return "tls"
    return "unknown"


class _Socks5Session(threading.Thread):
    """Handles one SOCKS5 client session."""

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple,
        cert_path: str,
        key_path: str,
        sem: threading.BoundedSemaphore | None = None,
    ):
        super().__init__(daemon=True)
        self.conn      = conn
        self.addr      = addr
        self.cert_path = cert_path
        self.key_path  = key_path
        self._sem      = sem

    # â”€â”€ I/O helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _recv_exact(self, n: int) -> bytes | None:
        """Read exactly n bytes, returning None on EOF/error."""
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.conn.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    def _send(self, data: bytes):
        try:
            self.conn.sendall(data)
        except OSError:
            pass

    # â”€â”€ SOCKS5 handshake â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _handshake(self) -> bool:
        """
        SOCKS5 method negotiation (RFC 1928 Â§3).
        Returns True if the client is SOCKS5 and we agreed on no-auth (0x00).
        """
        header = self._recv_exact(2)
        if not header or header[0] != _VER:
            return False
        n_methods = header[1]
        if n_methods < 1:
            return False
        _methods = self._recv_exact(n_methods)
        # Always select no-auth (0x00) regardless of what the client offers
        self._send(bytes([_VER, 0x00]))
        return True

    def _read_address(self, atyp: int) -> str | None:
        """Parse destination address based on address type."""
        if atyp == _ATYP_IPV4:
            raw = self._recv_exact(4)
            return socket.inet_ntoa(raw) if raw else None
        if atyp == _ATYP_DOMAIN:
            length_byte = self._recv_exact(1)
            if not length_byte:
                return None
            raw = self._recv_exact(length_byte[0])
            return raw.decode("utf-8", errors="replace") if raw else None
        if atyp == _ATYP_IPV6:
            raw = self._recv_exact(16)
            return socket.inet_ntop(socket.AF_INET6, raw) if raw else None
        return None

    def _read_connect(self) -> tuple[str, int | None]:
        """
        Read a SOCKS5 CONNECT request (RFC 1928 Â§4).
        Returns (destination_host, destination_port) or None on error.
        BIND and UDP ASSOCIATE are rejected (SSRF/amplification vectors).
        """
        req = self._recv_exact(4)
        if not req or req[0] != _VER:
            return None

        if req[1] != _CMD_CONNECT:
            self._send(_CONNECT_FAIL)
            return None

        host = self._read_address(req[3])
        if host is None:
            return None

        port_raw = self._recv_exact(2)
        if not port_raw:
            return None
        return host, struct.unpack("!H", port_raw)[0]
    # â”€â”€ Tunnel snooping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _try_tls_wrap(
        self, sock: socket.socket, safe_addr: str,
        destination: str, dest_port: int,
    ) -> socket.socket:
        """Attempt TLS wrap on the tunnel socket; return (possibly wrapped) socket."""
        if not (
            self.cert_path
            and self.key_path
            and os.path.exists(self.cert_path)
            and os.path.exists(self.key_path)
        ):
            return sock
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
            wrapped = ctx.wrap_socket(sock, server_side=True)
            logger.debug(
                "SOCKS5 TLS tunnel handshake complete: %s -> %s:%d",
                safe_addr, destination, dest_port,
            )
            return wrapped
        except ssl.SSLError as e:
            logger.debug("SOCKS5 TLS wrap failed %s: %s", safe_addr, e)
            raise  # socket unrecoverable after partial handshake

    def _snoop_tunnel(self, destination: str, dest_port: int, safe_addr: str):
        """
        After sending CONNECT OK, snoop the tunnelled connection.
        Detect the protocol (TLS / HTTP / unknown) and respond accordingly,
        then log all data received for forensic capture.
        """
        sock = self.conn
        sock.settimeout(0.5)

        try:
            peek = sock.recv(8, socket.MSG_PEEK)
        except OSError:
            peek = b""

        protocol = _detect_protocol(peek)

        if protocol == "tls":
            try:
                sock = self._try_tls_wrap(sock, safe_addr, destination, dest_port)
            except ssl.SSLError:
                return
            self.conn = sock

        sock.settimeout(SESSION_TIMEOUT)

        first_data = b""
        try:
            first_data = sock.recv(4096)
        except OSError:
            pass

        if first_data:
            preview = sanitize_log_string(
                first_data[:LOG_PREVIEW].decode("utf-8", errors="replace")
            )
            logger.debug(
                "SOCKS5 [%s] tunnel %s -> %s:%d  %dB: %s",
                protocol.upper(), safe_addr, destination, dest_port,
                len(first_data), preview,
            )

        response = _HTTP_200 if protocol in ("http", "tls") else _GENERIC_BANNER
        try:
            sock.sendall(response)
        except OSError:
            return

        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                preview = sanitize_log_string(
                    chunk[:LOG_PREVIEW].decode("utf-8", errors="replace")
                )
                logger.debug(
                    "SOCKS5 [%s] follow-on %s -> %s:%d  %dB: %s",
                    protocol.upper(), safe_addr, destination, dest_port,
                    len(chunk), preview,
                )
        except OSError:
            pass
    # â”€â”€ Thread main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            if not self._handshake():
                logger.debug("SOCKS5 bad handshake from %s", safe_addr)
                return

            result = self._read_connect()
            if result is None:
                return

            destination, dest_port = result
            safe_dest = sanitize_log_string(destination)
            logger.info(
                "SOCKS5 CONNECT [%s] → %s:%d", safe_addr, safe_dest, dest_port
            )
            if jl:
                jl.log(
                    "socks5_connect",
                    src_ip=self.addr[0],
                    destination=destination,
                    dest_port=dest_port,
                )

            # Report success to the client
            self._send(_CONNECT_OK)

            # Snoop & respond to tunnelled traffic
            self._snoop_tunnel(destination, dest_port, safe_addr)

        except OSError:
            logger.debug("SOCKS5 session error", exc_info=True)
        finally:
            if self._sem is not None:
                self._sem.release()
            try:
                self.conn.close()
            except OSError:
                pass
            logger.debug("SOCKS5 [%s] session ended", safe_addr)


class Socks5Service:
    """Fake SOCKS5 proxy server â€” captures tunnelled C2 destinations."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled   = config.get("enabled", True)
        self.port      = int(config.get("port", 1080))
        self.bind_ip   = bind_ip
        self.cert_path = str(config.get("cert_file", "certs/server.crt"))
        self.key_path  = str(config.get("key_file",  "certs/server.key"))
        self._sem      = threading.BoundedSemaphore(int(config.get("max_connections", 200)))
        self._sock:   socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop    = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="socks5-server"
            )
            self._thread.start()
            logger.info("SOCKS5 proxy service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("SOCKS5 failed to bind: %s", e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("SOCKS5 at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _Socks5Session(
                conn, addr,
                cert_path=self.cert_path,
                key_path=self.key_path,
                sem=self._sem,
            ).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("SOCKS5 proxy service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
