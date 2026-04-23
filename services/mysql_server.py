"""
NotTheNet - Fake MySQL Server (TCP port 3306)

Why this matters:
    SQL-injecting stealers, database credential harvesters, and malware that
    exfiltrates data to a remote MySQL instance all speak the MySQL wire
    protocol.  Common families:
      - RedLine, Vidar, Raccoon  â€” exfiltrate logs to actor-controlled MySQL
      - Web shells               â€” probe for local MySQL with default creds
      - Brute-force tools        â€” spray username/password combos over TCP/3306

    This server:
      1. Sends an authentic MySQL 5.7.x Handshake V10 greeting packet
      2. Reads the client's HandshakeResponse41 and extracts the username
         (the auth response is an SHA1 hash â€” not reversible â€” but the
         username arrives in plaintext)
      3. Returns an OK packet so the client proceeds to issue queries
      4. Logs every COM_QUERY the client sends (credentials, commands, etc.)

Security notes (OpenSSF):
- Auth challenge is os.urandom(20) â€” never reused, never predictable
- Received query strings are sanitised before logging (log injection)
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import logging
import os
import socket
import struct
import threading

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 15  # seconds
_MAX_CONNECTIONS = 50
_COM_QUERY = 0x03


def _make_handshake() -> bytes:
    """
    Build a MySQL Handshake V10 packet (MySQL 5.7.39).

    Layout (RFC-style MySQL protocol specification):
      protocol_version    1  byte   = 10
      server_version      n  bytes  null-terminated
      connection_id       4  bytes  LE
      auth_data_1         8  bytes  (first half of auth challenge)
      filler              1  byte   = 0x00
      capability_flags_1  2  bytes
      character_set       1  byte   = 0x21 (utf8mb4)
      status_flags        2  bytes
      capability_flags_2  2  bytes
      auth_plugin_data_len 1 byte
      reserved           10  bytes  = 0x00
      auth_data_2        13  bytes  (second half + null)
      auth_plugin_name    n  bytes  null-terminated
    """
    auth_data = os.urandom(20)
    payload = (
        b"\x0a"                          # protocol version 10
        + b"5.7.39\x00"                  # server version
        + b"\x01\x00\x00\x00"            # connection ID = 1
        + auth_data[:8] + b"\x00"        # auth-plugin-data part 1 (8 bytes + filler)
        + b"\xff\xf7"                    # capability flags low
        + b"\x21"                        # character set utf8mb4
        + b"\x02\x00"                    # status flags: SERVER_STATUS_AUTOCOMMIT
        + b"\xff\x81"                    # capability flags high
        + bytes([21])                    # length of auth plugin data (8+12+null=21)
        + b"\x00" * 10                   # reserved
        + auth_data[8:] + b"\x00"        # auth-plugin-data part 2 (12 bytes + null)
        + b"mysql_native_password\x00"   # auth plugin name
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"  # 3-byte LE len + seq=0
    return header + payload


def _ok_packet() -> bytes:
    """MySQL OK packet (seq=2, no rows affected, no insert id)."""
    payload = b"\x00\x00\x00\x02\x00\x00\x00"
    return struct.pack("<I", len(payload))[:3] + b"\x02" + payload


def _read_mysql_packet(sock: socket.socket) -> bytes | None:
    """Read one MySQL packet. Returns payload bytes or None."""
    hdr = sock.recv(4)
    if len(hdr) < 4:
        return None
    pkt_len = struct.unpack("<I", hdr[:3] + b"\x00")[0]
    pkt_len = min(pkt_len, 16 * 1024)
    if pkt_len == 0:
        return b""
    payload = b""
    while len(payload) < pkt_len:
        chunk = sock.recv(pkt_len - len(payload))
        if not chunk:
            return None
        payload += chunk
    return payload


class _MySQLSession(threading.Thread):
    """Handles one MySQL client session."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: threading.BoundedSemaphore | None = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    @staticmethod
    def _parse_username(payload: bytes) -> str:
        """Extract null-terminated username from HandshakeResponse41 (byte 32+)."""
        if len(payload) <= 32:
            return ""
        end = payload.find(b"\x00", 32)
        if end < 32:
            return ""
        return payload[32:end].decode("utf-8", errors="replace")

    def _query_loop(self, safe_addr: str, jl) -> None:
        """Read and log MySQL queries until the client disconnects."""
        while True:
            payload = _read_mysql_packet(self.conn)
            if payload is None or not payload:
                break
            if payload[0] == _COM_QUERY:
                query = payload[1:].decode("utf-8", errors="replace")
                logger.info(
                    "MySQL query from %s: %s",
                    safe_addr,
                    sanitize_log_string(query[:300]),
                )
                if jl:
                    jl.log("mysql_query", src_ip=self.addr[0], query=query[:300])
            self.conn.sendall(_ok_packet())

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            self.conn.sendall(_make_handshake())

            payload = _read_mysql_packet(self.conn)
            if payload is None:
                return

            username = self._parse_username(payload)
            safe_user = sanitize_log_string(username)
            logger.info("MySQL login attempt from %s: user=%s", safe_addr, safe_user)
            if jl:
                jl.log("mysql_auth", src_ip=self.addr[0], username=username)

            self.conn.sendall(_ok_packet())
            self._query_loop(safe_addr, jl)

        except OSError:
            logger.debug("MySQL session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()

class MySQLService:
    """Fake MySQL server on TCP port 3306."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 3306))
        self.bind_ip = bind_ip
        self._sem = threading.BoundedSemaphore(int(config.get("max_connections", _MAX_CONNECTIONS)))
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

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
                target=self._serve, daemon=True, name="mysql-server"
            )
            self._thread.start()
            logger.info("MySQL service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("MySQL failed to bind on port %s: %s", self.port, e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("MySQL at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _MySQLSession(conn, addr, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("MySQL service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
