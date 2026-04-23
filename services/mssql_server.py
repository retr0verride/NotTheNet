"""
NotTheNet - Fake MSSQL Server (TCP port 1433)

Why this matters:
    SQL Server is heavily targeted in enterprise environments by:
      - QakBot / Emotet     â€” lateral movement via SQL server
      - Ransomware           â€” query stored creds before encrypting
      - Password sprayers    â€” sa / admin account brute-force over TCP/1433
      - Impacket mssqlclient â€” red-team and malware C2 implants

    Key trick in this service: the TDS Pre-Login response sets
    ENCRYPTION=ENCRYPT_NOT_SUPPORTED (0x02), which causes clients that follow
    the spec to send their Login7 record in plaintext.  The password in Login7
    is only XOR-obfuscated (nibble-swap + XOR 0xA5) â€” completely reversible â€”
    so we recover the plaintext credential without any key material.

Security notes (OpenSSF):
- Credential de-obfuscation is one-way (never re-obfuscated or forwarded)
- All offsets and lengths validated against packet size before slicing
- Received strings are sanitised before logging (log injection)
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import hashlib
import logging
import socket
import struct
import threading

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 15
_MAX_CONNECTIONS = 50

# TDS packet type codes
_TDS_PRELOGIN = 0x12
_TDS_LOGIN7   = 0x10


def _prelogin_response() -> bytes:
    """
    TDS Pre-Login response.

    Tokens (offset relative to start of Pre-Login message body, after TDS header):
      VERSION    offset=0x001a  length=6   â†’ 15.0.2000.5 (SQL Server 2019 RTM)
      ENCRYPTION offset=0x0020  length=1   â†’ 0x02 (ENCRYPT_NOT_SUP)
      TERMINATOR 0xFF

    With ENCRYPT_NOT_SUP, the client sends Login7 without TLS, and the
    password is only XOR-obfuscated (recoverable by _deobfuscate below).
    """
    # Pre-Login option tokens (5 bytes each: type, uint16 offset, uint16 length)
    tokens = (
        b"\x00" + struct.pack(">HH", 0x001a, 6)   # VERSION
        + b"\x01" + struct.pack(">HH", 0x0020, 1)  # ENCRYPTION
        + b"\xff"                                   # TERMINATOR
    )
    # Data: version (6 bytes) then encryption setting (1 byte)
    version = b"\x0f\x00\x07\xd0\x00\x05"  # 15.0.2000.5
    encrypt = b"\x02"                        # ENCRYPT_NOT_SUP
    body = tokens + version + encrypt

    hdr = struct.pack(">BBHHBB", _TDS_PRELOGIN, 0x01, len(body) + 8, 0, 1, 0)
    return hdr + body


def _deobfuscate_tds_password(raw: bytes) -> str:
    """
    Reverse TDS Login7 password obfuscation: for each byte, XOR with 0xA5
    then swap the nibbles.  The result is UTF-16-LE.
    """
    buf = bytearray()
    for byte in raw:
        byte ^= 0xA5
        byte = ((byte & 0x0F) << 4) | ((byte & 0xF0) >> 4)
        buf.append(byte)
    return buf.decode("utf-16-le", errors="replace")


class _MSSQLSession(threading.Thread):
    """Handles one MSSQL client session."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: threading.BoundedSemaphore | None = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    def _read_tds_packet(self) -> tuple[int, bytes]:
        """Read one TDS packet. Returns (type, payload) or (-1, b'') on error."""
        hdr = self.conn.recv(8)
        if len(hdr) < 8:
            return -1, b""
        pkt_type = hdr[0]
        total_len = struct.unpack(">H", hdr[2:4])[0]
        body_len = total_len - 8
        if body_len <= 0 or body_len > 65535:
            return pkt_type, b""
        body = b""
        while len(body) < body_len:
            chunk = self.conn.recv(body_len - len(body))
            if not chunk:
                break
            body += chunk
        return pkt_type, body

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            # â”€â”€ 1. Read Pre-Login request â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            pkt_type, _ = self._read_tds_packet()
            if pkt_type != _TDS_PRELOGIN:
                return

            # â”€â”€ 2. Send Pre-Login response (ENCRYPT_NOT_SUP) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            self.conn.sendall(_prelogin_response())

            # â”€â”€ 3. Read Login7 (arrives plaintext) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            pkt_type, body = self._read_tds_packet()
            if pkt_type != _TDS_LOGIN7 or len(body) < 48:
                return

            # Login7 offset table (bytes 36â€¦47):
            #   [36] ibHostName  [38] cchHostName
            #   [40] ibUserName  [42] cchUserName
            #   [44] ibPassword  [46] cchPassword
            username = ""  # nosec B105 â€” honeypot: captures whatever the malware sends
            password = ""  # nosec B105
            try:
                user_off, user_len = struct.unpack("<HH", body[40:44])
                pass_off, pass_len = struct.unpack("<HH", body[44:48])

                if 0 < user_off and user_off + user_len * 2 <= len(body):
                    username = body[user_off:user_off + user_len * 2].decode(
                        "utf-16-le", errors="replace"
                    )
                if 0 < pass_off and pass_off + pass_len * 2 <= len(body):
                    password = _deobfuscate_tds_password(
                        body[pass_off:pass_off + pass_len * 2]
                    )
            except (struct.error, ValueError):
                logger.debug("Login7 parse error", exc_info=True)

            logger.info(
                "MSSQL login from %s: user=%s pass=[captured]",
                safe_addr,
                sanitize_log_string(username),
            )
            if jl:
                pw_hash = hashlib.sha256(password.encode()).hexdigest()[:16] if password else ""
                jl.log("mssql_auth", src_ip=self.addr[0],
                       username=username, password_sha256_prefix=pw_hash)

        except OSError:
            logger.debug("MSSQL session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()


class MSSQLService:
    """Fake MSSQL server on TCP port 1433."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 1433))
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
                target=self._serve, daemon=True, name="mssql-server"
            )
            self._thread.start()
            logger.info("MSSQL service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("MSSQL failed to bind on port %s: %s", self.port, e)
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
                logger.debug("MSSQL at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _MSSQLSession(conn, addr, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("MSSQL service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
