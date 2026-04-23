"""
NotTheNet - Fake RDP Server (TCP port 3389)

Why this matters:
    RDP is one of the most-targeted services for:
      - Ransomware operators â€” manual access before encryption
      - Brute-force botnets  â€” NLBrute, Hydra, Crowbar spraying creds
      - RATs                 â€” initial foothold via exposed RDP
      - Worms                â€” BlueKeep (CVE-2019-0708), DejaBlue lateral movement

    Key intelligence: many RDP clients send a TPKT cookie of the form
    "Cookie: mstshash=USERNAME\r\n" in the Connection Request TPDU â€”
    the username arrives BEFORE any authentication.  This gives us the
    Windows username being sprayed without needing to decrypt anything.

    This server:
      1. Reads the X.224 Connection Request TPDU (over TPKT)
      2. Extracts the mstshash cookie (username) if present
      3. Sends a valid X.224 Connection Confirm with PROTOCOL_RDP (no NLA)
      4. Drains follow-on traffic and logs it

Security notes (OpenSSF):
- Cookie is extracted with a strict regex; no exec of any received data
- Received data is sanitised before logging (log injection)
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import logging
import re
import socket
import threading

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 15
_MAX_CONNECTIONS = 50

_COOKIE_RE = re.compile(rb"Cookie:\s*mstshash=([^\r\n]{1,256})")

# X.224 Connection Confirm TPDU + RDP Negotiation Response
# selectedProtocol = 0x00000000 (PROTOCOL_RDP â€” no NLA, no CredSSP).
# Clients will proceed to standard RDP security exchange.
#
# Byte layout:
#   03 00 00 13   â€” TPKT header (version=3, length=19)
#   0e            â€” X.224 TPDU length indicator (14)
#   d0            â€” TPDU code: Connection Confirm (CC)
#   00 00         â€” dst-ref = 0
#   12 34         â€” src-ref = 0x1234
#   00            â€” class/options = 0
#   02 00 08 00   â€” RDP Negotiation Response header (type=2, flags=0, length=8)
#   00 00 00 00   â€” selectedProtocol = PROTOCOL_RDP
_CONNECTION_CONFIRM = bytes([
    0x03, 0x00, 0x00, 0x13,
    0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
    0x02, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00,
])


class _RDPSession(threading.Thread):
    """Handles one RDP client session."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: threading.BoundedSemaphore | None = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    def _read_tpkt(self) -> bytes | None:
        """Read a TPKT frame (header + body). Returns body or None."""
        hdr = self.conn.recv(4)
        if len(hdr) < 4 or hdr[0] != 0x03:
            return None
        total_len = (hdr[2] << 8) | hdr[3]
        body_len = total_len - 4
        if body_len <= 0 or body_len > 512:
            return None
        body = b""
        while len(body) < body_len:
            chunk = self.conn.recv(body_len - len(body))
            if not chunk:
                break
            body += chunk
        return body

    @staticmethod
    def _extract_cookie_user(body: bytes) -> str:
        """Extract username from RDP cookie, or return empty string."""
        m = _COOKIE_RE.search(body)
        if not m:
            return ""
        return m.group(1).decode("utf-8", errors="replace").strip()

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            body = self._read_tpkt()
            if body is None:
                return

            username = self._extract_cookie_user(body)
            logger.info(
                "RDP connect from %s username=%s",
                safe_addr,
                sanitize_log_string(username) if username else "(no cookie)",
            )
            if jl:
                jl.log("rdp_connect", src_ip=self.addr[0], username=username)

            self.conn.sendall(_CONNECTION_CONFIRM)

            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break

        except OSError:
            logger.debug("RDP session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()

class RDPService:
    """Fake RDP server on TCP port 3389."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 3389))
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
                target=self._serve, daemon=True, name="rdp-server"
            )
            self._thread.start()
            logger.info("RDP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("RDP failed to bind on port %s: %s", self.port, e)
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
                logger.debug("RDP at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _RDPSession(conn, addr, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("RDP service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
