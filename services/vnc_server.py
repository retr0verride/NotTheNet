"""
NotTheNet - Fake VNC Server (TCP port 5900)

Why this matters:
    VNC is a favourite for:
      - Remote-access trojans  â€” UltraVNC, TinyVNC, Hidden-VNC (hVNC) payloads
      - Botnets                â€” spread by scanning for open 5900 with weak passwords
      - Ransomware pre-ops     â€” manual reconnaissance before detonation

    Key intelligence:
      - The RFB version string the client sends reveals the client software
      - The 16-byte VNC-Auth challenge response can be saved for offline DES
        cracking (the response = DES(challenge, first-8-bytes-of-password))

    This server:
      1. Sends RFB 003.008 version string
      2. Reads the client version
      3. Offers security type 2 (VNC Auth)
      4. Sends a random 16-byte challenge
      5. Reads the 16-byte DES response and logs it alongside the challenge
         (sufficient for offline brute-force of short passwords)
      6. Always accepts (sends SecurityResult = 0 OK)

Security notes (OpenSSF):
- Challenge is os.urandom(16) â€” never reused, never predictable
- DES response bytes are only logged as hex; no crypto operation is performed
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import logging
import os
import socket
import threading

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 15
_MAX_CONNECTIONS = 50

_VNC_VERSION    = b"RFB 003.008\n"

_SEC_TYPE_VNC   = b"\x01\x02"   # 1 type offered: type 2 (VNC Auth)
_SECURITY_OK    = b"\x00\x00\x00\x00"


class _VNCSession(threading.Thread):
    """Handles one VNC client session."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: threading.BoundedSemaphore | None = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    def _do_handshake(self):
        """Exchange RFB version and security type. Returns (client_ver, sec_choice) or None."""
        self.conn.sendall(_VNC_VERSION)
        ver_bytes = self.conn.recv(12)
        if len(ver_bytes) < 12:
            return None
        client_ver = ver_bytes[:12].decode("ascii", errors="replace").strip()
        self.conn.sendall(_SEC_TYPE_VNC)
        sec_choice = self.conn.recv(1)
        if not sec_choice:
            return None
        return client_ver, sec_choice[0]

    def _handle_no_auth(self, safe_addr: str, client_ver: str) -> None:
        """Client chose None auth — log and accept."""
        self.conn.sendall(_SECURITY_OK)
        logger.info(
            "VNC connect from %s (version=%s, no-auth)",
            safe_addr,
            sanitize_log_string(client_ver),
        )
        jl = get_json_logger()
        if jl:
            jl.log("vnc_connect", src_ip=self.addr[0],
                   client_version=client_ver, auth_type="none")
        self._drain()

    def _handle_vnc_auth(self, safe_addr: str, client_ver: str) -> None:
        """VNC Auth type 2: send challenge, read DES response, accept."""
        challenge = os.urandom(16)
        self.conn.sendall(challenge)
        response = self.conn.recv(16)

        logger.info(
            "VNC auth from %s (version=%s) challenge=%s response=%s",
            safe_addr,
            sanitize_log_string(client_ver),
            challenge.hex(),
            response.hex() if response else "(empty)",
        )
        jl = get_json_logger()
        if jl:
            jl.log(
                "vnc_auth",
                src_ip=self.addr[0],
                client_version=client_ver,
                challenge_hex=challenge.hex(),
                response_hex=response.hex() if response else "",
            )
        self.conn.sendall(_SECURITY_OK)
        self._drain()

    def _drain(self) -> None:
        """Read and discard follow-on traffic until EOF."""
        while True:
            if not self.conn.recv(4096):
                break

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            result = self._do_handshake()
            if result is None:
                logger.debug("VNC handshake failed from %s — closing", safe_addr)
                return
            client_ver, sec_choice = result

            if sec_choice == 1:
                self._handle_no_auth(safe_addr, client_ver)
                return

            if sec_choice != 2:
                logger.debug("VNC unknown security type %d from %s — closing", sec_choice, safe_addr)
                return

            self._handle_vnc_auth(safe_addr, client_ver)

        except OSError:
            logger.debug("VNC session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()


class VNCService:
    """Fake VNC server on TCP port 5900."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 5900))
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
                target=self._serve, daemon=True, name="vnc-server"
            )
            self._thread.start()
            logger.info("VNC service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("VNC failed to bind on port %s: %s", self.port, e)
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
                logger.debug("VNC at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _VNCSession(conn, addr, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("VNC service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
