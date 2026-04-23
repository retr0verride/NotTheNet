"""
NotTheNet - Fake Telnet Server (port 23)

Why this matters:
    Mirai and all its descendants (Satori, Okiru, Masuta, etc.) spread and
    receive C2 commands exclusively over Telnet. The bot opens a TCP connection,
    waits for a "login:" prompt, sends default credentials (root/root, admin/admin,
    etc.), then awaits a shell prompt before executing downloaded payloads.

    Without a proper Telnet login sequence the bot drops the connection
    immediately â€” none of its credential spray or payload execution is visible.

    This server:
      - Sends realistic Telnet option negotiations (WILL ECHO, WILL SGA)
      - Issues a configurable hostname / OS banner
      - Presents "login:" and "Password:" prompts
      - Accepts any credentials and logs them (intel: botnet cred lists)
      - Returns a minimal BusyBox-style shell prompt
      - Responds to common shell commands (id, uname, ls, wget, curl, cd, exit)
        with plausible-but-harmless output so the bot keeps executing
      - Logs every command issued for forensic analysis

Security notes (OpenSSF):
- Received command strings are sanitized before logging (log injection)
- No shell=True subprocess calls; all responses are static strings
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import logging
import socket
import threading

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 60  # seconds per session

# â”€â”€â”€ Telnet option bytes (RFC 854) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
IAC  = b"\xff"
WILL = b"\xfb"
WONT = b"\xfc"
DO   = b"\xfd"
DONT = b"\xfe"
ECHO = b"\x01"
SGA  = b"\x03"   # Suppress Go Ahead

# Server sends these immediately after connection:
#   IAC WILL ECHO  â†’ we echo characters (standard Telnet)
#   IAC WILL SGA   â†’ suppress go-ahead (standard Telnet)
#   IAC DO SGA
_NEGOTIATE = IAC + WILL + ECHO + IAC + WILL + SGA + IAC + DO + SGA

# Echo-off: IAC WILL ECHO tells the client not to echo locally (for password)
_ECHO_OFF = IAC + WILL + ECHO
_ECHO_ON  = IAC + WONT + ECHO

# â”€â”€â”€ Fake shell command responses â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_SHELL_RESPONSES: dict[str, bytes | None] = {
    "id":       b"uid=0(root) gid=0(root)\r\n",
    "whoami":   b"root\r\n",
    "uname -a": b"Linux router 4.19.0-18-mips #1 SMP Mon Mar 16 06:00:00 UTC 2020 mips GNU/Linux\r\n",
    "uname":    b"Linux\r\n",
    "hostname": b"router\r\n",
    "pwd":      b"/root\r\n",  # nosec B105 â€” shell command key, not a credential
    "ls":       b"bin  dev  etc  lib  proc  root  tmp  usr  var\r\n",
    "ls -la":   b"total 0\r\ndrwxr-xr-x 12 root root 0 Jan  1 00:00 .\r\n",
    "cat /proc/cpuinfo": b"processor\t: 0\r\ncpu model\t: MIPS 24Kc\r\n",
    "free":     b"             total       used       free\r\nMem:         62976      41280      21696\r\n",
    "ps":       b"PID   USER     COMMAND\r\n    1 root     init\r\n",
    "ps aux":   b"PID   USER     COMMAND\r\n    1 root     init\r\n",
    "exit":     None,  # special â€” close session
    "quit":     None,
    "logout":   None,
}


def _shell_response(cmd: str) -> bytes | None:
    """Return a canned shell response, or a generic 'sh: not found' line."""
    stripped = cmd.strip()
    if stripped in _SHELL_RESPONSES:
        return _SHELL_RESPONSES[stripped]
    # wget / curl / tftp â€” acknowledge but do nothing (no real download)
    lower = stripped.lower()
    if lower.startswith(("wget ", "curl ", "tftp ")):
        return b"connecting...\r\n"
    # cd â€” always succeed
    if lower.startswith("cd "):
        return b""
    # empty line
    if not stripped:
        return b""
    return f"sh: {stripped.split()[0]}: not found\r\n".encode()


class _TelnetSession(threading.Thread):
    """Handles one Telnet client connection."""

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple,
        banner: str,
        prompt: str,
        sem: threading.BoundedSemaphore | None = None,
    ):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.banner = banner
        self.prompt = prompt.encode()
        self._sem = sem

    # â”€â”€ I/O helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _send(self, data: bytes) -> bool:
        try:
            self.conn.sendall(data)
            return True
        except OSError:
            return False

    def _consume_iac(self) -> None:
        """Read and discard a Telnet IAC command sequence."""
        try:
            verb = self.conn.recv(1)
            if verb and verb[0] in (0xFB, 0xFC, 0xFD, 0xFE):
                self.conn.recv(1)  # WILL/WONT/DO/DONT: skip option byte
        except OSError:
            pass

    def _consume_cr(self) -> bytes:
        """After receiving CR, consume LF or NUL; return leftover byte."""
        try:
            nxt = self.conn.recv(1)
            if nxt in (b"\n", b"\x00", b""):
                return b""
            return nxt
        except OSError:
            return b""

    def _recv_line(self, max_bytes: int = 256) -> bytes | None:
        """Read bytes until CRLF or LF, stripping IAC sub-sequences."""
        buf = b""
        while True:
            try:
                ch = self.conn.recv(1)
            except OSError:
                return None
            if not ch:
                return None
            if ch == b"\xff":
                self._consume_iac()
                continue
            if ch in (b"\r", b"\n"):
                if ch == b"\r":
                    buf += self._consume_cr()
                break
            if len(buf) < max_bytes:
                buf += ch
        return buf
    # â”€â”€ Session main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _do_login(self, safe_addr: str) -> tuple[str, str | None]:
        """Run login: / Password: sequence. Returns (username, password) or None."""
        self._send(b"\r\nlogin: ")
        raw_user = self._recv_line()
        if raw_user is None:
            return None
        username = raw_user.decode("utf-8", errors="replace").strip()

        self._send(_ECHO_OFF)
        self._send(b"Password: ")
        raw_pass = self._recv_line()
        if raw_pass is None:
            return None
        password = raw_pass.decode("utf-8", errors="replace").strip()
        self._send(_ECHO_ON)
        self._send(b"\r\n")

        safe_user = sanitize_log_string(username)
        logger.info(
            f"Telnet credentials [{safe_addr}] user={safe_user} pass=[captured]"
        )
        jl = get_json_logger()
        if jl:
            jl.log(  # lgtm[py/clear-text-logging-sensitive-data]
                "telnet_auth",
                src_ip=self.addr[0],
                username=username,
                password=password,
            )
        return username, password

    def _shell_loop(self, safe_addr: str) -> None:
        """Read commands in a loop and send canned responses."""
        jl = get_json_logger()
        while True:
            if not self._send(self.prompt):
                break
            raw = self._recv_line()
            if raw is None:
                break
            cmd = raw.decode("utf-8", errors="replace").strip()
            if not cmd:
                continue

            safe_cmd = sanitize_log_string(cmd)
            logger.info("Telnet cmd [%s] %s", safe_addr, safe_cmd)
            if jl:
                jl.log("telnet_command", src_ip=self.addr[0], command=cmd)

            resp = _shell_response(cmd)
            if resp is None:  # exit / quit / logout
                self._send(b"\r\n")
                break
            if resp:
                self._send(resp)

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        logger.info("Telnet connection from %s", safe_addr)

        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            # Telnet option negotiation + banner
            self._send(_NEGOTIATE)
            if self.banner:
                self._send(self.banner.encode() + b"\r\n")

            # Login sequence
            creds = self._do_login(safe_addr)
            if creds is None:
                return

            # Brief pause then accept login unconditionally
            self._send(b"\r\n")

            # Shell loop
            self._shell_loop(safe_addr)

        except OSError:
            logger.debug("Telnet session error", exc_info=True)
        finally:
            if self._sem is not None:
                self._sem.release()
            try:
                self.conn.close()
            except OSError:
                pass
            logger.info("Telnet [%s] disconnected", safe_addr)


class TelnetService:
    """Fake Telnet server on port 23."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled  = config.get("enabled", True)
        self.port     = int(config.get("port", 23))
        self.bind_ip  = bind_ip
        self.banner   = config.get("banner", "router login")
        self.prompt   = config.get("prompt", "# ")
        self._sem     = threading.BoundedSemaphore(int(config.get("max_connections", 100)))
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
                target=self._serve, daemon=True, name="telnet-server"
            )
            self._thread.start()
            logger.info("Telnet service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("Telnet failed to bind: %s", e)
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
                logger.debug("Telnet at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _TelnetSession(conn, addr, self.banner, self.prompt, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("Telnet service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
