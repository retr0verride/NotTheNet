"""
NotTheNet - Fake Redis Server (TCP port 6379)

Why this matters:
    Redis on an exposed port is heavily abused for:
      - Cryptominer C2       â€” SLAVEOF <actor-ip> to exfiltrate the keyspace
      - Webshell planting    â€” CONFIG SET dir /var/www + CONFIG SET dbfilename
                               shell.php + SET payload <?php system($_GET[e]); ?>
                               + SAVE to write a file to the web root
      - Privilege escalation â€” write SSH authorized_keys via CONFIG SET dir
      - DarkComet/NjRAT      â€” some variants use Redis as a C2 message queue

    This service responds to all common RESP commands and logs every command
    issued.  The SLAVEOF / REPLICAOF and CONFIG SET dir / dbfilename commands
    are explicitly flagged as high-interest in the log.

    RESP (Redis Serialization Protocol) is simple enough to parse inline:
      *N\\r\\n â€” array of N elements
      $N\\r\\n  â€” bulk string of N bytes
      +string\\r\\n â€” simple string
      Inline commands: PING\\r\\n (legacy format)

Security notes (OpenSSF):
- Commands are only logged, never executed
- CONFIG SET dir / dbfilename is flagged but no file is written
- SLAVEOF is accepted but no real replication connection is opened
- Each session runs in a daemon thread; cannot block process exit
- Sessions are bounded to SESSION_TIMEOUT seconds
"""

import logging
import socket
import threading
from typing import Callable

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 60   # Redis clients hold long-lived connections
_MAX_CONNECTIONS = 50

_INFO_BODY = (
    "# Server\r\nredis_version:7.0.15\r\nredis_git_sha1:00000000\r\n"
    "redis_mode:standalone\r\nos:Linux 5.15.0-91-generic x86_64\r\n"
    "arch_bits:64\r\nmonotonic_clock:POSIX clock_gettime\r\nhz:10\r\n"
    "aof_enabled:0\r\nexecutable:/usr/bin/redis-server\r\n"
    "config_file:/etc/redis/redis.conf\r\n\r\n"
    "# Clients\r\nconnected_clients:1\r\nblocked_clients:0\r\n\r\n"
    "# Memory\r\nused_memory:1000000\r\nused_memory_human:976.56K\r\n\r\n"
    "# Stats\r\ntotal_connections_received:42\r\ntotal_commands_processed:512\r\n\r\n"
    "# Replication\r\nrole:master\r\nconnected_slaves:0\r\n\r\n"
    "# CPU\r\nused_cpu_sys:0.012\r\nused_cpu_user:0.048\r\n"
)

_HIGH_INTEREST_CMDS = frozenset(["SLAVEOF", "REPLICAOF", "CONFIG", "DEBUG", "SAVE", "BGSAVE"])


class _RedisSession(threading.Thread):
    """Handles one Redis client session using RESP protocol."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: threading.BoundedSemaphore | None = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    # â”€â”€ RESP reader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _readline(self) -> bytes | None:
        """Read until \\r\\n (max 4 KB). Returns line without the terminator."""
        buf = b""
        while True:
            ch = self.conn.recv(1)
            if not ch:
                return None
            buf += ch
            if len(buf) > 4096:
                return None
            if buf.endswith(b"\r\n"):
                return buf[:-2]

    def _read_bulk_string(self) -> "str | None":
        """Read one RESP bulk-string ($<len>\r\n<data>\r\n). Returns str or None."""
        hdr = self._readline()
        if hdr is None or not hdr.startswith(b"$"):
            return None
        try:
            slen = int(hdr[1:])
        except ValueError:
            return None
        if slen < 0 or slen > 65535:
            return None
        data = b""
        while len(data) < slen + 2:
            chunk = self.conn.recv(slen + 2 - len(data))
            if not chunk:
                return None
            data += chunk
        return data[:slen].decode("utf-8", errors="replace")

    def _read_resp_array(self, n: int) -> "list[str] | None":
        """Read *n* RESP bulk-string elements. Returns list or None on error."""
        parts: list[str] = []
        total_bytes = 0
        for _ in range(n):
            elem = self._read_bulk_string()
            if elem is None:
                return None
            total_bytes += len(elem)
            if total_bytes > 1024 * 1024:
                return None
            parts.append(elem)
        return parts
    def _read_command(self) -> list[str | None]:
        """
        Parse one RESP command.  Returns a list of strings (the command and
        its arguments) or None on connection close / parse error.
        """
        line = self._readline()
        if line is None:
            return None
        if not line:
            return []

        if line[:1] == b"*":
            try:
                n = int(line[1:])
            except ValueError:
                return None
            if n <= 0 or n > 256:
                return None
            return self._read_resp_array(n)

        # Inline command (legacy, e.g. PING\r\n)
        return line.decode("utf-8", errors="replace").split()

    # â”€â”€ RESP response helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _send(self, data: bytes):
        try:
            self.conn.sendall(data)
        except OSError:
            pass

    def _ok(self):       self._send(b"+OK\r\n")
    def _pong(self):     self._send(b"+PONG\r\n")
    def _nil(self):      self._send(b"$-1\r\n")
    def _empty_array(self): self._send(b"*0\r\n")

    def _bulk(self, s: str):
        enc = s.encode()
        self._send(f"${len(enc)}\r\n".encode() + enc + b"\r\n")

    def _error(self, msg: str):
        self._send(f"-ERR {msg}\r\n".encode())

    def _cmd_ping(self, args: list[str]) -> bool:
        self._bulk(args[0]) if args else self._pong()
        return True

    def _cmd_info(self, _args: list[str]) -> bool:
        self._bulk(_INFO_BODY)
        return True

    def _cmd_config(self, args: list[str]) -> bool:
        sub = args[0].upper() if args else ""
        if sub == "GET":
            self._empty_array()
        else:
            self._ok()
        return True

    def _cmd_quit(self, _args: list[str]) -> bool:
        self._ok()
        return False  # signal close

    # Commands that return +OK
    _OK_CMDS = frozenset([
        "SET", "MSET", "SETEX", "PSETEX", "SETNX",
        "LPUSH", "RPUSH", "SADD", "ZADD", "HSET",
        "SLAVEOF", "REPLICAOF", "SAVE", "BGSAVE",
        "BGREWRITEAOF", "FLUSHALL", "FLUSHDB",
        "DEBUG", "SHUTDOWN", "AUTH", "CLIENT", "SELECT",
    ])
    # Commands that return $-1 (nil)
    _NIL_CMDS = frozenset(["GET", "MGET", "HGET", "LRANGE", "SMEMBERS"])
    # Commands that return *0 (empty array)
    _ARRAY_CMDS = frozenset(["COMMAND"])

    _CMD_DISPATCH: "dict[str, Callable]" = {
        "PING": _cmd_ping,
        "INFO": _cmd_info,
        "CONFIG": _cmd_config,
        "QUIT": _cmd_quit,
    }

    def _dispatch_command(self, cmd: str, args: list[str]) -> bool:
        """Handle one Redis command. Returns False to close the connection."""
        handler = self._CMD_DISPATCH.get(cmd)
        if handler:
            return handler(self, args)  # type: ignore[operator]
        if cmd in self._OK_CMDS:
            self._ok()
        elif cmd in self._NIL_CMDS:
            self._nil()
        elif cmd in self._ARRAY_CMDS:
            self._empty_array()
        else:
            self._error(f"unknown command '{cmd}'")
        return True

    # â”€â”€ Session main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        logger.info("Redis connect from %s", safe_addr)

        try:
            self.conn.settimeout(SESSION_TIMEOUT)
            while True:
                parts = self._read_command()
                if parts is None:
                    break
                if not parts:
                    continue

                cmd = parts[0].upper()
                args = parts[1:]

                # Log with elevated priority for high-interest commands
                safe_cmd = sanitize_log_string(f"{cmd} {' '.join(args)}"[:300])
                if cmd in _HIGH_INTEREST_CMDS:
                    logger.warning("Redis [HIGH-INTEREST] from %s: %s", safe_addr, safe_cmd)
                else:
                    logger.info("Redis cmd from %s: %s", safe_addr, safe_cmd)
                if jl:
                    jl.log(
                        "redis_command",
                        src_ip=self.addr[0],
                        command=cmd,
                        high_interest=cmd in _HIGH_INTEREST_CMDS,
                        args=[sanitize_log_string(a[:100]) for a in args[:8]],
                    )

                # Respond to command
                if not self._dispatch_command(cmd, args):
                    break

        except OSError:
            logger.debug("Redis session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()


class RedisService:
    """Fake Redis server on TCP port 6379."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 6379))
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
                target=self._serve, daemon=True, name="redis-server"
            )
            self._thread.start()
            logger.info("Redis service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("Redis failed to bind on port %s: %s", self.port, e)
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
                logger.debug("Redis at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _RedisSession(conn, addr, sem=self._sem).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("Redis service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
