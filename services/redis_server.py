"""
NotTheNet - Fake Redis Server (TCP port 6379)

Why this matters:
    Redis on an exposed port is heavily abused for:
      - Cryptominer C2       — SLAVEOF <actor-ip> to exfiltrate the keyspace
      - Webshell planting    — CONFIG SET dir /var/www + CONFIG SET dbfilename
                               shell.php + SET payload <?php system($_GET[e]); ?>
                               + SAVE to write a file to the web root
      - Privilege escalation — write SSH authorized_keys via CONFIG SET dir
      - DarkComet/NjRAT      — some variants use Redis as a C2 message queue

    This service responds to all common RESP commands and logs every command
    issued.  The SLAVEOF / REPLICAOF and CONFIG SET dir / dbfilename commands
    are explicitly flagged as high-interest in the log.

    RESP (Redis Serialization Protocol) is simple enough to parse inline:
      *N\\r\\n — array of N elements
      $N\\r\\n  — bulk string of N bytes
      +string\\r\\n — simple string
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
from typing import Optional

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

    def __init__(self, conn: socket.socket, addr: tuple, sem: Optional[threading.BoundedSemaphore] = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    # ── RESP reader ──────────────────────────────────────────────────────────

    def _readline(self) -> Optional[bytes]:
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

    def _read_command(self) -> Optional[list[str]]:
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
            # Array format
            try:
                n = int(line[1:])
            except ValueError:
                return None
            if n <= 0 or n > 256:
                return None
            parts: list[str] = []
            total_bytes = 0
            for _ in range(n):
                hdr = self._readline()
                if hdr is None or not hdr.startswith(b"$"):
                    return None
                try:
                    slen = int(hdr[1:])
                except ValueError:
                    return None
                if slen < 0 or slen > 65535:
                    return None
                total_bytes += slen
                if total_bytes > 1024 * 1024:  # 1 MB total args cap
                    return None
                # Read exactly slen bytes + CRLF
                data = b""
                while len(data) < slen + 2:
                    chunk = self.conn.recv(slen + 2 - len(data))
                    if not chunk:
                        return None
                    data += chunk
                parts.append(data[:slen].decode("utf-8", errors="replace"))
            return parts

        # Inline command (legacy, e.g. PING\r\n)
        return line.decode("utf-8", errors="replace").split()

    # ── RESP response helpers ─────────────────────────────────────────────────

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

    # ── Session main ─────────────────────────────────────────────────────────

    def run(self):
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

                # ── Respond to common commands ────────────────────────────
                if cmd == "PING":
                    if args:
                        self._bulk(args[0])
                    else:
                        self._pong()
                elif cmd == "INFO":
                    self._bulk(_INFO_BODY)
                elif cmd in ("SET", "MSET", "SETEX", "PSETEX", "SETNX",
                             "LPUSH", "RPUSH", "SADD", "ZADD", "HSET"):
                    self._ok()
                elif cmd in ("GET", "MGET", "HGET", "LRANGE", "SMEMBERS"):
                    self._nil()
                elif cmd == "CONFIG":
                    if args and args[0].upper() == "SET":
                        self._ok()
                    elif args and args[0].upper() == "GET":
                        self._empty_array()
                    else:
                        self._ok()
                elif cmd in ("SLAVEOF", "REPLICAOF", "SAVE", "BGSAVE",
                             "BGREWRITEAOF", "FLUSHALL", "FLUSHDB",
                             "DEBUG", "SHUTDOWN", "AUTH"):
                    self._ok()
                elif cmd in ("CLIENT",):
                    self._ok()
                elif cmd == "COMMAND":
                    self._empty_array()
                elif cmd == "QUIT":
                    self._ok()
                    break
                elif cmd == "SELECT":
                    self._ok()
                else:
                    self._error(f"unknown command '{cmd}'")

        except OSError:
            pass
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
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
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

    def _serve(self):
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

    def stop(self):
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
