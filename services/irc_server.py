"""
NotTheNet - IRC Server

Fake IRC server for capturing IRC-based C2 (botnet) traffic.

Many botnets use IRC for command-and-control: the bot connects to an IRC
server, joins a private channel, and waits for PRIVMSG commands from an
operator.  This server accepts all connections, responds with a realistic
IRC welcome sequence (numerics 001â€“005, LUSERS, MOTD), and handles the
full set of common IRC commands so bots proceed to join channels and sit
waiting for orders â€” fully captured in the sandbox.

Security notes (OpenSSF):
- Lines are capped at 512 bytes (RFC 1459 Â§2.3); data beyond is discarded
- Nick, channel, and message strings are sanitized before logging
- Runs each connection in a daemon thread; cannot block process exit
- No data is forwarded to any external host; all traffic is intercepted
"""

import logging
import os
import socket
import ssl
import threading
import time
from collections.abc import Callable

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

_MAX_LINE = 512       # RFC 1459 Â§2.3
_PING_INTERVAL = 120  # idle seconds before the server sends a keepalive PING
_PING_TIMEOUT  = 60   # seconds to wait for PONG before forcibly closing
_CHANNEL_EPOCH = 1735689600  # 2025-01-01T00:00:00Z

class _IRCClientThread(threading.Thread):
    """Handles one IRC client connection in its own daemon thread."""

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple,
        hostname: str,
        network: str,
        channel: str,
        motd: str,
        sem: threading.BoundedSemaphore | None = None,
    ):
        super().__init__(daemon=True, name=f"irc-{addr[0]}:{addr[1]}")
        self.conn = conn
        self.addr = addr
        self.hostname = hostname
        self.network = network
        self.channel = channel.lstrip("#")
        self.motd_text = motd
        self.nick: str | None = None
        self.user: str | None = None
        self.registered = False
        self._sem = sem
        self._waiting_for_pong: bool = False

    # â”€â”€ I/O helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _send(self, line: str):
        """Send a server-originated message (prefixed with :hostname)."""
        try:
            self.conn.sendall(f":{self.hostname} {line}\r\n".encode())
        except OSError:
            pass

    def _send_raw(self, line: str):
        """Send a raw (already-prefixed) line."""
        try:
            self.conn.sendall(f"{line}\r\n".encode())
        except OSError:
            pass

    # â”€â”€ Registration burst â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _welcome(self):
        """
        Send the RFC 1459 registration burst: 001â€“005, LUSERS, MOTD end.
        This is the sequence that tells the client it has successfully
        registered and may begin sending channel commands.
        """
        nick = self.nick
        host = self.hostname
        net = self.network

        # 001 RPL_WELCOME
        self._send(f"001 {nick} :Welcome to {net} {nick}!{self.user}@{host}")
        # 002 RPL_YOURHOST
        self._send(f"002 {nick} :Your host is {host}, running version InspIRCd-3.0")
        # 003 RPL_CREATED
        self._send(f"003 {nick} :This server was created Thu Jan  1 00:00:00 2026")
        # 004 RPL_MYINFO  <servername> <version> <user modes> <channel modes>
        self._send(f"004 {nick} {host} InspIRCd-3.0 iosw biklmnopstv")
        # 005 RPL_ISUPPORT
        self._send(
            f"005 {nick} NETWORK={net} MAXNICKLEN=30 MAXCHANNELLEN=50 "
            f"CHANTYPES=# CHANMODES=b,k,l,imnpst MODES=20 "
            f"PREFIX=(qaohv)~&@%+ CASEMAPPING=rfc1459 :are supported by this server"
        )
        # 251 RPL_LUSERCLIENT
        self._send(f"251 {nick} :There are 1 users and 0 invisible on 1 servers")
        # 254 RPL_LUSERCHANNELS
        self._send(f"254 {nick} 1 :channels formed")
        # MOTD (375, one or more 372, 376)
        self._send(f"375 {nick} :- {host} Message of the Day -")
        for motd_line in self.motd_text.splitlines():
            self._send(f"372 {nick} :- {motd_line}")
        self._send(f"376 {nick} :End of /MOTD command.")

    # â”€â”€ Channel join response â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _do_join(self, channel: str):
        """Emit RFC-correct join response: JOIN echo + topic + NAMREPLY."""
        nick = self.nick
        safe_chan = sanitize_log_string(channel)
        logger.info("IRC  JOIN [%s] %s -> %s", sanitize_ip(self.addr[0]), nick, safe_chan)
        jl = get_json_logger()
        if jl:
            jl.log("irc_join", src_ip=self.addr[0], nick=nick, channel=safe_chan)

        # Echo the join to the client (required for client-side channel tracking)
        self._send_raw(f":{nick}!{self.user}@{self.hostname} JOIN :{channel}")
        # 332 RPL_TOPIC
        self._send(f"332 {nick} {channel} :Welcome")
        # 333 RPL_TOPICWHOTIME (epoch for 2025-01-01)
        self._send(f"333 {nick} {channel} admin!admin@{self.hostname} {_CHANNEL_EPOCH}")
        # 353 RPL_NAMEREPLY  (= means public channel)
        self._send(f"353 {nick} = {channel} :@admin {nick}")
        # 366 RPL_ENDOFNAMES
        self._send(f"366 {nick} {channel} :End of /NAMES list.")

    # â”€â”€ Main read loop â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        logger.info("IRC  [%s] connected", safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("irc_connect", src_ip=self.addr[0])
        self.conn.settimeout(_PING_INTERVAL)
        try:
            buf = b""
            while True:
                chunk = self._recv_or_ping()
                if chunk is None:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    line = raw_line.rstrip(b"\r").decode("utf-8", errors="replace")
                    line = line[:_MAX_LINE]
                    if line:
                        self._dispatch(line, safe_addr)
        except OSError:
            logger.debug("IRC session error", exc_info=True)
        finally:
            if self._sem is not None:
                self._sem.release()
            try:
                self.conn.close()
            except OSError:
                pass
            logger.info("IRC  [%s] disconnected", safe_addr)

    def _recv_or_ping(self) -> "bytes | None":
        """Read from the socket, sending PING on idle timeout.

        Returns received bytes, or None to signal disconnect/timeout.
        """
        while True:
            try:
                chunk = self.conn.recv(1024)
            except TimeoutError:
                if self._waiting_for_pong:
                    self._send_raw(f"ERROR :Closing Link: {self.hostname} (Ping timeout)")
                    return None
                self._waiting_for_pong = True
                self.conn.settimeout(_PING_TIMEOUT)
                token = str(int(time.monotonic() * 1e6) % 0xFFFF_FFFF)
                self._send_raw(f"PING :{token}")
                continue
            if not chunk:
                return None
            if self._waiting_for_pong:
                self._waiting_for_pong = False
                self.conn.settimeout(_PING_INTERVAL)
            return chunk

    # â”€â”€ Command dispatcher â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _dispatch(self, line: str, safe_addr: str):
        """Dispatch one IRC client message."""
        # Strip optional leading server prefix (clients sometimes echo it back)
        if line.startswith(":"):
            parts = line.split(None, 2)
            cmd = parts[1].upper() if len(parts) > 1 else ""
            rest = parts[2] if len(parts) > 2 else ""
        else:
            parts = line.split(None, 1)
            cmd = parts[0].upper()
            rest = parts[1] if len(parts) > 1 else ""

        handler = self._COMMAND_MAP.get(cmd)
        if handler is not None:
            handler(self, rest, safe_addr)
        elif self.registered and cmd:
            self._send(f"421 {self.nick} {cmd} :Unknown command")

    # â”€â”€ Per-command handlers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _cmd_cap(self, rest: str, _sa: str):
        sub = rest.split()[0].upper() if rest.split() else ""
        if sub == "LS":
            self._send_raw(f":{self.hostname} CAP * LS :")
        elif sub == "REQ":
            caps = rest[3:].strip().lstrip(":")
            self._send_raw(f":{self.hostname} CAP * NAK :{caps}")

    def _cmd_pass(self, _rest: str, _sa: str):
        pass  # Accept any password silently

    def _cmd_nick(self, rest: str, _sa: str):
        new_nick = rest.strip().split()[0] if rest.strip() else "bot"
        _nick_special = "-_[]{}\\|`^"
        _stripped = new_nick.translate(str.maketrans("", "", _nick_special))
        if len(new_nick) > 30 or not _stripped.isalnum():
            self._send(f"432 * {sanitize_log_string(new_nick[:30])} :Erroneous Nickname")
            return
        self.nick = sanitize_log_string(new_nick[:30]) or "bot"
        if self.user and not self.registered:
            self.registered = True
            self._welcome()

    def _cmd_user(self, rest: str, _sa: str):
        u_parts = rest.split(None, 1)
        self.user = u_parts[0][:20] if u_parts else "user"
        if self.nick and not self.registered:
            self.registered = True
            self._welcome()

    def _cmd_ping(self, rest: str, _sa: str):
        token = rest.lstrip(":").strip() or self.hostname
        self._send_raw(f":{self.hostname} PONG {self.hostname} :{token}")

    def _cmd_pong(self, _rest: str, _sa: str):
        self._waiting_for_pong = False
        self.conn.settimeout(_PING_INTERVAL)

    def _cmd_join(self, rest: str, _sa: str):
        if not self.registered:
            return
        if rest.strip() == "0":
            return
        for ch in rest.split(","):
            ch = ch.strip().split()[0]
            if ch.startswith(("#", "&")):
                self._do_join(ch)

    def _cmd_part(self, rest: str, _sa: str):
        if not self.registered:
            return
        ch = rest.split()[0] if rest.split() else ""
        self._send_raw(
            f":{self.nick}!{self.user}@{self.hostname} PART {ch} :Leaving"
        )

    def _cmd_privmsg(self, rest: str, safe_addr: str):
        if not self.registered:
            return
        safe_msg = sanitize_log_string(rest)
        logger.info(
            f"IRC  PRIVMSG [{safe_addr}] {self.nick}: {safe_msg[:200]}"
        )
        jl = get_json_logger()
        if jl:
            jl.log(
                "irc_message",
                src_ip=self.addr[0],
                nick=self.nick, type="PRIVMSG", message=safe_msg[:200],
            )

    def _cmd_notice(self, rest: str, safe_addr: str):
        if not self.registered:
            return
        safe_msg = sanitize_log_string(rest)
        logger.info(
            f"IRC  NOTICE [{safe_addr}] {self.nick}: {safe_msg[:200]}"
        )
        jl = get_json_logger()
        if jl:
            jl.log(
                "irc_message",
                src_ip=self.addr[0],
                nick=self.nick, type="NOTICE", message=safe_msg[:200],
            )

    def _cmd_who(self, rest: str, _sa: str):
        if not self.registered:
            return
        target = rest.strip().lstrip(":").split()[0] if rest.strip() else "*"
        self._send(f"315 {self.nick} {target} :End of /WHO list.")

    def _cmd_whois(self, rest: str, _sa: str):
        if not self.registered:
            return
        target = rest.strip().split()[0] if rest.strip() else ""
        safe_target = sanitize_log_string(target)
        self._send(
            f"401 {self.nick} {safe_target} :No such nick/channel"
        )

    def _cmd_mode(self, rest: str, _sa: str):
        if not self.registered:
            return
        target = rest.strip().split()[0] if rest.strip() else ""
        if target.startswith(("#", "&")):
            self._send(f"324 {self.nick} {target} +")
            self._send(f"329 {self.nick} {target} {_CHANNEL_EPOCH}")
        else:
            self._send(f"221 {self.nick} +i")

    def _cmd_list(self, _rest: str, _sa: str):
        if not self.registered:
            return
        self._send(f"321 {self.nick} Channel :Users  Name")
        self._send(f"322 {self.nick} #{self.channel} 1 :Fake channel")
        self._send(f"323 {self.nick} :End of /LIST")

    def _cmd_names(self, rest: str, _sa: str):
        if not self.registered:
            return
        ch = rest.strip().split()[0] if rest.strip() else f"#{self.channel}"
        self._send(f"353 {self.nick} = {ch} :@admin {self.nick}")
        self._send(f"366 {self.nick} {ch} :End of /NAMES list.")

    def _cmd_topic(self, rest: str, _sa: str):
        if not self.registered:
            return
        ch = rest.strip().split()[0] if rest.strip() else ""
        self._send(f"332 {self.nick} {ch} :Welcome")

    def _cmd_ison(self, _rest: str, _sa: str):
        self._send(f"303 {self.nick} :")

    def _cmd_away(self, _rest: str, _sa: str):
        self._send(f"305 {self.nick} :You are no longer marked as being away")

    def _cmd_userhost(self, _rest: str, _sa: str):
        if not self.registered:
            return
        self._send(f"302 {self.nick} :")

    def _cmd_quit(self, _rest: str, _sa: str):
        try:
            self.conn.close()
        except OSError:
            pass

    _COMMAND_MAP: dict[str, Callable[["_IRCClientThread", str, str], None]] = {
        "CAP":     _cmd_cap,
        "PASS":    _cmd_pass,
        "NICK":    _cmd_nick,
        "USER":    _cmd_user,
        "PING":    _cmd_ping,
        "PONG":    _cmd_pong,
        "JOIN":    _cmd_join,
        "PART":    _cmd_part,
        "PRIVMSG": _cmd_privmsg,
        "NOTICE":  _cmd_notice,
        "WHO":     _cmd_who,
        "WHOIS":   _cmd_whois,
        "MODE":    _cmd_mode,
        "LIST":    _cmd_list,
        "NAMES":   _cmd_names,
        "TOPIC":   _cmd_topic,
        "ISON":    _cmd_ison,
        "AWAY":    _cmd_away,
        "USERHOST": _cmd_userhost,
        "QUIT":    _cmd_quit,
    }


# â”€â”€â”€ Service wrappers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€


class IRCService:
    """Fake IRC server â€” accepts botnet C2 connections on TCP."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 6667))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", "irc.example.com")
        self.network = config.get("network", "FakeNet")
        self.channel = config.get("channel", "botnet")
        self.motd = config.get("motd", "Welcome to IRC.")
        self._sem = threading.BoundedSemaphore(int(config.get("max_connections", 150)))
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            logger.info("IRC service disabled in config.")
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="irc-server"
            )
            self._thread.start()
            logger.info("IRC service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("IRC service failed to start: %s", e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("IRC at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _IRCClientThread(
                conn, addr,
                hostname=self.hostname,
                network=self.network,
                channel=self.channel,
                motd=self.motd,
                sem=self._sem,
            ).start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("IRC service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()


class IRCSTLSService:
    """
    TLS-wrapped IRC server on port 6697 (ircs).

    Modern botnets increasingly use SSL IRC to avoid plaintext interception.
    This service wraps each accepted connection in TLS before handing it to
    the same ``_IRCClientThread`` handler â€” giving you full IRC sinkholing
    over encrypted channels with no code duplication.
    """

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled   = config.get("enabled", True)
        self.port      = int(config.get("port", 6697))
        self.bind_ip   = bind_ip
        self.hostname  = config.get("hostname",  "irc.example.com")
        self.network   = config.get("network",   "FakeNet")
        self.channel   = config.get("channel",   "botnet")
        self.motd      = config.get("motd",      "Welcome to IRC.")
        self.cert_path = str(config.get("cert_file", "certs/server.crt"))
        self.key_path  = str(config.get("key_file",  "certs/server.key"))
        self._sem      = threading.BoundedSemaphore(int(config.get("max_connections", 150)))
        self._sock:   socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop    = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            return False
        if not (
            os.path.exists(self.cert_path) and os.path.exists(self.key_path)
        ):
            logger.warning(
                "IRC/TLS (port %d): cert or key not found â€” skipping", self.port
            )
            return False
        try:
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self._ssl_ctx.load_cert_chain(
                certfile=self.cert_path, keyfile=self.key_path
            )
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="ircs-server"
            )
            self._thread.start()
            logger.info("IRC/TLS service started on %s:%d", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("IRC/TLS failed to start: %s", e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                raw_conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("IRC/TLS at capacity, dropping %s", sanitize_ip(addr[0]))
                raw_conn.close()
                continue
            # TLS wrap before handing to the IRC handler
            try:
                conn = self._ssl_ctx.wrap_socket(raw_conn, server_side=True)
            except ssl.SSLError as e:
                logger.debug("IRC/TLS handshake failed %s: %s", addr[0], e)
                self._sem.release()   # release slot â€” session never started
                try:
                    raw_conn.close()
                except OSError:
                    pass
                continue
            _IRCClientThread(
                conn, addr,
                hostname=self.hostname,
                network=self.network,
                channel=self.channel,
                motd=self.motd,
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
        logger.info("IRC/TLS service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
