"""
NotTheNet - Fake SMTP / POP3 / IMAP Server
Accepts inbound mail connections and silently discards or archives messages.

Security notes (OpenSSF):
- Received email files are written to a sandboxed directory only
- File names are UUID-based (no attacker-controlled filename)
- Total saved file size capped to prevent disk exhaustion
- Command parsing uses a whitelist state machine â€” no eval/exec
- Banner string is config-supplied but sanitized before sending
"""

import logging
import os
import socket
import socketserver
import ssl
import threading
import uuid

from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE_BYTES = 5 * 1024 * 1024   # 5 MB per message
MAX_DISK_USAGE_BYTES = 100 * 1024 * 1024  # 100 MB total email storage cap

_SMTP_OK = "250 Ok"

_DEFAULT_HOSTNAME = "mail.example.com"
_DEFAULT_CERT = "certs/server.crt"
_DEFAULT_KEY = "certs/server.key"


_MAX_CONNECTIONS = 50   # maximum simultaneous connections per mail server instance


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address set as a class attribute.
    This MUST be a class attribute (not instance attribute) so it is read
    before server_bind() is called inside __init__.
    """
    allow_reuse_address = True
    daemon_threads = True
    # Mail-handler config; set by XxxService.start() before serve_forever().
    # Declared here so the attributes are always defined on the class.
    _mail_hostname: str = _DEFAULT_HOSTNAME
    _mail_cert_path: str = ""
    _mail_key_path: str = ""
    _conn_timeout: float = 30.0

    def configure_handler(
        self,
        hostname: str = _DEFAULT_HOSTNAME,
        cert_path: str = "",
        key_path: str = "",
        conn_timeout: float = 30.0,
    ) -> None:
        """Set per-instance mail-handler parameters before serve_forever()."""
        self._mail_hostname = hostname
        self._mail_cert_path = cert_path
        self._mail_key_path = key_path
        self._conn_timeout = conn_timeout

    def __init__(self, server_address, request_handler_class,
                 max_connections: int = _MAX_CONNECTIONS):
        self._sem = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, request_handler_class)

    def process_request(self, request, client_address):
        """Drop connection immediately if the session limit is reached."""
        if not self._sem.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                logger.debug("Mail request close failed at connection-cap limit", exc_info=True)
            return
        sem = self._sem

        def _run():
            try:
                self.finish_request(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
            finally:
                self.shutdown_request(request)
                sem.release()

        t = threading.Thread(target=_run, daemon=True)
        t.start()


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

class _SMTPClientThread(threading.Thread):
    """Handles a single SMTP client connection in its own thread."""

    def __init__(
        self, conn, addr, hostname: str, banner: str, save_dir: str | None,
        cert_path: str = "", key_path: str = "",
        conn_timeout: float = 30.0,
        max_email_size_bytes: int = MAX_EMAIL_SIZE_BYTES,
        max_disk_usage_bytes: int = MAX_DISK_USAGE_BYTES,
    ):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.hostname = hostname
        self.banner = banner
        self.save_dir = save_dir
        self.cert_path = cert_path
        self.key_path = key_path
        self.conn_timeout = conn_timeout
        self.max_email_size_bytes = max_email_size_bytes
        self.max_disk_usage_bytes = max_disk_usage_bytes
        self.data_mode = False
        self.mail_data: list = []
        self.current_size = 0
        # AUTH LOGIN is a two-step challenge; track which step we're on.
        # None = not in auth, 'login_user' = waiting for username,
        # 'login_pass' = waiting for password.
        self._auth_state: str | None = None

    def _send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            logger.debug("SMTP control send failed", exc_info=True)

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        logger.info("SMTP connection from %s", safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("smtp_connection", src_ip=self.addr[0])
        try:
            banner = sanitize_log_string(self.banner, max_length=200)
            self._send(banner)
            self.conn.settimeout(self.conn_timeout)
            buf = b""
            while True:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n" in buf or (self.data_mode and b"\n" in buf):
                    sep = b"\r\n" if b"\r\n" in buf else b"\n"
                    line, buf = buf.split(sep, 1)
                    self._handle_line(line.decode("utf-8", errors="replace"), safe_addr)
        except Exception as e:
            logger.debug("SMTP client %s error: %s", safe_addr, e)
        finally:
            try:
                self.conn.close()
            except Exception:
                logger.debug("SMTP socket close failed", exc_info=True)

    def _handle_line(self, line: str, safe_addr: str):
        if self.data_mode:
            if line.strip() == ".":
                self.data_mode = False
                self._save_email()
                self._send("250 OK: Message accepted")
                self.mail_data = []
                self.current_size = 0
            else:
                # Limit individual message size
                if self.current_size < self.max_email_size_bytes:
                    self.mail_data.append(line)
                    self.current_size += len(line)
            return

        # AUTH LOGIN is a two-step challenge.  Check auth state BEFORE
        # command parsing: the client sends raw base64 blobs that must not
        # be dispatched through the command table (a blob that uppercases
        # to e.g. "DATA" would fire the wrong branch).
        if self._auth_state == "login_user":
            self._auth_state = "login_pass"
            self._send("334 UGFzc3dvcmQ6")  # base64("Password:")
            return
        if self._auth_state == "login_pass":
            self._auth_state = None
            self._send("235 2.7.0 Authentication successful")
            return
        if self._auth_state is not None:
            # Unexpected state â€” reset
            self._auth_state = None

        cmd = line.strip().upper()[:10]
        logger.debug("SMTP  [%s] cmd=%s", safe_addr, sanitize_log_string(cmd))

        # Match the first SMTP verb token against the dispatch table.
        verb = cmd.split()[0] if cmd.split() else ""
        handler = self._SMTP_DISPATCH.get(verb)
        if handler is not None:
            handler(self, line, safe_addr)
        else:
            self._send("500 Unrecognized command")

    # -- Per-verb SMTP handlers ------------------------------------------------

    def _smtp_ehlo(self, _line: str, _safe_addr: str):
        starttls_line = ""
        if (
            self.cert_path
            and self.key_path
            and os.path.exists(self.cert_path)
            and os.path.exists(self.key_path)
        ):
            starttls_line = "250-STARTTLS\r\n"
        self._send(
            f"250-{self.hostname}\r\n"
            f"250-PIPELINING\r\n"
            f"250-SIZE 10240000\r\n"
            f"250-VRFY\r\n"
            f"250-ETRN\r\n"
            f"{starttls_line}"
            f"250-AUTH PLAIN LOGIN\r\n"
            f"250-AUTH=PLAIN LOGIN\r\n"
            f"250-ENHANCEDSTATUSCODES\r\n"
            f"250-8BITMIME\r\n"
            f"250 DSN"
        )

    def _smtp_auth(self, line: str, _safe_addr: str):
        parts = line.split(None, 2)
        mech = parts[1].upper() if len(parts) > 1 else ""
        if mech == "PLAIN":
            self._send("235 2.7.0 Authentication successful")
        elif mech == "LOGIN":
            self._auth_state = "login_user"
            self._send("334 VXNlcm5hbWU6")  # base64("Username:")
        else:
            self._send("535 5.7.8 Authentication credentials invalid")

    def _smtp_mail(self, _line: str, _sa: str):
        self._send(_SMTP_OK)

    def _smtp_rcpt(self, _line: str, _sa: str):
        self._send(_SMTP_OK)

    def _smtp_data(self, _line: str, _sa: str):
        self.data_mode = True
        self._send("354 End data with <CR><LF>.<CR><LF>")

    def _smtp_rset(self, _line: str, _sa: str):
        self.mail_data = []
        self.current_size = 0
        self._send(_SMTP_OK)

    def _smtp_vrfy(self, _line: str, _sa: str):
        self._send("252 Cannot VRFY user, but will accept message and attempt delivery")

    def _smtp_quit(self, _line: str, _sa: str):
        self._send("221 Bye")
        self.conn.close()

    def _smtp_noop(self, _line: str, _sa: str):
        self._send(_SMTP_OK)

    def _smtp_starttls(self, _line: str, safe_addr: str):
        if self.data_mode:
            self._send("503 Bad sequence of commands")
            return
        if (
            self.cert_path
            and self.key_path
            and os.path.exists(self.cert_path)
            and os.path.exists(self.key_path)
        ):
            self._send("220 Ready to start TLS")
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
                self.conn = ctx.wrap_socket(self.conn, server_side=True)
                self._auth_state = None
                logger.debug("SMTP STARTTLS handshake complete: %s", safe_addr)
            except ssl.SSLError as e:
                logger.debug("SMTP STARTTLS handshake failed %s: %s", safe_addr, e)
        else:
            self._send("454 TLS not available due to temporary reason")

    # Dispatch table: verb → handler (O(1) dict lookup).
    _SMTP_DISPATCH: dict[str, object] = {
        "EHLO":     _smtp_ehlo,
        "HELO":     _smtp_ehlo,
        "AUTH":     _smtp_auth,
        "MAIL":     _smtp_mail,
        "RCPT":     _smtp_rcpt,
        "DATA":     _smtp_data,
        "RSET":     _smtp_rset,
        "VRFY":     _smtp_vrfy,
        "QUIT":     _smtp_quit,
        "NOOP":     _smtp_noop,
        "STARTTLS": _smtp_starttls,
    }

    def _save_email(self):
        if not self.save_dir or not self.mail_data:
            return
        # Check total disk usage before writing
        try:
            total = sum(
                os.path.getsize(os.path.join(self.save_dir, f))
                for f in os.listdir(self.save_dir)
                if os.path.isfile(os.path.join(self.save_dir, f))
            )
            if total > self.max_disk_usage_bytes:
                logger.warning("SMTP: email storage cap reached; discarding message.")
                return
        except Exception:
            logger.debug("SMTP disk-usage check failed", exc_info=True)

        fname = f"{uuid.uuid4().hex}.eml"  # UUID filename â€” no attacker control
        path = os.path.join(self.save_dir, fname)
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write("\n".join(self.mail_data))
            logger.info("SMTP: email saved to %s", fname)
        except Exception as e:
            logger.error("SMTP: failed to save email: %s", e)


class _SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, hostname, banner, save_dir,
                 cert_path: str = "", key_path: str = "",
                 conn_timeout: float = 30.0,
                 max_email_size_bytes: int = MAX_EMAIL_SIZE_BYTES,
                 max_disk_usage_bytes: int = MAX_DISK_USAGE_BYTES,
                 max_connections: int | None = None):
        self.smtp_hostname = hostname
        self.smtp_banner = banner
        self.smtp_save_dir = save_dir
        self.smtp_cert_path = cert_path
        self.smtp_key_path = key_path
        self.smtp_conn_timeout = conn_timeout
        self.smtp_max_email_size_bytes = max_email_size_bytes
        self.smtp_max_disk_usage_bytes = max_disk_usage_bytes
        self.smtp_max_connections = int(
            _MAX_CONNECTIONS if max_connections is None else max_connections
        )
        super().__init__(address, None)

    def server_bind(self):
        self._sem = threading.BoundedSemaphore(self.smtp_max_connections)
        super().server_bind()

    def process_request(self, request, client_address):
        """Spawn a session thread that fully owns the socket lifetime.

        Overriding process_request (instead of finish_request) avoids the
        ThreadingTCPServer race where shutdown_request() â€” which closes the
        socket â€” is called immediately after finish_request() returns but
        before the session thread has read a single byte.
        """
        if not self._sem.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                logger.debug("SMTP request close failed at connection-cap limit", exc_info=True)
            return
        sem = self._sem
        t = _SMTPClientThread(
            request, client_address,
            self.smtp_hostname, self.smtp_banner, self.smtp_save_dir,
            cert_path=self.smtp_cert_path, key_path=self.smtp_key_path,
            conn_timeout=self.smtp_conn_timeout,
            max_email_size_bytes=self.smtp_max_email_size_bytes,
            max_disk_usage_bytes=self.smtp_max_disk_usage_bytes,
        )
        # Wrap run() so the semaphore is released and the socket is closed
        # when the session ends â€” the server lifecycle never touches it.
        _orig_run = t.run

        def _guarded_run():
            try:
                _orig_run()
            finally:
                sem.release()
                try:
                    request.close()
                except OSError:
                    logger.debug("SMTP request close failed after session", exc_info=True)

        t.run = _guarded_run
        t.daemon = True
        t.start()


class _SMTPSServer(_SMTPServer):
    """SMTPS variant â€” wraps each accepted socket in TLS before handing off."""

    def __init__(
        self,
        address,
        hostname,
        banner,
        save_dir,
        ssl_ctx: ssl.SSLContext,
        conn_timeout: float = 30.0,
        max_email_size_bytes: int = MAX_EMAIL_SIZE_BYTES,
        max_disk_usage_bytes: int = MAX_DISK_USAGE_BYTES,
        max_connections: int | None = None,
    ):
        self._ssl_ctx = ssl_ctx
        super().__init__(
            address,
            hostname,
            banner,
            save_dir,
            conn_timeout=conn_timeout,
            max_email_size_bytes=max_email_size_bytes,
            max_disk_usage_bytes=max_disk_usage_bytes,
            max_connections=max_connections,
        )

    def get_request(self):
        conn, addr = self.socket.accept()
        try:
            conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            logger.debug("SMTPS TLS handshake failed from %s: %s", addr, e)
            conn.close()
            raise
        return conn, addr


class _SSLReuseServer(_ReuseServer):
    """ThreadingTCPServer that wraps accepted sockets in TLS."""

    def __init__(self, address, handler, ssl_ctx: ssl.SSLContext,
                 max_connections: int = _MAX_CONNECTIONS):
        self._ssl_ctx = ssl_ctx
        super().__init__(address, handler, max_connections)

    def get_request(self):
        conn, addr = self.socket.accept()
        try:
            conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            logger.debug("TLS handshake failed from %s: %s", addr, e)
            conn.close()
            raise
        return conn, addr


class SMTPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 25))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", _DEFAULT_HOSTNAME)
        self.banner = config.get("banner", f"220 {_DEFAULT_HOSTNAME} ESMTP")
        self.cert_file = config.get("cert_file", _DEFAULT_CERT)
        self.key_file  = config.get("key_file",  _DEFAULT_KEY)
        save_emails = config.get("save_emails", True)
        self.save_dir = "logs/emails" if save_emails else None
        self.conn_timeout = float(config.get("conn_timeout_sec", 30))
        self.max_email_size_bytes = int(config.get("max_email_size_bytes", MAX_EMAIL_SIZE_BYTES))
        self.max_disk_usage_bytes = int(config.get("max_disk_usage_bytes", MAX_DISK_USAGE_BYTES))
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self._server: _SMTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        if self.save_dir:
            os.makedirs(self.save_dir, exist_ok=True)
        try:
            ensure_certs(self.cert_file, self.key_file)
            self._server = _SMTPServer(
                (self.bind_ip, self.port), self.hostname, self.banner, self.save_dir,
                cert_path=self.cert_file, key_path=self.key_file,
                conn_timeout=self.conn_timeout,
                max_email_size_bytes=self.max_email_size_bytes,
                max_disk_usage_bytes=self.max_disk_usage_bytes,
                max_connections=self.max_connections,
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("SMTP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("SMTP failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("SMTP server socket shutdown failed", exc_info=True)
            self._server.shutdown()
            self._server = None
        logger.info("SMTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class SMTPSService:
    """
    Fake SMTPS server (implicit TLS on port 465).
    Uses the same protocol handler as SMTP â€” just wraps the socket in TLS
    before the banner is sent.  RedLine, AgentTesla, FormBook, and most
    other stealers that exfiltrate via email use port 465 exclusively.
    """

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 465))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", _DEFAULT_HOSTNAME)
        self.banner = config.get("banner", f"220 {_DEFAULT_HOSTNAME} ESMTP")
        self.cert_file = config.get("cert_file", _DEFAULT_CERT)
        self.key_file = config.get("key_file", _DEFAULT_KEY)
        save_emails = config.get("save_emails", True)
        self.save_dir = "logs/emails" if save_emails else None
        self.conn_timeout = float(config.get("conn_timeout_sec", 30))
        self.max_email_size_bytes = int(config.get("max_email_size_bytes", MAX_EMAIL_SIZE_BYTES))
        self.max_disk_usage_bytes = int(config.get("max_disk_usage_bytes", MAX_DISK_USAGE_BYTES))
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self._server: _SMTPSServer | None = None
        self._thread: threading.Thread | None = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def start(self) -> bool:
        if not self.enabled:
            return False
        ensure_certs(self.cert_file, self.key_file)
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.error("SMTPS cert/key not found: %s / %s", self.cert_file, self.key_file)
            return False
        if self.save_dir:
            os.makedirs(self.save_dir, exist_ok=True)
        try:
            ssl_ctx = self._build_ssl_context()
            self._server = _SMTPSServer(
                (self.bind_ip, self.port),
                self.hostname,
                self.banner,
                self.save_dir,
                ssl_ctx,
                conn_timeout=self.conn_timeout,
                max_email_size_bytes=self.max_email_size_bytes,
                max_disk_usage_bytes=self.max_disk_usage_bytes,
                max_connections=self.max_connections,
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("SMTPS service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("SMTPS failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("SMTPS server socket shutdown failed", exc_info=True)
            self._server.shutdown()
            self._server = None
        logger.info("SMTPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


# ---------------------------------------------------------------------------
# POP3
# ---------------------------------------------------------------------------

class POP3Handler(socketserver.BaseRequestHandler):
    """POP3 request handler — reads config from the owning server instance."""

    def handle(self) -> None:
        safe_addr = sanitize_ip(self.client_address[0])
        logger.info("POP3 connection from %s", safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("pop3_connection", src_ip=self.client_address[0])
        try:
            srv = self.server
            self._hostname = getattr(srv, '_mail_hostname', _DEFAULT_HOSTNAME)
            self._cert_path = getattr(srv, '_mail_cert_path', '')
            self._key_path = getattr(srv, '_mail_key_path', '')
            self._conn_timeout = float(getattr(srv, '_conn_timeout', 30))
            self._tls_ready = (
                self._cert_path
                and self._key_path
                and os.path.exists(self._cert_path)
                and os.path.exists(self._key_path)
            )
            self._send(f"+OK {self._hostname} POP3 server ready")
            self.request.settimeout(self._conn_timeout)
            self._read_loop(safe_addr)
        except Exception as e:
            logger.debug("POP3 %s error: %s", safe_addr, e)

    def _read_loop(self, safe_addr: str) -> None:
        buf = b""
        while True:
            chunk = self.request.recv(1024)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                if self._dispatch_line(line, safe_addr) is False:
                    return

    def _dispatch_line(self, line: bytes, safe_addr: str) -> "bool | None":
        cmd = line.decode("utf-8", errors="replace").strip().upper()[:8]
        verb = cmd.split()[0] if cmd.split() else ""
        handler = self._POP3_DISPATCH.get(verb)
        if handler:
            return handler(self, safe_addr)
        self._send("-ERR Unknown command")
        return None

    def _pop3_user(self, _sa: str):
        self._send("+OK")

    def _pop3_pass(self, _sa: str):
        self._send("+OK Logged in")

    def _pop3_stat(self, _sa: str):
        self._send("+OK 0 0")

    def _pop3_list(self, _sa: str):
        self._send("+OK 0 messages\r\n.")

    def _pop3_uidl(self, _sa: str):
        self._send("+OK\r\n.")

    def _pop3_quit(self, _sa: str):
        self._send("+OK Bye")
        return False  # signal to close connection

    def _pop3_capa(self, _sa: str):
        capa = "+OK\r\nUSER\r\nUIDL\r\nSTLS\r\n." if self._tls_ready else "+OK\r\nUSER\r\nUIDL\r\n."
        self._send(capa)

    def _pop3_stls(self, safe_addr: str):
        if self._tls_ready:
            self._send("+OK Begin TLS negotiation")
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(
                    certfile=self._cert_path,
                    keyfile=self._key_path,
                )
                self.request = ctx.wrap_socket(
                    self.request, server_side=True
                )
                logger.debug(
                    "POP3 STLS handshake complete: %s", safe_addr
                )
            except ssl.SSLError as e:
                logger.debug(
                    "POP3 STLS handshake failed %s: %s", safe_addr, e
                )
                return False
        else:
            self._send("-ERR TLS not available")

    _POP3_DISPATCH: dict[str, object] = {
        "USER": _pop3_user,
        "PASS": _pop3_pass,
        "STAT": _pop3_stat,
        "LIST": _pop3_list,
        "UIDL": _pop3_uidl,
        "QUIT": _pop3_quit,
        "CAPA": _pop3_capa,
        "STLS": _pop3_stls,
    }

    def _send(self, msg: str):
        try:
            self.request.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            logger.debug("POP3 send failed", exc_info=True)


class POP3Service:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 110))
        self.bind_ip = bind_ip
        self.hostname  = config.get("hostname",  _DEFAULT_HOSTNAME)
        self.cert_file = config.get("cert_file", _DEFAULT_CERT)
        self.key_file  = config.get("key_file",  _DEFAULT_KEY)
        self.conn_timeout = float(config.get("conn_timeout_sec", 30))
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            ensure_certs(self.cert_file, self.key_file)
            self._server = _ReuseServer(
                (self.bind_ip, self.port), POP3Handler, self.max_connections
            )
            self._server.configure_handler(
                self.hostname, self.cert_file, self.key_file, self.conn_timeout
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("POP3 service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("POP3 failed to bind: %s", e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("POP3 server socket shutdown failed", exc_info=True)
            self._server.shutdown()
            self._server = None
        logger.info("POP3 service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class POP3SService:
    """Fake POP3S server (implicit TLS on port 995)."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 995))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", _DEFAULT_HOSTNAME)
        self.cert_file = config.get("cert_file", _DEFAULT_CERT)
        self.key_file = config.get("key_file", _DEFAULT_KEY)
        self.conn_timeout = float(config.get("conn_timeout_sec", 30))
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self._server = None
        self._thread = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def start(self) -> bool:
        if not self.enabled:
            return False
        ensure_certs(self.cert_file, self.key_file)
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.error("POP3S cert/key not found: %s / %s", self.cert_file, self.key_file)
            return False
        try:
            ssl_ctx = self._build_ssl_context()
            self._server = _SSLReuseServer(
                (self.bind_ip, self.port), POP3Handler, ssl_ctx, self.max_connections
            )
            self._server.configure_handler(self.hostname, conn_timeout=self.conn_timeout)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("POP3S service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("POP3S failed to bind: %s", e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("POP3S server socket shutdown failed", exc_info=True)
            self._server.shutdown()
            self._server = None
        logger.info("POP3S service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------

class IMAPHandler(socketserver.BaseRequestHandler):
    """IMAP request handler — reads config from the owning server instance."""

    def handle(self) -> None:
        safe_addr = sanitize_ip(self.client_address[0])
        logger.info("IMAP connection from %s", safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("imap_connection", src_ip=self.client_address[0])
        self._tag: str = ""
        self._parts: list[str] = []
        try:
            srv = self.server
            self._hostname = getattr(srv, '_mail_hostname', _DEFAULT_HOSTNAME)
            self._cert_path = getattr(srv, '_mail_cert_path', '')
            self._key_path = getattr(srv, '_mail_key_path', '')
            self._conn_timeout = float(getattr(srv, '_conn_timeout', 30))
            self._tls_ready = (
                self._cert_path
                and self._key_path
                and os.path.exists(self._cert_path)
                and os.path.exists(self._key_path)
            )
            self._send(f"* OK {self._hostname} IMAP4rev1 ready")
            self.request.settimeout(self._conn_timeout)
            self._read_loop(safe_addr)
        except Exception as e:
            logger.debug("IMAP %s error: %s", safe_addr, e)

    def _read_loop(self, safe_addr: str) -> None:
        buf = b""
        while True:
            chunk = self.request.recv(2048)
            if not chunk:
                break
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                if self._dispatch_line(line, safe_addr) is False:
                    return

    def _dispatch_line(self, line: bytes, safe_addr: str) -> "bool | None":
        text = line.decode("utf-8", errors="replace").strip()
        parts = text.split(None, 2)
        if len(parts) < 2:
            return None
        self._tag = parts[0]
        self._parts = parts
        cmd = parts[1].upper()
        handler = self._IMAP_DISPATCH.get(cmd)
        if handler:
            return handler(self, safe_addr)
        self._send(f"{self._tag} NO Command not implemented")
        return None

    def _imap_starttls(self, safe_addr: str):
        if self._tls_ready:
            self._send(f"{self._tag} OK Begin TLS negotiation")
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(
                    certfile=self._cert_path,
                    keyfile=self._key_path,
                )
                self.request = ctx.wrap_socket(
                    self.request, server_side=True
                )
                logger.debug(
                    "IMAP STARTTLS handshake complete: %s", safe_addr
                )
            except ssl.SSLError as e:
                logger.debug(
                    "IMAP STARTTLS handshake failed %s: %s", safe_addr, e
                )
                return False
        else:
            self._send(f"{self._tag} NO TLS not available")

    def _imap_login(self, _sa: str):
        self._send(f"{self._tag} OK LOGIN completed")

    def _imap_capability(self, _sa: str):
        cap = (
            "* CAPABILITY IMAP4rev1 STARTTLS"
            if self._tls_ready else
            "* CAPABILITY IMAP4rev1"
        )
        self._send(f"{cap}\r\n{self._tag} OK")

    def _imap_list(self, _sa: str):
        self._send(f'* LIST () "/" INBOX\r\n{self._tag} OK LIST completed')

    def _imap_select(self, _sa: str):
        self._send(
            f"* 0 EXISTS\r\n* 0 RECENT\r\n"
            f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen)\r\n"
            f"{self._tag} OK [READ-WRITE] SELECT completed"
        )

    def _imap_examine(self, _sa: str):
        self._send(
            f"* 0 EXISTS\r\n* 0 RECENT\r\n"
            f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen)\r\n"
            f"{self._tag} OK [READ-ONLY] EXAMINE completed"
        )

    def _imap_status(self, _sa: str):
        mailbox = self._parts[2].split()[0].strip('"') if len(self._parts) > 2 else "INBOX"
        self._send(
            f"* STATUS {mailbox} (MESSAGES 0 RECENT 0 UNSEEN 0)\r\n"
            f"{self._tag} OK STATUS completed"
        )

    def _imap_lsub(self, _sa: str):
        self._send(f'* LSUB () "/" INBOX\r\n{self._tag} OK LSUB completed')

    def _imap_logout(self, _sa: str):
        self._send(f"* BYE\r\n{self._tag} OK LOGOUT completed")
        return False  # signal to close connection

    def _imap_noop(self, _sa: str):
        self._send(f"{self._tag} OK NOOP completed")

    _IMAP_DISPATCH: dict[str, object] = {
        "STARTTLS":   _imap_starttls,
        "LOGIN":      _imap_login,
        "CAPABILITY": _imap_capability,
        "LIST":       _imap_list,
        "SELECT":     _imap_select,
        "EXAMINE":    _imap_examine,
        "STATUS":     _imap_status,
        "LSUB":       _imap_lsub,
        "LOGOUT":     _imap_logout,
        "NOOP":       _imap_noop,
    }

    def _send(self, msg: str):
        try:
            self.request.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            logger.debug("IMAP send failed", exc_info=True)


class IMAPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 143))
        self.bind_ip = bind_ip
        self.hostname  = config.get("hostname",  _DEFAULT_HOSTNAME)
        self.cert_file = config.get("cert_file", _DEFAULT_CERT)
        self.key_file  = config.get("key_file",  _DEFAULT_KEY)
        self.conn_timeout = float(config.get("conn_timeout_sec", 30))
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            ensure_certs(self.cert_file, self.key_file)
            self._server = _ReuseServer(
                (self.bind_ip, self.port), IMAPHandler, self.max_connections
            )
            self._server.configure_handler(
                self.hostname, self.cert_file, self.key_file, self.conn_timeout
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("IMAP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("IMAP failed to bind: %s", e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("IMAP server socket shutdown failed", exc_info=True)
            self._server.shutdown()
            self._server = None
        logger.info("IMAP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class IMAPSService:
    """Fake IMAPS server (implicit TLS on port 993)."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 993))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", _DEFAULT_HOSTNAME)
        self.cert_file = config.get("cert_file", _DEFAULT_CERT)
        self.key_file = config.get("key_file", _DEFAULT_KEY)
        self.conn_timeout = float(config.get("conn_timeout_sec", 30))
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self._server = None
        self._thread = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def start(self) -> bool:
        if not self.enabled:
            return False
        ensure_certs(self.cert_file, self.key_file)
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.error("IMAPS cert/key not found: %s / %s", self.cert_file, self.key_file)
            return False
        try:
            ssl_ctx = self._build_ssl_context()
            self._server = _SSLReuseServer(
                (self.bind_ip, self.port), IMAPHandler, ssl_ctx, self.max_connections
            )
            self._server.configure_handler(self.hostname, conn_timeout=self.conn_timeout)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("IMAPS service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("IMAPS failed to bind: %s", e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                logger.debug("IMAPS server socket shutdown failed", exc_info=True)
            self._server.shutdown()
            self._server = None
        logger.info("IMAPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
