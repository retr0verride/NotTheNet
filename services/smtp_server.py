"""
NotTheNet - Fake SMTP / SMTPS server.
Accepts inbound mail and archives messages to a sandboxed directory.

Security notes (OpenSSF):
- Received email files are written to a sandboxed directory only
- File names are UUID-based (no attacker-controlled filename)
- Total saved file size capped to prevent disk exhaustion
- Command parsing uses a whitelist state machine, no eval/exec
- Banner string is config-supplied but sanitized before sending
"""

from __future__ import annotations

import logging
import os
import socket
import socketserver
import ssl
import threading
import uuid
from collections.abc import Callable
from typing import Any

from services.mail_common import (
    _DEFAULT_CERT,
    _DEFAULT_HOSTNAME,
    _DEFAULT_KEY,
    _MAX_CONNECTIONS,
)
from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)


MAX_EMAIL_SIZE_BYTES = 5 * 1024 * 1024   # 5 MB per message
MAX_DISK_USAGE_BYTES = 100 * 1024 * 1024  # 100 MB total email storage cap

_SMTP_OK = "250 Ok"


class _SMTPClientThread(threading.Thread):
    """Handles a single SMTP client connection in its own thread."""

    def __init__(
        self, conn: socket.socket, addr: tuple[str, int],
        hostname: str, banner: str, save_dir: str | None,
        cert_path: str = "", key_path: str = "",
        conn_timeout: float = 30.0,
        max_email_size_bytes: int = MAX_EMAIL_SIZE_BYTES,
        max_disk_usage_bytes: int = MAX_DISK_USAGE_BYTES,
        on_exit: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(daemon=True)
        self._on_exit = on_exit  # runs after the socket closes, even on error
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
        self.mail_data: list[str] = []
        self.current_size = 0
        # AUTH LOGIN is a two-step challenge; track which step we're on.
        # None = not in auth, 'login_user' = waiting for username,
        # 'login_pass' = waiting for password.
        self._auth_state: str | None = None

    def _send(self, msg: str) -> None:
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except OSError:
            logger.debug("SMTP control send failed", exc_info=True)

    def run(self) -> None:
        try:
            self._session()
        finally:
            if self._on_exit is not None:
                self._on_exit()

    def _session(self) -> None:
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
        except Exception as e:  # noqa: BLE001  # untrusted-input boundary: one bad session must not kill the service
            logger.debug("SMTP client %s error: %s", safe_addr, e, exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                logger.debug("SMTP socket close failed", exc_info=True)

    def _handle_line(self, line: str, safe_addr: str) -> None:
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
            # Unexpected state — reset
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

    def _smtp_ehlo(self, _line: str, _safe_addr: str) -> None:
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

    def _smtp_auth(self, line: str, _safe_addr: str) -> None:
        parts = line.split(None, 2)
        mech = parts[1].upper() if len(parts) > 1 else ""
        if mech == "PLAIN":
            self._send("235 2.7.0 Authentication successful")
        elif mech == "LOGIN":
            self._auth_state = "login_user"
            self._send("334 VXNlcm5hbWU6")  # base64("Username:")
        else:
            self._send("535 5.7.8 Authentication credentials invalid")

    def _smtp_mail(self, _line: str, _sa: str) -> None:
        self._send(_SMTP_OK)

    def _smtp_rcpt(self, _line: str, _sa: str) -> None:
        self._send(_SMTP_OK)

    def _smtp_data(self, _line: str, _sa: str) -> None:
        self.data_mode = True
        self._send("354 End data with <CR><LF>.<CR><LF>")

    def _smtp_rset(self, _line: str, _sa: str) -> None:
        self.mail_data = []
        self.current_size = 0
        self._send(_SMTP_OK)

    def _smtp_vrfy(self, _line: str, _sa: str) -> None:
        self._send("252 Cannot VRFY user, but will accept message and attempt delivery")

    def _smtp_quit(self, _line: str, _sa: str) -> None:
        self._send("221 Bye")
        self.conn.close()

    def _smtp_noop(self, _line: str, _sa: str) -> None:
        self._send(_SMTP_OK)

    def _smtp_starttls(self, _line: str, safe_addr: str) -> None:
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
    _SMTP_DISPATCH: dict[str, Callable[[_SMTPClientThread, str, str], None]] = {
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

    def _save_email(self) -> None:
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
        except OSError:
            logger.debug("SMTP disk-usage check failed", exc_info=True)

        fname = f"{uuid.uuid4().hex}.eml"  # UUID filename — no attacker control
        path = os.path.join(self.save_dir, fname)
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write("\n".join(self.mail_data))
            logger.info("SMTP: email saved to %s", fname)
        except OSError as e:
            logger.error("SMTP: failed to save email: %s", e)


class _SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], hostname: str, banner: str, save_dir: str | None,
                 cert_path: str = "", key_path: str = "",
                 conn_timeout: float = 30.0,
                 max_email_size_bytes: int = MAX_EMAIL_SIZE_BYTES,
                 max_disk_usage_bytes: int = MAX_DISK_USAGE_BYTES,
                 max_connections: int | None = None) -> None:
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
        # process_request() is overridden and spawns _SMTPClientThread itself, so
        # no handler class is ever instantiated; None makes accidental use fail loudly.
        super().__init__(address, None)  # type: ignore[arg-type]

    def server_bind(self) -> None:
        self._sem = threading.BoundedSemaphore(self.smtp_max_connections)
        super().server_bind()

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:  # type: ignore[override]  # TCP-only server: request is always a socket
        """Spawn a session thread that fully owns the socket lifetime.

        Overriding process_request (instead of finish_request) avoids the
        ThreadingTCPServer race where shutdown_request() — which closes the
        socket — is called immediately after finish_request() returns but
        before the session thread has read a single byte.
        """
        if not self._sem.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                logger.debug("SMTP request close failed at connection-cap limit", exc_info=True)
            return
        _SMTPClientThread(
            request, client_address,
            self.smtp_hostname, self.smtp_banner, self.smtp_save_dir,
            cert_path=self.smtp_cert_path, key_path=self.smtp_key_path,
            conn_timeout=self.smtp_conn_timeout,
            max_email_size_bytes=self.smtp_max_email_size_bytes,
            max_disk_usage_bytes=self.smtp_max_disk_usage_bytes,
            on_exit=self._sem.release,  # the session thread owns the socket and the slot
        ).start()


class _SMTPSServer(_SMTPServer):
    """SMTPS variant — wraps each accepted socket in TLS before handing off."""

    def __init__(
        self,
        address: tuple[str, int],
        hostname: str,
        banner: str,
        save_dir: str | None,
        ssl_ctx: ssl.SSLContext,
        conn_timeout: float = 30.0,
        max_email_size_bytes: int = MAX_EMAIL_SIZE_BYTES,
        max_disk_usage_bytes: int = MAX_DISK_USAGE_BYTES,
        max_connections: int | None = None,
    ) -> None:
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

    def get_request(self) -> tuple[socket.socket, tuple[str, int]]:
        conn, addr = self.socket.accept()
        try:
            conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            logger.debug("SMTPS TLS handshake failed from %s: %s", addr, e)
            conn.close()
            raise
        return conn, addr


class SMTPService:
    def __init__(self, config: dict[str, Any], bind_ip: str = "0.0.0.0") -> None:
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
    Uses the same protocol handler as SMTP — just wraps the socket in TLS
    before the banner is sent.  RedLine, AgentTesla, FormBook, and most
    other stealers that exfiltrate via email use port 465 exclusively.
    """

    def __init__(self, config: dict[str, Any], bind_ip: str = "0.0.0.0") -> None:
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
