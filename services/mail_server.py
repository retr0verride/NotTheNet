"""
NotTheNet - Fake SMTP / POP3 / IMAP Server
Accepts inbound mail connections and silently discards or archives messages.

Security notes (OpenSSF):
- Received email files are written to a sandboxed directory only
- File names are UUID-based (no attacker-controlled filename)
- Total saved file size capped to prevent disk exhaustion
- Command parsing uses a whitelist state machine — no eval/exec
- Banner string is config-supplied but sanitized before sending
"""

import logging
import os
import socket
import socketserver
import ssl
import threading
import uuid
from typing import Optional

from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE_BYTES = 5 * 1024 * 1024   # 5 MB per message
MAX_DISK_USAGE_BYTES = 100 * 1024 * 1024  # 100 MB total email storage cap


_MAX_CONNECTIONS = 50   # maximum simultaneous connections per mail server instance


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address set as a class attribute.
    This MUST be a class attribute (not instance attribute) so it is read
    before server_bind() is called inside __init__.
    """
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        self._sem = threading.BoundedSemaphore(_MAX_CONNECTIONS)
        super().server_bind()

    def process_request(self, request, client_address):
        """Drop connection immediately if the session limit is reached."""
        if not self._sem.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
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
        self, conn, addr, hostname: str, banner: str, save_dir: Optional[str],
        cert_path: str = "", key_path: str = "",
    ):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.hostname = hostname
        self.banner = banner
        self.save_dir = save_dir
        self.cert_path = cert_path
        self.key_path = key_path
        self.data_mode = False
        self.mail_data: list = []
        self.current_size = 0
        # AUTH LOGIN is a two-step challenge; track which step we're on.
        # None = not in auth, 'login_user' = waiting for username,
        # 'login_pass' = waiting for password.
        self._auth_state: Optional[str] = None

    def _send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            pass

    def run(self):
        safe_addr = sanitize_ip(self.addr[0])
        logger.info(f"SMTP connection from {safe_addr}")
        jl = get_json_logger()
        if jl:
            jl.log("smtp_connection", src_ip=self.addr[0])
        try:
            banner = sanitize_log_string(self.banner, max_length=200)
            self._send(banner)
            self.conn.settimeout(30)
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
            logger.debug(f"SMTP client {safe_addr} error: {e}")
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

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
                if self.current_size < MAX_EMAIL_SIZE_BYTES:
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
        logger.debug(f"SMTP  [{safe_addr}] cmd={sanitize_log_string(cmd)}")

        if cmd.startswith("EHLO") or cmd.startswith("HELO"):
            # Advertise a realistic set of extensions so malware stealers
            # that check for AUTH before authenticating will find it.
            # Advertise STARTTLS when TLS certs are available — real Postfix
            # always does.  Stealers like AgentTesla/FormBook check for it.
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
        elif cmd.startswith("AUTH"):
            # Accept any credentials — AUTH PLAIN (single step) or
            # AUTH LOGIN (two-step challenge/response).
            parts = line.split(None, 2)
            mech = parts[1].upper() if len(parts) > 1 else ""
            if mech == "PLAIN":
                # AUTH PLAIN [initial-response] — accept immediately
                self._send("235 2.7.0 Authentication successful")
            elif mech == "LOGIN":
                # AUTH LOGIN — send Username: challenge
                self._auth_state = "login_user"
                self._send("334 VXNlcm5hbWU6")  # base64("Username:")
            else:
                self._send("535 5.7.8 Authentication credentials invalid")
        elif cmd.startswith("MAIL"):
            self._send("250 Ok")
        elif cmd.startswith("RCPT"):
            self._send("250 Ok")
        elif cmd.startswith("DATA"):
            self.data_mode = True
            self._send("354 End data with <CR><LF>.<CR><LF>")
        elif cmd.startswith("RSET"):
            self.mail_data = []
            self.current_size = 0
            self._send("250 Ok")
        elif cmd.startswith("VRFY"):
            # RFC 5321 §3.5.1: 252 = can’t verify but will try delivery
            self._send("252 Cannot VRFY user, but will accept message and attempt delivery")
        elif cmd.startswith("QUIT"):
            self._send("221 Bye")
            self.conn.close()
        elif cmd.startswith("NOOP"):
            self._send("250 Ok")
        elif cmd.startswith("STARTTLS"):
            if self.data_mode:
                self._send("503 Bad sequence of commands")
                return
            # Complete the TLS handshake so stealers that require STARTTLS
            # (AgentTesla, FormBook on port 25) proceed to send credentials.
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
                    # Reset state after TLS upgrade per RFC 3207
                    self._auth_state = None
                    logger.debug(f"SMTP STARTTLS handshake complete: {safe_addr}")
                except ssl.SSLError as e:
                    logger.debug(f"SMTP STARTTLS handshake failed {safe_addr}: {e}")
            else:
                self._send("454 TLS not available due to temporary reason")
        else:
            self._send("500 Unrecognized command")

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
            if total > MAX_DISK_USAGE_BYTES:
                logger.warning("SMTP: email storage cap reached; discarding message.")
                return
        except Exception:
            pass

        fname = f"{uuid.uuid4().hex}.eml"  # UUID filename — no attacker control
        path = os.path.join(self.save_dir, fname)
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write("\n".join(self.mail_data))
            logger.info(f"SMTP: email saved to {fname}")
        except Exception as e:
            logger.error(f"SMTP: failed to save email: {e}")


class _SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, hostname, banner, save_dir,
                 cert_path: str = "", key_path: str = ""):
        self.smtp_hostname = hostname
        self.smtp_banner = banner
        self.smtp_save_dir = save_dir
        self.smtp_cert_path = cert_path
        self.smtp_key_path = key_path
        super().__init__(address, None)

    def server_bind(self):
        self._sem = threading.BoundedSemaphore(_MAX_CONNECTIONS)
        super().server_bind()

    def process_request(self, request, client_address):
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
                pass
            return
        sem = self._sem
        t = _SMTPClientThread(
            request, client_address,
            self.smtp_hostname, self.smtp_banner, self.smtp_save_dir,
            cert_path=self.smtp_cert_path, key_path=self.smtp_key_path,
        )
        # Wrap run() so the semaphore is released and the socket is closed
        # when the session ends — the server lifecycle never touches it.
        _orig_run = t.run

        def _guarded_run():
            try:
                _orig_run()
            finally:
                sem.release()
                try:
                    request.close()
                except OSError:
                    pass

        t.run = _guarded_run
        t.daemon = True
        t.start()


class _SMTPSServer(_SMTPServer):
    """SMTPS variant — wraps each accepted socket in TLS before handing off."""

    def __init__(self, address, hostname, banner, save_dir, ssl_ctx: ssl.SSLContext):
        self._ssl_ctx = ssl_ctx
        super().__init__(address, hostname, banner, save_dir)

    def get_request(self):
        conn, addr = self.socket.accept()
        try:
            conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            logger.debug(f"SMTPS TLS handshake failed from {addr}: {e}")
            conn.close()
            raise
        return conn, addr


class _SSLReuseServer(_ReuseServer):
    """ThreadingTCPServer that wraps accepted sockets in TLS."""

    def __init__(self, address, handler, ssl_ctx: ssl.SSLContext):
        self._ssl_ctx = ssl_ctx
        super().__init__(address, handler)

    def get_request(self):
        conn, addr = self.socket.accept()
        try:
            conn = self._ssl_ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            logger.debug(f"TLS handshake failed from {addr}: {e}")
            conn.close()
            raise
        return conn, addr


class SMTPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 25))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", "mail.example.com")
        self.banner = config.get("banner", "220 mail.example.com ESMTP")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file  = config.get("key_file",  "certs/server.key")
        save_emails = config.get("save_emails", True)
        self.save_dir = "logs/emails" if save_emails else None
        self._server: Optional[_SMTPServer] = None
        self._thread: Optional[threading.Thread] = None

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
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(f"SMTP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"SMTP failed to bind {self.bind_ip}:{self.port}: {e}")
            return False

    def stop(self):
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 465))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", "mail.example.com")
        self.banner = config.get("banner", "220 mail.example.com ESMTP")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
        save_emails = config.get("save_emails", True)
        self.save_dir = "logs/emails" if save_emails else None
        self._server: Optional[_SMTPSServer] = None
        self._thread: Optional[threading.Thread] = None

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
            logger.error(f"SMTPS cert/key not found: {self.cert_file} / {self.key_file}")
            return False
        if self.save_dir:
            os.makedirs(self.save_dir, exist_ok=True)
        try:
            ssl_ctx = self._build_ssl_context()
            self._server = _SMTPSServer(
                (self.bind_ip, self.port),
                self.hostname, self.banner, self.save_dir, ssl_ctx
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(f"SMTPS service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"SMTPS failed to bind {self.bind_ip}:{self.port}: {e}")
            return False

    def stop(self):
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server = None
        logger.info("SMTPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


# ---------------------------------------------------------------------------
# POP3
# ---------------------------------------------------------------------------

def _make_pop3_handler(hostname: str = "mail.example.com",
                       cert_path: str = "", key_path: str = ""):
    class POP3Handler(socketserver.BaseRequestHandler):
        _hostname = hostname
        _cert_path = cert_path
        _key_path  = key_path

        def handle(self):
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(f"POP3 connection from {safe_addr}")
            jl = get_json_logger()
            if jl:
                jl.log("pop3_connection", src_ip=self.client_address[0])
            try:
                _tls_ready = (
                    self._cert_path
                    and self._key_path
                    and os.path.exists(self._cert_path)
                    and os.path.exists(self._key_path)
                )
                capa_extra = "+OK\r\nUSER\r\nUIDL\r\nSTLS\r\n." if _tls_ready else "+OK\r\nUSER\r\nUIDL\r\n."
                self._send(f"+OK {self._hostname} POP3 server ready")
                self.request.settimeout(30)
                buf = b""
                while True:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\r\n" in buf:
                        line, buf = buf.split(b"\r\n", 1)
                        cmd = line.decode("utf-8", errors="replace").strip().upper()[:8]
                        if cmd.startswith("USER"):
                            self._send("+OK")
                        elif cmd.startswith("PASS"):
                            self._send("+OK Logged in")
                        elif cmd.startswith("STAT"):
                            self._send("+OK 0 0")
                        elif cmd.startswith("LIST"):
                            self._send("+OK 0 messages\r\n.")
                        elif cmd.startswith("UIDL"):
                            self._send("+OK\r\n.")
                        elif cmd.startswith("QUIT"):
                            self._send("+OK Bye")
                            return
                        elif cmd.startswith("CAPA"):
                            self._send(capa_extra)
                        elif cmd.startswith("STLS"):
                            if _tls_ready:
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
                                        f"POP3 STLS handshake complete: {safe_addr}"
                                    )
                                except ssl.SSLError as e:
                                    logger.debug(
                                        f"POP3 STLS handshake failed {safe_addr}: {e}"
                                    )
                                    return
                            else:
                                self._send("-ERR TLS not available")
                        else:
                            self._send("-ERR Unknown command")
            except Exception as e:
                logger.debug(f"POP3 {safe_addr} error: {e}")

        def _send(self, msg: str):
            try:
                self.request.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
            except Exception:
                pass

    return POP3Handler


class POP3Service:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 110))
        self.bind_ip = bind_ip
        self.hostname  = config.get("hostname",  "mail.example.com")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file  = config.get("key_file",  "certs/server.key")
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            ensure_certs(self.cert_file, self.key_file)
            handler = _make_pop3_handler(
                self.hostname, cert_path=self.cert_file, key_path=self.key_file
            )
            self._server = _ReuseServer((self.bind_ip, self.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(f"POP3 service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"POP3 failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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
        self.hostname = config.get("hostname", "mail.example.com")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
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
            logger.error(f"POP3S cert/key not found: {self.cert_file} / {self.key_file}")
            return False
        try:
            ssl_ctx = self._build_ssl_context()
            handler = _make_pop3_handler(self.hostname)
            self._server = _SSLReuseServer((self.bind_ip, self.port), handler, ssl_ctx)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(f"POP3S service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"POP3S failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server = None
        logger.info("POP3S service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


# ---------------------------------------------------------------------------
# IMAP
# ---------------------------------------------------------------------------

def _make_imap_handler(hostname: str, cert_path: str = "", key_path: str = ""):
    class IMAPHandler(socketserver.BaseRequestHandler):
        _hostname  = hostname
        _cert_path = cert_path
        _key_path  = key_path

        def handle(self):
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(f"IMAP connection from {safe_addr}")
            jl = get_json_logger()
            if jl:
                jl.log("imap_connection", src_ip=self.client_address[0])
            try:
                _tls_ready = (
                    self._cert_path
                    and self._key_path
                    and os.path.exists(self._cert_path)
                    and os.path.exists(self._key_path)
                )
                capability = (
                    "* CAPABILITY IMAP4rev1 STARTTLS"
                    if _tls_ready else
                    "* CAPABILITY IMAP4rev1"
                )
                self._send(f"* OK {self._hostname} IMAP4rev1 ready")
                self.request.settimeout(30)
                buf = b""
                while True:
                    chunk = self.request.recv(2048)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\r\n" in buf:
                        line, buf = buf.split(b"\r\n", 1)
                        text = line.decode("utf-8", errors="replace").strip()
                        parts = text.split(None, 2)
                        if len(parts) < 2:
                            continue
                        tag, cmd = parts[0], parts[1].upper()
                        if cmd == "STARTTLS":
                            if _tls_ready:
                                self._send(f"{tag} OK Begin TLS negotiation")
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
                                        f"IMAP STARTTLS handshake complete: {safe_addr}"
                                    )
                                except ssl.SSLError as e:
                                    logger.debug(
                                        f"IMAP STARTTLS handshake failed {safe_addr}: {e}"
                                    )
                                    return
                            else:
                                self._send(f"{tag} NO TLS not available")
                        elif cmd == "LOGIN":
                            self._send(f"{tag} OK LOGIN completed")
                        elif cmd == "CAPABILITY":
                            self._send(f"{capability}\r\n{tag} OK")
                        elif cmd == "LIST":
                            self._send(f'* LIST () "/" INBOX\r\n{tag} OK LIST completed')
                        elif cmd == "SELECT":
                            self._send(
                                f"* 0 EXISTS\r\n* 0 RECENT\r\n"
                                f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen)\r\n"
                                f"{tag} OK [READ-WRITE] SELECT completed"
                            )
                        elif cmd == "EXAMINE":
                            # EXAMINE is identical to SELECT but read-only.
                            # Used by some IMAP clients to check for new mail
                            # without marking messages as seen.
                            self._send(
                                f"* 0 EXISTS\r\n* 0 RECENT\r\n"
                                f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen)\r\n"
                                f"{tag} OK [READ-ONLY] EXAMINE completed"
                            )
                        elif cmd == "STATUS":
                            # STATUS returns folder counts. Many IMAP client
                            # libraries (including those embedded in stealers)
                            # use STATUS to quickly check for new messages
                            # before doing a full SELECT.
                            mailbox = parts[2].split()[0].strip('"') if len(parts) > 2 else "INBOX"
                            self._send(
                                f"* STATUS {mailbox} (MESSAGES 0 RECENT 0 UNSEEN 0)\r\n"
                                f"{tag} OK STATUS completed"
                            )
                        elif cmd == "LSUB":
                            self._send(f'* LSUB () "/" INBOX\r\n{tag} OK LSUB completed')
                        elif cmd == "LOGOUT":
                            self._send(f"* BYE\r\n{tag} OK LOGOUT completed")
                            return
                        elif cmd == "NOOP":
                            self._send(f"{tag} OK NOOP completed")
                        else:
                            self._send(f"{tag} NO Command not implemented")
            except Exception as e:
                logger.debug(f"IMAP {safe_addr} error: {e}")

        def _send(self, msg: str):
            try:
                self.request.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
            except Exception:
                pass

    return IMAPHandler


class IMAPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 143))
        self.bind_ip = bind_ip
        self.hostname  = config.get("hostname",  "mail.example.com")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file  = config.get("key_file",  "certs/server.key")
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            ensure_certs(self.cert_file, self.key_file)
            handler = _make_imap_handler(
                self.hostname, cert_path=self.cert_file, key_path=self.key_file
            )
            self._server = _ReuseServer((self.bind_ip, self.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(f"IMAP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"IMAP failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
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
        self.hostname = config.get("hostname", "mail.example.com")
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
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
            logger.error(f"IMAPS cert/key not found: {self.cert_file} / {self.key_file}")
            return False
        try:
            ssl_ctx = self._build_ssl_context()
            handler = _make_imap_handler(self.hostname)
            self._server = _SSLReuseServer((self.bind_ip, self.port), handler, ssl_ctx)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(f"IMAPS service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"IMAPS failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server = None
        logger.info("IMAPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
