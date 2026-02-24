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
import socketserver
import threading
import uuid
from typing import Optional

from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_EMAIL_SIZE_BYTES = 5 * 1024 * 1024   # 5 MB per message
MAX_DISK_USAGE_BYTES = 100 * 1024 * 1024  # 100 MB total email storage cap


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address set as a class attribute.
    This MUST be a class attribute (not instance attribute) so it is read
    before server_bind() is called inside __init__.
    """
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------------------
# SMTP
# ---------------------------------------------------------------------------

class _SMTPClientThread(threading.Thread):
    """Handles a single SMTP client connection in its own thread."""

    def __init__(self, conn, addr, hostname: str, banner: str, save_dir: Optional[str]):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.hostname = hostname
        self.banner = banner
        self.save_dir = save_dir
        self.data_mode = False
        self.mail_data: list = []
        self.current_size = 0

    def _send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            pass

    def run(self):
        safe_addr = sanitize_ip(self.addr[0])
        logger.info(f"SMTP connection from {safe_addr}")
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

        cmd = line.strip().upper()[:10]
        logger.debug(f"SMTP  [{safe_addr}] cmd={sanitize_log_string(cmd)}")

        if cmd.startswith("EHLO") or cmd.startswith("HELO"):
            self._send(f"250-{self.hostname}\r\n250 Ok")
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
        elif cmd.startswith("QUIT"):
            self._send("221 Bye")
            self.conn.close()
        elif cmd.startswith("NOOP"):
            self._send("250 Ok")
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

    def __init__(self, address, hostname, banner, save_dir):
        self.smtp_hostname = hostname
        self.smtp_banner = banner
        self.smtp_save_dir = save_dir
        super().__init__(address, None)

    def finish_request(self, request, client_address):
        t = _SMTPClientThread(
            request, client_address,
            self.smtp_hostname, self.smtp_banner, self.smtp_save_dir
        )
        t.start()


class SMTPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 25))
        self.bind_ip = bind_ip
        self.hostname = config.get("hostname", "mail.notthenet.local")
        self.banner = config.get("banner", "220 mail.notthenet.local ESMTP")
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
            self._server = _SMTPServer(
                (self.bind_ip, self.port), self.hostname, self.banner, self.save_dir
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"SMTP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"SMTP failed to bind {self.bind_ip}:{self.port}: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("SMTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


# ---------------------------------------------------------------------------
# POP3 (minimal — enough to satisfy most malware polling)
# ---------------------------------------------------------------------------

def _make_pop3_handler(hostname: str = "mail.notthenet.local"):
    import socketserver

    class POP3Handler(socketserver.BaseRequestHandler):
        _hostname = hostname

        def handle(self):
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(f"POP3 connection from {safe_addr}")
            try:
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
                            self._send("+OK\r\nUSER\r\nUIDL\r\n.")
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
        self.hostname = config.get("hostname", "mail.notthenet.local")
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            handler = _make_pop3_handler(self.hostname)
            self._server = _ReuseServer((self.bind_ip, self.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"POP3 service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"POP3 failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("POP3 service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


# ---------------------------------------------------------------------------
# IMAP (minimal — enough to satisfy most malware polling)
# ---------------------------------------------------------------------------

def _make_imap_handler(hostname: str):
    class IMAPHandler(socketserver.BaseRequestHandler):
        _hostname = hostname

        def handle(self):
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(f"IMAP connection from {safe_addr}")
            try:
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
                        if cmd == "LOGIN":
                            self._send(f"{tag} OK LOGIN completed")
                        elif cmd == "CAPABILITY":
                            self._send(f"* CAPABILITY IMAP4rev1\r\n{tag} OK")
                        elif cmd == "LIST":
                            self._send(f'* LIST () "/" INBOX\r\n{tag} OK LIST completed')
                        elif cmd == "SELECT":
                            self._send(
                                f"* 0 EXISTS\r\n* 0 RECENT\r\n"
                                f"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen)\r\n"
                                f"{tag} OK [READ-WRITE] SELECT completed"
                            )
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
        self.hostname = config.get("hostname", "mail.notthenet.local")
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            handler = _make_imap_handler(self.hostname)
            self._server = _ReuseServer((self.bind_ip, self.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"IMAP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"IMAP failed to bind: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("IMAP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
