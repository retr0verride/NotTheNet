"""
NotTheNet - Fake IMAP / IMAPS server.
Accepts any login and reports an empty mailbox.
"""

import logging
import os
import socket
import socketserver
import ssl
import threading

from services.mail_common import (
    _DEFAULT_CERT,
    _DEFAULT_HOSTNAME,
    _DEFAULT_KEY,
    _MAX_CONNECTIONS,
    _ReuseServer,
    _SSLReuseServer,
)
from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip

logger = logging.getLogger(__name__)


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
