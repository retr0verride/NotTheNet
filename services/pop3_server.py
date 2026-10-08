"""
NotTheNet - Fake POP3 / POP3S server.
Accepts any login and reports an empty mailbox.
"""

from __future__ import annotations

import logging
import os
import socket
import socketserver
import ssl
import threading
from collections.abc import Callable

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
        except Exception as e:  # noqa: BLE001  # untrusted-input boundary: one bad session must not kill the service
            logger.debug("POP3 %s error: %s", safe_addr, e, exc_info=True)

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

    def _dispatch_line(self, line: bytes, safe_addr: str) -> bool | None:
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

    def _pop3_stls(self, safe_addr: str) -> bool | None:
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
        return None

    _POP3_DISPATCH: dict[str, Callable[[POP3Handler, str], bool | None]] = {
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
        except OSError:
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
        self._server: _ReuseServer | None = None
        self._thread: threading.Thread | None = None

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
        self._server: _ReuseServer | None = None
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
