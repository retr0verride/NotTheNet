"""
NotTheNet - Shared plumbing for the fake SMTP, POP3 and IMAP servers.

Connection-capped TCP/TLS server classes and the defaults all three
protocols share.
"""

import logging
import socketserver
import ssl
import threading

logger = logging.getLogger(__name__)


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
