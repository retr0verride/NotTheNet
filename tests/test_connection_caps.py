"""
Tests for connection-cap enforcement in FTP and mail servers.

The connection cap is what prevents a sustained flood of inbound connections
(e.g. malware scanning every port repeatedly) from accumulating thousands of
threads and eventually locking up the process.

All tests bind to 127.0.0.1 on an ephemeral port, verify the cap fires, and
shut the server down cleanly.  No network traffic leaves the loopback.
"""

import socket
import socketserver
import threading
import time
import unittest

import services.ftp_server as ftp_mod
import services.mail_server as mail_mod

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _connect(port: int, timeout: float = 1.0) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    return s


def _start_server(server_cls, port: int) -> socketserver.TCPServer:
    """Start *server_cls* on loopback:port in a daemon thread."""
    srv = server_cls(("127.0.0.1", port), None)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ---------------------------------------------------------------------------
# FTP
# ---------------------------------------------------------------------------

class TestFTPConnectionCap(unittest.TestCase):
    """_ReuseServer in ftp_server must not accept more than _MAX_CONNECTIONS."""

    def setUp(self):
        self._orig_max = ftp_mod._MAX_CONNECTIONS
        # Use a tiny cap so the test doesn't need to open 50 real sockets.
        ftp_mod._MAX_CONNECTIONS = 3
        self.port = _free_port()

        class _NullHandler(socketserver.BaseRequestHandler):
            """Hold the connection open until told to close."""
            _barrier = threading.Barrier(1)
            _stop = threading.Event()

            def handle(self):
                self._stop.wait(timeout=5.0)

        self._handler = _NullHandler
        self._server = ftp_mod._ReuseServer(("127.0.0.1", self.port), _NullHandler)
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()

    def tearDown(self):
        self._handler._stop.set()     # release any blocked handlers
        self._server.shutdown()
        ftp_mod._MAX_CONNECTIONS = self._orig_max

    def test_connections_up_to_cap_are_accepted(self):
        socks = []
        try:
            for _ in range(ftp_mod._MAX_CONNECTIONS):
                s = _connect(self.port)
                socks.append(s)
        finally:
            for s in socks:
                s.close()

    def test_connection_beyond_cap_is_dropped(self):
        """The (cap+1)th connection should be closed by the server immediately."""
        socks = []
        try:
            # Fill up to the cap; keep connections open.
            for _ in range(ftp_mod._MAX_CONNECTIONS):
                socks.append(_connect(self.port))

            # Give the server a moment to have all sessions running.
            time.sleep(0.1)

            # One more connection — server should close it right away.
            extra = _connect(self.port, timeout=2.0)
            extra.settimeout(2.0)
            data = b""
            try:
                data = extra.recv(4096)    # EOF (empty bytes) = server closed it
            except (socket.timeout, OSError):
                pass
            finally:
                extra.close()

            self.assertEqual(
                data, b"",
                "Server should close the connection immediately when cap is reached",
            )
        finally:
            self._handler._stop.set()
            for s in socks:
                s.close()

    def test_semaphore_released_after_session_ends(self):
        """Closing a connection must free a slot for a new one."""
        socks = []
        try:
            for _ in range(ftp_mod._MAX_CONNECTIONS):
                socks.append(_connect(self.port))
            time.sleep(0.1)

            # Close one.
            socks[0].close()
            socks = socks[1:]
            time.sleep(0.2)   # give the server time to release the semaphore

            # Now a new connection should succeed.
            new_sock = _connect(self.port, timeout=2.0)
            new_sock.close()
        finally:
            self._handler._stop.set()
            for s in socks:
                s.close()


# ---------------------------------------------------------------------------
# Mail (_ReuseServer — used by POP3 / IMAP)
# ---------------------------------------------------------------------------

class TestMailReuseServerConnectionCap(unittest.TestCase):
    """_ReuseServer in mail_server must not accept more than _MAX_CONNECTIONS."""

    def setUp(self):
        self._orig_max = mail_mod._MAX_CONNECTIONS
        mail_mod._MAX_CONNECTIONS = 3
        self.port = _free_port()

        class _NullHandler(socketserver.BaseRequestHandler):
            _stop = threading.Event()

            def handle(self):
                self._stop.wait(timeout=5.0)

        self._handler = _NullHandler
        self._server = mail_mod._ReuseServer(("127.0.0.1", self.port), _NullHandler)
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()

    def tearDown(self):
        self._handler._stop.set()
        self._server.shutdown()
        mail_mod._MAX_CONNECTIONS = self._orig_max

    def test_connection_beyond_cap_is_dropped(self):
        socks = []
        try:
            for _ in range(mail_mod._MAX_CONNECTIONS):
                socks.append(_connect(self.port))
            time.sleep(0.1)

            extra = _connect(self.port, timeout=2.0)
            extra.settimeout(2.0)
            data = b""
            try:
                data = extra.recv(4096)
            except (socket.timeout, OSError):
                pass
            finally:
                extra.close()

            self.assertEqual(data, b"")
        finally:
            self._handler._stop.set()
            for s in socks:
                s.close()


# ---------------------------------------------------------------------------
# SMTP (_SMTPServer — separate semaphore path)
# ---------------------------------------------------------------------------

class TestSMTPConnectionCap(unittest.TestCase):
    """_SMTPServer must enforce _MAX_CONNECTIONS independently."""

    def setUp(self):
        self._orig_max = mail_mod._MAX_CONNECTIONS
        mail_mod._MAX_CONNECTIONS = 3
        self.port = _free_port()

        # _SMTPServer needs hostname / banner / save_dir but no actual handler.
        self._server = mail_mod._SMTPServer(
            ("127.0.0.1", self.port),
            hostname="test.host",
            banner="220 test",
            save_dir=None,
        )
        t = threading.Thread(target=self._server.serve_forever, daemon=True)
        t.start()

    def tearDown(self):
        self._server.shutdown()
        mail_mod._MAX_CONNECTIONS = self._orig_max

    def test_smtp_banner_received(self):
        """A normal connection must receive the 220 banner."""
        s = _connect(self.port)
        s.settimeout(2.0)
        try:
            data = s.recv(4096)
        finally:
            s.close()
            self._server.shutdown()
        self.assertIn(b"220", data)

    def test_smtp_connection_beyond_cap_is_dropped(self):
        socks = []
        try:
            for _ in range(mail_mod._MAX_CONNECTIONS):
                s = _connect(self.port)
                socks.append(s)
                s.settimeout(1.0)
                try:
                    s.recv(256)   # consume banner so the slot stays open
                except socket.timeout:
                    pass
            time.sleep(0.1)

            extra = _connect(self.port, timeout=2.0)
            extra.settimeout(2.0)
            data = b""
            try:
                data = extra.recv(4096)
            except (socket.timeout, OSError):
                pass
            finally:
                extra.close()

            self.assertEqual(data, b"")
        finally:
            for s in socks:
                s.close()


if __name__ == "__main__":
    unittest.main()
