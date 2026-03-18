"""
Tests for the IRC server ping-timeout logic.

These tests use real loopback sockets so they exercise the exact
socket.timeout path that prevents parked bots from holding threads forever.
All timeouts are patched to milliseconds so the suite stays fast.
"""

import socket
import threading
import time
import unittest
from unittest.mock import patch

from services.irc_server import _IRCClientThread


def _make_pair():
    """Return a connected (server_sock, client_sock) loopback pair."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", port))
    conn, addr = srv.accept()
    srv.close()
    return conn, addr, client


def _make_thread(conn, addr, sem=None):
    return _IRCClientThread(
        conn=conn,
        addr=addr,
        hostname="fake.host",
        network="FakeNet",
        channel="#sandbox",
        motd="test",
        sem=sem,
    )


class TestIRCPingTimeout(unittest.TestCase):

    def test_server_sends_ping_on_idle(self):
        """After _PING_INTERVAL idle the server must send a PING line."""
        conn, addr, client = _make_pair()

        # Patch the interval to something tiny so the test doesn't wait 120 s.
        with patch("services.irc_server._PING_INTERVAL", 0.2):
            with patch("services.irc_server._PING_TIMEOUT", 5.0):
                t = _make_thread(conn, addr)  # no semaphore needed here
                t.start()

                client.settimeout(3.0)
                data = b""
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    try:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                        if b"PING" in data:
                            break
                    except socket.timeout:
                        break

        client.close()
        t.join(timeout=3.0)

        self.assertIn(b"PING", data, "Server should send PING after idle interval")

    def test_missing_pong_disconnects_client(self):
        """If no PONG arrives within _PING_TIMEOUT the server closes the link."""
        conn, addr, client = _make_pair()

        with patch("services.irc_server._PING_INTERVAL", 0.1):
            with patch("services.irc_server._PING_TIMEOUT", 0.2):
                t = _make_thread(conn, addr)  # no semaphore needed here
                t.start()

                # Drain until EOF (the server side closes after ping timeout).
                client.settimeout(3.0)
                data = b""
                try:
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except (socket.timeout, OSError):
                    pass

        client.close()
        t.join(timeout=3.0)

        self.assertFalse(t.is_alive(), "Session thread should have exited")
        self.assertIn(
            b"ERROR", data,
            "Server should send ERROR :Closing Link before disconnecting",
        )

    def test_pong_resets_keepalive(self):
        """A timely PONG must prevent the session from being dropped."""
        conn, addr, client = _make_pair()

        with patch("services.irc_server._PING_INTERVAL", 0.2):
            with patch("services.irc_server._PING_TIMEOUT", 0.3):
                t = _make_thread(conn, addr)  # no semaphore needed here
                t.start()

                client.settimeout(3.0)
                # Wait for the PING, then reply with PONG.
                data = b""
                deadline = time.monotonic() + 2.0
                while b"PING" not in data and time.monotonic() < deadline:
                    try:
                        data += client.recv(4096)
                    except socket.timeout:
                        break

                if b"PING" in data:
                    client.sendall(b"PONG :token\r\n")

                # Give it another idle cycle to confirm it doesn't close.
                time.sleep(0.5)
                alive = t.is_alive()

        client.close()
        t.join(timeout=3.0)

        self.assertTrue(alive, "Session should survive after a timely PONG")

    def test_semaphore_released_on_timeout_exit(self):
        """The BoundedSemaphore must be released when the session exits."""
        conn, addr, client = _make_pair()
        sem = threading.BoundedSemaphore(1)
        # In production the server acquires before spawning the thread.
        # Simulate that here so release() doesn't over-release.
        sem.acquire()

        with patch("services.irc_server._PING_INTERVAL", 0.1):
            with patch("services.irc_server._PING_TIMEOUT", 0.1):
                t = _make_thread(conn, addr, sem)
                t.start()

                client.settimeout(3.0)
                try:
                    while client.recv(4096):
                        pass
                except (socket.timeout, OSError):
                    pass

        client.close()
        t.join(timeout=3.0)

        # After the session ends the semaphore should be acquirable again.
        acquired = sem.acquire(blocking=False)
        self.assertTrue(acquired, "Semaphore should be released after session exit")
        if acquired:
            sem.release()

    def test_clean_disconnect_exits_quickly(self):
        """Closing the client socket should end the session immediately."""
        conn, addr, client = _make_pair()

        with patch("services.irc_server._PING_INTERVAL", 60.0):
            t = _make_thread(conn, addr)  # no semaphore needed here
            t.start()
            time.sleep(0.05)
            client.close()

        t.join(timeout=2.0)
        self.assertFalse(t.is_alive(), "Thread should exit quickly on client disconnect")


if __name__ == "__main__":
    unittest.main()
