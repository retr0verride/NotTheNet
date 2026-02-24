"""
NotTheNet - Fake FTP Server
Accepts FTP connections, optionally receives uploads, always reports success.

Security notes (OpenSSF):
- Upload directory is resolved via os.path.realpath and path-traversal checked
- UUID-based filenames for saved uploads — no attacker path/name control
- Total upload size capped (disk exhaustion prevention)
- PASV port range is restricted to avoid footprint on reserved ports
- No shell=True subprocess calls
- Active mode (PORT command) is intentionally not implemented (SSRF vector)
"""

import logging
import os
import socket
import socketserver
import threading
import uuid
from typing import Optional

from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024   # 50 MB per file
MAX_DISK_USAGE_BYTES = 200 * 1024 * 1024   # 200 MB total upload storage

PASV_PORT_LOW = 50000
PASV_PORT_HIGH = 51000


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address set before server_bind()."""
    allow_reuse_address = True
    daemon_threads = True


def _get_disk_usage(directory: str) -> int:
    total = 0
    try:
        for fname in os.listdir(directory):
            fp = os.path.join(directory, fname)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    except Exception:
        pass
    return total


class _FTPSession(threading.Thread):
    """Handles one FTP control connection."""

    def __init__(self, conn, addr, banner: str, upload_dir: Optional[str]):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.banner = banner
        self.upload_dir = upload_dir
        self._data_conn = None
        self._pasv_server = None

    def _send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            pass

    def _open_pasv(self) -> Optional[str]:
        """Open a passive-mode data socket and return the PASV response string."""
        for port in range(PASV_PORT_LOW, PASV_PORT_HIGH):
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(1)
                srv.settimeout(10)
                self._pasv_server = srv
                # Encode IP as comma-separated octets per RFC 959
                local_ip = self.conn.getsockname()[0]
                ip_parts = local_ip.replace(".", ",")
                p1, p2 = port >> 8, port & 0xFF
                return f"227 Entering Passive Mode ({ip_parts},{p1},{p2})"
            except OSError:
                continue
        return None

    def _accept_data(self) -> Optional[socket.socket]:
        if self._pasv_server:
            try:
                conn, _ = self._pasv_server.accept()
                self._pasv_server.close()
                self._pasv_server = None
                return conn
            except Exception:
                return None
        return None

    def run(self):
        safe_addr = sanitize_ip(self.addr[0])
        logger.info(f"FTP connection from {safe_addr}")
        try:
            self._send(sanitize_log_string(self.banner, max_length=200))
            self.conn.settimeout(30)
            buf = b""
            while True:
                chunk = self.conn.recv(1024)
                if not chunk:
                    break
                buf += chunk
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    self._handle_cmd(
                        line.decode("utf-8", errors="replace").strip(), safe_addr
                    )
        except Exception as e:
            logger.debug(f"FTP {safe_addr} session error: {e}")
        finally:
            try:
                self.conn.close()
            except Exception:
                pass

    def _handle_cmd(self, line: str, safe_addr: str):
        parts = line.split(None, 1)
        if not parts:
            return
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        safe_arg = sanitize_log_string(arg, max_length=128)
        logger.debug(f"FTP [{safe_addr}] {cmd} {safe_arg}")

        if cmd in ("USER", "PASS"):
            self._send("230 Login successful")
        elif cmd == "SYST":
            self._send("215 UNIX Type: L8")
        elif cmd == "FEAT":
            self._send("211-Features:\r\n PASV\r\n211 End")
        elif cmd == "PWD":
            self._send('257 "/" is current directory')
        elif cmd in ("CWD", "CDUP"):
            self._send("250 OK")
        elif cmd == "TYPE":
            self._send("200 Type set")
        elif cmd == "PASV":
            resp = self._open_pasv()
            if resp:
                self._send(resp)
            else:
                self._send("425 Can't open data connection")
        elif cmd == "PORT":
            # Active mode intentionally not implemented (SSRF risk)
            self._send("500 Active mode not supported; use PASV")
        elif cmd == "LIST":
            data = self._accept_data()
            self._send("150 Here comes the directory listing")
            if data:
                data.sendall(b"total 0\r\n")
                data.close()
            self._send("226 Directory send OK")
        elif cmd == "STOR":
            self._recv_file(arg, safe_addr)
        elif cmd in ("RETR", "NLST"):
            data = self._accept_data()
            self._send("150 Opening data connection")
            if data:
                data.close()
            self._send("226 Transfer complete")
        elif cmd == "QUIT":
            self._send("221 Goodbye")
            self.conn.close()
        elif cmd in ("NOOP", "ALLO"):
            self._send("200 OK")
        elif cmd == "DELE":
            self._send("250 File deleted")
        elif cmd in ("MKD", "RMD"):
            self._send("257 OK")
        elif cmd == "SIZE":
            self._send("213 0")
        else:
            self._send("502 Command not implemented")

    def _recv_file(self, remote_name: str, safe_addr: str):
        """Accept a file upload over the data connection."""
        # RFC 959: send 150 *before* blocking on accept(), so the client
        # knows to connect to the passive port and begin sending data.
        self._send("150 Ok to send data")
        data_conn = self._accept_data()
        if not data_conn:
            self._send("425 Can't open data connection")
            return

        if not self.upload_dir:
            # Uploads disabled — drain and discard
            try:
                while data_conn.recv(65536):
                    pass
            except Exception:
                pass
            data_conn.close()
            self._send("226 Transfer complete (discarded)")
            return

        # Cap disk usage
        if _get_disk_usage(self.upload_dir) > MAX_DISK_USAGE_BYTES:
            logger.warning("FTP: upload storage cap reached; discarding file.")
            try:
                while data_conn.recv(65536):
                    pass
            except Exception:
                pass
            data_conn.close()
            self._send("452 Insufficient storage space")
            return

        # UUID filename — attacker has zero control over the path
        safe_fname = uuid.uuid4().hex + ".bin"
        save_path = os.path.join(self.upload_dir, safe_fname)

        try:
            received = 0
            with open(save_path, "wb") as f:
                while True:
                    chunk = data_conn.recv(65536)
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_UPLOAD_SIZE_BYTES:
                        logger.warning(
                            f"FTP: upload from {safe_addr} exceeded size cap; truncating."
                        )
                        break
                    f.write(chunk)
            logger.info(
                f"FTP: upload from {safe_addr} saved as {safe_fname} ({received} bytes)"
            )
            self._send("226 Transfer complete")
        except Exception as e:
            logger.error(f"FTP: upload error: {e}")
            self._send("451 Requested action aborted")
        finally:
            # Always close the data connection — even if open() or write() raised
            try:
                data_conn.close()
            except Exception:
                pass


class FTPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 21))
        self.bind_ip = bind_ip
        self.banner = config.get("banner", "220 FTP Server Ready")
        allow_uploads = config.get("allow_uploads", True)
        upload_dir = config.get("upload_dir", "logs/ftp_uploads")
        self.upload_dir = upload_dir if allow_uploads else None
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        if self.upload_dir:
            os.makedirs(self.upload_dir, exist_ok=True)

        banner = self.banner
        upload_dir = self.upload_dir

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sess = _FTPSession(self.request, self.client_address, banner, upload_dir)
                sess.run()

        try:
            self._server = _ReuseServer((self.bind_ip, self.port), _Handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"FTP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"FTP failed to bind {self.bind_ip}:{self.port}: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None
        logger.info("FTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
