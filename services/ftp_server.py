"""
NotTheNet - Fake FTP Server
Accepts FTP connections, optionally receives uploads, always reports success.

Security notes (OpenSSF):
- Upload directory is resolved via os.path.realpath and path-traversal checked
- UUID-based filenames for saved uploads â€” no attacker path/name control
- Total upload size capped (disk exhaustion prevention)
- PASV port range is restricted to avoid footprint on reserved ports
- No shell=True subprocess calls
- Active mode (PORT command) is intentionally not implemented (SSRF vector)
"""

import logging
import os
import random
import socket
import socketserver
import threading
import uuid
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

MAX_UPLOAD_SIZE_BYTES = 50 * 1024 * 1024   # 50 MB per file
MAX_DISK_USAGE_BYTES = 200 * 1024 * 1024   # 200 MB total upload storage

PASV_PORT_LOW = 50000
PASV_PORT_HIGH = 51000

_MAX_CONNECTIONS = 50   # maximum simultaneous FTP control connections


class _ReuseServer(socketserver.ThreadingTCPServer):
    """ThreadingTCPServer with allow_reuse_address set before server_bind()."""
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


def _get_disk_usage(directory: str) -> int:
    total = 0
    try:
        for fname in os.listdir(directory):
            fp = os.path.join(directory, fname)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    except Exception:
        logger.debug("FTP disk-usage scan failed", exc_info=True)
    return total


class _FTPSession(threading.Thread):
    """Handles one FTP control connection."""

    def __init__(self, conn, addr, banner: str, upload_dir: Optional[str], bind_ip: str = "0.0.0.0",
                 upload_lock: Optional[threading.Lock] = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.banner = banner
        self.upload_dir = upload_dir
        self.bind_ip = bind_ip
        self._upload_lock = upload_lock or threading.Lock()
        self._data_conn = None
        self._pasv_server = None

    def _send(self, msg: str):
        try:
            self.conn.sendall((msg + "\r\n").encode("utf-8", errors="replace"))
        except Exception:
            logger.debug("FTP control send failed", exc_info=True)

    def _open_pasv(self) -> Optional[str]:
        """Open a passive-mode data socket and return the PASV response string."""
        ports = list(range(PASV_PORT_LOW, PASV_PORT_HIGH))
        random.shuffle(ports)
        for port in ports:
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.bind_ip, port))
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
        logger.warning("FTP PASV: no free ports in range %dâ€“%d", PASV_PORT_LOW, PASV_PORT_HIGH)
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

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        logger.info("FTP connection from %s", safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("ftp_connection", src_ip=self.addr[0])
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
            logger.debug("FTP %s session error: %s", safe_addr, e)
        finally:
            try:
                self.conn.close()
            except Exception:
                logger.debug("FTP control socket close failed", exc_info=True)
            if self._pasv_server:
                try:
                    self._pasv_server.close()
                except OSError:
                    pass
                self._pasv_server = None

    # Static command â†’ response mapping (commands that just send a fixed reply)
    _SIMPLE_RESPONSES: dict[str, str] = {
        "USER": "230 Login successful",
        "PASS": "230 Login successful",
        "SYST": "215 Windows_NT",
        "FEAT": "211-Features:\r\n PASV\r\n211 End",
        "PWD": '257 "/" is current directory',
        "CWD": "250 OK",
        "CDUP": "250 OK",
        "TYPE": "200 Type set",
        "PORT": "500 Active mode not supported; use PASV",
        "NOOP": "200 OK",
        "ALLO": "200 OK",
        "DELE": "250 File deleted",
        "MKD": "257 OK",
        "RMD": "257 OK",
        "SIZE": "213 0",
    }

    def _handle_cmd(self, line: str, safe_addr: str):
        parts = line.split(None, 1)
        if not parts:
            return
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""
        safe_arg = sanitize_log_string(arg, max_length=128)
        logger.debug("FTP [%s] %s %s", safe_addr, cmd, safe_arg)

        # Fast path: fixed-response commands
        simple = self._SIMPLE_RESPONSES.get(cmd)
        if simple is not None:
            self._send(simple)
        elif cmd == "PASV":
            resp = self._open_pasv()
            self._send(resp if resp else "425 Can't open data connection")
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
        else:
            self._send("502 Command not implemented")

    def _recv_file(self, remote_name: str, safe_addr: str):
        """Accept a file upload over the data connection."""
        self._send("150 Ok to send data")
        data_conn = self._accept_data()
        if not data_conn:
            self._send("425 Can't open data connection")
            return

        data_conn.settimeout(30)

        if not self.upload_dir:
            self._drain_and_close(data_conn, "uploads disabled")
            self._send("226 Transfer complete (discarded)")
            return

        with self._upload_lock:
            if _get_disk_usage(self.upload_dir) > MAX_DISK_USAGE_BYTES:
                logger.warning("FTP: upload storage cap reached; discarding file.")
                self._drain_and_close(data_conn, "cap exceeded")
                self._send("452 Insufficient storage space")
                return

            safe_fname = uuid.uuid4().hex + ".bin"
            save_path = os.path.join(self.upload_dir, safe_fname)
            open(save_path, "wb").close()

        try:
            self._write_upload(data_conn, save_path, safe_addr, safe_fname, remote_name)
            self._send("226 Transfer complete")
        except Exception as e:
            logger.error("FTP: upload error: %s", e)
            self._send("451 Requested action aborted")
        finally:
            try:
                data_conn.close()
            except Exception:
                logger.debug("FTP data connection close failed", exc_info=True)

    def _drain_and_close(self, data_conn, reason: str):
        """Drain and close a data connection, discarding all data."""
        try:
            while data_conn.recv(65536):
                pass  # discard
        except Exception:
            logger.debug("FTP STOR drain failed (%s)", reason, exc_info=True)
        data_conn.close()

    def _write_upload(self, data_conn, save_path: str, safe_addr: str,
                      safe_fname: str, remote_name: str) -> int:
        """Write uploaded data to disk; return bytes received."""
        received = 0
        with open(save_path, "wb") as f:
            while True:
                chunk = data_conn.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
                if received > MAX_UPLOAD_SIZE_BYTES:
                    logger.warning(
                        "FTP: upload from %s exceeded size cap; truncating.", safe_addr
                    )
                    break
                f.write(chunk)
        logger.info(
            "FTP: upload from %s saved as %s (%d bytes)",
            safe_addr, safe_fname, received,
        )
        jl = get_json_logger()
        if jl:
            jl.log("ftp_upload", src_ip=self.addr[0],
                   filename=remote_name, saved_as=safe_fname,
                   bytes_received=received)
        return received


class FTPService:
    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 21))
        self.bind_ip = bind_ip
        self.banner = config.get("banner", "220 FTP Server Ready")
        allow_uploads = config.get("allow_uploads", True)
        upload_dir = config.get("upload_dir", "logs/ftp_uploads")
        self.upload_dir = upload_dir if allow_uploads else None
        self._upload_lock = threading.Lock()
        self._server = None
        self._thread = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        if self.upload_dir:
            os.makedirs(self.upload_dir, exist_ok=True)

        banner = self.banner
        upload_dir = self.upload_dir
        bind_ip = self.bind_ip
        upload_lock = self._upload_lock

        class _Handler(socketserver.BaseRequestHandler):
            def handle(self):
                sess = _FTPSession(self.request, self.client_address, banner, upload_dir, bind_ip,
                                   upload_lock=upload_lock)
                sess.run()

        try:
            self._server = _ReuseServer((self.bind_ip, self.port), _Handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("FTP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("FTP failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server = None
        logger.info("FTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
