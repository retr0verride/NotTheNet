"""
NotTheNet - Fake SMB Server (TCP port 445)

Why this matters:
    SMB is the most-exploited protocol for lateral movement:
      - WannaCry / NotPetya  — EternalBlue (MS17-010, SMBv1 TRANS2 exploit)
      - Emotet, Ryuk         — SMBv2 credential spray over port 445
      - Impacket             — smbclient, psexec-style lateral movement
      - REvil / BlackMatter  — scan 445 before encrypting network shares

    Key intelligence:
      - Dialect list reveals whether the client is probing for SMBv1
        (EternalBlue prerequisite) or SMBv2/3 (modern tooling)
      - The _ETERNALBLUE_PROBE flag fires when a client sends the exact
        dialect set used by the NSA exploit: any list containing "NT LM 0.12"

    Protocol behaviour:
      - SMBv1 negotiate: returns STATUS_NOT_SUPPORTED — no v1 session proceeds
      - SMBv2 negotiate: returns STATUS_NOT_SUPPORTED packed in SMB2 header
      - Both cases still log the full dialect list for triage

Security notes (OpenSSF):
- Message body is bounded to 65 535 bytes
- No partial or forged SMB sessions are created
- struct offsets are validated against actual body size before reading
- Each session runs in a daemon thread; cannot block process exit
"""

import logging
import socket
import struct
import threading
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip

logger = logging.getLogger(__name__)

SESSION_TIMEOUT = 10
_MAX_CONNECTIONS = 50

_SMB1_MAGIC = b"\xff\x53\x4d\x42"
_SMB2_MAGIC = b"\xfe\x53\x4d\x42"
_SMB2_CMD_NEGOTIATE = 0x0000
_STATUS_NOT_SUPPORTED = 0xC00000BB


def _smb2_error_response(message_id: int) -> bytes:
    """
    Build an SMB2 ERROR Response with STATUS_NOT_SUPPORTED.

    Layout:
      NetBIOS session header  4 bytes
      SMB2 header            64 bytes
      SMB2 error body         9 bytes (StructureSize=9, empty)
    """
    # SMB2 Negotiate Error Response header (64 bytes)
    header = bytearray(64)
    header[0:4]   = _SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)                      # StructureSize
    struct.pack_into("<I", header, 8, _STATUS_NOT_SUPPORTED)   # NTStatus
    struct.pack_into("<H", header, 12, _SMB2_CMD_NEGOTIATE)    # Command
    struct.pack_into("<H", header, 14, 1)                      # CreditResponse
    struct.pack_into("<I", header, 16, 0x00000001)             # Flags: REPLY
    struct.pack_into("<Q", header, 28, message_id)             # MessageId

    # SMB2 Error Response body (9 bytes)
    error_body = bytearray(9)
    struct.pack_into("<H", error_body, 0, 9)                   # StructureSize

    payload = bytes(header) + bytes(error_body)
    netbios = b"\x00" + struct.pack(">I", len(payload))[1:]    # type=0, 3-byte length
    return netbios + payload


class _SMBSession(threading.Thread):
    """Handles one SMB client session."""

    def __init__(self, conn: socket.socket, addr: tuple, sem: Optional[threading.BoundedSemaphore] = None):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem

    def run(self):
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(SESSION_TIMEOUT)

            # ── 1. Read NetBIOS session header (4 bytes) ───────────────────
            nb_hdr = self.conn.recv(4)
            if len(nb_hdr) < 4:
                return
            nb_type = nb_hdr[0]
            if nb_type not in (0x00, 0x81):  # 0x00 = Session Message, 0x81 = Session Request
                return

            msg_len = struct.unpack(">I", b"\x00" + nb_hdr[1:4])[0]
            if msg_len == 0 or msg_len > 65535:
                return

            # ── 2. Read SMB message body ───────────────────────────────────
            data = b""
            while len(data) < msg_len:
                chunk = self.conn.recv(min(msg_len - len(data), 4096))
                if not chunk:
                    break
                data += chunk

            if len(data) < 4:
                return

            magic = data[:4]
            version = "unknown"
            dialects: list[str] = []
            eternalblue = False
            message_id = 0

            if magic == _SMB1_MAGIC:
                version = "SMBv1"
                # Dialect strings follow the 33-byte SMBv1 header+word-count:
                # each entry is \x02 + null-terminated ASCII name.
                if len(data) > 33:
                    for part in data[33:].split(b"\x02"):
                        name = part.rstrip(b"\x00").decode("ascii", errors="replace").strip()
                        if name:
                            dialects.append(name)
                eternalblue = any("NT LM 0.12" in d for d in dialects)

            elif magic == _SMB2_MAGIC:
                version = "SMBv2"
                # MessageId is at offset 28 in the 64-byte SMB2 header
                if len(data) >= 36:
                    message_id = struct.unpack("<Q", data[28:36])[0]

            eb_flag = " [ETERNALBLUE-PROBE]" if eternalblue else ""
            logger.info(
                "SMB %s negotiate from %s%s dialects=%s",
                version, safe_addr, eb_flag, dialects[:6],
            )
            if jl:
                jl.log(
                    "smb_negotiate",
                    src_ip=self.addr[0],
                    version=version,
                    dialects=dialects[:6],
                    eternalblue_probe=eternalblue,
                )

            # ── 3. Send error response to abort safely ─────────────────────
            if magic == _SMB2_MAGIC:
                self.conn.sendall(_smb2_error_response(message_id))

        except OSError:
            pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()


class SMBService:
    """Fake SMB server on TCP port 445."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 445))
        self.bind_ip = bind_ip
        self._sem = threading.BoundedSemaphore(int(config.get("max_connections", _MAX_CONNECTIONS)))
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.listen(50)
            self._sock.settimeout(1.0)
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="smb-server"
            )
            self._thread.start()
            logger.info("SMB service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("SMB failed to bind on port %s: %s", self.port, e)
            return False

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("SMB at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _SMBSession(conn, addr, sem=self._sem).start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("SMB service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
