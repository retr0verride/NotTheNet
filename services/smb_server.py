"""
NotTheNet - Fake SMB Server (TCP port 445)

Why this matters:
    SMB is the most-exploited protocol for lateral movement:
      - WannaCry / NotPetya  â€” EternalBlue (MS17-010, SMBv1 TRANS2 exploit)
      - Emotet, Ryuk         â€” SMBv2 credential spray over port 445
      - Impacket             â€” smbclient, psexec-style lateral movement
      - REvil / BlackMatter  â€” scan 445 before encrypting network shares

    Key intelligence:
      - Dialect list reveals whether the client is probing for SMBv1
        (EternalBlue prerequisite) or SMBv2/3 (modern tooling)
      - The _ETERNALBLUE_PROBE flag fires when a client sends the exact
        dialect set used by the NSA exploit: any list containing "NT LM 0.12"

    Protocol behaviour:
      - SMBv1 negotiate: returns a minimal NEGOTIATE response advertising
        NT LM 0.12 with no challenge — worms see "reached but not vulnerable"
        and continue scanning the subnet (prevents recv() block from aborting
        WannaCry's worm thread on the first IP). No real session is established.
      - SMBv2 negotiate: returns STATUS_NOT_SUPPORTED packed in SMB2 header.
      - Both cases still log the full dialect list for triage; SMBv1 EternalBlue
        probes additionally emit `smb_eternalblue_simulated` so post-analysis
        can distinguish faked responses from genuine compromise.

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

    def __init__(
        self,
        conn: socket.socket,
        addr: tuple,
        sem: threading.BoundedSemaphore | None = None,
        session_timeout: float = SESSION_TIMEOUT,
    ):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self._sem = sem
        self.session_timeout = session_timeout

    def _read_smb_message(self) -> "bytes | None":
        """Read a complete NetBIOS/SMB message. Returns data or None."""
        nb_hdr = self.conn.recv(4)
        if len(nb_hdr) < 4:
            return None
        if nb_hdr[0] not in (0x00, 0x81):
            return None
        msg_len = struct.unpack(">I", b"\x00" + nb_hdr[1:4])[0]
        if msg_len == 0 or msg_len > 65535:
            return None
        data = b""
        while len(data) < msg_len:
            chunk = self.conn.recv(min(msg_len - len(data), 4096))
            if not chunk:
                break
            data += chunk
        return data if len(data) >= 4 else None

    @staticmethod
    def _parse_smb1_negotiate(data: bytes) -> tuple[list[str], bool, int]:
        """Extract dialects, EternalBlue probe flag, and dialect index from SMBv1 negotiate."""
        dialects: list[str] = []
        if len(data) > 33:
            for part in data[33:].split(b"\x02"):
                name = part.rstrip(b"\x00").decode("ascii", errors="replace").strip()
                if name:
                    dialects.append(name)
        eternalblue = any("NT LM 0.12" in d for d in dialects)
        dialect_index = next(
            (i for i, d in enumerate(dialects) if "NT LM 0.12" in d), 0
        )
        return dialects, eternalblue, dialect_index

    @staticmethod
    def _parse_smb2_negotiate(data: bytes) -> int:
        """Extract message ID from SMBv2 negotiate header."""
        if len(data) >= 36:
            return struct.unpack("<Q", data[28:36])[0]
        return 0

    def _parse_negotiate(self, data: bytes) -> tuple:
        """Parse SMB negotiate data. Returns (version, dialects, eternalblue, message_id, dialect_index)."""
        magic = data[:4]
        if magic == _SMB1_MAGIC:
            dialects, eternalblue, dialect_index = self._parse_smb1_negotiate(data)
            return "SMBv1", dialects, eternalblue, 0, dialect_index
        if magic == _SMB2_MAGIC:
            return "SMBv2", [], False, self._parse_smb2_negotiate(data), 0
        return "unknown", [], False, 0, 0

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(self.session_timeout)
            data = self._read_smb_message()
            if data is None:
                return
            version, dialects, eternalblue, message_id, dialect_index = self._parse_negotiate(data)

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
            if data[:4] == _SMB2_MAGIC:
                self.conn.sendall(_smb2_error_response(message_id))
            elif data[:4] == _SMB1_MAGIC:
                self.conn.sendall(_smb1_negotiate_response(dialect_index))
                if jl and eternalblue:
                    jl.log(
                        "smb_eternalblue_simulated",
                        src_ip=self.addr[0],
                        note="Simulated SMBv1 NEGOTIATE response sent; no real exploit occurred."
                    )
        except OSError:
            logger.debug("SMB session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()


def _smb1_negotiate_response(dialect_index: int) -> bytes:
    """
    Build a minimal SMBv1 NEGOTIATE response for EternalBlue probes.
    Returns NetBIOS session header + SMBv1 NEGOTIATE response.
    """
    # SMBv1 NEGOTIATE response: 4-byte NetBIOS, 32-byte header, 34-byte body
    # See MS-SMB 2.2.4.52.2 for structure
    header = bytearray(32)
    header[0:4] = _SMB1_MAGIC
    header[4] = 0x72  # Command: NEGOTIATE_PROTOCOL_RESPONSE
    # Rest: zeros (flags, PID, UID, etc.)
    # Body: WordCount=17, DialectIndex, SecurityMode, MaxMpxCount, etc.
    body = bytearray(34)
    body[0] = 17  # WordCount
    struct.pack_into("<H", body, 1, dialect_index)  # DialectIndex
    body[3] = 0x03  # SecurityMode: user-level, encryption enabled
    struct.pack_into("<H", body, 4, 50)  # MaxMpxCount
    struct.pack_into("<H", body, 6, 1)   # MaxVCs
    struct.pack_into("<I", body, 8, 0x10000)  # MaxBufferSize
    struct.pack_into("<I", body, 12, 0x10000) # MaxRawSize
    struct.pack_into("<I", body, 16, 0)  # SessionKey
    struct.pack_into("<I", body, 20, 0)  # Capabilities
    struct.pack_into("<I", body, 24, 0)  # SystemTimeLow
    struct.pack_into("<I", body, 28, 0)  # SystemTimeHigh
    struct.pack_into("<H", body, 32, 0)  # ServerTimeZone
    body[33] = 0  # ChallengeLength
    payload = bytes(header) + bytes(body)
    netbios = b"\x00" + struct.pack(">I", len(payload))[1:]
    return netbios + payload


class SMBService:
    """Fake SMB server on TCP port 445."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 445))
        self.bind_ip = bind_ip
        self.max_connections = int(config.get("max_connections", _MAX_CONNECTIONS))
        self.session_timeout = float(config.get("session_timeout_sec", SESSION_TIMEOUT))
        self._sem = threading.BoundedSemaphore(self.max_connections)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
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

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            if not self._sem.acquire(blocking=False):
                logger.debug("SMB at capacity, dropping %s", sanitize_ip(addr[0]))
                conn.close()
                continue
            _SMBSession(
                conn,
                addr,
                sem=self._sem,
                session_timeout=self.session_timeout,
            ).start()

    def stop(self) -> None:
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
