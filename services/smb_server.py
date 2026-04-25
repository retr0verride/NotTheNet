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

# After replying to NEGOTIATE we keep the connection open briefly to absorb
# follow-up frames (session setup, tree connect, EternalBlue TRANS2 probes).
# Without this, worms re-target the same IP repeatedly instead of advancing.
_DRAIN_TIMEOUT = 3.0
_MAX_DRAIN_FRAMES = 16

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
    def _parse_smb1_negotiate(
        data: bytes,
    ) -> tuple[list[str], bool, int, int, int, int, int]:
        """Extract dialects, EternalBlue probe flag, dialect index, and TID/PID/UID/MID
        from an SMBv1 negotiate request. Header layout per MS-CIFS 2.2.3.1.

        SMB1 NEGOTIATE request body (after the 32-byte header) is:
            WordCount  (1 byte, == 0)
            ByteCount  (2 bytes, U16 LE)
            Bytes[]    (dialect entries: 0x02 DialectName 0x00 ...)
        So dialect entries start at offset 35, not 33. Reading from 33 includes
        the ByteCount bytes which produces a bogus leading entry and shifts
        dialect_index by +1, causing the response to advertise an index the
        client never offered.
        """
        dialects: list[str] = []
        if len(data) > 35:
            for part in data[35:].split(b"\x02"):
                name = part.rstrip(b"\x00").decode("ascii", errors="replace").strip()
                if name:
                    dialects.append(name)
        eternalblue = any("NT LM 0.12" in d for d in dialects)
        dialect_index = next(
            (i for i, d in enumerate(dialects) if "NT LM 0.12" in d), 0
        )
        tid = pid = uid = mid = 0
        if len(data) >= 32:
            tid, pid, uid, mid = struct.unpack("<HHHH", data[24:32])
        return dialects, eternalblue, dialect_index, tid, pid, uid, mid

    @staticmethod
    def _parse_smb2_negotiate(data: bytes) -> int:
        """Extract message ID from SMBv2 negotiate header."""
        if len(data) >= 36:
            return struct.unpack("<Q", data[28:36])[0]
        return 0

    def _parse_negotiate(self, data: bytes) -> tuple:
        """Parse SMB negotiate data.

        Returns (version, dialects, eternalblue, message_id, dialect_index, smb1_hdr)
        where smb1_hdr is a 4-tuple (tid, pid, uid, mid) for SMBv1, else (0,0,0,0).
        """
        magic = data[:4]
        if magic == _SMB1_MAGIC:
            dialects, eb, dialect_index, tid, pid, uid, mid = self._parse_smb1_negotiate(data)
            return "SMBv1", dialects, eb, 0, dialect_index, (tid, pid, uid, mid)
        if magic == _SMB2_MAGIC:
            return "SMBv2", [], False, self._parse_smb2_negotiate(data), 0, (0, 0, 0, 0)
        return "unknown", [], False, 0, 0, (0, 0, 0, 0)

    def run(self) -> None:
        safe_addr = sanitize_ip(self.addr[0])
        jl = get_json_logger()
        try:
            self.conn.settimeout(self.session_timeout)
            data = self._read_smb_message()
            if data is None:
                return
            version, dialects, eternalblue, message_id, dialect_index, smb1_hdr = (
                self._parse_negotiate(data)
            )

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
                tid, pid, uid, mid = smb1_hdr
                self.conn.sendall(
                    _smb1_negotiate_response(
                        dialect_index, tid=tid, pid=pid, uid=uid, mid=mid,
                    )
                )
                if jl and eternalblue:
                    jl.log(
                        "smb_eternalblue_simulated",
                        src_ip=self.addr[0],
                        note="Simulated SMBv1 NEGOTIATE response sent; no real exploit occurred."
                    )
                # After the negotiate, drain any follow-up SMB messages (session
                # setup, tree connect, EternalBlue trans2 probes) until the
                # client gives up. Without this the worm thread re-targets the
                # same IP repeatedly instead of advancing in its /24 scan.
                self._drain_smb1_session()
        except OSError:
            logger.debug("SMB session error", exc_info=True)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            if self._sem:
                self._sem.release()

    def _drain_smb1_session(self) -> None:
        """Read and discard follow-up SMB1 frames (session setup, tree connect,
        TRANS2 EternalBlue probes) until the peer closes or recv times out.
        Reply with STATUS_NOT_SUPPORTED for each so the client treats us as
        'reached but unexploitable' and advances to the next host."""
        try:
            self.conn.settimeout(min(self.session_timeout, _DRAIN_TIMEOUT))
        except OSError:
            return
        for _ in range(_MAX_DRAIN_FRAMES):
            try:
                follow = self._read_smb_message()
            except OSError:
                return
            if not follow:
                return
            if follow[:4] != _SMB1_MAGIC:
                return
            try:
                self.conn.sendall(_smb1_error_response(follow))
            except OSError:
                return


def _smb1_negotiate_response(
    dialect_index: int,
    *,
    tid: int = 0,
    pid: int = 0,
    uid: int = 0,
    mid: int = 0,
) -> bytes:
    """
    Build a minimal SMBv1 NEGOTIATE response for EternalBlue probes.

    Layout per MS-CIFS 2.2.4.5.2 (NT LM 0.12 dialect, no extended security):
      NetBIOS header               4 bytes
      SMB1 header                 32 bytes
      WordCount                    1 byte  = 17
      Words (parameter block)     34 bytes
        DialectIndex     U16
        SecurityMode     U8   = 0x03 (user-level, encryption enabled)
        MaxMpxCount      U16  = 50
        MaxNumberVcs     U16  = 1
        MaxBufferSize    U32  = 0x10000
        MaxRawSize       U32  = 0x10000
        SessionKey       U32  = 0
        Capabilities     U32  = 0
        SystemTime       U64  = 0
        ServerTimeZone   I16  = 0
        ChallengeLength  U8   = 0
      ByteCount                    2 bytes = 0
    Total SMB body = 37 bytes; total payload = 32 + 37 = 69 bytes.

    The previous version was 34 bytes total (missing ByteCount and overwrote
    ServerTimeZone's high byte with ChallengeLength) which Windows clients
    rejected, causing WannaCry's worm thread to retry the same IP repeatedly
    instead of advancing to the next host in its /24 scan.

    TID/PID/UID/MID are echoed from the request so the response correlates.
    """
    # SMB1 header (32 bytes)
    header = bytearray(32)
    header[0:4] = _SMB1_MAGIC
    header[4] = 0x72                                    # Command: NEGOTIATE_RESPONSE
    # bytes 5-8: NTStatus = 0 (success)
    header[9] = 0x88                                    # Flags: REPLY | CASE_INSENSITIVE
    struct.pack_into("<H", header, 10, 0xC001)          # Flags2: UNICODE|NT_STATUS|LONG_NAMES
    # bytes 12-23: PIDHigh + SecurityFeatures + Reserved (all zero is fine)
    struct.pack_into("<H", header, 24, tid & 0xFFFF)    # TID
    struct.pack_into("<H", header, 26, pid & 0xFFFF)    # PIDLow
    struct.pack_into("<H", header, 28, uid & 0xFFFF)    # UID
    struct.pack_into("<H", header, 30, mid & 0xFFFF)    # MID

    # SMB body: WordCount(1) + 34 word-bytes + ByteCount(2) = 37 bytes
    body = bytearray(37)
    body[0] = 17                                        # WordCount = 17 words
    struct.pack_into("<H", body, 1, dialect_index)      # DialectIndex
    body[3] = 0x03                                      # SecurityMode
    struct.pack_into("<H", body, 4, 50)                 # MaxMpxCount
    struct.pack_into("<H", body, 6, 1)                  # MaxNumberVcs
    struct.pack_into("<I", body, 8, 0x10000)            # MaxBufferSize
    struct.pack_into("<I", body, 12, 0x10000)           # MaxRawSize
    struct.pack_into("<I", body, 16, 0)                 # SessionKey
    struct.pack_into("<I", body, 20, 0)                 # Capabilities
    struct.pack_into("<Q", body, 24, 0)                 # SystemTime (FILETIME)
    struct.pack_into("<h", body, 32, 0)                 # ServerTimeZone (signed)
    body[34] = 0                                        # ChallengeLength
    struct.pack_into("<H", body, 35, 0)                 # ByteCount = 0

    payload = bytes(header) + bytes(body)
    netbios = b"\x00" + struct.pack(">I", len(payload))[1:]
    return netbios + payload


def _smb1_error_response(request: bytes) -> bytes:
    """Build a generic SMB1 error response (STATUS_NOT_SUPPORTED) echoing the
    request's command and TID/PID/UID/MID. Used to gracefully refuse follow-up
    frames after the negotiate, so the client cleanly aborts and moves on."""
    if len(request) < 32 or request[:4] != _SMB1_MAGIC:
        return b""
    command = request[4]
    tid, pid, uid, mid = struct.unpack("<HHHH", request[24:32])
    header = bytearray(32)
    header[0:4] = _SMB1_MAGIC
    header[4] = command
    struct.pack_into("<I", header, 5, _STATUS_NOT_SUPPORTED)  # NTStatus
    header[9] = 0x88                                          # Flags: REPLY
    struct.pack_into("<H", header, 10, 0xC001)                # Flags2
    struct.pack_into("<H", header, 24, tid)
    struct.pack_into("<H", header, 26, pid)
    struct.pack_into("<H", header, 28, uid)
    struct.pack_into("<H", header, 30, mid)
    body = b"\x00\x00\x00"  # WordCount=0, ByteCount=0
    payload = bytes(header) + body
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
