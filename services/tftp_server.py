"""
NotTheNet - TFTP Server

Fake TFTP server for capturing payload staging and lateral movement traffic.

TFTP (RFC 1350, UDP port 69) is used by malware for:
  - Payload download/staging: attacker pushes next-stage payloads via TFTP
  - Lateral movement over network devices (Cisco/Juniper use TFTP for firmware)
  - PXE-boot-style persistence mechanisms
  - Exfiltration over UDP to evade TCP-based IDS rules

This server:
  - Handles RRQ (read request) by serving a small benign stub response so
    the client completes its transfer and continues execution
  - Handles WRQ (write request) by accepting and saving uploaded data to
    disk for forensic analysis, up to a configurable size cap
  - Uses proper TIDs (each transfer gets its own ephemeral UDP socket) per
    RFC 1350 Â§4, so well-behaved clients are not confused by responses from
    an unexpected port

Security notes (OpenSSF):
- Filename is basename-sanitised to prevent path traversal
- Upload size is capped at MAX_UPLOAD_BYTES (10 MB) per transfer
- Each upload is saved with a UUID prefix so filenames cannot collide or
  overwrite existing files
- Malformed / undersized packets are silently discarded
- Each transfer runs in a daemon thread; cannot block process exit
"""

import logging
import os
import socket
import struct
import threading
import uuid
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string

logger = logging.getLogger(__name__)

# â”€â”€â”€ TFTP constants (RFC 1350) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_OP_RRQ   = 1  # Read request
_OP_WRQ   = 2  # Write request
_OP_DATA  = 3  # Data block
_OP_ACK   = 4  # Acknowledgement
_OP_ERROR = 5  # Error

_BLOCK_SIZE = 512           # RFC 1350 Â§2: fixed 512-byte data blocks
_TRANSFER_TIMEOUT = 5.0     # seconds to wait for each ACK/DATA
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB per upload
_MAX_TRANSFERS = 50         # concurrent transfer cap (BoundedSemaphore)
# Small benign stub served in response to any RRQ so the malware's transfer
# completes without error and execution continues.
_RRQ_STUB = (
    b"# Configuration file\r\n"
    b"# Auto-generated\r\n"
)
if len(_RRQ_STUB) >= _BLOCK_SIZE:
    raise RuntimeError("RRQ stub must fit in a single DATA block")


# â”€â”€â”€ Packet builders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _parse_rrq_wrq(data: bytes) -> tuple[Optional[str], Optional[str]]:
    """
    Parse a RRQ or WRQ packet: 2-byte opcode + filename\\0 + mode\\0.
    Returns (filename, mode) or (None, None) if the packet is malformed.
    """
    rest = data[2:]
    null_pos = rest.find(b"\x00")
    if null_pos < 0:
        return None, None
    raw_filename = rest[:null_pos]
    # Reject filenames containing embedded null bytes (before the terminator)
    if b"\x00" in raw_filename:
        return None, None
    filename = raw_filename.decode("utf-8", errors="replace")
    mode_raw = rest[null_pos + 1:]
    mode_null = mode_raw.find(b"\x00")
    mode = mode_raw[:mode_null].decode("utf-8", errors="replace") if mode_null >= 0 else ""
    return filename, mode


def _ack(block: int) -> bytes:
    return struct.pack("!HH", _OP_ACK, block)


def _data(block: int, payload: bytes) -> bytes:
    return struct.pack("!HH", _OP_DATA, block) + payload


def _error(code: int, msg: str) -> bytes:
    return struct.pack("!HH", _OP_ERROR, code) + msg.encode() + b"\x00"


# â”€â”€â”€ Per-transfer thread â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class _TFTPTransferThread(threading.Thread):
    """
    Handles one TFTP transfer (RRQ or WRQ) on its own ephemeral UDP socket.

    Per RFC 1350 Â§4, each transfer uses a new TID (Transfer ID = port number)
    so that the client can distinguish responses to concurrent transfers.
    """

    def __init__(
        self,
        opcode: int,
        client_addr: tuple,
        filename: str,
        allow_uploads: bool,
        upload_dir: str,
        bind_ip: str = "0.0.0.0",
        sem: Optional[threading.BoundedSemaphore] = None,
    ):
        super().__init__(daemon=True, name=f"tftp-{client_addr[0]}")
        self.opcode = opcode
        self.client_addr = client_addr
        self.filename = filename
        self.allow_uploads = allow_uploads
        self.upload_dir = upload_dir
        self.bind_ip = bind_ip
        self._sem = sem

    def run(self) -> None:
        safe_addr = sanitize_ip(self.client_addr[0])
        safe_file = sanitize_log_string(self.filename)
        # Bind an ephemeral TID socket for this transfer
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((self.bind_ip, 0))
            sock.settimeout(_TRANSFER_TIMEOUT)
        except OSError as e:
            logger.error("TFTP: failed to bind TID socket: %s", e)
            return
        try:
            if self.opcode == _OP_RRQ:
                self._handle_rrq(sock, safe_addr, safe_file)
            else:
                self._handle_wrq(sock, safe_addr, safe_file)
        finally:
            sock.close()
            if self._sem:
                self._sem.release()

    # â”€â”€ RRQ (client reads a file from us) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _handle_rrq(self, sock: socket.socket, safe_addr: str, safe_file: str):
        """
        Serve the static stub to any RRQ.  Sending a single DATA block
        smaller than 512 bytes signals end-of-file per RFC 1350 Â§6.
        """
        logger.info("TFTP RRQ [%s] file=%s", safe_addr, safe_file)
        jl = get_json_logger()
        if jl:
            jl.log("tftp_rrq", src=self.client_addr[0], filename=safe_file)

        pkt = _data(1, _RRQ_STUB)
        retries = 3
        while retries > 0:
            try:
                sock.sendto(pkt, self.client_addr)
                ack, _ = sock.recvfrom(8)
                if len(ack) >= 4:
                    op, blk = struct.unpack("!HH", ack[:4])
                    if op == _OP_ACK and blk == 1:
                        break  # Transfer complete
            except socket.timeout:
                retries -= 1
        logger.debug("TFTP RRQ [%s] complete", safe_addr)

    # â”€â”€ WRQ (client writes a file to us) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _handle_wrq(self, sock: socket.socket, safe_addr: str, safe_file: str):
        """
        Accept a WRQ upload: ACK block 0, then receive DATA blocks until
        a short block signals end-of-file or the size cap is reached.
        """
        logger.info("TFTP WRQ [%s] file=%s", safe_addr, safe_file)
        jl = get_json_logger()
        if jl:
            jl.log("tftp_wrq", src=self.client_addr[0], filename=safe_file)

        if not self.allow_uploads:
            sock.sendto(_error(2, "Access violation"), self.client_addr)
            return

        os.makedirs(self.upload_dir, exist_ok=True)
        # Sanitize to basename to prevent path traversal attacks
        safe_name = os.path.basename(self.filename) or "upload"
        out_path = os.path.join(
            self.upload_dir, f"{uuid.uuid4().hex}_{safe_name[:64]}"
        )

        # ACK block 0 â€” signals we accept the write
        sock.sendto(_ack(0), self.client_addr)

        received_bytes = 0
        expected_block = 1

        with open(out_path, "wb") as fh:
            while True:
                try:
                    pkt, _ = sock.recvfrom(4 + _BLOCK_SIZE)
                except socket.timeout:
                    break
                if len(pkt) < 4:
                    break
                op, blk = struct.unpack("!HH", pkt[:4])
                if op != _OP_DATA or blk != expected_block:
                    break

                chunk = pkt[4:]
                received_bytes += len(chunk)
                if received_bytes > _MAX_UPLOAD_BYTES:
                    sock.sendto(_error(3, "Disk full"), self.client_addr)
                    break

                fh.write(chunk)
                sock.sendto(_ack(blk), self.client_addr)

                if len(chunk) < _BLOCK_SIZE:
                    break  # Short block = last block (RFC 1350 Â§6)

                expected_block = (expected_block + 1) & 0xFFFF  # wrap at 65535

        logger.info(
            "TFTP WRQ [%s] saved %dB → %s", safe_addr, received_bytes, out_path
        )


# â”€â”€â”€ Service wrapper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class TFTPService:
    """Fake TFTP server â€” handles RRQ (read) and WRQ (write) on UDP."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 69))
        self.bind_ip = bind_ip
        self.allow_uploads = config.get("allow_uploads", True)
        self.upload_dir = config.get("upload_dir", "logs/tftp_uploads")
        self._sem = threading.BoundedSemaphore(_MAX_TRANSFERS)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            logger.info("TFTP service disabled in config.")
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.settimeout(1.0)
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="tftp-server"
            )
            self._thread.start()
            logger.info("TFTP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("TFTP service failed to start: %s", e)
            return False

    def _serve(self) -> None:
        """Main loop: read initial RRQ/WRQ datagrams and spawn transfer threads."""
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < 4:
                continue

            opcode = struct.unpack("!H", data[:2])[0]
            if opcode not in (_OP_RRQ, _OP_WRQ):
                continue

            filename, _mode = _parse_rrq_wrq(data)
            if not filename:
                continue

            if not self._sem.acquire(blocking=False):
                logger.debug("TFTP at capacity, dropping %s", sanitize_ip(addr[0]))
                continue
            _TFTPTransferThread(
                opcode, addr, filename,
                self.allow_uploads, self.upload_dir,
                self.bind_ip,
                sem=self._sem,
            ).start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3.0)
        logger.info("TFTP service stopped.")

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()
