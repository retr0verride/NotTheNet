"""
NotTheNet - NTP Server
Returns current system time to defeat clock-skew sandbox detection.

Some malware queries NTP (UDP port 123) before executing to verify it is not
inside a paused or time-shifted sandbox environment.  A significant difference
between system time and an NTP response is a known sandbox indicator.  This
service responds to any valid NTP client request with the current system time,
keeping the apparent NTP time in sync with the host clock.

Security notes (OpenSSF):
- Only the first 512 bytes of each UDP datagram are read; oversized packets
  are truncated before parsing
- Malformed / undersized NTP packets (< 48 bytes) are silently dropped
- No reflection amplification: response is exactly 48 bytes regardless of
  request size
- The response spoofs Stratum 2 from reference "LOCL" â€” realistic enough to
  satisfy clients without exposing internal details
- Runs in a daemon thread; cannot block process exit
"""

import logging
import socket
import struct
import threading
import time

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip

logger = logging.getLogger(__name__)

# NTP epoch starts 1900-01-01; Unix epoch starts 1970-01-01.
# Difference = 70 years in seconds.
_NTP_DELTA = 2208988800


def _ntp_timestamp(t: float) -> tuple[int, int]:
    """Convert a Unix timestamp to (NTP seconds, NTP fraction)."""
    ntp = t + _NTP_DELTA
    secs = int(ntp)
    frac = int((ntp - secs) * (2 ** 32))
    return secs, frac


def _build_response(request: bytes) -> bytes | None:
    """
    Build a 48-byte NTP server response packet.

    The client's Transmit Timestamp is echoed back as our Originate Timestamp,
    which is required by RFC 5905 for the client to validate the exchange.
    Returns None if the request is too short to be a valid NTP message.
    """
    if len(request) < 48:
        return None

    # Echo client's transmit timestamp as originate timestamp (RFC 5905 Â§8)
    orig_secs, orig_frac = struct.unpack("!II", request[40:48])

    now = time.time()
    ref_secs, ref_frac = _ntp_timestamp(now)
    rcv_secs, rcv_frac = ref_secs, ref_frac
    xmt_secs, xmt_frac = ref_secs, ref_frac

    # Packet layout (48 bytes, big-endian):
    #   1B  LI=0 | VN=3 | Mode=4 (server)   â†’ 0b00_011_100 = 0x1C
    #   1B  Stratum = 2 (secondary reference)
    #   1B  Poll interval = 6 (log2 max interval, signed)
    #   1B  Precision = -20 (log2 clock precision â‰ˆ 1 Âµs, signed)
    #   4B  Root delay     (fixed-point 16.16, â‰ˆ 10 ms upstream RTT)
    #   4B  Root dispersion (fixed-point 16.16, â‰ˆ 20 ms cumulative dispersion)
    #   4B  Reference ID   upstream Stratum-1 IP (time.google.com = 216.239.35.0)
    #       RFC 5905 Â§7.3: for Stratum 2+, Reference ID must be the IPv4 address
    #       of the upstream reference clock, NOT an ASCII keyword like "LOCL".
    #       Sending "LOCL" at Stratum 2 is a detectable fingerprint â€” real
    #       stratum-2 servers always encode an upstream IP here.
    #   8B  Reference timestamp  (secs + frac)
    #   8B  Originate timestamp  (echoed from client)
    #   8B  Receive timestamp
    #   8B  Transmit timestamp
    return struct.pack(
        "!BBbbII4sIIIIIIII",
        0x1C,           # LI:0, VN:3, Mode:4 (server)
        2,              # Stratum 2
        6,              # Poll exponent
        -20,            # Precision exponent
        655,            # Root delay     (â‰ˆ 10 ms; NTP 16.16 fixed-point, 0.010 Ã— 65536)
        1311,           # Root dispersion (â‰ˆ 20 ms; Stratum-2 servers never report zero)
        b"\xd8\xef\x23\x00",  # Reference ID: 216.239.35.0 (time.google.com Stratum 1)
        ref_secs, ref_frac,
        orig_secs, orig_frac,
        rcv_secs, rcv_frac,
        xmt_secs, xmt_frac,
    )


class NTPService:
    """Fake NTP server â€” responds to all NTP queries with system time."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 123))
        self.bind_ip = bind_ip
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> bool:
        if not self.enabled:
            logger.info("NTP service disabled in config.")
            return False
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.bind_ip, self.port))
            self._sock.settimeout(1.0)
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._serve, daemon=True, name="ntp-server"
            )
            self._thread.start()
            logger.info("NTP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("NTP service failed to start on port %s: %s", self.port, e)
            return False

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                response = _build_response(data)
                if response is None:
                    logger.debug("NTP  dropped undersized packet from %s", sanitize_ip(addr[0]))
                    continue
                self._sock.sendto(response, addr)
                safe_ip = sanitize_ip(addr[0])
                logger.info(
                    "NTP  query from %s:%s \u2192 replied with system time",
                    safe_ip, addr[1],
                )
                jl = get_json_logger()
                if jl:
                    jl.log("ntp_query", src_ip=addr[0], src_port=addr[1])
            except Exception as e:
                logger.debug("NTP handler error: %s", e)

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                logger.debug("NTP socket close failed", exc_info=True)
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("NTP service stopped.")

    @property
    def running(self) -> bool:
        return (
            self._thread is not None
            and self._thread.is_alive()
            and not self._stop_event.is_set()
        )
