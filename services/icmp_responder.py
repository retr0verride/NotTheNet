"""
NotTheNet - ICMP Echo Responder

Logs ICMP echo-request (ping) packets from monitored hosts.  The companion
iptables DNAT rule (applied by iptables_manager) redirects all forwarded
ICMP echo-requests to this host so the kernel issues echo-replies, making
the simulated internet appear reachable to malware connectivity checks.

This service opens a raw ICMP socket for logging only; the kernel sends
the actual echo-reply after DNAT rewrites the destination IP.

Security notes (OpenSSF):
- Requires CAP_NET_RAW (root). Gracefully skips if unavailable.
- Raw recvfrom is bounded to 65 535 bytes.
- IP header length field is validated before slicing ICMP data.
- Only ICMP type 8 (echo-request) packets are logged; all others ignored.
- Runs in a daemon thread; cannot block process exit.
"""

import logging
import socket
import threading
import time
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip

logger = logging.getLogger(__name__)

_ICMP_ECHO_REQUEST = 8
_MIN_IP_HDR        = 20
_MIN_ICMP_HDR      = 8
_LOG_INTERVAL      = 5.0  # seconds between repeated log entries for the same srcâ†’dst pair


class ICMPResponder:
    """
    Opens a raw ICMP socket to observe echo-request packets and log them.
    The iptables DNAT rule ensures all forwarded ICMP echo-requests are
    redirected to this host, where the kernel issues genuine echo-replies
    automatically, making every ping appear to succeed.
    """

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._last_logged: dict[tuple[str, str], float] = {}

    def start(self) -> bool:
        if not self.enabled:
            return False
        try:
            self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
            self._sock.settimeout(1.0)
        except PermissionError:
            logger.warning(
                "ICMP responder requires root / CAP_NET_RAW; skipping."
            )
            return False
        except OSError as e:
            logger.error("ICMP responder socket error: %s", e)
            return False

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="icmp-responder", daemon=True
        )
        self._thread.start()
        logger.info("ICMP echo responder started (raw socket, kernel replies)")
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

    @staticmethod
    def _parse_echo_request(raw: bytes, addr: tuple) -> "tuple[str, str] | None":
        """Validate IP+ICMP headers and extract (src_ip, dst_ip) or None."""
        if len(raw) < _MIN_IP_HDR:
            return None
        ip_hdr_len = (raw[0] & 0x0F) * 4
        if ip_hdr_len < _MIN_IP_HDR or len(raw) < ip_hdr_len + _MIN_ICMP_HDR:
            return None
        if raw[ip_hdr_len] != _ICMP_ECHO_REQUEST:
            return None
        src_ip = addr[0]
        dst_ip = socket.inet_ntoa(raw[16:20])
        return src_ip, dst_ip

    def _should_log(self, key: tuple, now: float) -> bool:
        """Rate-limit check: returns True if this key should be logged now."""
        with self._lock:
            if now - self._last_logged.get(key, 0.0) < _LOG_INTERVAL:
                return False
            self._last_logged[key] = now
            if len(self._last_logged) > 500:
                stale = [k for k, v in self._last_logged.items()
                         if now - v >= _LOG_INTERVAL]
                for k in stale:
                    del self._last_logged[k]
        return True

    def _run(self) -> None:
        assert self._sock is not None
        jl = get_json_logger()
        while not self._stop.is_set():
            try:
                raw, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            result = self._parse_echo_request(raw, addr)
            if result is None:
                continue
            src_ip, dst_ip = result

            now = time.monotonic()
            if not self._should_log((src_ip, dst_ip), now):
                continue

            logger.info(
                "ICMP ping: %s \u2192 %s",
                sanitize_ip(src_ip),
                sanitize_ip(dst_ip),
            )
            if jl:
                jl.log("icmp_ping", src_ip=src_ip, dst_ip=dst_ip)
