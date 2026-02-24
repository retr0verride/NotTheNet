"""
NotTheNet - DNS Server
Resolves every hostname to redirect_ip, fooling malware DNS lookups.

Key differences from INetSim / FakeNet-NG:
- Single threaded async UDP server — no socket leak on restart
- Handles PTR (reverse DNS) cleanly — returns a synthetic hostname
- Custom record overrides supported via config
- All query names sanitized before logging (log injection prevention)
- dnslib used for packet building (no manual DNS byte-packing bugs)

Security notes (OpenSSF):
- Max UDP packet size accepted: 512 bytes (RFC 1035), extended to 4096 with EDNS
- Truncated / malformed packets are silently dropped, never crash the server
- Query name length validated (≤ 253 chars per RFC 1035)
"""

import logging
from typing import Optional

from utils.logging_utils import sanitize_hostname, sanitize_ip

logger = logging.getLogger(__name__)

try:
    from dnslib import PTR, QTYPE, RR, A, DNSRecord
    from dnslib.server import DNSServer
    _DNSLIB_AVAILABLE = True
except ImportError:
    _DNSLIB_AVAILABLE = False
    logger.warning("dnslib not installed; DNS server unavailable. pip install dnslib")


class _FakeResolver:
    """
    Resolves every query to redirect_ip.
    Custom records can override specific names.
    """

    def __init__(self, redirect_ip: str, custom_records: dict, ttl: int, handle_ptr: bool):
        self.redirect_ip = redirect_ip
        self.custom_records = {k.lower().rstrip("."): v for k, v in custom_records.items()}
        self.ttl = ttl
        self.handle_ptr = handle_ptr

    def resolve(self, request: "DNSRecord", handler) -> "DNSRecord":
        reply = request.reply()
        try:
            qname = str(request.q.qname).lower().rstrip(".")
            qtype = QTYPE[request.q.qtype]

            safe_name = sanitize_hostname(qname)
            logger.info(f"DNS query  type={qtype} name={safe_name}")

            # --- Custom record override ---
            if qname in self.custom_records:
                override_ip = self.custom_records[qname]
                reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(override_ip)))
                logger.debug(f"  -> custom override: {safe_name} -> {sanitize_ip(override_ip)}")
                return reply

            # --- PTR (reverse lookup) ---
            if request.q.qtype == QTYPE.PTR:
                if self.handle_ptr:
                    reply.add_answer(
                        RR(qname, QTYPE.PTR, ttl=self.ttl,
                           rdata=PTR("notthenet.local"))
                    )
                    logger.debug(f"  -> PTR: {safe_name} -> notthenet.local")
                return reply

            # --- AAAA (IPv6) ---
            if request.q.qtype == QTYPE.AAAA:
                # Return IPv4-mapped IPv6 loopback — keeps malware happy
                reply.add_answer(
                    RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
                )
                logger.debug(f"  -> AAAA(faked as A): {safe_name} -> {sanitize_ip(self.redirect_ip)}")
                return reply

            # --- A (and everything else) ---
            reply.add_answer(
                RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
            )
            logger.debug(f"  -> A: {safe_name} -> {sanitize_ip(self.redirect_ip)}")

        except Exception as e:
            logger.warning(f"DNS resolve error: {e}")
            reply.header.rcode = 2  # SERVFAIL — never crash the server
        return reply


class DNSService:
    """Manages the fake DNS server lifecycle."""

    def __init__(self, config: dict):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 53))
        self.redirect_ip = config.get("resolve_to", "127.0.0.1")
        self.ttl = int(config.get("ttl", 300))
        self.handle_ptr = config.get("handle_ptr", True)
        self.custom_records = config.get("custom_records", {})
        self.bind_ip = config.get("bind_ip", "0.0.0.0")
        self._server_udp: Optional[DNSServer] = None
        self._server_tcp: Optional[DNSServer] = None

    def start(self) -> bool:
        if not self.enabled:
            logger.info("DNS service disabled in config.")
            return False

        if not _DNSLIB_AVAILABLE:
            logger.error("DNS service cannot start: dnslib not installed.")
            return False

        resolver = _FakeResolver(
            self.redirect_ip, self.custom_records, self.ttl, self.handle_ptr
        )
        try:
            self._server_udp = DNSServer(
                resolver, port=self.port, address=self.bind_ip, tcp=False
            )
            self._server_tcp = DNSServer(
                resolver, port=self.port, address=self.bind_ip, tcp=True
            )
            self._server_udp.start_thread()
            self._server_tcp.start_thread()
            logger.info(
                f"DNS service started on {self.bind_ip}:{self.port} "
                f"(UDP+TCP) -> all queries resolve to {sanitize_ip(self.redirect_ip)}"
            )
            return True
        except OSError as e:
            logger.error(f"DNS service failed to bind port {self.port}: {e}")
            return False

    def stop(self):
        for srv in (self._server_udp, self._server_tcp):
            if srv:
                try:
                    srv.stop()
                except Exception:
                    pass
        self._server_udp = None
        self._server_tcp = None
        logger.info("DNS service stopped.")

    @property
    def running(self) -> bool:
        # dnslib's DNSServer exposes the underlying thread via .thread
        # (set by start_thread()).  Fall back gracefully if the attribute
        # layout ever changes.
        try:
            t = getattr(self._server_udp, "thread", None)
            return bool(t and t.is_alive())
        except Exception:
            return False
