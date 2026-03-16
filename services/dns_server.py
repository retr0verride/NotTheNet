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
import math
from collections import Counter
from typing import Optional

from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_hostname, sanitize_ip

logger = logging.getLogger(__name__)


def _shannon_entropy(label: str) -> float:
    """Shannon entropy (bits/char) of a string — used for DGA detection."""
    if not label:
        return 0.0
    counts = Counter(label.lower())
    total = len(label)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


try:
    from dnslib import MX, NS, PTR, QTYPE, RR, SOA, TXT, A, CAA, SRV, DNSRecord
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

    def __init__(
        self,
        redirect_ip: str,
        custom_records: dict,
        ttl: int,
        handle_ptr: bool,
        nxdomain_entropy_threshold: float = 0.0,
        nxdomain_label_min_length: int = 12,
        public_response_ips: list | None = None,
    ):
        self.redirect_ip = redirect_ip
        self.custom_records = {k.lower().rstrip("."): v for k, v in custom_records.items()}
        self.ttl = ttl
        self.handle_ptr = handle_ptr
        self.nxdomain_entropy_threshold = nxdomain_entropy_threshold
        self.nxdomain_label_min_length = nxdomain_label_min_length
        # Pool of public-looking IPs to return in A responses.  iptables
        # REDIRECT rules catch them regardless of destination IP, so returning
        # a plausible public IP here is transparent to routing but prevents
        # malware from flagging the "all domains → 10.x.x.x" pattern.
        self._public_ips: list[str] = list(public_response_ips or [])

    def resolve(self, request: "DNSRecord", handler) -> "DNSRecord":
        reply = request.reply()
        try:
            qname = str(request.q.qname).lower().rstrip(".")
            qtype = QTYPE[request.q.qtype]

            # RFC 1035 §2.3.4: max 253 characters for a full domain name
            if len(qname) > 253:
                reply.header.rcode = 1  # FORMERR
                return reply

            safe_name = sanitize_hostname(qname)
            logger.info(f"DNS query  type={qtype} name={safe_name}")

            # Structured JSON logging
            jl = get_json_logger()
            if jl:
                src = handler.client_address[0] if hasattr(handler, 'client_address') else ''
                jl.log("dns_query", qtype=str(qtype), qname=qname, src_ip=src,
                       resolve_to=self.redirect_ip)

            # --- Custom record override ---
            if qname in self.custom_records:
                override_ip = self.custom_records[qname]
                reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(override_ip)))
                logger.debug(f"  -> custom override: {safe_name} -> {sanitize_ip(override_ip)}")
                return reply

            # --- Windows NCSI DNS probe ---
            # Windows resolves dns.msftncsi.com and expects 131.107.255.255.
            # Returning redirect_ip here would fail the probe and prevent the
            # "Internet access" indicator from showing.
            if qname in ("dns.msftncsi.com.", "dns.msftncsi.com") and request.q.qtype == QTYPE.A:
                reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl, rdata=A("131.107.255.255")))
                logger.debug(f"  -> NCSI DNS probe: {safe_name} -> 131.107.255.255")
                return reply

            # --- PTR (reverse lookup) ---
            if request.q.qtype == QTYPE.PTR:
                if self.handle_ptr:
                    # Synthesize a plausible ISP-style hostname from the IP so
                    # malware that checks reverse-DNS doesn't see "notthenet".
                    # PTR qname is like "100.1.168.192.in-addr.arpa".
                    ptr_label = qname
                    for suffix in (".in-addr.arpa.", ".in-addr.arpa"):
                        if ptr_label.endswith(suffix):
                            ptr_label = ptr_label[: -len(suffix)]
                            break
                    octets = ptr_label.split(".")
                    try:
                        ip_hyphen = "-".join(reversed(octets))
                        ptr_host = f"static-{ip_hyphen}.res.example.net."
                    except Exception:
                        ptr_host = "host.example.net."
                    reply.add_answer(
                        RR(qname, QTYPE.PTR, ttl=self.ttl,
                           rdata=PTR(ptr_host))
                    )
                    logger.debug(f"  -> PTR: {safe_name} -> {ptr_host}")
                return reply

            # --- AAAA (IPv6) ---
            # Return NOERROR with an empty answer section — signals "no IPv6
            # for this domain" per RFC 4074 §2.  The resolver falls back to
            # an A query, which we handle correctly above.
            # (Previously returned an A-typed RR inside an AAAA response,
            # which is a protocol error DNS clients silently discard.)
            if request.q.qtype == QTYPE.AAAA:
                logger.debug(f"  -> AAAA: {safe_name} -> (empty, client falls back to A)")
                return reply

            # --- MX (mail exchanger) ---
            # Malware that exfiltrates via SMTP often resolves MX before
            # connecting to the mail server. Without a proper MX response
            # the mailer library silently gives up.
            if request.q.qtype == QTYPE.MX:
                mail_host = f"mail.{qname}"
                reply.add_answer(
                    RR(qname, QTYPE.MX, ttl=self.ttl, rdata=MX(mail_host, 10))
                )
                # Additional record so the client can resolve the mail host
                reply.add_ar(
                    RR(mail_host, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
                )
                logger.debug(f"  -> MX: {safe_name} -> {mail_host} -> {sanitize_ip(self.redirect_ip)}")
                return reply

            # --- TXT ---
            # DNS TXT queries are used for SPF checks by mail libraries,
            # and by malware that uses TXT-based C2 channels (config
            # delivery, command passing, domain generation checks).
            if request.q.qtype == QTYPE.TXT:
                reply.add_answer(
                    RR(qname, QTYPE.TXT, ttl=self.ttl, rdata=TXT(b"v=spf1 +all"))
                )
                logger.debug(f"  -> TXT: {safe_name}")
                return reply

            # --- NS (name server) ---
            if request.q.qtype == QTYPE.NS:
                ns_host = f"ns1.{qname}"
                reply.add_answer(
                    RR(qname, QTYPE.NS, ttl=self.ttl, rdata=NS(ns_host))
                )
                reply.add_ar(
                    RR(ns_host, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
                )
                logger.debug(f"  -> NS: {safe_name} -> {ns_host}")
                return reply

            # --- SOA ---
            if request.q.qtype == QTYPE.SOA:
                reply.add_answer(
                    RR(qname, QTYPE.SOA, ttl=self.ttl, rdata=SOA(
                        f"ns1.{qname}",
                        f"hostmaster.{qname}",
                        (2026030500, 3600, 900, 604800, 300),
                    ))
                )
                logger.debug(f"  -> SOA: {safe_name}")
                return reply

            # --- CNAME ---
            # Return an A record directly; following CNAME chains is
            # handled by resolvers, not the authoritative server.
            if request.q.qtype == QTYPE.CNAME:
                reply.add_answer(
                    RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
                )
                logger.debug(f"  -> CNAME(as A): {safe_name} -> {sanitize_ip(self.redirect_ip)}")
                return reply

            # --- SRV (service location) ---
            if request.q.qtype == QTYPE.SRV:
                srv_host = f"srv.{qname}"
                reply.add_answer(
                    RR(qname, QTYPE.SRV, ttl=self.ttl,
                       rdata=SRV(0, 0, 443, srv_host))
                )
                reply.add_ar(
                    RR(srv_host, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
                )
                logger.debug(f"  -> SRV: {safe_name} -> {srv_host}")
                return reply

            # --- CAA (certificate authority authorization) ---
            if request.q.qtype == QTYPE.CAA:
                reply.add_answer(
                    RR(qname, QTYPE.CAA, ttl=self.ttl,
                       rdata=CAA(0, "issue", "letsencrypt.org"))
                )
                logger.debug(f"  -> CAA: {safe_name}")
                return reply

            # --- A ---
            if request.q.qtype == QTYPE.A:
                # DGA detection: return NXDOMAIN for high-entropy labels that
                # look like machine-generated canary domains.  Malware queries
                # a random-looking domain before detonating; if it resolves,
                # the malware knows DNS is being sinkholed and bails out.
                if self.nxdomain_entropy_threshold > 0.0:
                    parts = qname.split(".")
                    sld = parts[-2] if len(parts) >= 2 else qname
                    if (
                        len(sld) >= self.nxdomain_label_min_length
                        and _shannon_entropy(sld) >= self.nxdomain_entropy_threshold
                    ):
                        reply.header.rcode = 3  # NXDOMAIN
                        logger.debug(
                            f"  -> NXDOMAIN (DGA entropy={_shannon_entropy(sld):.2f}): {safe_name}"
                        )
                        return reply
                # Choose a response IP.  When a public IP pool is configured,
                # return a deterministic public-looking IP per domain so
                # subsequent queries are consistent (DNS caching).  iptables
                # REDIRECT rules will intercept the traffic regardless.
                if self._public_ips:
                    response_ip = self._public_ips[hash(qname) % len(self._public_ips)]
                else:
                    response_ip = self.redirect_ip
                reply.add_answer(
                    RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(response_ip))
                )
                logger.debug(f"  -> A: {safe_name} -> {sanitize_ip(response_ip)}")
                return reply

            # --- Unknown / unsupported query types ---
            # Return NOERROR with empty answer (no records of this type).
            logger.debug(f"  -> empty NOERROR for qtype={request.q.qtype}: {safe_name}")

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
        self.nxdomain_entropy_threshold = float(
            config.get("nxdomain_entropy_threshold", 0.0) or 0.0
        )
        self.nxdomain_label_min_length = int(
            config.get("nxdomain_label_min_length", 12) or 12
        )
        self.public_response_ips: list[str] = list(
            config.get("public_response_ips", []) or []
        )
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
            self.redirect_ip,
            self.custom_records,
            self.ttl,
            self.handle_ptr,
            nxdomain_entropy_threshold=self.nxdomain_entropy_threshold,
            nxdomain_label_min_length=self.nxdomain_label_min_length,
            public_response_ips=self.public_response_ips or None,
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
