"""
NotTheNet - DNS Server
Resolves every hostname to redirect_ip, fooling malware DNS lookups.

Key differences from INetSim / FakeNet-NG:
- Single threaded async UDP server â€” no socket leak on restart
- Handles PTR (reverse DNS) cleanly â€” returns a synthetic hostname
- Custom record overrides supported via config
- All query names sanitized before logging (log injection prevention)
- dnslib used for packet building (no manual DNS byte-packing bugs)

Security notes (OpenSSF):
- Max UDP packet size accepted: 512 bytes (RFC 1035), extended to 4096 with EDNS
- Truncated / malformed packets are silently dropped, never crash the server
- Query name length validated (â‰¤ 253 chars per RFC 1035)
"""

from __future__ import annotations

import logging
import math
import re
import threading
from collections import Counter

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


def _log_dns_query(request, handler, reply) -> None:
    """Emit a structured dns_query event reflecting the *actual* response sent.

    Must be called after resolution so that NXDOMAIN (kill-switch, DGA),
    custom record overrides, and public-IP-pool responses are all captured
    correctly rather than always showing the configured redirect_ip.
    """
    jl = get_json_logger()
    if not jl:
        return
    try:
        qname = str(request.q.qname).lower().rstrip(".")
        try:
            qtype = str(QTYPE[request.q.qtype])
        except Exception:
            qtype = str(request.q.qtype)
        src = handler.client_address[0] if hasattr(handler, "client_address") else ""
        rcode = reply.header.rcode
        if rcode == 3:
            resolve_to = "NXDOMAIN"
        elif rcode != 0:
            resolve_to = f"rcode={rcode}"
        elif reply.rr:
            resolve_to = str(reply.rr[0].rdata)
        else:
            resolve_to = "(empty)"
        jl.log("dns_query", qtype=qtype, qname=qname, src_ip=src, resolve_to=resolve_to)
    except Exception as exc:
        logger.debug("dns_query log error: %s", exc, exc_info=True)


try:
    from dnslib import A, CAA, DNSRecord, MX, NS, PTR, QTYPE, RR, SOA, SRV, TXT  # noqa: I001
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

    _QTYPE_HANDLERS: dict = {}  # populated after class body when dnslib is available

    def __init__(
        self,
        redirect_ip: str,
        custom_records: dict,
        ttl: int,
        handle_ptr: bool,
        nxdomain_entropy_threshold: float = 0.0,
        nxdomain_label_min_length: int = 12,
        public_response_ips: list | None = None,
        kill_switch_domains: list | None = None,
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
        # malware from flagging the "all domains â†' 10.x.x.x" pattern.
        self._public_ips: list[str] = list(public_response_ips or [])
        # Kill-switch domains: return NXDOMAIN so malware that checks for
        # an "intercepted" domain (expecting resolution) sees the domain as
        # dead and continues executing.  Matches exact names and any
        # subdomain (e.g. "example.com" also matches "www.example.com").
        self._kill_switch_domains: frozenset[str] = frozenset(
            d.lower().rstrip(".") for d in (kill_switch_domains or [])
        )

    def resolve(self, request: DNSRecord, handler) -> DNSRecord:
        """Resolve a DNS request and emit a structured log event reflecting the
        actual response sent (NXDOMAIN, resolved IP, etc.) rather than the
        configured redirect_ip."""
        reply = self._do_resolve(request, handler)
        _log_dns_query(request, handler, reply)
        return reply

    def _do_resolve(self, request: DNSRecord, handler) -> DNSRecord:
        reply = request.reply()
        try:
            qname = str(request.q.qname).lower().rstrip(".")
            qtype = QTYPE[request.q.qtype]

            # RFC 1035 §2.3.4: max 253 characters for a full domain name
            if len(qname) > 253:
                reply.header.rcode = 1  # FORMERR
                return reply

            safe_name = sanitize_hostname(qname)
            logger.info("DNS query  type=%s name=%s", qtype, safe_name)

            # --- Custom record override ---
            if qname in self.custom_records:
                override_ip = self.custom_records[qname]
                reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(override_ip)))
                logger.debug("  -> custom override: %s -> %s", safe_name, sanitize_ip(override_ip))
                return reply

            # --- Windows NCSI DNS probe ---
            # Windows resolves dns.msftncsi.com and expects 131.107.255.255.
            # Returning redirect_ip here would fail the probe and prevent the
            # "Internet access" indicator from showing.
            if qname in ("dns.msftncsi.com.", "dns.msftncsi.com") and request.q.qtype == QTYPE.A:
                reply.add_answer(RR(qname, QTYPE.A, ttl=self.ttl, rdata=A("131.107.255.255")))
                logger.debug("  -> NCSI DNS probe: %s -> 131.107.255.255", safe_name)
                return reply

            # Dispatch to per-qtype handler.
            handler = self._QTYPE_HANDLERS.get(request.q.qtype)
            if handler:
                return handler(self, reply, qname, safe_name, request)

            # Unknown / unsupported query types â€” NOERROR with empty answer.
            logger.debug("  -> empty NOERROR for qtype=%s: %s", request.q.qtype, safe_name)


        except Exception as e:
            logger.warning("DNS resolve error: %s", e)
            reply.header.rcode = 2  # SERVFAIL â€” never crash the server
        return reply


    # -- Per-qtype resolver handlers -------------------------------------------

    def _resolve_ptr(self, reply, qname: str, safe_name: str, request):
        if self.handle_ptr:
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
                RR(qname, QTYPE.PTR, ttl=self.ttl, rdata=PTR(ptr_host))
            )
            logger.debug("  -> PTR: %s -> %s", safe_name, ptr_host)
        return reply

    def _resolve_aaaa(self, reply, qname: str, safe_name: str, _request):
        logger.debug("  -> AAAA: %s -> (empty, client falls back to A)", safe_name)
        return reply

    def _resolve_mx(self, reply, qname: str, safe_name: str, _request):
        mail_host = f"mail.{qname}"
        reply.add_answer(
            RR(qname, QTYPE.MX, ttl=self.ttl, rdata=MX(mail_host, 10))
        )
        reply.add_ar(
            RR(mail_host, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
        )
        logger.debug("  -> MX: %s -> %s -> %s", safe_name, mail_host, sanitize_ip(self.redirect_ip))
        return reply

    def _resolve_txt(self, reply, qname: str, safe_name: str, _request):
        reply.add_answer(
            RR(qname, QTYPE.TXT, ttl=self.ttl, rdata=TXT(b"v=spf1 +all"))
        )
        logger.debug("  -> TXT: %s", safe_name)
        return reply

    def _resolve_ns(self, reply, qname: str, safe_name: str, _request):
        ns_host = f"ns1.{qname}"
        reply.add_answer(
            RR(qname, QTYPE.NS, ttl=self.ttl, rdata=NS(ns_host))
        )
        reply.add_ar(
            RR(ns_host, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
        )
        logger.debug("  -> NS: %s -> %s", safe_name, ns_host)
        return reply

    def _resolve_soa(self, reply, qname: str, safe_name: str, _request):
        reply.add_answer(
            RR(qname, QTYPE.SOA, ttl=self.ttl, rdata=SOA(
                f"ns1.{qname}",
                f"hostmaster.{qname}",
                (2026030500, 3600, 900, 604800, 300),
            ))
        )
        logger.debug("  -> SOA: %s", safe_name)
        return reply

    def _resolve_cname(self, reply, qname: str, safe_name: str, _request):
        reply.add_answer(
            RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
        )
        logger.debug("  -> CNAME(as A): %s -> %s", safe_name, sanitize_ip(self.redirect_ip))
        return reply

    def _resolve_srv(self, reply, qname: str, safe_name: str, _request):
        srv_host = f"srv.{qname}"
        reply.add_answer(
            RR(qname, QTYPE.SRV, ttl=self.ttl,
               rdata=SRV(0, 0, 443, srv_host))
        )
        reply.add_ar(
            RR(srv_host, QTYPE.A, ttl=self.ttl, rdata=A(self.redirect_ip))
        )
        logger.debug("  -> SRV: %s -> %s", safe_name, srv_host)
        return reply

    def _resolve_caa(self, reply, qname: str, safe_name: str, _request):
        reply.add_answer(
            RR(qname, QTYPE.CAA, ttl=self.ttl,
               rdata=CAA(0, "issue", "letsencrypt.org"))
        )
        logger.debug("  -> CAA: %s", safe_name)
        return reply

    def _resolve_a(self, reply, qname: str, safe_name: str, _request):
        # FCrDNS: if the query is for a synthesized PTR hostname
        # (static-A-B-C-D.res.example.net), return the embedded IP.
        _fcrdns_m = re.match(
            r'^static-(\d+)-(\d+)-(\d+)-(\d+)\.res\.example\.net$',
            qname,
        )
        if _fcrdns_m:
            response_ip = ".".join(_fcrdns_m.groups())
            reply.add_answer(
                RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(response_ip))
            )
            logger.debug("  -> FCrDNS A: %s -> %s", safe_name, sanitize_ip(response_ip))
            return reply

        # Kill-switch domains: always NXDOMAIN.
        if self._kill_switch_domains and (
            qname in self._kill_switch_domains or any(
                qname.endswith("." + d) for d in self._kill_switch_domains
            )
        ):
            reply.header.rcode = 3  # NXDOMAIN
            logger.info(
                "  -> NXDOMAIN (kill-switch): %s", safe_name,
            )
            return reply

        # DGA detection: NXDOMAIN for high-entropy labels.
        if self.nxdomain_entropy_threshold > 0.0:
            parts = qname.split(".")
            sld = parts[-2] if len(parts) >= 2 else qname
            entropy = _shannon_entropy(sld)
            if (
                len(sld) >= self.nxdomain_label_min_length
                and entropy >= self.nxdomain_entropy_threshold
            ):
                reply.header.rcode = 3  # NXDOMAIN
                logger.debug(
                    "  -> NXDOMAIN (DGA entropy=%.2f): %s",
                    entropy, safe_name,
                )
                return reply

        # Choose a response IP from the public pool or redirect_ip.
        if self._public_ips:
            response_ip = self._public_ips[hash(qname) % len(self._public_ips)]
        else:
            response_ip = self.redirect_ip
        reply.add_answer(
            RR(qname, QTYPE.A, ttl=self.ttl, rdata=A(response_ip))
        )
        logger.debug("  -> A: %s -> %s", safe_name, sanitize_ip(response_ip))
        return reply


if _DNSLIB_AVAILABLE:
    _FakeResolver._QTYPE_HANDLERS = {
        QTYPE.PTR: _FakeResolver._resolve_ptr,
        QTYPE.AAAA: _FakeResolver._resolve_aaaa,
        QTYPE.MX: _FakeResolver._resolve_mx,
        QTYPE.TXT: _FakeResolver._resolve_txt,
        QTYPE.NS: _FakeResolver._resolve_ns,
        QTYPE.SOA: _FakeResolver._resolve_soa,
        QTYPE.CNAME: _FakeResolver._resolve_cname,
        QTYPE.SRV: _FakeResolver._resolve_srv,
        QTYPE.CAA: _FakeResolver._resolve_caa,
        QTYPE.A: _FakeResolver._resolve_a,
    }

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
        self.kill_switch_domains: list[str] = list(
            config.get("kill_switch_domains", []) or []
        )
        self._server_udp: DNSServer | None = None
        self._server_tcp: DNSServer | None = None

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
            kill_switch_domains=self.kill_switch_domains or None,
        )
        try:
            self._server_udp = DNSServer(
                resolver, port=self.port, address=self.bind_ip, tcp=False
            )
            self._server_tcp = DNSServer(
                resolver, port=self.port, address=self.bind_ip, tcp=True
            )
            # Launch threads manually instead of start_thread() so we can
            # pass poll_interval=2.0 to serve_forever(), reducing idle
            # wakeups from 4/sec to 1/sec (2 servers Ã— 0.5/sec each).
            for srv in (self._server_udp, self._server_tcp):
                def _run(s=srv):
                    s.isRunning = True
                    s.server.serve_forever(poll_interval=2.0)
                    s.isRunning = False
                srv.thread = threading.Thread(target=_run, daemon=True)
                srv.thread.start()
            logger.info(
                f"DNS service started on {self.bind_ip}:{self.port} "
                f"(UDP+TCP) -> all queries resolve to {sanitize_ip(self.redirect_ip)}"
            )
            return True
        except OSError as e:
            logger.error("DNS service failed to bind port %s: %s", self.port, e)
            return False

    def stop(self) -> None:
        for srv in (self._server_udp, self._server_tcp):
            if srv:
                try:
                    srv.stop()
                except Exception:
                    logger.debug("DNS server stop failed", exc_info=True)
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
