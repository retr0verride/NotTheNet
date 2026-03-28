"""
NotTheNet - DNS over HTTPS (DoH) & WebSocket Sinkhole

Modern malware increasingly uses:
  1. DNS over HTTPS (DoH) — standard HTTPS traffic containing DNS binary
     data (RFC 8484), bypassing traditional port-53 monitoring.
  2. WebSockets — persistent bidirectional connections for C2 communication.

This module:
  - Detects incoming DoH queries (Content-Type: application/dns-message)
    and answers them with the configured redirect_ip, just like the UDP
    DNS server does.
  - Detects WebSocket upgrade requests (Connection: Upgrade, Upgrade: websocket)
    and completes the handshake, then sends a close frame after a short
    sink period so the malware believes the connection was established.

Security notes (OpenSSF):
- DoH responses are built via dnslib (same as the UDP DNS server)
- WebSocket frame parsing is minimal — only enough to complete the
  handshake and send a clean close; no eval/exec of payload data
- All received data is logged (sanitized) but never executed
"""

from __future__ import annotations

import base64
import hashlib
import logging
import struct

from utils.logging_utils import sanitize_log_string

logger = logging.getLogger(__name__)

# ─── DNS over HTTPS (DoH) ────────────────────────────────────────────────────

# RFC 8484 wire format content type
DOH_CONTENT_TYPE = "application/dns-message"


def is_doh_request(content_type: str | None, path: str | None) -> bool:
    """Check whether an HTTP request looks like a DoH query."""
    if content_type and DOH_CONTENT_TYPE in content_type.lower():
        return True
    # GET-based DoH: /dns-query?dns=<base64url>
    if path and "/dns-query" in path.lower():
        return True
    return False


def handle_doh_get(path: str, redirect_ip: str) -> bytes | None:
    """
    Handle a DoH GET request (RFC 8484 §4.1).

    The query is base64url-encoded in the ?dns= parameter.
    Returns the wire-format DNS response bytes, or None on failure.
    """
    try:
        import dnslib  # noqa: F401 — availability check
    except ImportError:
        logger.warning("dnslib not available; cannot handle DoH GET")
        return None

    # Extract the dns= parameter
    import urllib.parse
    parsed = urllib.parse.urlparse(path)
    params = urllib.parse.parse_qs(parsed.query)
    dns_b64 = params.get("dns", [None])[0]
    if not dns_b64:
        return None

    try:
        # base64url decode (may or may not have padding)
        padding = 4 - (len(dns_b64) % 4)
        if padding != 4:
            dns_b64 += "=" * padding
        raw_query = base64.urlsafe_b64decode(dns_b64)
        return _build_doh_response(raw_query, redirect_ip)
    except Exception as e:
        logger.debug("DoH GET decode error: %s", e)
        return None


def handle_doh_post(body: bytes, redirect_ip: str) -> bytes | None:
    """
    Handle a DoH POST request (RFC 8484 §4.1).

    The body is the raw DNS wire-format query.
    Returns the wire-format DNS response bytes, or None on failure.
    """
    if not body:
        return None
    return _build_doh_response(body, redirect_ip)


def _build_doh_response(raw_query: bytes, redirect_ip: str) -> bytes | None:
    """Parse a DNS wire-format query and build a response pointing to redirect_ip."""
    try:
        from dnslib import QTYPE, RR, A, DNSRecord
    except ImportError:
        return None

    try:
        request = DNSRecord.parse(raw_query)
        reply = request.reply()
        qname = str(request.q.qname).lower().rstrip(".")
        qtype = QTYPE[request.q.qtype]

        logger.info("DoH   query type=%s name=%s", qtype, sanitize_log_string(qname, 253))

        # Always answer with redirect_ip for A/AAAA
        reply.add_answer(
            RR(request.q.qname, QTYPE.A, ttl=300, rdata=A(redirect_ip))
        )
        logger.debug("  -> DoH A: %s -> %s", sanitize_log_string(qname, 253), redirect_ip)

        return reply.pack()
    except Exception as e:
        logger.debug("DoH response build error: %s", e)
        return None


# ─── WebSocket Sinkhole ──────────────────────────────────────────────────────

_WS_MAGIC = "258EAFA5-E914-47DA-95CA-5AB5CD11AD85"


def is_websocket_upgrade(headers: dict) -> bool:
    """Check if the HTTP request headers indicate a WebSocket upgrade."""
    connection = (headers.get("Connection") or "").lower()
    upgrade = (headers.get("Upgrade") or "").lower()
    return "upgrade" in connection and upgrade == "websocket"


def build_websocket_accept(ws_key: str) -> str:
    """
    Compute the Sec-WebSocket-Accept header value per RFC 6455 §4.2.2.

    Sec-WebSocket-Accept = base64(SHA1(Sec-WebSocket-Key + MAGIC))
    """
    combined = ws_key.strip() + _WS_MAGIC
    sha1 = hashlib.sha1(combined.encode("ascii")).digest()  # noqa: S324 — required by RFC 6455
    return base64.b64encode(sha1).decode("ascii")


def build_websocket_handshake_response(ws_key: str) -> bytes:
    """Build the HTTP 101 Switching Protocols response for a WebSocket upgrade."""
    accept = build_websocket_accept(ws_key)
    return (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n"
        "\r\n"
    ).encode("ascii")


def build_websocket_close_frame(code: int = 1000, reason: str = "") -> bytes:
    """Build a WebSocket close frame (opcode 0x8)."""
    payload = struct.pack("!H", code)
    if reason:
        payload += reason.encode("utf-8")[:123]  # max 125 bytes total

    frame = bytearray()
    frame.append(0x88)  # FIN + opcode 0x8 (close)
    length = len(payload)
    if length <= 125:
        frame.append(length)
    frame.extend(payload)
    return bytes(frame)


def build_websocket_text_frame(text: str) -> bytes:
    """Build a WebSocket text frame (opcode 0x1)."""
    payload = text.encode("utf-8")
    frame = bytearray()
    frame.append(0x81)  # FIN + opcode 0x1 (text)
    length = len(payload)
    if length <= 125:
        frame.append(length)
    elif length <= 65535:
        frame.append(126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(payload)
    return bytes(frame)
