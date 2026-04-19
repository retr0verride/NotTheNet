"""
NotTheNet - HTTP / HTTPS Fake Server
Returns configurable responses to all HTTP(S) requests.

Security notes (OpenSSF):
- TLS: minimum TLSv1.2, OP_NO_SSLv2/SSLv3/TLSv1/TLSv1_1 set explicitly
- Only safe cipher suites (ECDHE + AES-GCM / CHACHA20)
- Request path sanitized before logging (path traversal / log-injection)
- Request body never written to disk unless explicitly configured
- No eval/exec of any request data
- Thread-per-connection model with a bounded ThreadPoolExecutor
"""

from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import logging
import os
import random
import re
import select
import socket
import socketserver
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from services.doh_websocket import (
    DOH_CONTENT_TYPE,
    build_websocket_close_frame,
    build_websocket_handshake_response,
    handle_doh_get,
    handle_doh_post,
    is_doh_request,
    is_websocket_upgrade,
)
from services.dynamic_response import compile_custom_rules, resolve_dynamic_response
from utils.cert_utils import ensure_certs
from utils.json_logger import get_json_logger
from utils.logging_utils import sanitize_ip, sanitize_log_string
from utils.validators import sanitize_path

logger = logging.getLogger(__name__)

# Thread pool sized to match the connection cap of other services.
# HTTP/1.1 keep-alive means threads can be held by idle connections;
# 50 workers ensures new connections aren't starved even under concurrent load.
_MAX_WORKER_THREADS = 50

_DEFAULT_SERVER_HEADER = "Apache/2.4.51"

# Cipher suites: ECDHE forward secrecy + AEAD â€” no RC4, 3DES, CBC
_SECURE_CIPHERS = (
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!3DES"
)

_DEFAULT_BODY = "<html><body><h1>200 OK</h1></body></html>"

_CT_JSON = "application/json"

# Well-known public-IP-check services. When spoof_public_ip is set and a
# request Host header matches one of these, the handler returns the spoofed
# IP instead of the normal response body. This defeats the most common
# sandbox-evasion technique of checking "am I on the real internet?".
_IP_CHECK_HOSTS = frozenset({
    "api.ipify.org", "api4.ipify.org", "api6.ipify.org",
    "icanhazip.com", "ipv4.icanhazip.com",
    "checkip.amazonaws.com",
    "ifconfig.me", "ifconfig.io",
    "ip.me",
    "wtfismyip.com",
    "ipecho.net",
    "ident.me", "v4.ident.me",
    "ipinfo.io",
    "api.my-ip.io",
    "checkip.dyndns.org", "checkip.dyndns.com",
    "eth0.me",
    "ip4.seeip.org",
    "myexternalip.com",
    "httpbin.org",
    "ip-api.com",
})

# Windows Network Connectivity Status Indicator (NCSI) endpoints.
# Windows queries these to determine whether the "Internet access" indicator
# is shown in the system tray.  Some malware waits for NCSI to report
# connectivity before detonating.  The responses MUST be exact byte-for-byte
# matches of what a real Microsoft server returns.
_NCSI_HOSTS = frozenset({
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "ipv6.msftconnecttest.com",
    "www.msftncsi.com",
})
_NCSI_BODY = b"Microsoft Connect Test"
_NCSI_RESPONSES: dict[str, bytes] = {
    "www.msftconnecttest.com":  _NCSI_BODY,
    "msftconnecttest.com":      _NCSI_BODY,
    "ipv6.msftconnecttest.com": _NCSI_BODY,
    "www.msftncsi.com":         b"Microsoft NCSI",
}

# Google / Android / ChromeOS connectivity checks and Apple captive portal
# detection hosts.  These are queried by the OS (not just the browser) and
# must return EXACT expected responses â€” wrong body or status code causes the
# OS to show "No internet" and some malware will stall waiting for connectivity.
_CAPTIVE_PORTAL_HOSTS = frozenset({
    # Google generate_204: Chrome OS, Android, Windows/macOS Chrome
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients1.google.com",
    "clients3.google.com",
    "ipv4.google.com",
    # Apple captive portal / hotspot detection: macOS + iOS
    "captive.apple.com",
    "www.apple.com",
})

# Telegram Bot API host.  Agent Tesla (and other stealers) use the Bot API
# to exfiltrate credentials/keylog data.  Returning a valid {"ok": true, ...}
# response prevents the malware from entering an error/retry path.
_TELEGRAM_HOST = "api.telegram.org"
_TELEGRAM_PATH_RE = re.compile(r"^/bot[^/]+/([A-Za-z]+)")

# Discord webhook hosts.  20+ stealer families (Raccoon, RedLine, Vidar,
# Agent Tesla, Lumma, Stealc, etc.) exfiltrate via Discord webhooks.
_DISCORD_HOSTS = frozenset({
    "discord.com", "discordapp.com",
    "canary.discord.com", "ptb.discord.com",
})
_DISCORD_WEBHOOK_RE = re.compile(r"^/api(?:/v\d+)?/webhooks/(\d+)/([A-Za-z0-9_-]+)")

# Pastebin and paste-site hosts used as dead-drop resolvers by 15+ RAT/stealer
# families (AsyncRAT, Remcos, njRAT, Quasar, XWorm, etc.).
_PASTE_HOSTS = frozenset({
    "pastebin.com", "paste.ee", "rentry.co", "rentry.org",
    "hastebin.com", "pastebin.pl", "dpaste.org",
    "paste.nrecom.net",
})

# Slack webhook host.  DCRat, Orcus, Sliver, and custom stealers.
_SLACK_HOST = "hooks.slack.com"

# Microsoft Teams webhook hosts.
_TEAMS_HOSTS = frozenset({
    "outlook.office.com", "outlook.office365.com",
})
_TEAMS_WEBHOOK_RE = re.compile(r"\.webhook\.office\.com$")

# GitHub raw content hosts used by 10+ RATs as dead-drop for configs/payloads.
_GITHUB_RAW_HOSTS = frozenset({
    "raw.githubusercontent.com", "gist.githubusercontent.com",
    "objects.githubusercontent.com",
})

# File-hosting sites used by Agent Tesla and similar stealers to stage
# second-stage payloads before activating C2.  Returning HTTP 200 prevents
# the "no connectivity" pre-check from aborting detonation.
_FILE_HOSTING_HOSTS = frozenset({
    "catbox.moe", "files.catbox.moe",
    "litterbox.catbox.moe",
    "anonfiles.com",          # legacy, still seen in older samples
    "gofile.io",
    "transfer.sh",
    "file.io",
    "tmpfiles.org",
})

# Google Docs/Drive hosts used by Emotet, Qakbot, IcedID, etc. for
# payload staging and config dead-drops.
_GOOGLE_CONTENT_HOSTS = frozenset({
    "docs.google.com", "sheets.google.com", "drive.google.com",
    "drive.usercontent.google.com", "www.googleapis.com",
})

# Windows PKI infrastructure hosts -- CRL, OCSP, and Certificate Trust List
# (CTL) download endpoints.  Windows CryptoAPI hits these during every HTTPS
# connection to validate the server cert chain.  If the response is HTML (our
# default page) instead of binary, cert validation fails -- a giveaway.
_PKI_HOSTS = frozenset({
    "crl.microsoft.com",
    "crl3.digicert.com", "crl4.digicert.com",
    "ocsp.digicert.com", "ocsp.msocsp.com", "oneocsp.microsoft.com",
    "ocsp.verisign.com", "ocsp.thawte.com", "ocsp.sectigo.com",
    "ocsp.comodoca.com", "ocsp.usertrust.com",
    "ctldl.windowsupdate.com",
    "cacerts.digicert.com",
    "www.download.windowsupdate.com",
    "download.windowsupdate.com",
    # Let's Encrypt OCSP
    "ocsp.int-x3.letsencrypt.org",
    "r3.o.lencr.org", "e1.o.lencr.org", "r4.o.lencr.org",
    "r10.o.lencr.org", "r11.o.lencr.org",
})

# Minimal CRL stub â€” an empty DER-encoded X.509 Certificate Revocation List.
# We generate it lazily on first use.
_STUB_CRL_CACHE: bytes | None = None
_STUB_CRL_LOCK = threading.Lock()


def _get_stub_crl() -> bytes:
    """Return a minimal valid DER-encoded CRL (empty revocation list)."""
    global _STUB_CRL_CACHE  # noqa: PLW0603
    if _STUB_CRL_CACHE is not None:
        return _STUB_CRL_CACHE
    with _STUB_CRL_LOCK:
        if _STUB_CRL_CACHE is not None:  # re-check after acquiring the lock
            return _STUB_CRL_CACHE
        try:
            from cryptography import x509 as cx509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            issuer = cx509.Name([
                cx509.NameAttribute(NameOID.COMMON_NAME, "DigiCert Global Root CA"),
            ])
            now = datetime.now(timezone.utc)
            crl = (
                cx509.CertificateRevocationListBuilder()
                .issuer_name(issuer)
                .last_update(now)
                .next_update(now + timedelta(days=30))
                .sign(key, hashes.SHA256())
            )
            _STUB_CRL_CACHE = crl.public_bytes(serialization.Encoding.DER)
        except Exception:
            # Fallback: return a minimal plausible binary blob
            _STUB_CRL_CACHE = b"\x30\x00"
    return _STUB_CRL_CACHE


# Minimal OCSP "good" response stub (DER).  Real OCSP responses are complex;
# we return a small valid-looking binary payload with the correct content-type.
# Most CryptoAPI implementations accept a timeout/error gracefully and don't
# hard-fail on soft-fail OCSP â€” but returning HTML would be worse.
_STUB_OCSP_RESPONSE = (
    b"\x30\x03"    # SEQUENCE { OCSPResponse
    b"\x0a\x01"    # ENUMERATED (1 byte)
    b"\x00"        # successful (0)
    # responseBytes omitted â€” this is a "successful but no details" stub.
    # CryptoAPI treats this as soft-pass (same as timeout).
)


def _resolve_pki_response(host: str, path: str) -> tuple[int, bytes, str]:
    """Determine the appropriate PKI stub response from host and path.

    Returns (status_code, body_bytes, content_type).
    """
    low = path.lower()
    if "ocsp" in host or "/ocsp" in low:
        return 200, _STUB_OCSP_RESPONSE, "application/ocsp-response"
    if low.endswith(".crl") or "crl" in host:
        return 200, _get_stub_crl(), "application/pkix-crl"
    if low.endswith((".crt", ".cer")) or "cacerts" in host:
        return 404, b"", ""
    if "ctldl" in host or low.endswith((".stl", ".cab")):
        return 200, b"", "application/octet-stream"
    return 200, b"", "application/octet-stream"


_MAX_BODY_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Stable "last content modification" timestamp for Last-Modified response headers.
# Computed once at module load to approximate a deployed server whose content was
# last updated ~60 days before startup â€” prevents absence-of-header fingerprinting.
_SERVER_LAST_MODIFIED = (
    datetime.now(timezone.utc) - timedelta(days=60)
).strftime("%a, %d %b %Y 12:00:00 GMT")

# RFC 1918 private address ranges â€” returning one of these as a "public" IP
# would let sandbox-aware malware detect the private network.
_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
)


def _validate_spoof_ip(raw: str, context: str = "") -> str:
    """Validate spoof_public_ip from config.

    Returns the IP string if valid and globally routable.
    Logs a warning on RFC1918 addresses (still allowed but suspicious).
    Returns '' and logs an error on parse failures.
    """
    if not raw:
        return ""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        logger.error(
            "Invalid spoof_public_ip '%s' in %s config â€” must be a valid IPv4/IPv6 address; "
            "IP spoofing disabled.", raw, context or "http"
        )
        return ""
    if any(addr in net for net in _RFC1918_NETWORKS):
        logger.warning(
            "spoof_public_ip '%s' (%s) is a private/loopback address â€” "
            "sandbox detection tools may still flag this as non-internet traffic.",
            raw, context or "http"
        )
    return raw


# â”€â”€ IP-check response formatters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Pure functions: (ip, path) â†’ (body, content_type, extra_headers | None).
# Used by FakeHTTPHandler._send_ip_check_response via _IP_CHECK_FORMATTERS.

_COMCAST_GEO = {
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "region": "OH",
    "regionName": "Ohio",
    "city": "Columbus",
    "zip": "43215",
    "lat": "39.9612",
    "lon": "-82.9988",
    "timezone": "America/New_York",
    "isp": "Comcast Cable Communications",
    "org": "Comcast Cable Communications",
    "as": "AS7922 Comcast Cable Communications, LLC",
    "hosting": "false",
    "proxy": "false",
    "mobile": "false",
}

_IpCheckResult = tuple[bytes, str, "dict[str, str] | None"]


def _fmt_ipinfo(ip: str, _path: str) -> _IpCheckResult:
    body = (
        f'{{"ip":"{ip}",'
        f'"city":"Columbus","region":"Ohio","country":"US",'
        f'"loc":"39.9612,-82.9988",'
        f'"org":"AS7922 Comcast Cable Communications, LLC",'
        f'"postal":"43215","timezone":"America/New_York"}}\n'
    ).encode()
    return body, _CT_JSON, None


def _fmt_ip_api(ip: str, path: str) -> _IpCheckResult:
    extra: dict[str, str] = {
        "Server": "nginx",
        "Access-Control-Allow-Origin": "*",
        "X-Ttl": "60",
        "X-Rl": "44",
    }
    _path_base = path.split("?")[0].rstrip("/")
    if _path_base == "/line" or _path_base.startswith("/line/"):
        _qs = parse_qs(urlparse(path).query)
        _fields = [f.strip() for f in _qs.get("fields", ["query"])[0].split(",")]
        _field_map = {**_COMCAST_GEO, "query": ip}
        body = "\n".join(_field_map.get(f, "") for f in _fields).encode() + b"\n"
        return body, "text/plain; charset=utf-8", extra
    if _path_base == "/csv" or _path_base.startswith("/csv/") or "fields=csv" in path:
        _csv = (
            f"success,United States,US,OH,Ohio,Columbus,43215,"
            f"39.9612,-82.9988,America/New_York,"
            f"Comcast Cable Communications,"
            f"Comcast Cable Communications,"
            f"AS7922 Comcast Cable Communications LLC,"
            f"false,false,false,{ip}\n"
        )
        return _csv.encode(), "text/csv", extra
    body = (
        f'{{"status":"success","country":"United States",'
        f'"countryCode":"US","region":"OH","regionName":"Ohio",'
        f'"city":"Columbus","zip":"43215",'
        f'"lat":39.9612,"lon":-82.9988,'
        f'"timezone":"America/New_York",'
        f'"isp":"Comcast Cable Communications",'
        f'"org":"Comcast Cable Communications",'
        f'"as":"AS7922 Comcast Cable Communications, LLC",'
        f'"hosting":false,"proxy":false,"mobile":false,'
        f'"query":"{ip}"}}\n'
    ).encode()
    return body, _CT_JSON, extra


def _fmt_httpbin(ip: str, _path: str) -> _IpCheckResult:
    return f'{{"origin":"{ip}"}}\n'.encode(), _CT_JSON, None


def _fmt_checkip_aws(ip: str, _path: str) -> _IpCheckResult:
    body = (
        f"<html><head><title>Current IP Check</title></head>"
        f"<body>Current IP Address: {ip}</body></html>\n"
    ).encode()
    return body, "text/html", None


_IP_CHECK_FORMATTERS: dict[str, object] = {
    "ipinfo.io": _fmt_ipinfo,
    "ip-api.com": _fmt_ip_api,
    "httpbin.org": _fmt_httpbin,
    "checkip.amazonaws.com": _fmt_checkip_aws,
}


def _load_response_body(config: dict) -> str:
    """
    Resolve the HTTP response body from config.
    If 'response_body_file' is set, load the file contents (relative to the
    project root).  Falls back to the 'response_body' string if the file is
    missing or unreadable.
    """
    file_path = config.get("response_body_file", "").strip()
    if file_path:
        # Resolve relative to project root (directory of this file's parent)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        abs_path = sanitize_path(project_root, file_path)
        if abs_path is None:
            logger.error(
                "response_body_file '%s' rejected (path traversal attempt); "
                "falling back to response_body string.",
                file_path,
            )
            return config.get("response_body", _DEFAULT_BODY)
        try:
            size = os.path.getsize(abs_path)
            if size > _MAX_BODY_FILE_SIZE:
                logger.error(
                    "response_body_file '%s' is %d bytes (max %d); "
                    "falling back to response_body string.",
                    abs_path, size, _MAX_BODY_FILE_SIZE,
                )
            else:
                with open(abs_path, encoding="utf-8") as fh:
                    return fh.read()
        except OSError as exc:
            logger.warning("response_body_file '%s' could not be read: %s; "
                           "falling back to response_body string.", abs_path, exc)
    return config.get("response_body", _DEFAULT_BODY)


@dataclass(frozen=True)
class _HandlerConfig:
    """Immutable configuration bundle for FakeHTTPHandler."""
    response_code: int = 200
    response_body: bytes = b""
    server_header: str = _DEFAULT_SERVER_HEADER
    log_requests: bool = True
    spoof_ip: str = ""
    delay_ms: int = 0
    delay_jitter_ms: int = 0
    dynamic_responses: bool = False
    custom_rules: list = field(default_factory=list)
    doh_enabled: bool = False
    doh_redirect_ip: str = "127.0.0.1"
    websocket_sinkhole: bool = False
    pool_ips: frozenset = field(default_factory=frozenset)


def _build_handler_config(
    response_code: int, response_body: str, server_header: str,
    log_requests: bool, spoof_ip: str = "", delay_ms: int = 0,
    delay_jitter_ms: int = 0,
    dynamic_responses: bool = False, custom_rules: list | None = None,
    doh_enabled: bool = False, doh_redirect_ip: str = "127.0.0.1",
    websocket_sinkhole: bool = False,
    pool_ips: frozenset[str] = frozenset(),
) -> _HandlerConfig:
    """Build an immutable handler configuration bundle."""
    return _HandlerConfig(
        response_code=response_code,
        response_body=response_body.encode("utf-8", errors="replace"),
        server_header=server_header,
        log_requests=log_requests,
        spoof_ip=spoof_ip,
        delay_ms=delay_ms,
        delay_jitter_ms=delay_jitter_ms,
        dynamic_responses=dynamic_responses,
        custom_rules=compile_custom_rules(custom_rules or []),
        doh_enabled=doh_enabled,
        doh_redirect_ip=doh_redirect_ip,
        websocket_sinkhole=websocket_sinkhole,
        pool_ips=pool_ips,
    )


class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler — reads config from the owning server instance."""

    @property
    def _cfg(self) -> _HandlerConfig:
        return getattr(self.server, '_handler_cfg', _HandlerConfig())

    protocol_version = "HTTP/1.1"
    server_version = ""

    def send_response(self, code, message=None):
        """Override to suppress Python's auto-injected Server header."""
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ""
        if self.request_version != "HTTP/0.9":
            if not hasattr(self, "_headers_buffer"):
                self._headers_buffer = []
            self._headers_buffer.append(
                f"{self.protocol_version} {code} {message}\r\n"
                .encode("latin-1", "strict")
            )
        self.log_request(code)
        self.send_header("Date", self.date_time_string())

    def log_message(self, fmt, *args):
        pass  # suppress default stderr logging

    def _send_ip_check_response(self, host: str):
        """Return the spoofed public IP for known IP-check services."""
        path = self.path or "/"
        ip = self._cfg.spoof_ip or "98.245.112.43"

        formatter = _IP_CHECK_FORMATTERS.get(host)
        if formatter:
            body, content_type, extra_headers = formatter(ip, path)
        elif "format=json" in path or path.rstrip("/").endswith("/json"):
            body = f'{{"ip":"{ip}"}}\n'.encode()
            content_type = _CT_JSON
            extra_headers = None
        else:
            body = f"{ip}\n".encode()
            content_type = "text/plain"
            extra_headers = None

        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                f"HTTP  IP-CHECK {sanitize_log_string(host)}"
                f"{sanitize_log_string(path, 128)} "
                f"from {safe_addr} \u2192 spoofed {ip}"
            )
        try:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            if not extra_headers or "Server" not in extra_headers:
                self.send_header("Server", self._cfg.server_header)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def _handle_generate_204(self) -> None:
        """Google / Android / ChromeOS connectivity probe: 204 No Content."""
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info("HTTP  CAPTIVE generate_204 from %s", safe_addr)
        try:
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.send_header("Server", "GFE/2.0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
        except OSError:
            pass

    def _handle_apple_captive(self, path: str) -> bool:
        """Apple captive portal / hotspot detection; returns True if handled."""
        if "/hotspot-detect.html" not in path and "/library/test/success.html" not in path:
            return False
        body = b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  CAPTIVE apple %s from %s",
                sanitize_log_string(path, 64), safe_addr,
            )
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "AkamaiGHost")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    def _send_captive_portal_response(self, host: str) -> bool:
        """Handle OS-level captive portal and connectivity checks.

        Returns True if the request was handled, False to fall through.
        """
        path = (self.path or "/").split("?")[0]

        if path == "/generate_204":
            self._handle_generate_204()
            return True

        if host in ("captive.apple.com", "www.apple.com"):
            return self._handle_apple_captive(path)

        return False
    def _send_ncsi_response(self, host: str):
        """Return the exact response Windows NCSI expects.

        Windows polls these hosts to determine whether to show the
        'Internet access' indicator. When the response body matches
        exactly, Windows reports full connectivity â€” which prevents
        certain malware from stalling in a 'no network' idle loop.
        """
        path = (self.path or "/").split("?")[0]
        # www.msftconnecttest.com/redirect should return HTTP 302 â†’ HTTPS.
        # Returning 200+body here triggers mismatches in NCSI validator
        # tools and is a detectable fingerprint for savvy malware.
        if path == "/redirect":
            if self._cfg.log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  NCSI {sanitize_log_string(host)}/redirect "
                    f"from {safe_addr} \u2192 302"
                )
            try:
                self.send_response(302)
                self.send_header("Location", f"https://{host}/redirect")
                self.send_header("Content-Length", "0")
                self.send_header("Server", self._cfg.server_header)
                self.send_header("Connection", "close")
                self.end_headers()
            except OSError:
                pass
            return
        body = _NCSI_RESPONSES.get(host, b"Microsoft Connect Test")
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                f"HTTP  NCSI {sanitize_log_string(host)} "
                f"from {safe_addr} \u2192 {body.decode()}"
            )
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self._cfg.server_header)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass

    def _send_pki_response(self, host: str):
        """Return stub CRL/OCSP/CTL binary responses for Windows PKI hosts."""
        path = self.path or "/"
        if self._cfg.log_requests:
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                f"HTTP  PKI {sanitize_log_string(host)}{sanitize_log_string(path, 128)} "
                f"from {safe_addr}"
            )
        status, body, content_type = _resolve_pki_response(host, path)
        try:
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self._cfg.server_header)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD" and body:
                self.wfile.write(body)
        except OSError:
            pass

    def _handle_doh_request(self):
        """Handle a DNS-over-HTTPS (DoH) request and return a DNS response."""
        safe_addr = sanitize_ip(self.client_address[0])
        path = self.path or "/"
        if self.command == "GET":
            response_data = handle_doh_get(path, self._cfg.doh_redirect_ip)
        else:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(min(content_length, _MAX_BODY_FILE_SIZE)) if content_length > 0 else b""
            response_data = handle_doh_post(body, self._cfg.doh_redirect_ip)

        if response_data:
            if self._cfg.log_requests:
                logger.info("DoH   request from %s -> sinkholed", safe_addr)
            jl = get_json_logger()
            if jl:
                jl.log("doh_request", src_ip=self.client_address[0],
                       method=self.command or "", path=self.path or "/")
            try:
                self.send_response(200)
                self.send_header("Content-Type", DOH_CONTENT_TYPE)
                self.send_header("Content-Length", str(len(response_data)))
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Server", self._cfg.server_header)
                self.end_headers()
                self.wfile.write(response_data)
            except OSError:
                pass
        else:
            # Couldn't parse DoH â€” fall through to normal response
            self._send_normal_response()

    def _handle_websocket_upgrade(self):
        """Complete a WebSocket handshake then send a close frame."""
        safe_addr = sanitize_ip(self.client_address[0])
        ws_key = self.headers.get("Sec-WebSocket-Key", "")
        if not ws_key:
            self._send_normal_response()
            return

        if self._cfg.log_requests:
            safe_path = sanitize_log_string(self.path or "/", 256)
            logger.info(
                f"WS    WebSocket upgrade from {safe_addr} "
                f"path={safe_path} -> sinkholed"
            )
        jl = get_json_logger()
        if jl:
            jl.log("websocket_upgrade", src_ip=self.client_address[0],
                   path=self.path or "/")

        try:
            # Send 101 Switching Protocols
            handshake = build_websocket_handshake_response(ws_key)
            self.wfile.write(handshake)
            self.wfile.flush()

            # Drain up to 4KB of incoming WebSocket frames (log preview)
            readable, _, _ = select.select([self.rfile], [], [], 2.0)
            if readable:
                try:
                    data = self.rfile.read1(4096) if hasattr(self.rfile, 'read1') else self.rfile.read(4096)
                    if data and self._cfg.log_requests:
                        preview = sanitize_log_string(
                            data[:64].hex(), 128
                        )
                        logger.debug("WS    received frame preview: %s", preview)
                except Exception:
                    logger.debug("WebSocket frame recv failed", exc_info=True)

            # Send close frame
            close_frame = build_websocket_close_frame(1000, "sinkholed")
            self.wfile.write(close_frame)
            self.wfile.flush()
        except OSError:
            pass

    # â”€â”€ Route registry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # Each entry: (predicate(self, host) -> bool, handler(self, host) -> bool|None).
    # Handler returns True (or None) if it consumed the request, False to
    # fall through. Evaluated in priority order; first match wins.
    _ROUTES: list[tuple] = []  # populated after class body

    def _route_doh(self, _host: str):
        ct = self.headers.get("Content-Type", "")
        if is_doh_request(ct, self.path):
            self._handle_doh_request()
            return True
        return False

    def _route_websocket(self, _host: str):
        hdrs = {k: self.headers.get(k, "") for k in ("Connection", "Upgrade", "Sec-WebSocket-Key")}
        if is_websocket_upgrade(hdrs):
            self._handle_websocket_upgrade()
            return True
        return False

    def _route_ncsi(self, host: str):
        self._send_ncsi_response(host)
        return True

    def _route_captive(self, host: str):
        return self._send_captive_portal_response(host)

    def _route_pki(self, host: str):
        self._send_pki_response(host)
        return True

    def _route_ip_check(self, host: str):
        self._send_ip_check_response(host)
        return True

    def _route_telegram(self, host: str):
        """Fake Telegram Bot API responses for stealer/RAT C2 over Telegram.

        Agent Tesla and similar stealers POST to
        api.telegram.org/bot<token>/sendMessage with chat_id + text in the
        body.  The .NET HttpClient checks that the response JSON has
        ``"ok": true``; anything else causes a retry loop or a hard exit that
        can be a sinkhole-detection signal.  We return a plausible response
        for every method the Bot API exposes, and log the full request body
        so the analyst gets the bot token, chat ID, and exfil payload.
        """
        path = self.path or "/"
        m = _TELEGRAM_PATH_RE.match(path)
        if not m:
            return False

        method = m.group(1).lower()
        src_ip = sanitize_ip(self.client_address[0])

        # Read and log the POST body — contains bot token + exfil payload.
        try:
            cl = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            cl = 0
        raw_body = b""
        if cl > 0:
            raw_body = self.rfile.read(min(cl, _MAX_BODY_FILE_SIZE))

        # Extract token from path for logging.
        token_match = re.match(r"^/bot([^/]+)/", path)
        bot_token = token_match.group(1) if token_match else ""

        # Attempt to decode body as JSON or form-urlencoded for structured log.
        chat_id = ""
        text_preview = ""
        try:
            ct = self.headers.get("Content-Type", "")
            if "application/json" in ct:
                parsed = json.loads(raw_body)
            else:
                parsed_qs = parse_qs(raw_body.decode(errors="replace"))
                parsed = {k: v[0] for k, v in parsed_qs.items() if v}
            chat_id = str(parsed.get("chat_id", ""))
            text_preview = sanitize_log_string(
                str(parsed.get("text", "")), max_length=512
            )
        except Exception:  # noqa: BLE001
            pass

        logger.warning(
            "Telegram  Bot API call %s from %s | token=%s chat_id=%s text=%s",
            method, src_ip,
            sanitize_log_string(bot_token, max_length=64),
            sanitize_log_string(chat_id, max_length=32),
            text_preview,
        )
        jl = get_json_logger()
        if jl:
            jl.log("telegram_c2",
                   src_ip=self.client_address[0],
                   method=method,
                   bot_token=bot_token,
                   chat_id=chat_id,
                   body=raw_body.decode(errors="replace")[:4096])

        # Build a plausible Telegram Bot API response for this method.
        now_ts = int(time.time())
        # getMe / getUpdates need slightly different shapes; everything else
        # gets a Message-shaped result which is what stealers expect from
        # sendMessage / sendDocument / sendPhoto.
        if method == "getme":
            result: object = {
                "id": 987654321,
                "is_bot": True,
                "first_name": "NotifyBot",
                "username": "notify_alertbot",
                "can_join_groups": False,
                "can_read_all_group_messages": False,
                "supports_inline_queries": False,
            }
        elif method == "getupdates":
            result = []  # empty update list — no commands pending
        else:
            # sendMessage / sendDocument / sendPhoto / sendAudio / etc.
            result = {
                "message_id": now_ts & 0xFFFF,
                "from": {
                    "id": 987654321,
                    "is_bot": True,
                    "first_name": "NotifyBot",
                    "username": "notify_alertbot",
                },
                "chat": {
                    "id": int(chat_id) if chat_id.lstrip("-").isdigit() else -1001234567890,
                    "type": "supergroup",
                    "title": "Logs",
                },
                "date": now_ts,
                "text": "OK",
            }

        response_body = json.dumps({"ok": True, "result": result}).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", _CT_JSON)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Server", "nginx")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response_body)
        except OSError:
            pass
        return True

    # ── Discord webhook route ─────────────────────────────────────────────
    def _route_discord(self, host: str):
        """Fake Discord webhook endpoint for stealer exfil.

        20+ stealer families POST to /api/webhooks/<id>/<token> or
        /api/v9/webhooks/<id>/<token>.  The .NET HttpClient / Python
        requests library checks for 200 + valid JSON.
        """
        path = self.path or "/"
        m = _DISCORD_WEBHOOK_RE.match(path)
        if not m:
            return False

        webhook_id = m.group(1)
        src_ip = sanitize_ip(self.client_address[0])

        try:
            cl = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            cl = 0
        raw_body = self.rfile.read(min(cl, _MAX_BODY_FILE_SIZE)) if cl > 0 else b""

        logger.warning(
            "Discord  Webhook POST from %s | webhook_id=%s body_len=%d",
            src_ip, webhook_id, len(raw_body),
        )
        jl = get_json_logger()
        if jl:
            jl.log("discord_c2",
                   src_ip=self.client_address[0],
                   webhook_id=webhook_id,
                   body=raw_body.decode(errors="replace")[:4096])

        # Discord message IDs are Twitter-style snowflakes (epoch 2015-01-01).
        # Using a plausible snowflake prevents anomaly detection by malware
        # that validates the response shape.
        _DISCORD_EPOCH_MS = 1420070400000
        now_ms = int(time.time() * 1000)
        snowflake = ((now_ms - _DISCORD_EPOCH_MS) << 22) | random.getrandbits(22)  # nosec B311

        resp = json.dumps({
            "id": str(snowflake),
            "type": 0,
            "content": "",
            "channel_id": "1100000000000000000",
            "webhook_id": webhook_id,
            "attachments": [],
            "embeds": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }).encode()
        try:
            self.send_response(200 if self.command == "POST" else 204)
            self.send_header("Content-Type", _CT_JSON)
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("Server", "cloudflare")
            self.send_header("CF-Ray", f"{os.urandom(8).hex()}-IAD")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp)
        except OSError:
            pass
        return True

    # ── Pastebin / paste dead-drop route ──────────────────────────────────
    def _route_paste(self, host: str):
        """Return a plausible paste response for dead-drop C2 config retrieval.

        15+ RAT/stealer families fetch C2 config from paste sites.  We return
        the sinkhole redirect_ip so stage-2 connections loop back here.
        """
        src_ip = sanitize_ip(self.client_address[0])
        path = sanitize_log_string(self.path or "/", max_length=256)

        logger.warning(
            "Paste  Dead-drop fetch from %s | host=%s path=%s",
            src_ip, host, path,
        )
        jl = get_json_logger()
        if jl:
            jl.log("paste_dead_drop",
                   src_ip=self.client_address[0],
                   host=host,
                   path=self.path or "/")

        # Return the sinkhole's redirect_ip as the "C2 config" — makes stage-2
        # connections loop back to the sinkhole for full capture.
        redirect_ip = self._cfg.spoof_ip or "10.10.10.10"
        body = redirect_ip.encode() + b"\n"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "nginx")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    # ── Slack webhook route ───────────────────────────────────────────────
    def _route_slack(self, _host: str):
        """Slack expects exactly 'ok' as the response body."""
        src_ip = sanitize_ip(self.client_address[0])

        try:
            cl = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            cl = 0
        raw_body = self.rfile.read(min(cl, _MAX_BODY_FILE_SIZE)) if cl > 0 else b""

        logger.warning("Slack  Webhook POST from %s | body_len=%d", src_ip, len(raw_body))
        jl = get_json_logger()
        if jl:
            jl.log("slack_c2",
                   src_ip=self.client_address[0],
                   body=raw_body.decode(errors="replace")[:4096])

        body = b"ok"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "Apache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    # ── Teams webhook route ───────────────────────────────────────────────
    def _route_teams(self, _host: str):
        """Teams webhooks expect '1' as the body with 200 or 202."""
        src_ip = sanitize_ip(self.client_address[0])

        try:
            cl = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            cl = 0
        raw_body = self.rfile.read(min(cl, _MAX_BODY_FILE_SIZE)) if cl > 0 else b""

        logger.warning("Teams  Webhook POST from %s | body_len=%d", src_ip, len(raw_body))
        jl = get_json_logger()
        if jl:
            jl.log("teams_c2",
                   src_ip=self.client_address[0],
                   body=raw_body.decode(errors="replace")[:4096])

        body = b"1"
        try:
            self.send_response(202)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "Microsoft-IIS/10.0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    # ── GitHub raw content route ──────────────────────────────────────────
    def _route_github_raw(self, host: str):
        """Return plausible raw file content for dead-drop config retrieval."""
        src_ip = sanitize_ip(self.client_address[0])
        path = sanitize_log_string(self.path or "/", max_length=256)

        logger.warning(
            "GitHub  Raw fetch from %s | host=%s path=%s",
            src_ip, host, path,
        )
        jl = get_json_logger()
        if jl:
            jl.log("github_dead_drop",
                   src_ip=self.client_address[0],
                   host=host,
                   path=self.path or "/")

        redirect_ip = self._cfg.spoof_ip or "10.10.10.10"
        body = redirect_ip.encode() + b"\n"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "github.com")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    # ── File-hosting / payload-staging route ───────────────────────────────
    def _route_file_hosting(self, host: str):
        """Return a plausible 200 response for file-hosting payload fetches.

        Agent Tesla (and similar stealers) check that they can reach a
        file-hosting site before fetching their second-stage payload.  If
        DNS resolves the host but the HTTP response is an error or our
        default HTML page, the malware detects a fake network and aborts.
        Returning HTTP 200 with a minimal octet-stream body keeps the
        pre-check alive so detonation proceeds and the request is logged.
        """
        src_ip = sanitize_ip(self.client_address[0])
        path = sanitize_log_string(self.path or "/", max_length=256)

        logger.warning(
            "FileHost  Payload fetch from %s | host=%s path=%s",
            src_ip, host, path,
        )
        jl = get_json_logger()
        if jl:
            jl.log("file_hosting_fetch",
                   src_ip=self.client_address[0],
                   host=host,
                   path=self.path or "/")

        # Minimal stub body — enough for the connectivity pre-check to pass.
        body = b"\x00" * 64
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "nginx")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    # ── Google Docs/Drive route ───────────────────────────────────────────
    def _route_google_content(self, host: str):
        """Return plausible content for Google Docs/Sheets/Drive dead-drops."""
        src_ip = sanitize_ip(self.client_address[0])
        path = sanitize_log_string(self.path or "/", max_length=256)

        logger.warning(
            "Google  Content fetch from %s | host=%s path=%s",
            src_ip, host, path,
        )
        jl = get_json_logger()
        if jl:
            jl.log("google_dead_drop",
                   src_ip=self.client_address[0],
                   host=host,
                   path=self.path or "/")

        redirect_ip = self._cfg.spoof_ip or "10.10.10.10"
        low = (self.path or "").lower()
        if "format=csv" in low or "tqx=out:csv" in low:
            body = redirect_ip.encode() + b"\n"
            ct = "text/csv; charset=utf-8"
        elif "export=download" in low or "uc?" in low:
            # Minimal valid PE stub — e_lfanew at 0x3C points to a PE\0\0
            # signature so loaders that parse the PE header don't crash.
            pe_stub = bytearray(512)
            pe_stub[0:2] = b"MZ"
            pe_stub[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew
            pe_stub[0x80:0x84] = b"PE\x00\x00"                # PE signature
            pe_stub[0x84:0x86] = (0x14C).to_bytes(2, "little") # Machine: i386
            body = bytes(pe_stub)
            ct = "application/octet-stream"
        else:
            body = redirect_ip.encode() + b"\n"
            ct = "text/plain; charset=utf-8"

        try:
            self.send_response(200)
            self.send_header("Content-Type", ct)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", "ESF")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass
        return True

    def _send_fake_response(self):
        host = self.headers.get("Host", "").split(":")[0].strip().lower()

        # Skip artificial delay for OS connectivity probes.
        _probe_host = host in _NCSI_HOSTS or host in _PKI_HOSTS or host in _CAPTIVE_PORTAL_HOSTS
        if self._cfg.delay_ms > 0 and not _probe_host:
            jitter = self._cfg.delay_jitter_ms
            actual = (
                self._cfg.delay_ms + random.randint(-jitter, jitter)  # noqa: S311  # nosec B311
                if jitter > 0
                else self._cfg.delay_ms
            )
            time.sleep(max(0, actual) / 1000.0)

        # Iterate the route registry; first matching handler wins.
        for predicate, handler in self._ROUTES:
            if predicate(self, host) and handler(self, host):
                return
        self._send_normal_response()

    def _send_normal_response(self):
        if self._cfg.log_requests:
            safe_path = sanitize_log_string(self.path, max_length=256)
            safe_addr = sanitize_ip(self.client_address[0])
            logger.info(
                "HTTP  %s %s from %s",
                sanitize_log_string(self.command), safe_path, safe_addr,
            )

        # Structured JSON logging
        jl = get_json_logger()
        if jl:
            jl.log("http_request",
                   method=self.command or "",
                   path=self.path or "/",
                   src_ip=self.client_address[0],
                   host=self.headers.get("Host", ""),
                   user_agent=self.headers.get("User-Agent", ""),
                   content_type=self.headers.get("Content-Type", ""))

        # --- Dynamic response: match path to MIME type + stub body ---
        if self._cfg.dynamic_responses:
            content_type, body = resolve_dynamic_response(
                self.path or "/",
                custom_rules=self._cfg.custom_rules,
                fallback_body=self._cfg.response_body,
            )
        else:
            content_type = "text/html; charset=utf-8"
            body = self._cfg.response_body

        try:
            self.send_response(self._cfg.response_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Server", self._cfg.server_header)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Vary", "Accept-Encoding")
            # ETag varies per path â€” a single static value for every URL is
            # a detectable fingerprint (real servers use inode/mtime/size).
            _path_etag = hashlib.md5(  # noqa: S324  # nosec B324 â€” not crypto
                (self.path or "/").encode(), usedforsecurity=False
            ).hexdigest()[:13]
            self.send_header("ETag", f'"3a4b1c-{_path_etag}"')
            self.send_header("Last-Modified", _SERVER_LAST_MODIFIED)
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            # HEAD requests MUST NOT include a message body (RFC 7231 Â§4.3.2).
            # send_response() / send_header() still ran, so headers are correct.
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass  # Client disconnected â€” normal for malware scanners

    def _send_connect_response(self):
        """Handle HTTP CONNECT tunnel request.

        Malware configured to route traffic via an HTTP proxy sends
        CONNECT to tunnel to its C2 (typically port 443).  Returning
        a proper 200 response â€” rather than an HTML page â€” lets the
        malware believe the tunnel was established; the subsequent TLS
        handshake fails (no real upstream), but the connection is logged
        and the client closes cleanly instead of seeing garbled HTML.
        """
        safe_addr = sanitize_ip(self.client_address[0])
        target = sanitize_log_string(self.path or "", 256)
        if self._cfg.log_requests:
            logger.info("HTTP  CONNECT %s from %s", target, safe_addr)
        jl = get_json_logger()
        if jl:
            jl.log("http_connect", src_ip=self.client_address[0],
                   target=self.path or "")
        try:
            self.wfile.write(
                f"{self.protocol_version} 200 Connection established\r\n\r\n".encode()
            )
            self.wfile.flush()
            # Drain the incoming stream (TLS handshake bytes, app data, etc.)
            # until the client closes the connection.
            self.request.settimeout(30)
            while self.request.recv(4096):
                pass  # drain until client closes
        except OSError:
            pass  # client disconnected during CONNECT tunnel drain

    # Respond identically to most methods; CONNECT is special-cased because
    # it must not return headers/body in the normal HTTP sense.
    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = \
        do_OPTIONS = do_PATCH = do_TRACE = _send_fake_response
    do_CONNECT = _send_connect_response

    # First line of the HTTP/2 client connection preface (RFC 7540 Â§3.5).
    _HTTP2_PREFACE_LINE = b"PRI * HTTP/2.0"

    def _handle_http2_goaway(self):
        """
        Respond to an HTTP/2 connection preface with a server SETTINGS
        frame followed by GOAWAY(HTTP_1_1_REQUIRED).

        RFC 7540 Â§3.5  â€” the server sends its own connection preface
                         (a SETTINGS frame) before any other frame.
        RFC 7540 Â§6.8  â€” GOAWAY carries the last processed stream ID
                         and an error code.
        Error 0x0D (HTTP_1_1_REQUIRED) tells the client to retry the
        request using HTTP/1.1 rather than h2.  Well-behaved HTTP/2
        clients will reconnect and fall back to http/1.1 via ALPN.
        """
        try:
            # The first readline() consumed "PRI * HTTP/2.0\r\n" (16 bytes).
            # The remaining preface bytes are "\r\nSM\r\n\r\n" = 8 bytes.
            self.rfile.read(8)
        except OSError:
            return
        try:
            # Empty SETTINGS frame â€” server connection preface (RFC 7540 Â§6.5)
            settings_frame = (
                b"\x00\x00\x00"       # payload length: 0
                b"\x04"               # frame type: SETTINGS
                b"\x00"               # no flags
                b"\x00\x00\x00\x00"  # stream ID: 0
            )
            # GOAWAY: last_stream_id=0, error=HTTP_1_1_REQUIRED (0x0D)
            goaway_frame = (
                b"\x00\x00\x08"       # payload length: 8
                b"\x07"               # frame type: GOAWAY
                b"\x00"               # no flags
                b"\x00\x00\x00\x00"  # stream ID: 0
                b"\x00\x00\x00\x00"  # last stream ID: 0
                b"\x00\x00\x00\x0d"  # error code 0x0D (HTTP_1_1_REQUIRED)
            )
            self.wfile.write(settings_frame + goaway_frame)
            self.wfile.flush()
        except OSError:
            pass

    def handle_one_request(self):
        try:
            # Read the request line ourselves so we can inspect it before
            # parse_request() sees it â€” needed for HTTP/2 preface detection.
            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                self.close_connection = True
                return
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                self.close_connection = True
                return
            # HTTP/2 connection preface (RFC 7540 Â§3.5): respond with
            # SETTINGS + GOAWAY(HTTP_1_1_REQUIRED) and close.
            if self.raw_requestline.startswith(self._HTTP2_PREFACE_LINE):
                safe_addr = sanitize_ip(self.client_address[0])
                logger.debug("HTTP2 preface from %s -> GOAWAY(HTTP_1_1_REQUIRED)", safe_addr)
                self._handle_http2_goaway()
                self.close_connection = True
                return
            if not self.parse_request():
                return
            # Explicit allowlist prevents do___init__ style attribute probing
            # and gives a clean 501 for genuinely unknown HTTP methods.
            _KNOWN_METHODS = frozenset({
                "GET", "POST", "PUT", "DELETE", "HEAD",
                "OPTIONS", "PATCH", "TRACE", "CONNECT",
            })
            if self.command not in _KNOWN_METHODS:
                self.send_error(501, f"Unsupported method ({self.command!r})")
                return
            mname = "do_" + self.command
            if not hasattr(self, mname):
                self.send_error(501, f"Unsupported method ({self.command!r})")
                return
            getattr(self, mname)()
            self.wfile.flush()
        except Exception as e:
            logger.debug("HTTP handler error (benign): %s", e)
            self.close_connection = True


# Populate route registry after class body so method refs are valid.
FakeHTTPHandler._ROUTES = [
    (lambda s, h: s._cfg.doh_enabled,                           FakeHTTPHandler._route_doh),
    (lambda s, h: s._cfg.websocket_sinkhole,                    FakeHTTPHandler._route_websocket),
    (lambda s, h: h in _NCSI_HOSTS,                             FakeHTTPHandler._route_ncsi),
    (lambda s, h: h in _CAPTIVE_PORTAL_HOSTS,                   FakeHTTPHandler._route_captive),
    (lambda s, h: h in _PKI_HOSTS,                              FakeHTTPHandler._route_pki),
    (lambda s, h: h in _IP_CHECK_HOSTS or h in s._cfg.pool_ips, FakeHTTPHandler._route_ip_check),
    (lambda s, h: h == _TELEGRAM_HOST,                          FakeHTTPHandler._route_telegram),
    (lambda s, h: h in _DISCORD_HOSTS,                          FakeHTTPHandler._route_discord),
    (lambda s, h: h in _PASTE_HOSTS,                            FakeHTTPHandler._route_paste),
    (lambda s, h: h == _SLACK_HOST,                             FakeHTTPHandler._route_slack),
    (lambda s, h: h in _TEAMS_HOSTS or _TEAMS_WEBHOOK_RE.search(h),
                                                                FakeHTTPHandler._route_teams),
    (lambda s, h: h in _GITHUB_RAW_HOSTS,                       FakeHTTPHandler._route_github_raw),
    (lambda s, h: h in _FILE_HOSTING_HOSTS,                     FakeHTTPHandler._route_file_hosting),
    (lambda s, h: h in _GOOGLE_CONTENT_HOSTS,                   FakeHTTPHandler._route_google_content),
]


class _ThreadedServer(socketserver.ThreadingTCPServer):
    """TCP server using a bounded thread pool."""
    allow_reuse_address = True
    daemon_threads = True
    _handler_cfg: _HandlerConfig = _HandlerConfig()

    def __init__(self, *args, **kwargs):
        self._pool = ThreadPoolExecutor(max_workers=_MAX_WORKER_THREADS)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        self._pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        # Set a read timeout before handing the socket to the handler.
        # Without this, a client that negotiates h2 via ALPN but never sends
        # the connection preface holds a pool worker indefinitely.
        try:
            request.settimeout(30)
        except OSError:
            pass
        super().process_request_thread(request, client_address)

    def server_close(self):
        self._pool.shutdown(wait=False)
        super().server_close()


class HTTPService:
    """Fake HTTP server that returns a canned response to everything."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 80))
        self.bind_ip = bind_ip
        self.response_code = int(config.get("response_code", 200))
        self.response_body = _load_response_body(config)
        self.server_header = config.get("server_header", _DEFAULT_SERVER_HEADER)
        self.log_requests = config.get("log_requests", True)
        raw_spoof = str(config.get("spoof_public_ip", "") or "").strip()
        self.spoof_ip = _validate_spoof_ip(raw_spoof, "http")
        self.delay_ms = int(config.get("response_delay_ms", 0) or 0)
        self.delay_jitter_ms = int(config.get("response_delay_jitter_ms", 0) or 0)
        self.dynamic_responses = config.get("dynamic_responses", False)
        self.custom_rules = config.get("dynamic_response_rules", [])
        self.doh_enabled = config.get("doh_sinkhole", False)
        self.doh_redirect_ip = config.get("doh_redirect_ip", "127.0.0.1")
        self.websocket_sinkhole = config.get("websocket_sinkhole", False)
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        if not self.enabled:
            return False
        cfg = _build_handler_config(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
            delay_jitter_ms=self.delay_jitter_ms,
            dynamic_responses=self.dynamic_responses,
            custom_rules=self.custom_rules,
            doh_enabled=self.doh_enabled,
            doh_redirect_ip=self.doh_redirect_ip,
            websocket_sinkhole=self.websocket_sinkhole,
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), FakeHTTPHandler)
            self._server._handler_cfg = cfg
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info("HTTP service started on %s:%s", self.bind_ip, self.port)
            return True
        except OSError as e:
            logger.error("HTTP service failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTP service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None


class HTTPSService:
    """Fake HTTPS server with hardened TLS configuration."""

    def __init__(self, config: dict, bind_ip: str = "0.0.0.0"):
        self.enabled = config.get("enabled", True)
        self.port = int(config.get("port", 443))
        self.bind_ip = bind_ip
        self.cert_file = config.get("cert_file", "certs/server.crt")
        self.key_file = config.get("key_file", "certs/server.key")
        self.response_code = int(config.get("response_code", 200))
        self.response_body = _load_response_body(config)
        self.server_header = config.get("server_header", _DEFAULT_SERVER_HEADER)
        self.log_requests = config.get("log_requests", True)
        raw_spoof = str(config.get("spoof_public_ip", "") or "").strip()
        self.spoof_ip = _validate_spoof_ip(raw_spoof, "https")
        self.delay_ms = int(config.get("response_delay_ms", 0) or 0)
        self.delay_jitter_ms = int(config.get("response_delay_jitter_ms", 0) or 0)
        self.dynamic_responses = config.get("dynamic_responses", False)
        self.custom_rules = config.get("dynamic_response_rules", [])
        self.dynamic_certs = config.get("dynamic_certs", False)
        self.doh_enabled = config.get("doh_sinkhole", False)
        self.doh_redirect_ip = config.get("doh_redirect_ip", "127.0.0.1")
        self.websocket_sinkhole = config.get("websocket_sinkhole", False)
        self._server: _ThreadedServer | None = None
        self._thread: threading.Thread | None = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """
        Build a hardened SSLContext.
        - TLSv1.2 minimum
        - OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_TLSv1, OP_NO_TLSv1_1
        - Strong cipher list, no export / null / anonymous
        - ALPN: h2 + http/1.1 (matches real Apache 2.4 behaviour)
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.options |= (
            ssl.OP_NO_SSLv2
            | ssl.OP_NO_SSLv3
            | ssl.OP_NO_TLSv1
            | ssl.OP_NO_TLSv1_1
            | ssl.OP_CIPHER_SERVER_PREFERENCE
            | ssl.OP_SINGLE_DH_USE
            | ssl.OP_SINGLE_ECDH_USE
        )
        ctx.set_ciphers(_SECURE_CIPHERS)
        # Advertise h2 + http/1.1 via ALPN â€” matches real Apache 2.4.x ServerHello.
        # When h2 is negotiated the handler detects the connection preface and
        # sends GOAWAY(HTTP_1_1_REQUIRED) so the client retries on HTTP/1.1.
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        return ctx

    def start(self) -> bool:
        if not self.enabled:
            return False

        # Auto-generate certs if missing
        ensure_certs(self.cert_file, self.key_file)

        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.error(
                f"HTTPS cert/key not found: {self.cert_file} / {self.key_file}"
            )
            return False

        cfg = _build_handler_config(
            self.response_code, self.response_body,
            self.server_header, self.log_requests,
            spoof_ip=self.spoof_ip, delay_ms=self.delay_ms,
            delay_jitter_ms=self.delay_jitter_ms,
            dynamic_responses=self.dynamic_responses,
            custom_rules=self.custom_rules,
            doh_enabled=self.doh_enabled,
            doh_redirect_ip=self.doh_redirect_ip,
            websocket_sinkhole=self.websocket_sinkhole,
        )
        try:
            self._server = _ThreadedServer((self.bind_ip, self.port), FakeHTTPHandler)
            self._server._handler_cfg = cfg
            ssl_ctx = self._build_ssl_context()
            if self.dynamic_certs:
                from utils.cert_utils import DynamicCertCache
                self._cert_cache = DynamicCertCache(
                    self.cert_file, self.key_file
                )
                ssl_ctx.sni_callback = self._cert_cache.sni_callback
            self._server.socket = ssl_ctx.wrap_socket(
                self._server.socket, server_side=True
            )
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                kwargs={"poll_interval": 2.0},
                daemon=True,
            )
            self._thread.start()
            logger.info(
                "HTTPS service started on %s:%s (TLS 1.2+ enforced)",
                self.bind_ip, self.port,
            )
            return True
        except ssl.SSLError as e:
            logger.error("HTTPS TLS setup error: %s", e)
            return False
        except OSError as e:
            logger.error("HTTPS service failed to bind %s:%s: %s", self.bind_ip, self.port, e)
            return False

    def stop(self) -> None:
        if self._server:
            try:
                self._server.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
