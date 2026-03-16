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

import http.server
import ipaddress
import logging
import os
import select
import socketserver
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse
import ssl
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor

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

logger = logging.getLogger(__name__)

# Bounded thread pool — prevents resource exhaustion from flooded connections
_MAX_WORKER_THREADS = 50

# Cipher suites: ECDHE forward secrecy + AEAD — no RC4, 3DES, CBC
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
_NCSI_RESPONSES: dict[str, bytes] = {
    "www.msftconnecttest.com":  b"Microsoft Connect Test",
    "msftconnecttest.com":      b"Microsoft Connect Test",
    "ipv6.msftconnecttest.com": b"Microsoft Connect Test",
    "www.msftncsi.com":         b"Microsoft NCSI",
}

# Google / Android / ChromeOS connectivity checks and Apple captive portal
# detection hosts.  These are queried by the OS (not just the browser) and
# must return EXACT expected responses — wrong body or status code causes the
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

# Windows PKI infrastructure hosts — CRL, OCSP, and Certificate Trust List
# (CTL) download endpoints.  Windows CryptoAPI hits these during every HTTPS
# connection to validate the server cert chain.  If the response is HTML (our
# default page) instead of binary, cert validation fails — a giveaway.
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
})

# Minimal CRL stub — an empty DER-encoded X.509 Certificate Revocation List.
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
# hard-fail on soft-fail OCSP — but returning HTML would be worse.
_STUB_OCSP_RESPONSE = (
    b"\x30\x03"    # SEQUENCE { OCSPResponse
    b"\x0a\x01"    # ENUMERATED (1 byte)
    b"\x00"        # successful (0)
    # responseBytes omitted — this is a "successful but no details" stub.
    # CryptoAPI treats this as soft-pass (same as timeout).
)


_MAX_BODY_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# RFC 1918 private address ranges — returning one of these as a "public" IP
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
            "Invalid spoof_public_ip '%s' in %s config — must be a valid IPv4/IPv6 address; "
            "IP spoofing disabled.", raw, context or "http"
        )
        return ""
    if any(addr in net for net in _RFC1918_NETWORKS):
        logger.warning(
            "spoof_public_ip '%s' (%s) is a private/loopback address — "
            "sandbox detection tools may still flag this as non-internet traffic.",
            raw, context or "http"
        )
    return raw


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
        abs_path = os.path.join(project_root, file_path)
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
            logger.warning(f"response_body_file '{abs_path}' could not be read: {exc}; "
                           "falling back to response_body string.")
    return config.get("response_body", _DEFAULT_BODY)


def _make_handler(response_code: int, response_body: str, server_header: str,
                  log_requests: bool, spoof_ip: str = "", delay_ms: int = 0,
                  delay_jitter_ms: int = 0,
                  dynamic_responses: bool = False, custom_rules: list | None = None,
                  doh_enabled: bool = False, doh_redirect_ip: str = "127.0.0.1",
                  websocket_sinkhole: bool = False):
    """Factory: create a BaseHTTPRequestHandler subclass with captured config."""

    class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
        _response_code = response_code
        _response_body = response_body.encode("utf-8", errors="replace")
        _server_header = server_header
        _log_requests = log_requests
        _spoof_ip = spoof_ip
        _delay_ms = delay_ms
        _delay_jitter_ms = delay_jitter_ms
        _dynamic_responses = dynamic_responses
        _custom_rules = compile_custom_rules(custom_rules or [])
        _doh_enabled = doh_enabled
        _doh_redirect_ip = doh_redirect_ip
        _websocket_sinkhole = websocket_sinkhole

        # Use HTTP/1.1 to match real-world server behaviour.  Python's
        # BaseHTTPRequestHandler defaults to HTTP/1.0, which is a detectable
        # fingerprint — real Apache/nginx never respond with HTTP/1.0 for
        # normal requests.  Setting this here overrides the default for all
        # responses emitted by this handler.
        protocol_version = "HTTP/1.1"

        # Prevent send_response() from prepending its own
        # "Server: BaseHTTP/0.6 Python/3.x" header before ours.  Without
        # this, every response carries two Server headers — an obvious
        # fingerprint that sandbox-detection tools check for.
        server_version = ""

        def send_response(self, code, message=None):
            """Override to suppress Python's auto-injected Server header.

            Python's BaseHTTPRequestHandler.send_response() unconditionally
            calls send_header('Server', self.version_string()), which emits
            'Server:  Python/3.x.y' even when server_version is set to "".
            This would create two Server headers in every response — the
            Python one and the spoofed 'Apache/...' one we add explicitly.
            We reproduce the same status-line + Date logic without the Server
            header so only our explicit Server declaration is transmitted.
            """
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
            # Add Date (required by HTTP/1.1) but NOT the Python Server header.
            self.send_header("Date", self.date_time_string())

        # Suppress default BaseHTTPServer stderr logging (we do our own)
        def log_message(self, fmt, *args):
            pass

        def _send_ip_check_response(self, host: str):
            """Return the spoofed public IP for known IP-check services."""
            path = self.path or "/"
            ip = self._spoof_ip

            # ipinfo.io — returns detailed JSON including ISP/org.
            # Malware often checks the 'org' field for datacenter/hosting ASNs
            # to detect sandboxes; we return a realistic residential ISP.
            if host == "ipinfo.io":
                body = (
                    f'{{"ip":"{ip}",'
                    f'"city":"Columbus","region":"Ohio","country":"US",'
                    f'"loc":"39.9612,-82.9988",'
                    f'"org":"AS7922 Comcast Cable Communications, LLC",'
                    f'"postal":"43215","timezone":"America/New_York"}}\n'
                ).encode()
                content_type = "application/json"
            # ip-api.com — handle /line/, /csv/, and /json/ endpoints.
            # AgentTesla and other stealers use GET /line/?fields=hosting to
            # detect sandbox/datacenter IPs via a plain-text response.
            # The /line/ endpoint returns one value per requested field,
            # newline-separated, as text/plain — NOT a JSON object.
            # Must return "false" for hosting; "true" would cause the malware
            # to abort C2 activation thinking it's in a datacenter/sandbox.
            elif host == "ip-api.com":
                # Normalise the path component so we match both /line/ and
                # /line?...  (no trailing slash) — some malware omits the
                # slash and the check must not fall through to the JSON branch,
                # which would return a JSON body that gets parsed as "true".
                _path_base = path.split("?")[0].rstrip("/")
                if _path_base == "/line" or _path_base.startswith("/line/"):
                    # Parse requested fields from query string
                    # e.g. ?fields=hosting  or  ?fields=hosting,isp,country
                    _qs = parse_qs(urlparse(path).query)
                    _fields = [f.strip() for f in _qs.get("fields", ["query"])[0].split(",")]
                    _field_map = {
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
                        "query": ip,
                    }
                    body = "\n".join(_field_map.get(f, "") for f in _fields).encode() + b"\n"
                    content_type = "text/plain; charset=utf-8"
                elif (_path_base == "/csv" or _path_base.startswith("/csv/") or "fields=csv" in path):
                    body = f"success,United States,US,OH,Ohio,Columbus,43215,39.9612,-82.9988,America/New_York,Comcast Cable Communications,Comcast Cable Communications,AS7922 Comcast Cable Communications LLC,false,false,false,{ip}\n".encode()
                    content_type = "text/csv"
                else:
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
                    content_type = "application/json"
            # httpbin.org/ip uses {"origin": "..."}
            elif host == "httpbin.org":
                body = f'{{"origin":"{ip}"}}\n'.encode()
                content_type = "application/json"
            # ipify ?format=json or URL ending in /json
            elif "format=json" in path or path.rstrip("/").endswith("/json"):
                body = f'{{"ip":"{ip}"}}\n'.encode()
                content_type = "application/json"
            else:
                body = f"{ip}\n".encode()
                content_type = "text/plain"
            if self._log_requests:
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
                # ip-api.com runs nginx; sending Apache here is a detectable
                # fingerprint. Override for ip-api.com and add the standard
                # CORS + rate-limit headers the real API always includes.
                if host == "ip-api.com":
                    self.send_header("Server", "nginx")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("X-Ttl", "60")
                    self.send_header("X-Rl", "44")
                else:
                    self.send_header("Server", self._server_header)
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_captive_portal_response(self, host: str) -> bool:
            """Handle OS-level captive portal and connectivity checks.

            Google / Android / ChromeOS: GET /generate_204 → 204 No Content
            Apple macOS / iOS: specific paths → 200 with exact success payload

            Returns True if the request was handled, False to fall through to
            the normal response handler (unrecognised paths on these hosts).
            """
            path = (self.path or "/").split("?")[0]

            # Google / Android / ChromeOS connectivity probe
            if path == "/generate_204":
                if self._log_requests:
                    safe_addr = sanitize_ip(self.client_address[0])
                    logger.info(
                        f"HTTP  CAPTIVE generate_204 from {safe_addr}"
                    )
                try:
                    self.send_response(204)
                    self.send_header("Content-Length", "0")
                    # Real Google response uses GFE server header
                    self.send_header("Server", "GFE/2.0")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return True

            # Apple captive portal / hotspot detection
            if host in ("captive.apple.com", "www.apple.com"):
                if "/hotspot-detect.html" in path or "/library/test/success.html" in path:
                    # Exact byte-for-byte match of what Apple’s captive portal
                    # servers return — iOS/macOS will not show “Connected”
                    # without this precise body.
                    body = b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
                    if self._log_requests:
                        safe_addr = sanitize_ip(self.client_address[0])
                        logger.info(
                            f"HTTP  CAPTIVE apple {sanitize_log_string(path, 64)}"
                            f" from {safe_addr}"
                        )
                    try:
                        self.send_response(200)
                        self.send_header("Content-Type", "text/html")
                        self.send_header("Content-Length", str(len(body)))
                        # Apple’s hotspot pages are served via Akamai CDN
                        self.send_header("Server", "AkamaiGHost")
                        self.send_header("Connection", "keep-alive")
                        self.end_headers()
                        if self.command != "HEAD":
                            self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return True

            return False  # fall through to normal handler

        def _send_ncsi_response(self, host: str):
            """Return the exact response Windows NCSI expects.

            Windows polls these hosts to determine whether to show the
            'Internet access' indicator. When the response body matches
            exactly, Windows reports full connectivity — which prevents
            certain malware from stalling in a 'no network' idle loop.
            """
            body = _NCSI_RESPONSES.get(host, b"Microsoft Connect Test")
            if self._log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  NCSI {sanitize_log_string(host)} "
                    f"from {safe_addr} \u2192 {body.decode()}"
                )
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _send_pki_response(self, host: str):
            """Return stub CRL/OCSP/CTL binary responses for Windows PKI hosts.

            Windows CryptoAPI fetches CRLs, OCSP responses, and CTLs over HTTP
            during every HTTPS cert validation.  Returning HTML (our default
            response) breaks validation.  We return the correct content-type
            with a minimal valid binary stub.
            """
            path = (self.path or "/").lower()
            if self._log_requests:
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  PKI {sanitize_log_string(host)}{sanitize_log_string(path, 128)} "
                    f"from {safe_addr}"
                )
            # Determine response type from path/host
            if "ocsp" in host or "/ocsp" in path:
                body = _STUB_OCSP_RESPONSE
                content_type = "application/ocsp-response"
            elif path.endswith(".crl") or "crl" in host:
                body = _get_stub_crl()
                content_type = "application/pkix-crl"
            elif path.endswith(".crt") or path.endswith(".cer") or "cacerts" in host:
                # CA cert download — return an empty 404 rather than HTML.
                # Windows treats a missing issuer cert as soft-fail.
                try:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.send_header("Server", self._server_header)
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                return
            elif "ctldl" in host or path.endswith(".stl") or path.endswith(".cab"):
                # Certificate Trust List — return empty cab-like response
                body = b""
                content_type = "application/octet-stream"
            else:
                # Generic PKI host — return empty binary
                body = b""
                content_type = "application/octet-stream"
            try:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _handle_doh_request(self):
            """Handle a DNS-over-HTTPS (DoH) request and return a DNS response."""
            safe_addr = sanitize_ip(self.client_address[0])
            path = self.path or "/"
            if self.command == "GET":
                response_data = handle_doh_get(path, self._doh_redirect_ip)
            else:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length > 0 else b""
                response_data = handle_doh_post(body, self._doh_redirect_ip)

            if response_data:
                if self._log_requests:
                    logger.info(f"DoH   request from {safe_addr} -> sinkholed")
                jl = get_json_logger()
                if jl:
                    jl.log("doh_request", src_ip=self.client_address[0],
                           method=self.command or "", path=self.path or "/")
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", DOH_CONTENT_TYPE)
                    self.send_header("Content-Length", str(len(response_data)))
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Server", self._server_header)
                    self.end_headers()
                    self.wfile.write(response_data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                # Couldn't parse DoH — fall through to normal response
                self._send_normal_response()

        def _handle_websocket_upgrade(self):
            """Complete a WebSocket handshake then send a close frame."""
            safe_addr = sanitize_ip(self.client_address[0])
            ws_key = self.headers.get("Sec-WebSocket-Key", "")
            if not ws_key:
                self._send_normal_response()
                return

            if self._log_requests:
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
                        if data and self._log_requests:
                            preview = sanitize_log_string(
                                data[:64].hex(), 128
                            )
                            logger.debug(f"WS    received frame preview: {preview}")
                    except Exception:
                        pass

                # Send close frame
                close_frame = build_websocket_close_frame(1000, "sinkholed")
                self.wfile.write(close_frame)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def _send_fake_response(self):
            # Compute host early so we can skip delay for probe requests.
            # NCSI / PKI / captive-portal probes have strict timing expectations
            # and must never be held up by artificial latency.
            host = self.headers.get("Host", "").split(":")[0].strip().lower()

            # Optional artificial delay with jitter (simulates realistic
            # network latency, defeats timing-based sandbox detection).
            # Skipped for OS connectivity probes that expect near-instant replies.
            _probe_host = host in _NCSI_HOSTS or host in _PKI_HOSTS or host in _CAPTIVE_PORTAL_HOSTS
            if self._delay_ms > 0 and not _probe_host:
                jitter = self._delay_jitter_ms
                actual = (
                    self._delay_ms + random.randint(-jitter, jitter)
                    if jitter > 0
                    else self._delay_ms
                )
                time.sleep(max(0, actual) / 1000.0)

            # --- DNS over HTTPS (DoH) interception ---
            if self._doh_enabled:
                ct = self.headers.get("Content-Type", "")
                if is_doh_request(ct, self.path):
                    self._handle_doh_request()
                    return

            # --- WebSocket sinkhole ---
            if self._websocket_sinkhole:
                hdrs = {k: self.headers.get(k, "") for k in ("Connection", "Upgrade", "Sec-WebSocket-Key")}
                if is_websocket_upgrade(hdrs):
                    self._handle_websocket_upgrade()
                    return

            # Windows NCSI: must respond correctly regardless of spoof_ip setting
            if host in _NCSI_HOSTS:  # host already computed above
                self._send_ncsi_response(host)
                return

            # Google / Android / Apple captive portal connectivity checks
            if host in _CAPTIVE_PORTAL_HOSTS:
                if self._send_captive_portal_response(host):
                    return

            # Windows PKI: CRL, OCSP, CTL downloads — return binary stubs
            if host in _PKI_HOSTS:
                self._send_pki_response(host)
                return

            # Public IP spoof: intercept well-known IP-check hostnames
            if self._spoof_ip and host in _IP_CHECK_HOSTS:
                self._send_ip_check_response(host)
                return
            self._send_normal_response()

        def _send_normal_response(self):
            if self._log_requests:
                safe_path = sanitize_log_string(self.path, max_length=256)
                safe_addr = sanitize_ip(self.client_address[0])
                logger.info(
                    f"HTTP  {sanitize_log_string(self.command)} {safe_path} "
                    f"from {safe_addr}"
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
            if self._dynamic_responses:
                content_type, body = resolve_dynamic_response(
                    self.path or "/",
                    custom_rules=self._custom_rules,
                    fallback_body=self._response_body,
                )
            else:
                content_type = "text/html; charset=utf-8"
                body = self._response_body

            try:
                self.send_response(self._response_code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Server", self._server_header)
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Vary", "Accept-Encoding")
                self.send_header("ETag", '"3a4b1c-264-5f8a7d63c0bc0"')
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                # HEAD requests MUST NOT include a message body (RFC 7231 §4.3.2).
                # send_response() / send_header() still ran, so headers are correct.
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass  # Client disconnected — normal for malware scanners

        def _send_connect_response(self):
            """Handle HTTP CONNECT tunnel request.

            Malware configured to route traffic via an HTTP proxy sends
            CONNECT to tunnel to its C2 (typically port 443).  Returning
            a proper 200 response — rather than an HTML page — lets the
            malware believe the tunnel was established; the subsequent TLS
            handshake fails (no real upstream), but the connection is logged
            and the client closes cleanly instead of seeing garbled HTML.
            """
            safe_addr = sanitize_ip(self.client_address[0])
            target = sanitize_log_string(self.path or "", 256)
            if self._log_requests:
                logger.info(f"HTTP  CONNECT {target} from {safe_addr} \u2192 tunnelled")
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
                    pass
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        # Respond identically to most methods; CONNECT is special-cased because
        # it must not return headers/body in the normal HTTP sense.
        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = \
            do_OPTIONS = do_PATCH = do_TRACE = _send_fake_response
        do_CONNECT = _send_connect_response

        # First line of the HTTP/2 client connection preface (RFC 7540 §3.5).
        _HTTP2_PREFACE_LINE = b"PRI * HTTP/2.0"

        def _handle_http2_goaway(self):
            """
            Respond to an HTTP/2 connection preface with a server SETTINGS
            frame followed by GOAWAY(HTTP_1_1_REQUIRED).

            RFC 7540 §3.5  — the server sends its own connection preface
                             (a SETTINGS frame) before any other frame.
            RFC 7540 §6.8  — GOAWAY carries the last processed stream ID
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
                # Empty SETTINGS frame — server connection preface (RFC 7540 §6.5)
                settings_frame = (
                    b"\x00\x00\x00"       # payload length = 0
                    b"\x04"               # frame type = SETTINGS
                    b"\x00"               # flags = 0
                    b"\x00\x00\x00\x00"  # stream ID = 0
                )
                # GOAWAY: last_stream_id=0, error=HTTP_1_1_REQUIRED (0x0D)
                goaway_frame = (
                    b"\x00\x00\x08"       # payload length = 8
                    b"\x07"               # frame type = GOAWAY
                    b"\x00"               # flags = 0
                    b"\x00\x00\x00\x00"  # stream ID = 0
                    b"\x00\x00\x00\x00"  # last stream ID = 0
                    b"\x00\x00\x00\x0d"  # error = HTTP_1_1_REQUIRED
                )
                self.wfile.write(settings_frame + goaway_frame)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass

        def handle_one_request(self):
            try:
                # Read the request line ourselves so we can inspect it before
                # parse_request() sees it — needed for HTTP/2 preface detection.
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
                # HTTP/2 connection preface (RFC 7540 §3.5): respond with
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
                logger.debug(f"HTTP handler error (benign): {e}")

    return FakeHTTPHandler


class _ThreadedServer(socketserver.ThreadingTCPServer):
    """TCP server using a bounded thread pool."""
    allow_reuse_address = True
    daemon_threads = True

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
        self.server_header = config.get("server_header", "Apache/2.4.51")
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
        handler = _make_handler(
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
            self._server = _ThreadedServer((self.bind_ip, self.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(f"HTTP service started on {self.bind_ip}:{self.port}")
            return True
        except OSError as e:
            logger.error(f"HTTP service failed to bind {self.bind_ip}:{self.port}: {e}")
            return False

    def stop(self):
        if self._server:
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
        self.server_header = config.get("server_header", "Apache/2.4.51")
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
        # Advertise h2 + http/1.1 via ALPN — matches real Apache 2.4.x ServerHello.
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

        handler = _make_handler(
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
            self._server = _ThreadedServer((self.bind_ip, self.port), handler)
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
                target=self._server.serve_forever, daemon=True
            )
            self._thread.start()
            logger.info(
                f"HTTPS service started on {self.bind_ip}:{self.port} "
                f"(TLS 1.2+ enforced)"
            )
            return True
        except OSError as e:
            logger.error(f"HTTPS service failed to bind {self.bind_ip}:{self.port}: {e}")
            return False
        except ssl.SSLError as e:
            logger.error(f"HTTPS TLS setup error: {e}")
            return False

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        logger.info("HTTPS service stopped.")

    @property
    def running(self) -> bool:
        return self._server is not None
