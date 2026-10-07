"""
NotTheNet - HTTP host catalog and canned responses.

The hostnames the fake HTTP server recognises (connectivity checks, IP-check
services, PKI, chat/paste/cloud exfil endpoints) and the static bodies it
returns for them. Pure data and pure functions: no sockets, no handler state.
"""

from __future__ import annotations

import re
import threading
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

_CT_JSON = "application/json"
_CT_HTML = "text/html"
_CT_PLAIN = "text/plain"

# When spoof_public_ip is set and a request Host matches one of these,
# the handler returns the spoofed IP. Defeats the most common sandbox-evasion
# technique: checking "am I on the real internet?".
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

# Telegram Bot API host.  Agent Tesla (and other stealers) use the Bot API
# to exfiltrate credentials/keylog data.  Returning a valid {"ok": true, ...}
# response prevents the malware from entering an error/retry path.
_TELEGRAM_HOST = "api.telegram.org"

# Discord webhook hosts.  20+ stealer families (Raccoon, RedLine, Vidar,
# Agent Tesla, Lumma, Stealc, etc.) exfiltrate via Discord webhooks.
_DISCORD_HOSTS = frozenset({
    "discord.com", "discordapp.com",
    "canary.discord.com", "ptb.discord.com",
})

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

# ── Cloud exfiltration hosts ──────────────────────────────────────────────────
# AWS S3: matches virtual-hosted ({bucket}.s3.amazonaws.com,
# {bucket}.s3.{region}.amazonaws.com) and path-style (s3.amazonaws.com,
# s3.{region}.amazonaws.com).  checkip.amazonaws.com is excluded — it is
# handled earlier by the IP-check route.
_AWS_S3_RE = re.compile(r"(?:^|\.)s3(?:\.[a-z0-9-]+)?\.amazonaws\.com$")

# Azure Blob Storage: {account}.blob.core.windows.net
_AZURE_BLOB_RE = re.compile(r"\.blob\.core\.windows\.net$")

# Microsoft Graph / OneDrive API
_GRAPH_HOST = "graph.microsoft.com"

# Dropbox upload + API hosts
_DROPBOX_HOSTS = frozenset({
    "content.dropboxapi.com",
    "api.dropboxapi.com",
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

# Minimal CRL stub — an empty DER-encoded X.509 Certificate Revocation List.
# We generate it lazily on first use.
_STUB_CRL_CACHE: bytes | None = None
_STUB_CRL_LOCK = threading.Lock()


def _get_stub_crl() -> bytes:
    """Return a minimal valid DER-encoded CRL (empty revocation list)."""
    global _STUB_CRL_CACHE  # noqa: PLW0603  # NOSONAR
    if _STUB_CRL_CACHE is not None:  # unsynchronized read — safe under CPython GIL
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
        except Exception:  # noqa: BLE001
            _STUB_CRL_CACHE = b"\x30\x00"  # empty DER SEQUENCE — CryptoAPI treats as soft-fail
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


# ── IP-check response formatters ────────────────────────────────────────────
# Pure functions: (ip, path) → (body, content_type, extra_headers | None).
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
    return body, _CT_HTML, None


_IP_CHECK_FORMATTERS: dict[str, object] = {
    "ipinfo.io": _fmt_ipinfo,
    "ip-api.com": _fmt_ip_api,
    "httpbin.org": _fmt_httpbin,
    "checkip.amazonaws.com": _fmt_checkip_aws,
}
