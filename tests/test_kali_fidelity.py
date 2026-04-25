#!/usr/bin/env python3
"""
NotTheNet — Kali Fidelity Test Suite
=====================================
Run from Kali Linux against a live NotTheNet instance to verify
handshake integrity for the top services.

Usage:
    python3 test_kali_fidelity.py                      # default: 127.0.0.1
    python3 test_kali_fidelity.py --target 192.168.24.20
    python3 test_kali_fidelity.py --target 192.168.24.20 -v

Requires: Python 3.9+ (stdlib only — no pip deps).
"""

from __future__ import annotations

import argparse
import socket
import ssl
import struct
import sys
import time

# ── Defaults ────────────────────────────────────────────────────────────────
DEFAULT_TARGET = "127.0.0.1"
TIMEOUT = 8  # seconds per connection


# ── Helpers ─────────────────────────────────────────────────────────────────

def _tcp_connect(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    return s


def _recv_line(s: socket.socket, max_bytes: int = 4096) -> str:
    """Receive until \\n or max_bytes, return decoded string."""
    data = b""
    while len(data) < max_bytes:
        chunk = s.recv(1)
        if not chunk:
            break
        data += chunk
        if chunk == b"\n":
            break
    return data.decode("utf-8", errors="replace").rstrip("\r\n")


def _recv_all(s: socket.socket, timeout: float = 2.0) -> bytes:
    """Drain socket until timeout; return raw bytes."""
    s.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (TimeoutError, OSError):
        pass
    return buf


# ── colour helpers (safe on dumb terminals) ────────────────────────────────

_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _ok(msg: str) -> str:
    return f"  {_GREEN}✓ PASS{_RESET}  {msg}"


def _fail(msg: str) -> str:
    return f"  {_RED}✗ FAIL{_RESET}  {msg}"


def _warn(msg: str) -> str:
    return f"  {_YELLOW}⚠ WARN{_RESET}  {msg}"


def _header(name: str) -> str:
    return f"\n{_BOLD}━━ {name} ━━{_RESET}"


# ── Individual Service Tests ────────────────────────────────────────────────

class FidelityResults:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.warned = 0
        self.lines: list[str] = []

    def ok(self, msg: str) -> None:
        self.passed += 1
        self.lines.append(_ok(msg))

    def fail(self, msg: str) -> None:
        self.failed += 1
        self.lines.append(_fail(msg))

    def warn(self, msg: str) -> None:
        self.warned += 1
        self.lines.append(_warn(msg))

    def header(self, name: str) -> None:
        self.lines.append(_header(name))


def test_ftp(host: str, port: int, r: FidelityResults) -> None:
    """FTP: banner + SYST + FEAT + unknown cmd."""
    r.header(f"FTP :{port}")
    try:
        s = _tcp_connect(host, port)
        banner = _recv_line(s)

        # 1. Banner starts with 220
        if banner.startswith("220"):
            r.ok(f"Banner: {banner[:60]}")
        else:
            r.fail(f"Expected 220 banner, got: {banner[:60]}")

        # 2. SYST response
        s.sendall(b"SYST\r\n")
        syst = _recv_line(s)
        if syst.startswith("215"):
            r.ok(f"SYST: {syst}")
            # Check for Python leak
            if "python" in syst.lower() or "cpython" in syst.lower():
                r.fail("SYST leaks Python identity")
        else:
            r.fail(f"SYST unexpected: {syst}")

        # 3. FEAT
        s.sendall(b"FEAT\r\n")
        feat = _recv_line(s)
        if "211" in feat:
            r.ok(f"FEAT: {feat[:50]}")
        else:
            r.warn(f"FEAT response: {feat[:50]}")

        # 4. Unknown command — should not leak traceback
        s.sendall(b"XYZZY\r\n")
        unk = _recv_line(s)
        if "Traceback" in unk or "Error" in unk:
            r.fail(f"Unknown cmd leaks error: {unk[:60]}")
        elif unk.startswith("5"):
            r.ok(f"Unknown cmd handled: {unk[:40]}")
        else:
            r.warn(f"Unknown cmd response: {unk[:40]}")

        s.sendall(b"QUIT\r\n")
        s.close()
    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_smtp(host: str, port: int, r: FidelityResults) -> None:
    """SMTP: banner + EHLO + AUTH advertisement."""
    r.header(f"SMTP :{port}")
    try:
        s = _tcp_connect(host, port)
        banner = _recv_line(s)

        if banner.startswith("220"):
            r.ok(f"Banner: {banner[:60]}")
        else:
            r.fail(f"Expected 220, got: {banner[:60]}")

        # Check for Python leaks in banner
        if "python" in banner.lower():
            r.fail("Banner leaks Python identity")

        # EHLO
        s.sendall(b"EHLO kali.local\r\n")
        ehlo_data = _recv_all(s, timeout=2.0).decode("utf-8", errors="replace")

        if "250" in ehlo_data:
            r.ok("EHLO accepted")
        else:
            r.fail(f"EHLO rejected: {ehlo_data[:60]}")

        if "AUTH" in ehlo_data:
            r.ok("AUTH advertised in EHLO")
        else:
            r.warn("No AUTH in EHLO response")

        if "STARTTLS" in ehlo_data:
            r.ok("STARTTLS advertised")

        # Check SIZE isn't suspiciously round
        if "SIZE 10240000" in ehlo_data:
            r.warn("SIZE 10240000 is an exact round number (real Postfix uses 52428800)")

        s.sendall(b"QUIT\r\n")
        s.close()
    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_http(host: str, port: int, r: FidelityResults) -> None:
    """HTTP: GET / — check Server header, no Python leaks."""
    r.header(f"HTTP :{port}")
    try:
        s = _tcp_connect(host, port)
        s.sendall(
            f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        resp = _recv_all(s, timeout=3.0)
        s.close()
        text = resp.decode("utf-8", errors="replace")
        lines = text.split("\r\n")

        # 1. Status line
        if lines and lines[0].startswith("HTTP/1."):
            r.ok(f"Status: {lines[0][:50]}")
        else:
            r.fail(f"Bad status line: {lines[0][:50] if lines else '(empty)'}")

        # 2. Server header — must NOT say Python/BaseHTTP
        server_hdr = ""
        for line in lines:
            if line.lower().startswith("server:"):
                server_hdr = line
                break
        if server_hdr:
            low = server_hdr.lower()
            if "python" in low or "basehttp" in low or "cpython" in low:
                r.fail(f"Server header leaks Python: {server_hdr}")
            elif "apache" in low or "nginx" in low or "iis" in low:
                r.ok(f"Server header: {server_hdr}")
            else:
                r.warn(f"Server header: {server_hdr}")
        else:
            r.warn("No Server header present")

        # 3. Body should not contain tracebacks
        if "Traceback" in text or "File \"" in text:
            r.fail("Response body contains Python traceback")
        else:
            r.ok("No Python artifacts in body")

    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_https(host: str, port: int, r: FidelityResults) -> None:
    """HTTPS: TLS handshake + GET — check cert and response."""
    r.header(f"HTTPS :{port}")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False  # nosec B501 — connecting to NTN's own self-signed cert
        ctx.verify_mode = ssl.CERT_NONE  # nosec B501 — intentional: test client for fake-internet server
        raw = _tcp_connect(host, port)
        s = ctx.wrap_socket(raw, server_hostname=host)

        # 1. TLS version
        tls_ver = s.version()
        if tls_ver and "TLSv1.2" in tls_ver or "TLSv1.3" in tls_ver:
            r.ok(f"TLS version: {tls_ver}")
        else:
            r.warn(f"TLS version: {tls_ver}")

        # 2. Certificate subject
        cert = s.getpeercert(binary_form=True)
        if cert:
            r.ok(f"Certificate present ({len(cert)} bytes)")
        else:
            r.warn("No certificate returned")

        # 3. HTTP over TLS
        s.sendall(
            f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
        )
        resp = _recv_all(s, timeout=3.0)
        s.close()
        text = resp.decode("utf-8", errors="replace")

        if text.startswith("HTTP/1."):
            r.ok("HTTP response over TLS OK")
        else:
            r.fail(f"Unexpected TLS response: {text[:40]}")

        # Check for Python leaks
        if "python" in text.lower() or "Traceback" in text:
            r.fail("HTTPS response leaks Python artifacts")
        else:
            r.ok("No Python artifacts in HTTPS response")

    except ssl.SSLError as e:
        r.fail(f"TLS handshake failed: {e}")
    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_dns(host: str, port: int, r: FidelityResults) -> None:
    """DNS: A query for example.com — verify answer section."""
    r.header(f"DNS :{port}")
    try:
        # Build a minimal DNS query for example.com A record
        txid = b"\xaa\xbb"
        flags = b"\x01\x00"         # standard query, RD=1
        counts = b"\x00\x01" * 1 + b"\x00\x00" * 3  # 1 question
        # QNAME: example.com
        qname = b"\x07example\x03com\x00"
        qtype = b"\x00\x01"         # A
        qclass = b"\x00\x01"        # IN
        query = txid + flags + counts + qname + qtype + qclass

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIMEOUT)
        s.sendto(query, (host, port))
        data, _ = s.recvfrom(4096)
        s.close()

        if len(data) < 12:
            r.fail(f"DNS response too short ({len(data)} bytes)")
            return

        # Check TXID matches
        if data[:2] == txid:
            r.ok("Transaction ID echoed correctly")
        else:
            r.fail("Transaction ID mismatch")

        # Check QR=1 (response), RCODE=0 (no error)
        resp_flags = struct.unpack("!H", data[2:4])[0]
        qr = (resp_flags >> 15) & 1
        rcode = resp_flags & 0x0F
        aa = (resp_flags >> 10) & 1

        if qr == 1:
            r.ok("QR bit set (response)")
        else:
            r.fail("QR bit not set — not a response")

        if rcode == 0:
            r.ok("RCODE=0 (no error)")
        else:
            r.warn(f"RCODE={rcode}")

        if aa:
            r.ok("AA bit set (authoritative)")
        else:
            r.warn("AA bit not set")

        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount >= 1:
            r.ok(f"Answer count: {ancount}")
        else:
            r.fail("No answers in DNS response")

    except Exception as e:
        r.fail(f"DNS query error: {e}")


def test_telnet(host: str, port: int, r: FidelityResults) -> None:
    """Telnet: IAC negotiation + banner + login prompt."""
    r.header(f"Telnet :{port}")
    try:
        s = _tcp_connect(host, port)
        # Read initial data (IAC negotiation + banner + login prompt)
        data = _recv_all(s, timeout=3.0)

        if not data:
            r.fail("No data received")
            s.close()
            return

        # 1. Check for IAC bytes (0xFF = telnet option negotiation)
        iac_count = data.count(b"\xff")
        if iac_count > 0:
            r.ok(f"IAC negotiation present ({iac_count} IAC bytes)")
        else:
            r.warn("No IAC negotiation (unusual for real Telnet)")

        text = data.decode("latin-1", errors="replace")

        # 2. Check for login prompt
        low = text.lower()
        if "login" in low or "username" in low:
            r.ok("Login prompt detected")
        else:
            r.warn("No login prompt in initial handshake")

        # 3. No Python leaks
        if "python" in low or "traceback" in low:
            r.fail("Telnet banner leaks Python artifacts")
        else:
            r.ok("No Python artifacts in banner")

        # 4. Try sending a username + password and check for shell
        s.settimeout(TIMEOUT)
        s.sendall(b"admin\r\n")
        time.sleep(0.5)
        resp1 = _recv_all(s, timeout=2.0)

        if b"assword" in resp1 or b"ASSWORD" in resp1:
            r.ok("Password prompt after username")
            s.sendall(b"admin\r\n")
            time.sleep(0.5)
            resp2 = _recv_all(s, timeout=2.0)
            text2 = resp2.decode("latin-1", errors="replace").lower()
            if "#" in text2 or "$" in text2 or ">" in text2:
                r.ok("Shell prompt after login")
            else:
                r.warn(f"No shell prompt detected: {resp2[:40]}")
        else:
            r.warn("No password prompt after username")

        s.close()
    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_irc(host: str, port: int, r: FidelityResults) -> None:
    """IRC: registration + JOIN — check RPL_WELCOME."""
    r.header(f"IRC :{port}")
    try:
        s = _tcp_connect(host, port)
        # Send NICK + USER
        s.sendall(b"NICK kalitest\r\n")
        s.sendall(b"USER kalitest 0 * :Kali Fidelity Test\r\n")

        # Collect registration burst
        burst = _recv_all(s, timeout=4.0).decode("utf-8", errors="replace")

        if "001" in burst and "Welcome" in burst:
            r.ok("RPL_WELCOME (001) received")
        else:
            r.fail(f"No 001 WELCOME in burst: {burst[:80]}")

        if "002" in burst:
            r.ok("RPL_YOURHOST (002) received")
        if "005" in burst:
            r.ok("RPL_ISUPPORT (005) received")

        # Check for Python leaks
        low = burst.lower()
        if "python" in low or "traceback" in low:
            r.fail("IRC registration leaks Python")
        else:
            r.ok("No Python artifacts in registration burst")

        # JOIN a channel
        s.settimeout(TIMEOUT)
        s.sendall(b"JOIN #test\r\n")
        join_resp = _recv_all(s, timeout=3.0).decode("utf-8", errors="replace")

        if "JOIN" in join_resp:
            r.ok("JOIN echo received")
        else:
            r.warn(f"No JOIN echo: {join_resp[:60]}")

        if "353" in join_resp:  # RPL_NAMREPLY
            r.ok("NAMES list received (353)")
        if "366" in join_resp:  # RPL_ENDOFNAMES
            r.ok("End of NAMES (366)")

        s.sendall(b"QUIT :bye\r\n")
        s.close()
    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_mysql(host: str, port: int, r: FidelityResults) -> None:
    """MySQL: check handshake V10 packet."""
    r.header(f"MySQL :{port}")
    try:
        s = _tcp_connect(host, port)
        # MySQL sends greeting immediately
        data = _recv_all(s, timeout=3.0)
        s.close()

        if len(data) < 10:
            r.fail(f"MySQL response too short ({len(data)} bytes)")
            return

        # Packet header: 3-byte length + 1-byte sequence
        struct.unpack("<I", data[:3] + b"\x00")[0]
        seq = data[3]
        proto = data[4]

        if seq == 0:
            r.ok("Sequence ID=0 (initial greeting)")
        else:
            r.warn(f"Unexpected sequence ID: {seq}")

        if proto == 10:
            r.ok("Protocol version 10 (correct)")
        else:
            r.fail(f"Protocol version {proto} — expected 10")

        # Server version string (null-terminated after byte 5)
        ver_end = data.index(b"\x00", 5)
        version = data[5:ver_end].decode("utf-8", errors="replace")
        r.ok(f"Server version: {version}")

        if "python" in version.lower():
            r.fail("MySQL version string leaks Python")

    except Exception as e:
        r.fail(f"Connection error: {e}")


def test_rdp(host: str, port: int, r: FidelityResults) -> None:
    """RDP: X.224 Connection Request → confirm."""
    r.header(f"RDP :{port}")
    try:
        s = _tcp_connect(host, port)
        # Send X.224 Connection Request (TPKT header + CR)
        # TPKT: version=3, reserved=0, length=13
        # X.224: length=6, CR=0xE0, dst-ref=0, src-ref=0, class=0
        cr_pkt = (
            b"\x03\x00"            # TPKT version 3
            b"\x00\x0b"            # TPKT length = 11 bytes total
            b"\x06"                # X.224 LI = 6
            b"\xe0"                # CR (Connection Request)
            b"\x00\x00"            # DST-REF
            b"\x00\x00"            # SRC-REF
            b"\x00"                # Class 0
        )
        s.sendall(cr_pkt)
        resp = _recv_all(s, timeout=3.0)
        s.close()

        if len(resp) < 7:
            r.fail(f"RDP response too short ({len(resp)} bytes)")
            return

        # TPKT header check
        if resp[0] == 0x03:
            r.ok("TPKT version 3")
        else:
            r.fail(f"TPKT version {resp[0]}")

        # X.224 Connection Confirm (0xD0)
        if len(resp) > 5 and resp[5] == 0xD0:
            r.ok("X.224 Connection Confirm (0xD0)")
        else:
            r.fail(f"Expected CC (0xD0), got 0x{resp[5]:02x}" if len(resp) > 5 else "No CC")

        # Check no Python artifacts in response
        if b"python" in resp.lower() or b"Traceback" in resp:
            r.fail("RDP response leaks Python artifacts")
        else:
            r.ok("No Python artifacts")

    except Exception as e:
        r.fail(f"Connection error: {e}")


# ── Main ────────────────────────────────────────────────────────────────────

_SERVICE_TESTS = [
    ("FTP",    21,   test_ftp),
    ("SMTP",   25,   test_smtp),
    ("HTTP",   80,   test_http),
    ("HTTPS",  443,  test_https),
    ("DNS",    53,   test_dns),
    ("Telnet", 23,   test_telnet),
    ("IRC",    6667, test_irc),
    ("MySQL",  3306, test_mysql),
    ("RDP",    3389, test_rdp),
]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NotTheNet Kali Fidelity Test — handshake integrity checks"
    )
    parser.add_argument(
        "--target", "-t", default=DEFAULT_TARGET,
        help=f"Target IP (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--services", "-s", default="all",
        help="Comma-separated service names to test (e.g. ftp,http,dns), or 'all'",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    target = args.target
    selected = {s.strip().upper() for s in args.services.split(",")} if args.services != "all" else None

    print(f"\n{_BOLD}NotTheNet Kali Fidelity Test{_RESET}")
    print(f"Target: {target}\n")

    results = FidelityResults()

    for name, port, test_fn in _SERVICE_TESTS:
        if selected and name.upper() not in selected:
            continue
        try:
            test_fn(target, port, results)
        except Exception as e:
            results.header(f"{name} :{port}")
            results.fail(f"Unhandled error: {e}")

    # Print all results
    for line in results.lines:
        print(line)

    # Summary
    total = results.passed + results.failed + results.warned
    print(f"\n{_BOLD}{'━' * 50}{_RESET}")
    print(
        f"  {_GREEN}{results.passed} passed{_RESET}  "
        f"{_RED}{results.failed} failed{_RESET}  "
        f"{_YELLOW}{results.warned} warnings{_RESET}  "
        f"({total} total checks)"
    )

    if results.failed == 0:
        print(f"\n  {_GREEN}{_BOLD}All handshake integrity checks passed.{_RESET}\n")
    else:
        print(f"\n  {_RED}{_BOLD}{results.failed} issue(s) need attention.{_RESET}\n")

    return 1 if results.failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
