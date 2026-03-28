#!/usr/bin/env python3
"""
NotTheNet load tester — hits every service with concurrent workers for DURATION seconds.
Usage:  python3 load_test.py [--host 127.0.0.1] [--duration 30] [--workers 10]
"""

import argparse
import socket
import ssl
import struct
import threading
import time
from collections import defaultdict

# ── Default settings ──────────────────────────────────────────────────────────
DEFAULT_HOST     = "127.0.0.1"
DEFAULT_DURATION = 30          # seconds
DEFAULT_WORKERS  = 10          # concurrent workers per service

# ── Stats tracking ────────────────────────────────────────────────────────────
stats_lock = threading.Lock()
stats = defaultdict(lambda: {"ok": 0, "err": 0, "latency": []})

def record(name, ok, latency_ms):
    with stats_lock:
        if ok:
            stats[name]["ok"] += 1
            stats[name]["latency"].append(latency_ms)
        else:
            stats[name]["err"] += 1

# ── Generic TCP handshake helper ──────────────────────────────────────────────
def tcp_connect(host, port, send=None, expect=None, tls=False, timeout=3):
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock)
        sock.recv(1024)
        if send:
            sock.sendall(send)
            if expect:
                sock.recv(1024)
        sock.close()
        return True, int((time.monotonic() - t0) * 1000)
    except Exception:
        return False, int((time.monotonic() - t0) * 1000)

def udp_send(host, port, payload, timeout=3):
    t0 = time.monotonic()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        sock.recvfrom(512)
        sock.close()
        return True, int((time.monotonic() - t0) * 1000)
    except Exception:
        return False, int((time.monotonic() - t0) * 1000)

# ── Per-service worker functions ──────────────────────────────────────────────

def w_http(host):
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 80), timeout=3)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        ok = b"HTTP/" in data
        record("http", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("http", False, 0)

def w_https(host):
    try:
        t0 = time.monotonic()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, 443), timeout=3)
        sock = ctx.wrap_socket(sock)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        ok = b"HTTP/" in data
        record("https", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("https", False, 0)

def w_smtp(host):
    ok, ms = tcp_connect(host, 25, send=b"EHLO loadtest\r\n", expect=True)
    record("smtp", ok, ms)

def w_smtps(host):
    ok, ms = tcp_connect(host, 465, tls=True)
    record("smtps", ok, ms)

def w_pop3(host):
    ok, ms = tcp_connect(host, 110, send=b"CAPA\r\n")
    record("pop3", ok, ms)

def w_pop3s(host):
    ok, ms = tcp_connect(host, 995, tls=True)
    record("pop3s", ok, ms)

def w_imap(host):
    ok, ms = tcp_connect(host, 143, send=b"a001 CAPABILITY\r\n")
    record("imap", ok, ms)

def w_imaps(host):
    ok, ms = tcp_connect(host, 993, tls=True)
    record("imaps", ok, ms)

def w_ftp(host):
    ok, ms = tcp_connect(host, 21, send=b"USER anonymous\r\n", expect=True)
    record("ftp", ok, ms)

def w_telnet(host):
    ok, ms = tcp_connect(host, 23)
    record("telnet", ok, ms)

def w_irc(host):
    # IRC sends nothing until after NICK/USER registration
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 6667), timeout=5)
        sock.sendall(b"NICK loadtest\r\nUSER load 0 * :Load Test\r\n")
        data = sock.recv(2048)
        sock.close()
        ok = b"001" in data or b"NOTICE" in data or b"NICK" in data
        record("irc", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("irc", False, 0)

def w_ircs(host):
    try:
        t0 = time.monotonic()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, 6697), timeout=5)
        sock = ctx.wrap_socket(sock)
        sock.sendall(b"NICK loadtest\r\nUSER load 0 * :Load Test\r\n")
        data = sock.recv(2048)
        sock.close()
        ok = b"001" in data or b"NOTICE" in data or b"NICK" in data
        record("ircs", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("ircs", False, 0)

def w_socks5(host):
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 1080), timeout=3)
        # SOCKS5 greeting
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        sock.close()
        ok = len(resp) == 2 and resp[0] == 5
        record("socks5", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("socks5", False, 0)

def w_dns(host):
    # Raw DNS query for example.com A record over UDP port 53
    # Build a minimal DNS query by hand (no external libs needed)
    try:
        t0 = time.monotonic()
        # Transaction ID=1, flags=standard query, 1 question
        qname = b"\x07example\x03com\x00"
        query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(query, (host, 53))
        data, _ = sock.recvfrom(512)
        sock.close()
        ok = len(data) > 12
        record("dns", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("dns", False, 0)

def w_ntp(host):
    # NTPv3 client request
    payload = b"\x1b" + b"\x00" * 47
    try:
        t0 = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(payload, (host, 123))
        data, _ = sock.recvfrom(512)
        sock.close()
        ok = len(data) >= 48
        record("ntp", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("ntp", False, 0)

def w_tftp(host):
    # TFTP RRQ for a file
    payload = b"\x00\x01test.txt\x00octet\x00"
    # TFTP will error (file not found) but should respond with an error packet
    try:
        t0 = time.monotonic()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(payload, (host, 69))
        data, _ = sock.recvfrom(512)
        sock.close()
        ok = len(data) >= 4  # any response means the service responded
        record("tftp", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("tftp", False, 0)

def w_mysql(host):
    # MySQL sends a handshake greeting on connect
    ok, ms = tcp_connect(host, 3306)
    record("mysql", ok, ms)

def w_mssql(host):
    # Send TDS 7 pre-login packet and read response
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 1433), timeout=3)
        # TDS pre-login: type=0x12, status=0x01, length=0x002F, SPID=0, packet=1, window=0
        prelogin = bytes.fromhex(
            "12010002f0000001000000150006000100200001000200350001"
            "00036b000400ff0800000000000000"
        )
        sock.sendall(prelogin)
        data = sock.recv(256)
        sock.close()
        ok = len(data) > 4
        record("mssql", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("mssql", False, 0)

def w_rdp(host):
    # Send X.224 CR TPDU and read CC response
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 3389), timeout=3)
        # TPKT + X.224 Connection Request
        tpkt = bytes.fromhex("0300002be6200000000000436f6f6b69653a206d737473686173683d55736572310d0a0100080000000000")
        sock.sendall(tpkt)
        data = sock.recv(256)
        sock.close()
        ok = len(data) > 4
        record("rdp", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("rdp", False, 0)

def w_smb(host):
    # SMB2 Negotiate: correct NetBIOS(4) + SMB2 header(64) + Negotiate body(38)
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 445), timeout=3)
        # NetBIOS: type=0x00 (Session Message), length=102=0x66 (3-byte big-endian)
        netbios = bytes.fromhex("00000066")
        # SMB2 header (64 bytes)
        smb2_hdr = bytes.fromhex(
            "fe534d42"                              # ProtocolId
            "4000"                                  # StructureSize=64
            "0000"                                  # CreditCharge
            "00000000"                              # Status/ChannelSeq
            "0000"                                  # Command: NEGOTIATE=0
            "0100"                                  # CreditRequest
            "00000000"                              # Flags
            "00000000"                              # NextCommand
            "0000000000000000"                      # MessageId
            "0000000000000000"                      # ProcessId+TreeId
            "0000000000000000"                      # SessionId
            "00000000000000000000000000000000"      # Signature (16 bytes)
        )
        # Negotiate body (38 bytes incl. 1 dialect)
        neg_body = bytes.fromhex(
            "2400"                                  # StructureSize=36
            "0100"                                  # DialectCount=1
            "0100"                                  # SecurityMode
            "0000"                                  # Reserved
            "7f000000"                              # Capabilities
            "00000000000000000000000000000000"      # ClientGuid (16 bytes)
            "0000000000000000"                      # ClientStartTime (8 bytes)
            "0202"                                  # Dialect: SMB 2.0.2
        )
        sock.sendall(netbios + smb2_hdr + neg_body)
        data = sock.recv(256)
        sock.close()
        ok = len(data) > 4
        record("smb", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("smb", False, 0)

def w_vnc(host):
    # VNC sends RFB version banner
    ok, ms = tcp_connect(host, 5900)
    record("vnc", ok, ms)

def w_redis(host):
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 6379), timeout=3)
        sock.sendall(b"PING\r\n")
        data = sock.recv(64)
        sock.close()
        ok = b"PONG" in data or b"+PONG" in data or len(data) > 0
        record("redis", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("redis", False, 0)

def w_ldap(host):
    # LDAP bind request (anonymous)
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 389), timeout=3)
        # LDAPMessage: BindRequest anonymous
        bind_req = bytes.fromhex("300c020101600702010304000480")
        sock.sendall(bind_req)
        data = sock.recv(64)
        sock.close()
        ok = len(data) > 4
        record("ldap", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("ldap", False, 0)

def w_dot(host):
    # DNS over TLS on port 853
    try:
        t0 = time.monotonic()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, 853), timeout=3)
        sock = ctx.wrap_socket(sock)
        # DNS-over-TLS: 2-byte length prefix + DNS query
        qname = b"\x07example\x03com\x00"
        dns_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
        msg = struct.pack("!H", len(dns_query)) + dns_query
        sock.sendall(msg)
        resp = sock.recv(512)
        sock.close()
        ok = len(resp) > 4
        record("dot", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("dot", False, 0)

def w_catch_all(host):
    # catch_all waits for client to send data first (PEEK_TIMEOUT=0.5s).
    # Send an HTTP GET so it detects the protocol and responds with HTTP 200.
    # Connect directly to port 9999 (iptables PREROUTING doesn't redirect loopback).
    try:
        t0 = time.monotonic()
        sock = socket.create_connection((host, 9999), timeout=5)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
        data = sock.recv(4096)
        sock.close()
        ok = b"HTTP/" in data
        record("catch_all", ok, int((time.monotonic() - t0) * 1000))
    except Exception:
        record("catch_all", False, 0)

# ── Service dispatch table ─────────────────────────────────────────────────────
SERVICES = {
    "http":      w_http,
    "https":     w_https,
    "smtp":      w_smtp,
    "smtps":     w_smtps,
    "pop3":      w_pop3,
    "pop3s":     w_pop3s,
    "imap":      w_imap,
    "imaps":     w_imaps,
    "ftp":       w_ftp,
    "telnet":    w_telnet,
    "irc":       w_irc,
    "ircs":      w_ircs,
    "socks5":    w_socks5,
    "dns":       w_dns,
    "ntp":       w_ntp,
    "tftp":      w_tftp,
    "mysql":     w_mysql,
    "mssql":     w_mssql,
    "rdp":       w_rdp,
    "smb":       w_smb,
    "vnc":       w_vnc,
    "redis":     w_redis,
    "ldap":      w_ldap,
    "dot":       w_dot,
    "catch_all": w_catch_all,
}

# ── Worker thread: loop until stop_event ──────────────────────────────────────
def worker(fn, host, stop_event):
    while not stop_event.is_set():
        fn(host)

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host",     default=DEFAULT_HOST)
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION)
    parser.add_argument("--workers",  type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--services", default="all",
                        help="Comma-separated list or 'all'")
    args = parser.parse_args()

    if args.services == "all":
        selected = SERVICES
    else:
        selected = {k: SERVICES[k] for k in args.services.split(",") if k in SERVICES}

    print(f"\n{'='*62}")
    print("  NotTheNet Load Test")
    print(f"  Host: {args.host}  Workers/service: {args.workers}  Duration: {args.duration}s")
    print(f"  Services: {', '.join(selected.keys())}")
    print(f"{'='*62}\n")

    stop_event = threading.Event()
    threads = []
    for _name, fn in selected.items():
        for _ in range(args.workers):
            t = threading.Thread(target=worker, args=(fn, args.host, stop_event), daemon=True)
            t.start()
            threads.append(t)

    # Progress bar
    for elapsed in range(args.duration):
        time.sleep(1)
        with stats_lock:
            total_ok  = sum(v["ok"]  for v in stats.values())
            total_err = sum(v["err"] for v in stats.values())
        bar = "#" * (elapsed + 1) + "-" * (args.duration - elapsed - 1)
        print(f"\r  [{bar}] {elapsed+1:3d}s  ok={total_ok:6d}  err={total_err:5d}", end="", flush=True)

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    # ── Print report ──────────────────────────────────────────────────────────
    print(f"\n\n{'='*62}")
    print(f"  {'Service':<12} {'OK':>7} {'ERR':>6} {'AvgMs':>7} {'MinMs':>7} {'MaxMs':>7} {'OK%':>6}")
    print(f"  {'-'*58}")
    grand_ok = grand_err = 0
    for name in sorted(stats.keys()):
        s = stats[name]
        ok  = s["ok"]
        err = s["err"]
        lats = s["latency"]
        avg  = int(sum(lats) / len(lats)) if lats else 0
        mn   = min(lats) if lats else 0
        mx   = max(lats) if lats else 0
        pct  = f"{100*ok/(ok+err):.0f}%" if (ok + err) else "n/a"
        grand_ok  += ok
        grand_err += err
        print(f"  {name:<12} {ok:>7} {err:>6} {avg:>7} {mn:>7} {mx:>7} {pct:>6}")
    print(f"  {'-'*58}")
    total = grand_ok + grand_err
    pct_all = f"{100*grand_ok/total:.1f}%" if total else "n/a"
    print(f"  {'TOTAL':<12} {grand_ok:>7} {grand_err:>6} {'':>7} {'':>7} {'':>7} {pct_all:>6}")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
