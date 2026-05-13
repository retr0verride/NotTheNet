# NotTheNet Linux Services Architecture Analysis

**Project:** NotTheNet - Multi-protocol fake network service framework
**Date:** May 2026
**Platform:** Linux (Kali, Debian-based)

---

## Executive Summary

NotTheNet implements a sophisticated, multi-service fake network framework using a **protocol-based service interface** with a registry-driven lifecycle manager. Services are loosely coupled via the `ServiceProtocol` interface, allowing independent implementations of DNS, HTTP/HTTPS, FTP, SMTP, MySQL, and 20+ other protocols. Threading strategies vary by protocol: DNS uses built-in async handlers, HTTP uses bounded thread pools, and FTP uses per-connection threads with semaphore limiting. All services follow **socket reuse + daemon thread** patterns to handle restart cleanly.

---

## 1. Base Service Pattern / Interface

### ServiceProtocol (Abstract Interface)

All services must implement the `ServiceProtocol` runtime-checkable interface defined in [services/base.py](services/base.py):

```python
@runtime_checkable
class ServiceProtocol(Protocol):
    """Minimal interface all NotTheNet services must satisfy."""

    enabled: bool

    def start(self) -> bool: ...      # Returns True on successful bind
    def stop(self) -> None: ...       # Clean shutdown

    @property
    def running(self) -> bool: ...    # True if thread alive
```

**Key Design Decisions:**
- **Runtime-checkable**: Pylance validates conformance statically; no explicit inheritance needed
- **Boolean enabled**: Configuration-driven opt-in per service
- **Idempotent stop()**: Safe to call multiple times
- **running property**: Queried by ServiceManager for health checks

### Service Registry (_SERVICE_REGISTRY)

The master list of all services is in [service_manager.py](service_manager.py):

```python
@dataclass(frozen=True)
class ServiceSpec:
    name: str                # e.g., "dns", "http", "ftp"
    factory: type            # Class constructor (e.g., DNSService)
    config_section: str      # Config file section (e.g., "http")
    default_port: int        # Fallback port (0 = no fixed port)
    protocol: str            # "tcp" | "udp" | "both"
    tls: bool = False        # Requires cert/key
    bind_ip: bool = True     # Passed bind_ip parameter

_SERVICE_REGISTRY = [
    ServiceSpec("dns",       DNSService,         "dns",       53,   "both"),
    ServiceSpec("https",     HTTPSService,       "https",     443,  "tcp",  tls=True),
    ServiceSpec("ftp",       FTPService,         "ftp",       21,   "tcp"),
    # ... 27 more services
]
```

**30+ Registered Services:**
- **DNS/DoT:** DNS, DNS-over-TLS
- **Web:** HTTP, HTTPS, DoH (DNS-over-HTTPS)
- **Mail:** SMTP, SMTPS, POP3, POP3S, IMAP, IMAPS
- **File Transfer:** FTP, TFTP, SMB
- **Databases:** MySQL, MSSQL
- **Remote Access:** RDP, Telnet, SSH (via catch-all), VNC, SOCKS5
- **Other:** IRC, IRCS, NTP, LDAP, Redis, catch-all UDP/TCP

---

## 2. Key Implementation Details by Service Type

### 2.1 DNS Server (services/dns_server.py)

**Architecture:** Async UDP + TCP via dnslib.DNSServer wrapper

**Threading Model:**
```python
# Manual thread creation with reduced polling
for srv in (self._server_udp, self._server_tcp):
    def _run(s=srv):
        s.isRunning = True
        s.server.serve_forever(poll_interval=2.0)  # Reduces wakeups
        s.isRunning = False
    srv.thread = threading.Thread(target=_run, daemon=True)
    srv.thread.start()
```

**Key Features:**
1. **Unified resolver** (`_FakeResolver` class) handles A, AAAA, MX, TXT, NS, SOA, SRV, CAA, PTR, CNAME records
2. **Special DNS probes:**
   - Windows NCSI: `dns.msftncsi.com` → hardcoded `131.107.255.255`
   - Forward-confirmed reverse DNS (FCrDNS): synthetic PTR records with embedded IPs
3. **DGA detection:** High-entropy labels return NXDOMAIN (blocks algorithm-generated domains)
4. **Kill-switch domains:** Exact name + subdomain matching → NXDOMAIN
5. **Custom record overrides:** Config-driven rewrites for specific hostnames
6. **Public IP pool:** Rotate through pool of realistic-looking IPs instead of always returning redirect_ip

**Response Pipeline:**
1. Parse DNS query (qname, qtype)
2. Validate hostname length (≤253 chars, RFC 1035 §2.3.4)
3. Check custom records → Windows NCSI → per-qtype handler → entropy check → public pool
4. **Emit structured log** with actual resolution (not configured redirect_ip)

**Socket Pattern:**
```python
self._server_udp = DNSServer(resolver, port=self.port, address=self.bind_ip, tcp=False)
self._server_tcp = DNSServer(resolver, port=self.port, address=self.bind_ip, tcp=True)
```

---

### 2.2 HTTP / HTTPS Server (services/http_server.py)

**Architecture:** ThreadingTCPServer + ThreadPoolExecutor (50 workers)

**Threading Model:**
```python
class _ThreadedServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self._pool = ThreadPoolExecutor(max_workers=50)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        # Drain thread pool to bounded size
        self._pool.submit(self.process_request_thread, request, client_address)

    def process_request_thread(self, request, client_address):
        request.settimeout(30)  # Prevent indefinite HTTP/2 preface hangs
        super().process_request_thread(request, client_address)
```

**Handler Architecture:**

```python
class FakeHTTPHandler(http.server.BaseHTTPRequestHandler):
    # Route registry: predicates + handlers (priority order)
    _ROUTES = [
        (lambda s, h: s._cfg.doh_enabled, FakeHTTPHandler._route_doh),
        (lambda s, h: h in _NCSI_HOSTS, FakeHTTPHandler._route_ncsi),
        (lambda s, h: h in _PKI_HOSTS, FakeHTTPHandler._route_pki),
        (lambda s, h: h in _IP_CHECK_HOSTS, FakeHTTPHandler._route_ip_check),
        (lambda s, h: h in _TELEGRAM_HOST, FakeHTTPHandler._route_telegram),
        # ... 15 more routes
    ]

    def do_GET(self):
        # Dispatch via route registry
        for predicate, handler in self._ROUTES:
            if predicate(self, host) and handler(self, host):
                return
        self._send_normal_response()
```

**Response Categories:**

1. **Windows Connectivity Checks (NCSI):**
   - Hosts: `www.msftconnecttest.com`, `www.msftncsi.com`, `ipv6.msftconnecttest.com`
   - Returns exact byte-for-byte Microsoft responses
   - `/redirect` endpoint returns HTTP 302 HTTPS redirect

2. **Captive Portal Detection:**
   - Google: `connectivitycheck.gstatic.com` → HTTP 204 (empty response)
   - Apple: `captive.apple.com` + `/hotspot-detect.html` → HTML success page
   - Android: `clients*.google.com`, `ipv4.google.com`

3. **PKI Infrastructure (CRL/OCSP/CTL):**
   - Hosts: crl.microsoft.com, ocsp.digicert.com, ctldl.windowsupdate.com, etc.
   - Returns DER-encoded binary stubs (not HTML) to prevent certificate validation failures

4. **IP Detection Services (for IP spoofing):**
   - Hosts: ipify.org, ip-api.com, httpbin.org, icanhazip.com, etc.
   - Returns JSON/plaintext with configurable spoofed public IP
   - Geo data hardcoded to Columbus, OH (Comcast ISP)

5. **Cloud Exfiltration Interception:**
   - AWS S3: Virtual-hosted (`{bucket}.s3.amazonaws.com`) + path-style
   - Azure Blob: `{account}.blob.core.windows.net`
   - Google Drive: `docs.google.com`, `sheets.google.com`, `drive.googleapis.com`
   - Dropbox, OneDrive APIs captured

6. **Stealer/RAT Command & Control:**
   - **Telegram Bot API**: `api.telegram.org` → returns `{"ok": true, ...}`
   - **Discord webhooks**: `discord.com`, `discordapp.com` → `{"id": "..."}` JSON
   - **Slack webhooks**: `hooks.slack.com` → `"ok"` plaintext
   - **Pastebin/paste sites**: Multiple hosts → log + return `{"key": "..."}`

7. **Normal Response (dynamic or static):**
   - Default HTML page + custom status code + custom headers
   - Optional dynamic response generator (content-type based on path)
   - Optional delays + jitter for sandbox evasion

**HTTP/2 Preface Detection:**
```python
if self.raw_requestline.startswith(self._HTTP2_PREFACE_LINE):
    # HTTP/2 client attempting h2 upgrade
    # Respond with SETTINGS frame + GOAWAY(HTTP_1_1_REQUIRED)
    self._handle_http2_goaway()
    self.close_connection = True
```

**CONNECT Tunnel Handling:**
```python
def _send_connect_response(self):
    # Proxy tunnel requests: return 200, drain until client closes
    self.wfile.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    self.request.settimeout(30)
    while self.request.recv(4096):
        pass  # Drain (TLS handshake bytes, etc.)
```

**Configuration:**
```python
@dataclass(frozen=True)
class _HandlerConfig:
    response_code: int = 200
    response_body: bytes = b""
    server_header: str = "Apache/2.4.51"
    log_requests: bool = True
    spoof_ip: str = ""                    # For IP-check routes
    delay_ms: int = 0
    delay_jitter_ms: int = 0
    dynamic_responses: bool = False
    custom_rules: list = []               # For path-based response selection
    doh_enabled: bool = False
    doh_redirect_ip: str = "127.0.0.1"
    websocket_intercept: bool = False
    pool_ips: frozenset = frozenset()     # IP-check hosts to spoof
    exfil_log_dir: str = "logs/exfil"
```

---

### 2.3 FTP Server (services/ftp_server.py)

**Architecture:** ThreadingTCPServer + per-connection thread + BoundedSemaphore

**Threading Model:**
```python
class _ReuseServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, request_handler_class, max_connections: int):
        self._sem = threading.BoundedSemaphore(max_connections)
        super().__init__(server_address, request_handler_class)

    def process_request(self, request, client_address):
        if not self._sem.acquire(blocking=False):
            request.close()  # Drop connection at limit
            return

        def _run():
            try:
                self.finish_request(request, client_address)
            finally:
                self.shutdown_request(request)
                self._sem.release()

        t = threading.Thread(target=_run, daemon=True)
        t.start()
```

**Per-Connection Handler:**

Each FTP connection is a `_FTPSession(threading.Thread)` that:
1. Sends banner
2. Reads commands line-by-line (buffered with CRLF splitting)
3. Dispatches to handler methods

**FTP Command Responses:**
```python
_SIMPLE_RESPONSES = {
    "USER": "230 Login successful",
    "PASS": "230 Login successful",
    "SYST": "215 Windows_NT",
    "FEAT": "211-Features:\r\n PASV\r\n211 End",
    "PWD": '257 "/" is current directory',
    "PASV": "227 Entering Passive Mode (...)",  # Dynamic
    "LIST": "150 Here comes the directory listing\r\n...\r\n226 Send OK",
    "STOR": "150 Opening connection\r\n226 Transfer complete",
}
```

**Passive Mode Port Selection:**
```python
def _open_pasv(self) -> str | None:
    ports = list(range(self.pasv_port_low, self.pasv_port_high))
    random.shuffle(ports)  # Randomize for detection evasion
    for port in ports:
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_ip, port))
            srv.listen(1)
            srv.settimeout(self.pasv_timeout)
            # Encode as comma-separated octets (RFC 959)
            ip_parts = local_ip.replace(".", ",")
            p1, p2 = port >> 8, port & 0xFF
            return f"227 Entering Passive Mode ({ip_parts},{p1},{p2})"
```

**Upload Handling:**
- Disk space cap: 200 MB total
- Per-file cap: 50 MB
- UUID-based filenames (attacker cannot control saved filename)
- Thread-safe with `threading.Lock()` for shared disk-usage counter

**Active Mode Rejection:**
```python
"PORT": "500 Active mode not supported; use PASV"
# SSRF prevention: PORT command can be used to probe internal ports
```

---

## 3. Threading Approach

### Pattern 1: Async Built-in (DNS via dnslib)
- **Model:** Single server wraps async UDP/TCP implementation
- **Threads:** 2 (one UDP, one TCP with `serve_forever()`)
- **Scalability:** Unlimited concurrent queries (no thread-per-connection)
- **Pros:** No thread pool management overhead
- **Cons:** Limited to dnslib's implementation

### Pattern 2: Bounded Thread Pool (HTTP/HTTPS)
- **Model:** ThreadingTCPServer + ThreadPoolExecutor
- **Threads:** Fixed 50-worker pool shared for all connections
- **Scalability:** 50 concurrent connections max
- **Pros:** Prevents thread explosion, lightweight for short requests
- **Cons:** Long-held connections (HTTP keep-alive, slow clients) starve new connections

### Pattern 3: Per-Connection Thread with Semaphore (FTP)
- **Model:** Custom ThreadingTCPServer with BoundedSemaphore
- **Threads:** 1 thread per connection, capped by semaphore
- **Scalability:** Configurable limit (default 50)
- **Pros:** Supports long-lived stateful protocols, control flow
- **Cons:** Thread-per-connection overhead for high concurrency

### Global Patterns
- **Daemon threads:** `daemon_threads = True` prevents process hang on shutdown
- **Poll intervals:** DNS uses `poll_interval=2.0` to reduce idle CPU wakeups
- **Connection limits:** FTP semaphore + HTTP thread pool both max at 50
- **Timeouts:** 30-second read timeout prevents indefinite socket holds

---

## 4. Socket Binding and Listening Patterns

### Standard TCP Binding
```python
# In service start() method:
self._server = socketserver.ThreadingTCPServer(
    (self.bind_ip, self.port),
    RequestHandlerClass
)
self._thread = threading.Thread(
    target=self._server.serve_forever,
    kwargs={"poll_interval": 2.0},
    daemon=True
)
self._thread.start()
```

### Socket Reuse Configuration
All TCP servers set:
```python
class CustomServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True  # SO_REUSEADDR
    daemon_threads = True        # Don't hold process on exit
```

**Why SO_REUSEADDR is critical:**
- Default: TIME_WAIT state holds port for 60-120 seconds after close
- `allow_reuse_address = True` sets SO_REUSEADDR, allows immediate rebind
- Essential for rapid Stop → Start cycles (testing, restart on config change)

### Bind Address Selection
```python
bind_ip = config.get("general", "bind_ip") or "0.0.0.0"
# "0.0.0.0" = listen on all interfaces
# "127.0.0.1" = loopback only (lab testing)
# Specific IP = single interface (gateway mode)
```

### UDP Binding (DNS, NTP, TFTP)
```python
# dnslib handles UDP binding internally
self._server_udp = DNSServer(
    resolver, port=self.port, address=self.bind_ip, tcp=False
)

# Custom UDP (NTP, TFTP pattern):
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((self.bind_ip, self.port))
```

---

## 5. Connection Handling

### Accept Loop Pattern (TCP)
```
listen(backlog)
  └─→ serve_forever()
      └─→ [while self._BaseServer__shutdown_request is False]
          └─→ self._sock.accept()
              └─→ process_request(socket, client_address)
                  └─→ [ThreadPool/Thread] new handler thread
                      └─→ RequestHandler.handle()
                          └─→ User code (do_GET, _FTPSession.run(), etc.)
```

### Stateless Protocols (HTTP GET/POST, DNS queries)
1. Accept connection
2. Spawn handler thread
3. Handler reads request, generates response, sends
4. Close connection
5. Release thread back to pool

### Stateful Protocols (FTP, SMTP, MySQL)
1. Accept connection
2. Spawn handler thread
3. Handler sends banner
4. Loop: read command → process → send response
5. On QUIT/error, close connection
6. Release thread

### Connection Limits
- **HTTP**: 50 threads in ThreadPoolExecutor (cannot exceed)
- **FTP**: BoundedSemaphore(50) - new connections rejected if at limit
- **DNS**: Unlimited (async, not thread-per-request)

### Timeout Management
```python
# HTTP: read timeout on socket before handler spawns
request.settimeout(30)

# FTP: per-connection timeout
self.conn.settimeout(self.control_timeout)

# DNS: per-query timeout (dnslib internal)
```

---

## 6. Response Generation Logic

### DNS Response Flow
```
Query (hostname, record type)
  ├─→ Validate hostname length
  ├─→ Check custom_records override
  ├─→ Check Windows NCSI probe → hardcoded response
  ├─→ Dispatch to per-qtype handler (_resolve_a, _resolve_mx, etc.)
  │   └─→ For A records:
  │       ├─→ Check FCrDNS pattern (synthetic reverse hostname)
  │       ├─→ Check kill-switch domains
  │       ├─→ Check DGA entropy threshold
  │       └─→ Select from public_response_ips pool or redirect_ip
  ├─→ Build DNS response record (A/AAAA/MX/etc.)
  └─→ Emit structured JSON log with actual resolution result
```

### HTTP Response Flow
```
Request (Host header, path, method)
  ├─→ Parse HTTP request line
  ├─→ [Check HTTP/2 preface → send GOAWAY]
  ├─→ Extract Host header
  ├─→ Iterate route registry:
  │   ├─→ NCSI hosts? → Return exact Windows response
  │   ├─→ Captive portal? → Return 204 or success HTML
  │   ├─→ PKI hosts? → Return DER-encoded CRL/OCSP stub
  │   ├─→ IP-check hosts? → Return spoofed IP + geo JSON
  │   ├─→ Telegram/Discord/etc.? → Return C2 response JSON
  │   ├─→ Cloud exfil hosts? → Intercept/log upload
  │   └─→ [first match wins]
  └─→ [no match] → Send default response (HTML + custom status/headers)
```

### FTP Response Flow
```
Command (from control channel)
  ├─→ Parse command + arguments
  ├─→ Fast-path: fixed response dict
  │   └─→ USER, PASS, SYST, PWD, CWD, TYPE, NOOP, etc.
  ├─→ Dynamic responses:
  │   ├─→ PASV: Open random high-numbered port, return response
  │   ├─→ LIST: Accept data connection, send dir listing
  │   ├─→ STOR: Accept data connection, receive file to disk (with caps)
  │   ├─→ RETR/NLST: Accept data connection, drain it
  │   └─→ QUIT: Close control connection
  └─→ Send response back to client
```

### Configuration-Driven Responses
```python
# HTTP
response_body: str | from file
response_code: int
server_header: str
dynamic_responses: bool  # Match content-type to path
custom_rules: list       # Path regex → content-type + stub body

# FTP
banner: str
allow_uploads: bool
upload_dir: str
max_connections: int

# DNS
resolve_to: str  # Default redirect IP
ttl: int
custom_records: dict  # hostname → IP overrides
```

---

## 7. Platform-Specific Code Requiring Windows Adaptation

### 7.1 Network Redirection (CRITICAL)
**Status:** Linux-only via iptables

**Linux Implementation:**
```python
# network/iptables_manager.py
class IPTablesManager:
    def _apply_redirect_rules(self):
        """iptables -t nat -A PREROUTING -d <victim_ip> -p tcp --dport X -j REDIRECT --to-port Y"""
        # REDIRECT (localhost) or DNAT (remote gateway)
```

**Windows Alternative Needed:**
- Option 1: **NetSh + WinDivert** (packet filtering)
- Option 2: **WinDivert library** (user-mode packet filter)
- Option 3: **Proxy at application layer** (ARP spoofing relay)
- Option 4: **Hyper-V / WSL integration** (VM-level bridging)

**Impact on Services:** None directly (services bind normally), but test lab topology changes significantly.

---

### 7.2 Privilege Model (MODERATE)
**Status:** Linux-only root/unprivileged model

**Linux Implementation:**
```python
# utils/privilege.py
def drop_privileges(run_as_user: str = "nobody"):
    """os.setuid(), os.setgid() after binding ports"""
    # Ports 1-1024 require root; drop after binding

def require_root_or_warn():
    """Check os.geteuid() == 0"""
```

**Windows:** No equivalent (Windows doesn't restrict port binding to admin). Optional admin check.

---

### 7.3 Conflicting System Services (LOW)
**Status:** Linux systemctl integration

**Current:**
```python
def _evict_conflicting_services(self):
    """systemctl stop apache2 nginx bind9 dnsmasq systemd-resolved"""
    # Stops competing system services
```

**Windows:** Use `sc stop <service>` or taskkill instead. Less critical (fewer default services on Windows).

---

### 7.4 Process Masquerade (NICE-TO-HAVE)
**Status:** Linux setproctitle module

**Current:**
```python
import setproctitle
setproctitle.setproctitle("[kworker/u2:1-events]")  # Appears as kernel thread
```

**Windows:** Limited options:
- Cannot change process name post-launch
- Rename executable before launch (limited)
- No API equivalent to setproctitle

**Mitigation:** Accept that process name is visible.

---

### 7.5 TCP/IP OS Fingerprint Spoofing (DIAGNOSTIC)
**Status:** Linux tcpdump-based fingerprint modification

**Current:**
```python
# network/tcp_fingerprint.py
def apply_os_fingerprint(sock, os_name: str = "windows"):
    """Modify TCP MSS, window size, TTL, IP flags via tcpdump filter"""
    # Sets TCP option values to match target OS behavior
```

**Windows:** No direct equivalent. Optional feature (can disable).

---

### 7.6 ICMP Raw Sockets (NICHE)
**Status:** Linux raw socket responder

**Current:**
```python
# services/icmp_responder.py
class ICMPResponder:
    """Raw socket ICMP echo request → reply"""
    # Responds to ping requests
```

**Windows:** Raw ICMP requires admin + special handling. Can be stubbed or implemented via ICMP API.

---

### 7.7 OS-Level Connectivity Checks (TRANSPARENT)
**Status:** Handled in HTTP/HTTPS services

**Windows-Specific Responses (Already Implemented):**
- NCSI (Network Connectivity Status Indicator)
- Captive portal detection (Apple, Google)
- Certificate validation (CRL/OCSP)

**No Changes Needed:** HTTP handler already returns correct responses; they work on any OS.

---

## 8. Service Lifecycle and Startup

### ServiceManager.start() Flow
```
1. Validate config (or return error list)
2. Restore root privileges (if previously dropped)
3. [If auto_evict_services] Stop conflicting system services
4. [If auto_hardening] Run harden-lab.sh (iptables)
5. Check port conflicts (warn on duplicates)
6. Setup JSON logging (new session log file)
7. Setup TLS certs (if HTTPS/DoT enabled)
8. _start_all_services()
   └─→ For each ServiceSpec in _SERVICE_REGISTRY:
       1. _build_service(spec, bind_ip, spoof_ip, redirect_ip)
       2. Call svc.start()
           └─→ Bind socket, launch thread, return True/False
9. [If auto_iptables] Apply iptables REDIRECT/DNAT rules
10. Apply TCP/IP fingerprints (if enabled)
11. Apply process masquerade (if enabled)
12. [If drop_privileges] Drop to nobody:nogroup (permanent)
13. Return (started_names, failed_names)
```

### Service Configuration Resolution

**Special Services** (dns, dot, http, https) get config merging:
```python
# DNS in gateway mode auto-derives resolve_to from interface IP
if mode == "gateway" and configured_resolve in ("", "127.0.0.1"):
    dns_cfg["resolve_to"] = derived_redirect_ip  # from interface IP

# HTTP/HTTPS get spoof_public_ip + doh_redirect_ip injected
http_cfg.update({
    "spoof_public_ip": spoof_ip,
    "doh_redirect_ip": redirect_ip,
})
```

**Uniform Services** (others) get standard instantiation:
```python
svc = spec.factory(config_section, bind_ip=bind_ip)
```

---

## 9. Summary: Platform-Specific Adaptations for Windows

| Component | Linux | Windows Adaptation | Priority |
|-----------|-------|-------------------|----------|
| **iptables REDIRECT** | Native netfilter rules | WinDivert or netsh + ARP spoofing | CRITICAL |
| **Privilege drop** | `os.setuid()` after binding | Optional admin check | LOW |
| **Conflicting services** | `systemctl stop` | `sc stop` or taskkill | LOW |
| **Process masquerade** | `setproctitle` | N/A (accept visible process) | OPTIONAL |
| **TCP fingerprint** | tcpdump-based filters | Disable feature | OPTIONAL |
| **ICMP raw socket** | Raw socket responder | ICMP API or disable | NICHE |
| **Bash scripts** | harden-lab.sh | Port to PowerShell or disable | LOW |
| **JSON logging** | Works as-is | Works as-is | N/A |
| **Service threading** | Works as-is | Works as-is | N/A |
| **Socket reuse (SO_REUSEADDR)** | Works as-is | Works as-is | N/A |
| **Configuration (JSON/env)** | Works as-is | Test path separators | N/A |
| **HTTP/DNS responses** | Generic code | Works as-is | N/A |

---

## 10. Architecture Diagrams

### Service Lifecycle
```
ServiceOrchestrator
    │
    └─→ ServiceRepoAdapter (Adapter Pattern)
        │
        └─→ ServiceManager
            │
            ├─→ ServiceSpec Registry (_SERVICE_REGISTRY)
            │   ├─→ [dns, http, https, ftp, ...]
            │   └─→ (30+ services)
            │
            ├─→ _start_all_services()
            │   └─→ For each spec:
            │       ├─→ _build_service(spec, config)
            │       ├─→ svc.start() → bind socket, launch thread
            │       └─→ Store in _services dict
            │
            ├─→ _apply_iptables() [Linux-only]
            │
            └─→ _maybe_drop_privileges() [Linux-only]
```

### HTTP Request Dispatch
```
Request (Host: api.telegram.org, POST /bot...)
    │
    ├─→ FakeHTTPHandler.do_POST()
    │
    └─→ Route Registry Loop:
        ├─→ is_doh_request()? → _route_doh
        ├─→ host in _NCSI_HOSTS? → _route_ncsi
        ├─→ host in _CAPTIVE_PORTAL_HOSTS? → _route_captive
        ├─→ host in _PKI_HOSTS? → _route_pki
        ├─→ host in _IP_CHECK_HOSTS? → _route_ip_check
        ├─→ host == _TELEGRAM_HOST? → _route_telegram [MATCH]
        │   └─→ route_telegram(self, max_body_size, content_type)
        │       └─→ Intercept + log + return {"ok": true, ...}
        │
        └─→ [no match] → _send_normal_response()
```

### FTP State Machine (Per Connection)
```
Client connects
    │
    ├─→ Server: 220 <banner>
    │
    └─→ Loop:
        ├─→ Client: USER <name>
        ├─→ Server: 230 Login successful
        │
        ├─→ Client: PASV
        ├─→ Server: 227 Entering Passive Mode (IP,P1,P2)
        ├─→ [Open random high port for data]
        │
        ├─→ Client: STOR <filename>
        ├─→ Server: 150 Opening connection
        ├─→ [Accept data connection]
        ├─→ [Receive file → UUID filename]
        ├─→ Server: 226 Transfer complete
        │
        ├─→ Client: QUIT
        ├─→ Server: 221 Goodbye
        │
        └─→ Close control + data sockets
```

---

## 11. Key Takeaways for Windows Port

1. **Thread/Socket Basics Work:** Python threading, socket module, and TCP/UDP are OS-agnostic. No changes needed for core service logic.

2. **Network Redirection is Critical:** The entire lab setup depends on iptables (Linux) redirecting victim traffic. Windows needs an alternative (WinDivert, netsh, or proxy-based).

3. **Services are Loosely Coupled:** Via ServiceProtocol, adding Windows-specific adaptations (conditional iptables skip, privilege drop stub) is straightforward.

4. **Config + DI Abstraction Helps:** ServiceRepoAdapter uses a port-based interface, allowing easy swapping of platform-specific implementations.

5. **Response Handling is Generic:** HTTP, DNS, FTP responses are pure logic (no OS calls). Existing code handles Windows connectivity probes correctly.

6. **Test Coverage Essential:** Many Linux assumptions (root check, systemctl, bash scripts). Unit tests should stub these; integration tests verify on-platform behavior.

---

## References

- **Files Analyzed:**
  - `services/base.py` — Protocol definition
  - `service_manager.py` — Registry + lifecycle
  - `services/dns_server.py`, `http_server.py`, `ftp_server.py` — Examples
  - `infrastructure/di/container.py` — DI setup
  - `infrastructure/adapters/service_repo_adapter.py` — Adapter pattern

- **Key Patterns:**
  - Service Protocol (interface-based architecture)
  - Registry pattern (30+ services)
  - Factory pattern (service instantiation)
  - Adapter pattern (DI layer)
  - Route dispatch (HTTP handler)
  - Thread pool + semaphore (concurrency control)

---

**Document Generated:** May 13, 2026
**Analysis Scope:** Linux services directory + orchestration layer
**Next Steps:** Port networking layer (iptables → Windows) + privilege model
