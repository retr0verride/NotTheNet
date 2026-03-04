# Services Reference

Detailed technical reference for every fake service included in NotTheNet.

## Table of Contents

- [DNS](#dns-service)
- [HTTP](#http-service)
- [HTTPS](#https-service)
- [SMTP](#smtp-service)
- [POP3](#pop3-service)
- [IMAP](#imap-service)
- [FTP](#ftp-service)
- [TCP Catch-All](#tcp-catch-all)
- [UDP Catch-All](#udp-catch-all)

---

## DNS Service

**File:** `services/dns_server.py`  
**Library:** [dnslib](https://github.com/paulc/dnslib) (pure Python)  
**Protocol:** UDP + TCP on port 53

### Behaviour

Every DNS query — regardless of type, domain, or record class — receives a synthesised `A` record pointing to `resolve_to`. This affects:

| Query Type | Response |
|------------|----------|
| `A` | `resolve_to` IP |
| `AAAA` | Returns A record with `resolve_to` (keeps malware happy without requiring IPv6) |
| `PTR` (reverse DNS) | Returns `notthenet.local` (when `handle_ptr: true`) |
| `MX`, `NS`, `TXT`, `CNAME`, `SOA` | Returns `resolve_to` as an A record |
| Custom record override | Returns the configured IP for that specific hostname |

### Key Design Decisions vs INetSim/FakeNet-NG

- **Both UDP and TCP** listeners start simultaneously. Many INetSim setups only bind UDP, causing DNS-over-TCP failures when responses exceed 512 bytes.
- **SERVFAIL on parse error** — malformed or truncated DNS packets return SERVFAIL and never crash the server.
- **PTR handled correctly** — INetSim often ignores PTR queries, causing repeated reverse-lookup timeouts. NotTheNet answers them immediately.
- **Custom record overrides** — specific domains can resolve to different IPs without restarting.

### Verifying

```bash
# A record
dig @127.0.0.1 c2.evil.com A +short
# → 127.0.0.1

# PTR
dig @127.0.0.1 -x 8.8.8.8 +short
# → notthenet.local.

# AAAA (returned as A)
dig @127.0.0.1 evil.com AAAA +short
# → 127.0.0.1

# Custom override
dig @127.0.0.1 update.microsoft.com +short
# → whatever you set in custom_records
```

---

## HTTP Service

**File:** `services/http_server.py`  
**Protocol:** TCP on port 80  
**Model:** Threaded (`ThreadPoolExecutor`, max 50 workers)

### Behaviour

Responds identically to **every** HTTP request — any method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `CONNECT`, `TRACE`), any path, any host header.

#### Response body

The response body is loaded from `response_body_file` if set in `config.json` (e.g. `"assets/notthenet-page.html"`), otherwise the `response_body` string is used. The default ships with the **NotTheNet branded landing page** — a dark-themed splash page showing service status, which makes it immediately obvious to the analyst that traffic is being intercepted.

Response headers always include:
- `Content-Type: text/html; charset=utf-8`
- `Content-Length`
- `Server: <configured value>`
- `Connection: close`

### Public-IP Spoof

When `general.spoof_public_ip` is set to a non-empty IP string, any HTTP request whose `Host` header matches a well-known public-IP-check service is given a special response containing only the spoofed IP — either as plain text or as `{"ip": "<value>"}` JSON, matching the format the real service would return.

Services covered include: `api.ipify.org`, `icanhazip.com`, `checkip.amazonaws.com`, `ifconfig.me`, `httpbin.org/ip`, `ipecho.net/plain`, `myexternalip.com`, `wtfismyip.com`, `api4.my-ip.io`, `ip-api.com`, `ipinfo.io/ip`, and 10+ others.

When `spoof_public_ip` is blank (the default) the normal response body is served for all requests.

### Response Delay

The `response_delay_ms` option (default `0`) inserts an artificial sleep before every HTTP response. Values of 50–200 ms simulate realistic network round-trip latency and defeat timing-based sandbox-detection techniques used by some malware families.

### Dynamic Response Engine

**Config:** `http.dynamic_responses` (default: `true`)

When a request path contains a recognisable file extension, the server returns a response with the correct MIME type and a minimal valid file stub — a tiny file with the correct magic bytes and headers sufficient to pass basic checks.

**Covered extensions (70+):** `.exe`, `.dll`, `.bin`, `.elf`, `.so`, `.png`, `.jpg`, `.gif`, `.bmp`, `.ico`, `.pdf`, `.zip`, `.jar`, `.apk`, `.doc`, `.xls`, `.ppt`, `.docx`, `.xlsx`, `.pptx`, `.swf`, `.class`, `.ps1`, `.bat`, `.sh`, `.py`, `.vbs`, `.js`, `.mp3`, `.mp4`, `.avi`, `.woff`, `.ttf`, `.wasm`, and many more.

**Custom rules** (`http.dynamic_response_rules`) take priority over the built-in map. Each rule is a regex pattern matched against the request path, with a MIME type and Base64-encoded body. See [Configuration → Dynamic Response Rules](configuration.md#dynamic-response-rules).

**Resolution order:** custom rules → extension map → fallback static response (the configured `response_body` / `response_body_file`).

### DNS-over-HTTPS (DoH) Sinkhole

**Config:** `http.doh_sinkhole` (default: `true`)

Detects DNS-over-HTTPS requests by:
- `Content-Type: application/dns-message`
- Request path `/dns-query`

Handles both:
- **GET** — base64url-encoded DNS query in the `?dns=` parameter
- **POST** — raw DNS wire-format body

Builds a DNS response using `dnslib` pointing to `http.doh_redirect_ip` (default: `127.0.0.1`). Prevents malware from bypassing the fake DNS server via DoH to services like `dns.google`, `cloudflare-dns.com`, or `dns.quad9.net`.

### WebSocket Sinkhole

**Config:** `http.websocket_sinkhole` (default: `true`)

Detects WebSocket upgrade requests (`Connection: Upgrade`, `Upgrade: websocket`), completes the RFC 6455 handshake (101 Switching Protocols + `Sec-WebSocket-Accept`), drains up to 4 KB of incoming frames, logs a hex preview, then sends a clean close frame.

This satisfies malware that uses WebSocket-based C2 channels — the connection completes successfully, and the C2 frame data is captured in the log.

### Logged per request (when `log_requests: true`)

```
HTTP  GET /update/check.php from 127.0.0.1
HTTP  POST /gate.php from 192.168.100.20
```

### Verifying

```bash
curl -v http://127.0.0.1/any/path/at/all
curl -v -X POST http://127.0.0.1/gate.php -d "bot_id=abc123"

# Verify public-IP spoof (requires spoof_public_ip set, e.g. "93.184.216.34")
curl -H "Host: api.ipify.org" http://127.0.0.1/
# → 93.184.216.34

curl -H "Host: httpbin.org" http://127.0.0.1/ip
# → {"origin": "93.184.216.34"}

# Verify dynamic response (returns a minimal valid PE stub)
curl -o test.exe http://127.0.0.1/update/payload.exe
file test.exe
# → PE32 executable ...

# Verify DoH sinkhole
curl -H "Content-Type: application/dns-message" -X POST http://127.0.0.1/dns-query --data-binary @dns-query.bin
# → DNS response pointing to doh_redirect_ip

# Verify WebSocket sinkhole (using websocat or similar)
websocat ws://127.0.0.1/ws
# → Connection accepted, then cleanly closed
```

---

## HTTPS Service

**File:** `services/http_server.py` (`HTTPSService` class)  
**Protocol:** TCP on port 443 with TLS  
**TLS:** Minimum TLS 1.2, ECDHE + AEAD ciphers only

### TLS Configuration

| Setting | Value |
|---------|-------|
| Minimum version | TLS 1.2 |
| Disabled | SSLv2, SSLv3, TLS 1.0, TLS 1.1 |
| Cipher suites | ECDHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-CHACHA20-POLY1305 and ECDSA variants |
| Key exchange | Ephemeral ECDHE (forward secrecy) |
| Certificate | 4096-bit RSA, self-signed, SHA-256 |
| SAN | localhost, notthenet.local, 127.0.0.1 |

The certificate is auto-generated at `certs/server.crt` / `certs/server.key` on first start if not present.

### Public-IP Spoof and Response Delay

The HTTPS service shares the same public-IP spoof and response delay logic as HTTP. Both are configured in `general.spoof_public_ip` and `https.response_delay_ms` respectively. See the [HTTP section](#http-service) above for full details.

### Dynamic Responses, DoH Sinkhole, and WebSocket Sinkhole

The HTTPS service supports the same dynamic response engine, DoH sinkhole, and WebSocket sinkhole as HTTP — all operating inside the TLS tunnel. See the [HTTP section](#http-service) for details; configuration keys are identical but under the `https` section.

### Dynamic TLS Certificate Forging

**Config:** `https.dynamic_certs` (default: `true`)

When enabled, NotTheNet forges a unique TLS certificate for every hostname the client connects to. When malware connects to `https://evil-c2.com`, it receives a certificate with `CN=evil-c2.com` and a wildcard SAN (`*.evil-c2.com`), signed by NotTheNet's Root CA.

**How it works:**

1. On first start, a Root CA is auto-generated at `certs/ca.crt` / `certs/ca.key` (4096-bit RSA, 10-year validity)
2. An SNI callback is set on the `ssl.SSLContext` — when a client sends a `ClientHello` with a hostname, the callback fires
3. A per-domain certificate is generated on-the-fly, signed by the Root CA, with `AuthorityKeyIdentifier` extension
4. Certificates are cached in a thread-safe LRU cache (max 500 entries) for performance
5. Temporary cert files are written with sanitized filenames (hostname cleaned of path traversal characters) and mode `0o600`

**Installing the Root CA in the analysis VM:**

For malware that validates TLS certificates, install `certs/ca.crt` in the analysis VM's trust store:

- **Windows (FlareVM):** Double-click `ca.crt` → Install → Local Machine → Trusted Root Certification Authorities
- **Linux:** `sudo cp certs/ca.crt /usr/local/share/ca-certificates/notthenet.crt && sudo update-ca-certificates`

This allows full HTTPS interception without certificate errors.

### Verifying

```bash
# -k skips cert verification for self-signed
curl -kv https://127.0.0.1/

# Check TLS details
openssl s_client -connect 127.0.0.1:443 -no_ssl3 -no_tls1 2>&1 | head -30

# Verify public-IP spoof over TLS
curl -k -H "Host: api.ipify.org" https://127.0.0.1/
# → 93.184.216.34

# Verify dynamic cert forging (check CN matches requested host)
openssl s_client -connect 127.0.0.1:443 -servername evil-c2.com 2>/dev/null | openssl x509 -noout -subject
# → subject=CN = evil-c2.com

# Verify dynamic response over HTTPS
curl -ko /dev/null -w "%{content_type}" https://127.0.0.1/malware.dll
# → application/x-msdownload
```

---

## SMTP Service

**File:** `services/mail_server.py` (`SMTPService` class)  
**Protocol:** TCP on port 25  
**Standard:** RFC 5321 (ESMTP subset)

### Supported SMTP Commands

| Command | Response |
|---------|----------|
| `EHLO` / `HELO` | `250 <hostname>` |
| `MAIL FROM:<...>` | `250 Ok` |
| `RCPT TO:<...>` | `250 Ok` |
| `DATA` | `354 …` → waits for `.` on its own line |
| `RSET` | `250 Ok` |
| `NOOP` | `250 Ok` |
| `QUIT` | `221 Bye` |
| Unknown | `500 Unrecognized command` |

### Email Saving

When `save_emails: true`, received email bodies are written to `logs/emails/` as:
```
logs/emails/3f4a8b2e1c0d...hex.eml
```
- Filename is a UUID hex string — **the attacker has zero control over the filename or path**
- Per-message cap: 5 MB
- Total directory cap: 100 MB (messages discarded when exceeded, with a log warning)

### Verifying

```bash
nc 127.0.0.1 25
# 220 mail.notthenet.local ESMTP
EHLO test
MAIL FROM:<malware@evil.com>
RCPT TO:<victim@corp.com>
DATA
Subject: Ransomware invoice

Your files are encrypted. Pay 1 BTC.
.
QUIT
# Check: ls logs/emails/
```

---

## POP3 Service

**File:** `services/mail_server.py` (`POP3Service` class)  
**Protocol:** TCP on port 110

### Behaviour

Presents an **empty mailbox** (`STAT` returns `0 0`). All credential attempts return `+OK` (accepts any username/password). This satisfies malware that polls for email responses from C2.

### Supported Commands

`USER`, `PASS`, `STAT`, `LIST`, `UIDL`, `QUIT`, `CAPA`

### Verifying

```bash
nc 127.0.0.1 110
# +OK NotTheNet POP3 server ready
USER anything
# +OK
PASS anything
# +OK Logged in
STAT
# +OK 0 0
QUIT
```

---

## IMAP Service

**File:** `services/mail_server.py` (`IMAPService` class)  
**Protocol:** TCP on port 143  
**Standard:** IMAP4rev1 (minimal subset)

### Behaviour

Presents an empty `INBOX`. Accepts any `LOGIN` credentials. This satisfies malware that uses IMAP to check for C2 commands delivered as email.

### Supported Commands

`CAPABILITY`, `LOGIN`, `LIST`, `SELECT`, `LOGOUT`, `NOOP`

### Verifying

```bash
nc 127.0.0.1 143
# * OK mail.notthenet.local IMAP4rev1 ready
a1 LOGIN user pass
# a1 OK LOGIN completed
a2 SELECT INBOX
# * 0 EXISTS
# a2 OK [READ-WRITE] SELECT completed
a3 LOGOUT
```

---

## FTP Service

**File:** `services/ftp_server.py`  
**Protocol:** TCP control on port 21; data on dynamic PASV ports 50000–51000

### Behaviour

Accepts all logins, responds to all commands with success. Acts as a data sink — receives uploads, discards or saves them. Always reports transfers as successful.

### Supported Commands

| Command | Notes |
|---------|-------|
| `USER`, `PASS` | Always `230 Login successful` |
| `PASV` | Opens a port in range 50000–51000 |
| `PORT` | **Disabled** (SSRF/lateral movement risk) |
| `LIST` | Returns empty directory listing |
| `STOR` | Accepts file upload; saves if `allow_uploads: true` |
| `RETR` | Sends empty data connection; always `226 Transfer complete` |
| `CWD`, `CDUP`, `MKD`, `RMD`, `DELE` | Always succeed |
| `QUIT` | `221 Goodbye` |

### Upload Saving

Uploaded files are saved to `logs/ftp_uploads/` with UUID hex filenames (`.bin` extension). The cap is 50 MB per file and 200 MB total directory usage.

### Why PORT is disabled

The FTP `PORT` command tells the server to connect **back** to a client-specified IP:port. In a malware analysis context, this creates a Server-Side Request Forgery (SSRF) vector where malware could force the analysis host to connect to arbitrary internal IPs. NotTheNet refuses PORT commands with `500 Active mode not supported; use PASV`.

### Verifying

```bash
ftp 127.0.0.1
# Connected. Login with any credentials.
ls
# 226 Directory send OK.

# Test upload
put /etc/hostname
# 226 Transfer complete
# Check: ls logs/ftp_uploads/
```

---

## TCP Catch-All

**File:** `services/catch_all.py` (`CatchAllTCPService`)  
**Protocol:** TCP on the configured `catch_all.tcp_port` (default: 9999)

### Behaviour

Listens on the catch-all port. iptables redirects any TCP connection **not** already handled by a named service (and not in `excluded_ports`) to this port.

On connection:
1. Sends `200 OK\r\n`
2. Reads up to 1 KB of data (logged as a sanitised preview)
3. Closes the connection after `SESSION_TIMEOUT` (10 seconds)

This means malware that connects to any TCP port (custom C2 ports, custom protocols, etc.) receives a response and doesn't hang waiting.

### Verifying

```bash
# With iptables running, any non-excluded port should respond
nc 127.0.0.1 31337
# 200 OK

nc 127.0.0.1 4444
# 200 OK
```

---

## UDP Catch-All

**File:** `services/catch_all.py` (`CatchAllUDPService`)  
**Protocol:** UDP on `catch_all.udp_port` (default: 9998)  
**Default:** Disabled

### Behaviour

Receives a UDP datagram, logs the source and size, and replies with `OK\r\n`. Disabled by default because indiscriminate UDP interception can break legitimate services (NTP on port 123, mDNS on 5353, etc.).

Enable only when you specifically need to trap UDP-based C2 protocols and have carefully set `excluded_ports`.

### Verifying

```bash
echo -n "hello" | nc -u 127.0.0.1 9998
# OK
```

---

## JSON Event Logging

**File:** `utils/json_logger.py`  
**Config:** `general.json_logging`, `general.json_log_file`

When enabled, every service emits structured JSON events to a single `.jsonl` file. Each line is a self-contained JSON object with a timestamp, event type, source IP, and service-specific fields.

The logger is a module-level singleton (`JsonEventLogger`) that is thread-safe, file-size capped (500 MB), and auto-flushed. The convenience function `json_event()` is a fast no-op when logging is disabled, so there is zero overhead when the feature is off.

### Example events

```json
{"timestamp": "2026-03-04T14:23:01.123Z", "event": "dns_query", "src_ip": "10.0.0.50", "query_name": "evil-c2.com", "query_type": "A", "response_ip": "10.0.0.1"}
{"timestamp": "2026-03-04T14:23:01.456Z", "event": "http_request", "src_ip": "10.0.0.50", "method": "GET", "path": "/gate.php", "host": "evil-c2.com"}
{"timestamp": "2026-03-04T14:23:02.789Z", "event": "doh_request", "src_ip": "10.0.0.50", "method": "POST", "query_name": "dns.google", "response_ip": "10.0.0.1"}
```

### Viewing events in the GUI

The GUI includes a **JSON Events** page under the **ANALYSIS** sidebar group. It provides a live-updating treeview (polling every 1 s), text search, event-type dropdown filter, and a detail panel showing the raw JSON of the selected event.
