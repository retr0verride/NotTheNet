# Services Reference

This page describes every fake service that NotTheNet runs. Each service pretends to be a real network service (like a web server, email server, or DNS server) so that malware thinks it is talking to the real internet.

You don't need to understand every service to use NotTheNet — it works out of the box. Use this page as a reference when you want to know **what** a specific service does and **why** it responds the way it does.

## Table of Contents

- [DNS](#dns-service)
- [DNS-over-TLS (DoT)](#dns-over-tls-dot-service)
- [HTTP](#http-service)
- [HTTPS](#https-service)
- [SMTP](#smtp-service)
- [SMTPS](#smtps-service)
- [POP3](#pop3-service)
- [POP3S](#pop3s-service)
- [IMAP](#imap-service)
- [IMAPS](#imaps-service)
- [FTP](#ftp-service)
- [NTP](#ntp-service)
- [IRC](#irc-service)
- [IRCS / IRC-TLS](#ircs--irc-tls-service)
- [TFTP](#tftp-service)
- [Telnet](#telnet-service)
- [SOCKS5](#socks5-service)
- [ICMP Responder](#icmp-responder)
- [MySQL](#mysql-service)
- [MSSQL](#mssql-service)
- [RDP](#rdp-service)
- [SMB](#smb-service)
- [VNC](#vnc-service)
- [Redis](#redis-service)
- [LDAP](#ldap-service)
- [TCP Catch-All](#tcp-catch-all)
- [UDP Catch-All](#udp-catch-all)

---

## DNS Service

**What is DNS?** DNS translates domain names (like `evil-c2.com`) into IP addresses. It is the first thing almost all malware does when it tries to "phone home".

**File:** `services/dns_server.py`  
**Library:** [dnslib](https://github.com/paulc/dnslib) (pure Python)  
**Protocol:** UDP + TCP on port 53

### Behaviour

Every DNS query — regardless of type, domain, or record class — receives a response pointing to `resolve_to` (your NotTheNet IP). This means all domain lookups lead back to NotTheNet:

| Query Type | Response |
|------------|----------|
| `A` | `resolve_to` IP |
| `AAAA` | Returns A record with `resolve_to` (keeps malware happy without requiring IPv6) |
| `PTR` (reverse DNS) | Returns a synthetic ISP-style hostname (e.g. `static-8-8-8-8.res.example.net`) derived from the queried IP (when `handle_ptr: true`) |
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
# → static-8-8-8-8.res.example.net.

# AAAA (returned as A)
dig @127.0.0.1 evil.com AAAA +short
# → 127.0.0.1

# Custom override
dig @127.0.0.1 update.microsoft.com +short
# → whatever you set in custom_records
```

---

## DNS-over-TLS (DoT) Service

**What is DoT?** Some malware encrypts its DNS lookups inside a TLS tunnel to avoid detection. This service intercepts those encrypted DNS queries.

**File:** `services/dot_server.py`  
**Protocol:** TCP on port 853 with TLS  
**RFC:** [7858](https://datatracker.ietf.org/doc/html/rfc7858)  
**Requires:** dnslib (same as DNS service)

### Behaviour

Identical to the plain DNS server, but wrapped in TLS encryption. All DNS features (custom records, NCSI overrides, etc.) work the same way inside the encrypted tunnel.

Each DNS message is framed with a 2-byte big-endian length prefix as required by RFC 7858 (same framing as DNS-over-TCP per RFC 1035 §4.2.2). Multiple queries can be pipelined over a single TLS connection; the session times out after 10 s of inactivity.

### TLS Configuration

| Setting | Value |
|---------|-------|
| Minimum version | TLS 1.2 |
| ALPN | `"dot"` (RFC 7858 §4.1) |
| Certificate | Shared with HTTPS (`certs/server.crt` / `certs/server.key`) |

Because DoT reuses the HTTPS certificate, installing `certs/ca.crt` (the NotTheNet Root CA) in the analysis VM trust store makes DoT lookups appear fully validated.

### Connection Model

- Accepts on a raw `socket.SOCK_STREAM` socket, performs TLS handshake in the accept loop before submitting to the thread pool
- Bounded to `ThreadPoolExecutor(50)` workers — degrades gracefully under load
- Handshake failures (`ssl.SSLError`, `OSError`) log at DEBUG and continue without killing the loop
- Stop is clean: `SHUT_RDWR` forces the accept loop to unblock, then the pool is drained with `cancel_futures=True`

### Key Design Decisions vs INetSim/FakeNet-NG

- **Shared resolver** — all DNS anti-detection features (DGA NXDOMAIN, public IP pool, FCrDNS) apply over DoT without any duplication
- **Correct framing** — many fake DNS servers use raw `recv()` without length-prefix handling; malware that follows RFC 7858 framing exactly will get correct responses
- **Same cert as HTTPS** — no extra certificate management; analysts who have already installed the root CA get transparent DoT interception

### Verifying

```bash
# Requires kdig (knot-dnsutils) or any RFC 7858 DoT client
kdig @127.0.0.1 +tls-ca=certs/ca.crt c2.evil.com A +short
# → 127.0.0.1

# With openssl (manual framing test)
openssl s_client -connect 127.0.0.1:853 -quiet 2>/dev/null
# → Server sends TLS handshake, ALPN=dot

# Skip CA validation
kdig @127.0.0.1 +tls-no-auth c2.evil.com A +short
# → 127.0.0.1
```

---

## HTTP Service

**What is HTTP?** HTTP is the protocol your web browser uses. Malware uses it to download payloads, send stolen data, and communicate with command-and-control (C2) servers.

**File:** `services/http_server.py`  
**Protocol:** TCP on port 80  
**Model:** Threaded (`ThreadPoolExecutor`, max 50 workers)

### Behaviour

Responds to **every** HTTP request — any method (`GET`, `POST`, `PUT`, etc.), any path, any host header.

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
| ALPN | `h2`, `http/1.1`; HTTP/2 clients receive SETTINGS + GOAWAY(HTTP_1_1_REQUIRED) |
| Cipher suites | ECDHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-CHACHA20-POLY1305 and ECDSA variants |
| Key exchange | Ephemeral ECDHE (forward secrecy) |
| Certificate | 4096-bit RSA, self-signed, SHA-256 |
| SAN | localhost, notthenet.local, 127.0.0.1 |
| SCT extension | Fake `SignedCertificateTimestampList` (RFC 6962 v1) present in all certs |

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

**What is SMTP?** SMTP is the protocol for sending email. Malware uses it to send spam, exfiltrate data, or communicate with C2 servers via email.

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

## SMTPS Service

**File:** `services/mail_server.py` (`SMTPSService` class)  
**Protocol:** TCP on port 465 — TLS-wrapped SMTP (implicit TLS)

### Behaviour

Identical to [SMTP](#smtp-service) but the TLS handshake happens immediately on connection (implicit TLS, RFC 8314). Supports the same ESMTP command set, same email saving logic, and same credential capture. Uses `certs/server.crt` / `certs/server.key` from the HTTPS config.

### Verifying

```bash
openssl s_client -connect 127.0.0.1:465 -quiet
# 220 mail.example.com ESMTP Postfix
EHLO test
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@corp.com>
DATA
Subject: Test
.
QUIT
```

---

## POP3S Service

**File:** `services/mail_server.py` (`POP3SService` class)  
**Protocol:** TCP on port 995 — TLS-wrapped POP3 (implicit TLS)

### Behaviour

Identical to [POP3](#pop3-service) over an immediate TLS connection. Presents an empty mailbox, accepts any credentials, and logs the attempt. Uses `certs/server.crt` / `certs/server.key`.

### Verifying

```bash
openssl s_client -connect 127.0.0.1:995 -quiet
# +OK NotTheNet POP3 server ready
USER anything
PASS anything
STAT
# +OK 0 0
QUIT
```

---

## IMAP Service

**File:** `services/mail_server.py` (`IMAPService` class)  
**Protocol:** TCP on port 143

### Behaviour

Presents an empty IMAP mailbox. Accepts any credentials (`LOGIN` or `AUTHENTICATE PLAIN`), always returns `OK`. Clients can `SELECT INBOX` and issue `SEARCH` or `FETCH` commands — all return empty results. This satisfies malware that polls for email responses or exfiltrated data via IMAP.

### Supported Commands

`CAPABILITY`, `LOGIN`, `AUTHENTICATE PLAIN`, `SELECT`, `EXAMINE`, `LIST`, `LSUB`, `STATUS`, `SEARCH`, `FETCH`, `UID FETCH`, `LOGOUT`, `NOOP`

### Verifying

```bash
nc 127.0.0.1 143
# * OK NotTheNet IMAP4rev1
A001 LOGIN anything secret
# A001 OK LOGIN completed
A002 SELECT INBOX
# * 0 EXISTS
# A002 OK SELECT completed
A003 LOGOUT
```

---

## IMAPS Service

**File:** `services/mail_server.py` (`IMAPSService` class)  
**Protocol:** TCP on port 993 — TLS-wrapped IMAP (implicit TLS)

### Behaviour

Identical to [IMAP](#imap-service) over an immediate TLS connection. Uses `certs/server.crt` / `certs/server.key`.

### Verifying

```bash
openssl s_client -connect 127.0.0.1:993 -quiet
# * OK NotTheNet IMAP4rev1
A001 LOGIN anything secret
# A001 OK LOGIN completed
A003 LOGOUT
```

---

## FTP Service

**File:** `services/ftp_server.py`  
**Protocol:** TCP on port 21 (control), passive data ports 50000–51000

### Behaviour

Full FTP control session — accepts any credentials, always returns `230 Login successful`. File listing always returns an empty directory. Active mode (`PORT`) is intentionally **not implemented** — it is an SSRF vector. Only passive mode (`PASV`) is supported.

When `allow_uploads: true`, uploaded files are written to `upload_dir` with UUID-prefixed filenames (no attacker control over filename or path). Upload cap: 50 MB per file, 200 MB total.

### Supported Commands

`USER`, `PASS`, `SYST`, `FEAT`, `PWD`, `CWD`, `TYPE`, `PASV`, `LIST`, `NLST`, `STOR`, `RETR`, `QUIT`, `NOOP`

### Verifying

```bash
ftp 127.0.0.1
# Name: anything
# Password: anything (or blank)
# 230 Login successful
ftp> ls
# (empty listing)
ftp> put /tmp/sample.bin
# 226 Transfer complete
# Check: ls logs/ftp_uploads/
```

---

## NTP Service

**What is NTP?** NTP synchronizes clocks over a network. Some malware checks the time via NTP to detect sandboxes that have incorrect clocks.

**File:** `services/ntp_server.py`  
**Protocol:** UDP on port 123

### Behaviour

Responds to time-sync requests with the **current system time**. This prevents malware from detecting it's in a sandbox by comparing system time to NTP time.

Response is always exactly 48 bytes (no amplification). Client's Transmit Timestamp is echoed as the Originate Timestamp per RFC 5905.

### Verifying

```bash
ntpdate -q 127.0.0.1
# stratum 2, offset X
# adjust time server 127.0.0.1

# Or with sntp:
sntp -t 5 127.0.0.1
```

---

## IRC Service

**What is IRC?** IRC (Internet Relay Chat) is an old chat protocol. Many botnets use IRC channels to receive commands from their operator.

**File:** `services/irc_server.py`  
**Protocol:** TCP on port 6667

### Behaviour

Fake IRC server that captures botnet C2 traffic. When a bot connects, it sends a realistic welcome message so the bot thinks it has joined its command channel. All commands the bot sends or receives are logged.

| Command | Handling |
|---------|----------|
| `NICK` / `USER` | Completes registration, sends welcome burst |
| `JOIN #channel` | Joins the channel, sends JOIN echo |
| `PRIVMSG` | Logged; no response (operator side) |
| `KICK` / `MODE` / `WHO` / `WHOIS` | Accepted; minimal valid reply |
| `PING` | Immediate `PONG` |
| `QUIT` | Session closed |
| Unknown | `421 Unknown command` |

Lines are capped at 512 bytes per RFC 1459. Nick, channel, and message strings are sanitized before logging.

### Verifying

```bash
nc 127.0.0.1 6667
NICK bot123
USER bot 0 * :IRC Bot
# :irc.example.com 001 bot123 :Welcome to the IRCnet Network, bot123!
# ... (MOTD lines)
JOIN #botnet
# :bot123!bot@… JOIN :#botnet
QUIT
```

---

## IRCS / IRC-TLS Service

**File:** `services/irc_server.py` (`IRCSService` class)  
**Protocol:** TCP on port 6697 — TLS-wrapped IRC

### Behaviour

Identical to [IRC](#irc-service) but wrapped in TLS (implicit TLS on connection). Uses `certs/server.crt` / `certs/server.key`. All config options (`hostname`, `network`, `channel`, `motd`) apply identically.

### Verifying

```bash
openssl s_client -connect 127.0.0.1:6697 -quiet
NICK bot123
USER bot 0 * :Bot
# :irc.example.com 001 bot123 :Welcome to IRCnet
JOIN #botnet
QUIT
```

---

## TFTP Service

**What is TFTP?** TFTP (Trivial File Transfer Protocol) is a simple file transfer protocol with no authentication. Malware uses it to stage payloads and upload data.

**File:** `services/tftp_server.py`  
**Protocol:** UDP on port 69

### Behaviour

Handles both read and write requests:

| Request | Handling |
|---------|----------|
| **RRQ** (read) | Returns a small benign stub so the client's transfer completes without error and execution continues |
| **WRQ** (write) | Accepts and saves uploaded data for forensic analysis |

Each transfer uses its own ephemeral UDP socket (proper TID per RFC 1350 §4). Filenames are basename-sanitized to prevent path traversal. Uploads are UUID-prefixed and capped at 10 MB per file.

### Verifying

```bash
# Read (RRQ)
tftp 127.0.0.1
tftp> get malware.bin
# (receives stub content — transfer completes)

# Write (WRQ) — requires allow_uploads: true
tftp> put /tmp/sample.bin malware.bin
# Sent XXX bytes in ...
# Check: ls logs/tftp_uploads/
```

---

## Telnet Service

**What is Telnet?** Telnet is an old remote-login protocol with no encryption. Botnets like Mirai scan for Telnet on routers and IoT devices to spread.

**File:** `services/telnet_server.py`  
**Protocol:** TCP on port 23

### Behaviour

Pretends to be a Linux router (BusyBox-style). Shows a login prompt, accepts any username and password, and then presents a fake shell. Commands the malware types (like `wget` to download a payload) are logged with realistic-looking responses so the bot keeps going.

### Supported Shell Responses

| Command | Response |
|---------|----------|
| `id` | `uid=0(root) gid=0(root)` |
| `uname -a` | Linux MIPS `4.19.0-18-mips` kernel string |
| `ls` | `bin dev etc lib proc root tmp usr var` |
| `wget` / `curl` | Download attempt logged; empty response |
| `exit` / `quit` | Session closed |

### Verifying

```bash
nc 127.0.0.1 23
# router login:
# Password:
# (any credentials accepted)
# # id
# uid=0(root) gid=0(root)
# # uname -a
# Linux router 4.19.0-18-mips …
```

---

## SOCKS5 Service

**What is SOCKS5?** SOCKS5 is a proxy protocol. Some malware tunnels its traffic through a SOCKS proxy to hide the true destination.

**File:** `services/socks5_server.py`  
**Protocol:** TCP on port 1080

### Behaviour

Fake SOCKS5 proxy that reveals the **true C2 destination** — even when DNS has already been redirected. When malware says "connect me to evil-c2.com:443", that destination is logged. This is valuable because it captures addresses the malware might not look up via DNS.

1. Completes RFC 1928 SOCKS5 handshake (no-auth)
2. Accepts `CONNECT` for IPv4, IPv6, and domain-name targets
3. Logs the requested destination (the key intel)
4. Returns success so the malware continues
5. Snoops tunnelled traffic: HTTP 200 for HTTP, TLS-like response for TLS `ClientHello`, generic banner otherwise

`BIND` and `UDP ASSOCIATE` commands are refused (SSRF / amplification vectors).

### Verifying

```bash
# Verify SOCKS5 handshake + CONNECT
curl --proxy socks5://127.0.0.1:1080 http://c2.evil.com/beacon
# → 200 OK (sinkholed)

# Check logs for captured destination:
grep "CONNECT" logs/notthenet.log
# → socks5 CONNECT → c2.evil.com:80
```

---

## ICMP Responder

**What is ICMP?** ICMP is the protocol behind `ping`. When malware pings an IP address, ICMP tells it whether the host is reachable.

**File:** `services/icmp_responder.py`  
**Protocol:** Raw ICMP socket (no port number)

### Behaviour

Logs all incoming ping packets. When used with gateway mode, every ping to any IP address appears to succeed — the Linux kernel sends the replies while this service captures the details for your logs.

### Logged Fields

| Field | Description |
|-------|-------------|
| `src` | Source IP of the ping sender |
| `dst` | Original destination IP (the "internet" address being pinged) |
| `icmp_id` | ICMP identifier (useful for correlating ping sequences) |
| `icmp_seq` | ICMP sequence number |

### Verifying

```bash
# From the analysis VM (with gateway mode active):
ping 8.8.8.8
# → replies arrive (kernel generates them after DNAT)

# On the NotTheNet host:
grep icmp logs/events.jsonl | tail -5
# → { "service": "icmp", "src": "10.0.0.5", "dst": "8.8.8.8", "icmp_seq": 1 }
```

---

## MySQL Service

**What is MySQL?** MySQL is a popular database server. Credential-stealing malware and web shells often try to connect to MySQL to steal data.

**File:** `services/mysql_server.py`  
**Protocol:** TCP on port 3306

### Behaviour

Pretends to be a MySQL 5.7 server. Captures usernames, database queries, and other intel:

1. Sends an authentic MySQL 5.7.39 Handshake V10 packet (random 20-byte auth challenge)
2. Reads the client `HandshakeResponse41` — extracts the **username** (arrives in plaintext)
3. Returns `OK` so the client proceeds to issue queries
4. Logs every `COM_QUERY` the client sends

The auth response is SHA1-hashed by the client, so the password is not directly recoverable — but the username, targeted database, and all query strings are captured.

### Verifying

```bash
mysql -h 127.0.0.1 -u root -ppassword
# (connects, receives MySQL 5.7 greeting)
# Check logs for captured username + queries
grep '"service":"mysql"' logs/events.jsonl
```

---

## MSSQL Service

**What is MSSQL?** Microsoft SQL Server is a database commonly found in corporate networks. Malware targets it for credential theft and lateral movement.

**File:** `services/mssql_server.py`  
**Protocol:** TCP on port 1433

### Behaviour

Fake SQL Server that captures credentials — including recovering the actual plaintext password (MSSQL's obfuscation is trivially reversible):

1. Reads TDS Pre-Login request
2. Responds with `ENCRYPTION = ENCRYPT_NOT_SUP` — forces the client to send `Login7` in plaintext
3. Parses the `Login7` record: extracts username and **decodes the password** (only XOR-obfuscated with nibble-swap + XOR 0xA5 — fully reversible)
4. Returns a TDS Login ACK so the client thinks it is authenticated

Both username and recovered plaintext password are logged.

### Verifying

```bash
python3 -c "
import socket, struct
s = socket.create_connection(('127.0.0.1', 1433))
# (Pre-Login + Login7 exchange — use sqlcmd or Impacket in practice)
"
# Or with Impacket:
impacket-mssqlclient sa:Password1@127.0.0.1
grep '"service":"mssql"' logs/events.jsonl
```

---

## RDP Service

**What is RDP?** Remote Desktop Protocol lets you control a Windows computer remotely. Ransomware gangs and brute-force bots frequently target it.

**File:** `services/rdp_server.py`  
**Protocol:** TCP on port 3389

### Behaviour

Fake RDP server that captures the Windows username from the connection request:

1. Reads the X.224 Connection Request TPDU (over TPKT)
2. Extracts the `mstshash` cookie — the **Windows username** sent before any authentication
3. Sends a valid X.224 Connection Confirm with `PROTOCOL_RDP` (no NLA) to keep the client engaged
4. Drains and logs follow-on traffic

The username from `mstshash` is captured without breaking any encryption.

### Verifying

```bash
xfreerdp /v:127.0.0.1 /u:Administrator /p:Password1 /cert-ignore 2>/dev/null &
grep '"service":"rdp"' logs/events.jsonl
# → { "service": "rdp", "src": "127.0.0.1", "username": "Administrator" }
```

---

## SMB Service

**What is SMB?** SMB (Server Message Block) is Windows file sharing. Worms like WannaCry and NotPetya spread through SMB vulnerabilities.

**File:** `services/smb_server.py`  
**Protocol:** TCP on port 445

### Behaviour

Fake SMB server that detects what vulnerability a scanner is probing for:

- **SMBv1 negotiate:** returns `STATUS_NOT_SUPPORTED` and logs the full dialect list. Logs an explicit **EternalBlue probe** warning when the dialect list matches the NSA exploit fingerprint (`NT LM 0.12` present)
- **SMBv2 negotiate:** returns `STATUS_NOT_SUPPORTED` in a valid SMB2 header and logs the dialect list

No partial sessions are created. No authentication is attempted. The **dialect list** in the Negotiate request reveals exactly what vulnerability the scanner is probing for.

### Key Intel: EternalBlue Detection

When a client sends a Negotiate request containing `NT LM 0.12` (the SMBv1 dialect), the service logs an `eternalblue_probe` flag in the event. This is a reliable indicator that the connecting host is either the EternalBlue exploit or a scanner looking for unpatched SMBv1.

### Verifying

```bash
smbclient -L //127.0.0.1 -N 2>/dev/null
grep '"service":"smb"' logs/events.jsonl
# → { "service": "smb", "dialect": "SMB2", "eternalblue_probe": false }
```

---

## VNC Service

**What is VNC?** VNC is a remote desktop tool (like RDP but cross-platform). RATs (Remote Access Trojans) and botnets often target it.

**File:** `services/vnc_server.py`  
**Protocol:** TCP on port 5900

### Behaviour

Fake VNC server that captures authentication attempts:

1. Sends RFB `003.008` version string
2. Reads client version string (reveals client software)
3. Offers security type 2 (VNC Auth)
4. Sends a random 16-byte challenge (`os.urandom(16)`)
5. Reads the 16-byte DES response and logs it alongside the challenge
6. Returns `SecurityResult = OK` — always accepts

The challenge + response pair is sufficient for offline DES brute-force of short VNC passwords.

### Verifying

```bash
vncviewer 127.0.0.1:5900
# (connection accepted; client version + DES response captured in logs)
grep '"service":"vnc"' logs/events.jsonl
# → { "service": "vnc", "src": "…", "client_version": "RFB 003.008",
#     "challenge_hex": "…", "response_hex": "…" }
```

---

## Redis Service

**What is Redis?** Redis is an in-memory database often left exposed on the internet. Attackers exploit it to plant cryptominers, web shells, and backdoor SSH keys.

**File:** `services/redis_server.py`  
**Protocol:** TCP on port 6379

### Behaviour

Fake Redis server that logs every command. Flags high-interest commands (like `CONFIG SET dir` which is how attackers write files to disk):

High-interest commands are flagged in the log:

| Command | Flag |
|---------|------|
| `AUTH password` | Logs captured password |
| `SLAVEOF ip port` | `high_interest` flag |
| `REPLICAOF ip port` | `high_interest` flag |
| `CONFIG SET dir ...` | `high_interest` flag |
| `CONFIG SET dbfilename ...` | `high_interest` flag |
| `SAVE` / `BGSAVE` | `high_interest` flag |
| `PING` | `+PONG` |
| `INFO` | Returns realistic Redis 7.0 server info |
| `SET` / `GET` | Logged; `+OK` / `$-1` |
| `QUIT` | Session closed |

### Verifying

```bash
redis-cli -h 127.0.0.1
127.0.0.1:6379> AUTH secretpassword
# OK (password captured)
127.0.0.1:6379> CONFIG SET dir /var/www/html
# OK (high_interest flag in log)
127.0.0.1:6379> SLAVEOF 10.0.0.1 6379
# OK (high_interest flag in log)
grep '"service":"redis"' logs/events.jsonl
```

---

## LDAP Service

**What is LDAP?** LDAP is the protocol used to query Active Directory (the user/computer database in Windows networks). Attackers use tools like BloodHound and Mimikatz to enumerate users and extract credentials via LDAP.

**File:** `services/ldap_server.py`  
**Protocol:** TCP on port 389

### Behaviour

Fake LDAP server that captures login attempts:

1. When a client connects and tries to log in, the server extracts the **username** (e.g. `CN=svc_backup,OU=Service Accounts,DC=corp,DC=local`) and the **password in plaintext** (LDAP SimpleBind sends passwords unencrypted)
2. Returns a successful response so the malware continues its enumeration
3. All subsequent queries are logged

### Verifying

```bash
ldapsearch -H ldap://127.0.0.1 -D "CN=admin,DC=corp,DC=local" -w Password1 -b "DC=corp,DC=local"
grep '"service":"ldap"' logs/events.jsonl
# → { "service": "ldap", "src": "…", "bind_dn": "CN=admin,DC=corp,DC=local",
#     "password": "Password1" }
```

---

## TCP Catch-All

**What is this?** A safety net for any TCP connection that doesn't match a specific service. If malware connects to an unusual port (like 4444 or 8080), this service catches it.

**File:** `services/catch_all.py`  
**Protocol:** TCP on port 9999 (with iptables REDIRECT from all other TCP ports not in `excluded_ports`)

### Behaviour

Any TCP connection that does not match a specific service port is redirected here by iptables. The catch-all performs protocol detection on the first bytes received and responds appropriately:

| Detected Protocol | Response |
|------------------|----------|
| TLS `ClientHello` | Completes TLS handshake using `certs/server.crt`, then applies HTTP logic inside |
| HTTP (`GET`, `POST`, `PUT`, etc.) | Sends a complete `200 OK` HTTP/1.1 response |
| Unknown / binary | Sends a generic TCP banner and drains the connection |

This ensures malware that connects to arbitrary ports (e.g. custom C2 port 4444, port 8080, etc.) always gets a successful response and continues executing.

The `excluded_ports` list prevents iptables from redirecting ports that are already handled by dedicated services.

### Verifying

```bash
# Connect to an unhandled port — should get a response
nc 127.0.0.1 4444
# → generic banner

# TLS on arbitrary port
openssl s_client -connect 127.0.0.1:8443 -quiet
# → TLS handshake succeeds
```

---

## UDP Catch-All

**What is this?** Same idea as TCP Catch-All, but for UDP traffic on unknown ports.

**File:** `services/catch_all.py` (`UDPCatchAll` class)  
**Protocol:** UDP on port 9998 (with iptables REDIRECT from all other UDP ports not in `excluded_ports`)

### Behaviour

Any UDP datagram to a port not handled by a dedicated service is redirected here. The service echoes a short reply to every datagram so UDP-probing malware gets a response and does not time out.

### Verifying

```bash
echo -n "test" | nc -u 127.0.0.1 5555
# → (reply received)
```

---

## JSON Event Logging

**What is this?** A structured log that every service writes to. Each line is a JSON object you can search, filter, and analyse with any tool.

**File:** `utils/json_logger.py`  
**Config:** `general.json_logging`, `general.json_log_file`

### Example events

```json
{"timestamp": "2026-03-04T14:23:01.123Z", "event": "dns_query", "src_ip": "10.0.0.50", "query_name": "evil-c2.com", "query_type": "A", "response_ip": "10.0.0.1"}
{"timestamp": "2026-03-04T14:23:01.456Z", "event": "http_request", "src_ip": "10.0.0.50", "method": "GET", "path": "/gate.php", "host": "evil-c2.com"}
{"timestamp": "2026-03-04T14:23:02.789Z", "event": "doh_request", "src_ip": "10.0.0.50", "method": "POST", "query_name": "dns.google", "response_ip": "10.0.0.1"}
```

### Viewing events in the GUI

The GUI includes a **JSON Events** page under the **ANALYSIS** sidebar group. It provides a live-updating treeview (polling every 1 s), text search, event-type dropdown filter, and a detail panel showing the raw JSON of the selected event.
