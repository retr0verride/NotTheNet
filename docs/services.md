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

### Logged per request (when `log_requests: true`)

```
HTTP  GET /update/check.php from 127.0.0.1
HTTP  POST /gate.php from 192.168.100.20
```

### Verifying

```bash
curl -v http://127.0.0.1/any/path/at/all
curl -v -X POST http://127.0.0.1/gate.php -d "bot_id=abc123"
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

### Verifying

```bash
# -k skips cert verification for self-signed
curl -kv https://127.0.0.1/

# Check TLS details
openssl s_client -connect 127.0.0.1:443 -no_ssl3 -no_tls1 2>&1 | head -30
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
