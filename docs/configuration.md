# Configuration Reference

All configuration is stored in `config.json` in the project root.  
The GUI exposes every field — you can also edit the JSON directly.

## Table of Contents

- [general](#general)
- [dns](#dns)
- [http](#http)
- [https](#https)
- [smtp](#smtp)
- [smtps](#smtps)
- [pop3](#pop3)
- [pop3s](#pop3s)
- [imap](#imap)
- [imaps](#imaps)
- [ftp](#ftp)
- [ntp](#ntp)
- [irc](#irc)
- [ircs](#ircs)
- [tftp](#tftp)
- [telnet](#telnet)
- [socks5](#socks5)
- [icmp](#icmp)
- [mysql](#mysql)
- [mssql](#mssql)
- [rdp](#rdp)
- [smb](#smb)
- [vnc](#vnc)
- [redis](#redis)
- [ldap](#ldap)
- [catch\_all](#catch_all)
- [Custom DNS Records](#custom-dns-records)
- [Example Configurations](#example-configurations)

---

## `general`

Global settings that apply to all services.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind_ip` | string | `"0.0.0.0"` | IP address all services listen on. Use `"0.0.0.0"` to listen on all interfaces, or a specific IP to restrict to one interface. |
| `redirect_ip` | string | `"127.0.0.1"` | IP address returned by DNS for all queries. Should match the machine running NotTheNet. |
| `interface` | string | `"eth0"` | Network interface to apply iptables rules to. **Critical: set this to your isolated/internal interface, not your real network adapter.** |
| `log_dir` | string | `"logs"` | Directory for log files. Relative paths are resolved from the project root. |
| `log_level` | string | `"INFO"` | Python logging level. One of: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `log_to_file` | bool | `true` | Whether to write logs to `logs/notthenet.log` (rotating, 10 MB × 5 files). |
| `auto_iptables` | bool | `true` | Automatically apply iptables NAT REDIRECT rules when services start, and remove them when stopped. |
| `iptables_mode` | string | `"loopback"` | How iptables rules are applied. `"loopback"` = OUTPUT chain (local-only). `"gateway"` = PREROUTING chain (intercept traffic from other hosts). See [Network & iptables](network.md). |
| `spoof_public_ip` | string | `""` | When set, HTTP/HTTPS requests to well-known public-IP-check services (`api.ipify.org`, `icanhazip.com`, `checkip.amazonaws.com`, `ifconfig.me`, `httpbin.org`, and 15+ others) return this IP as plain text or JSON instead of the normal response body. Defeats malware that queries these services to detect sandbox environments. Leave blank to disable. Example: `"93.184.216.34"`. |
| `json_logging` | bool | `false` | Enable structured JSON Lines event logging. Every intercepted request is written as a JSON object to the event log file — one line per event. Useful for automated pipelines (CAPEv2, Splunk, ELK). |
| `json_log_file` | string | `"logs/events.jsonl"` | Path to the JSON Lines event log file. Relative paths resolve from the project root. File is size-capped at 500 MB. |
| `tcp_fingerprint` | bool | `false` | Enable TCP/IP OS fingerprint spoofing on all listening sockets. Modifies low-level TCP parameters so responses appear to come from the configured OS. Linux only. |
| `tcp_fingerprint_os` | string | `"windows"` | OS profile for TCP fingerprint spoofing. One of: `"windows"` (TTL=128, Win=65535), `"linux"` (TTL=64, Win=29200), `"macos"` (TTL=64, Win=65535), `"solaris"` (TTL=255, Win=49640). |

### Example

```json
"general": {
  "bind_ip": "0.0.0.0",
  "redirect_ip": "127.0.0.1",
  "interface": "virbr0",
  "log_dir": "logs",
  "log_level": "INFO",
  "log_to_file": true,
  "auto_iptables": true,
  "iptables_mode": "loopback",
  "json_logging": true,
  "json_log_file": "logs/events.jsonl",
  "tcp_fingerprint": true,
  "tcp_fingerprint_os": "windows"
}
```

---

## `dns`

Fake DNS server — resolves every query to `resolve_to`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the DNS service. |
| `port` | int | `53` | UDP + TCP port to listen on. |
| `resolve_to` | string | `"127.0.0.1"` | IP address returned for all A/AAAA queries. |
| `ttl` | int | `300` | DNS TTL in seconds for synthesised records. |
| `handle_ptr` | bool | `true` | When `true`, PTR (reverse DNS) queries return `notthenet.local`. When `false`, PTR queries get no answer. |
| `custom_records` | object | `{}` | Per-hostname overrides. Keys are lowercase hostnames; values are IP addresses. See [Custom DNS Records](#custom-dns-records). |

### Example

```json
"dns": {
  "enabled": true,
  "port": 53,
  "resolve_to": "127.0.0.1",
  "ttl": 300,
  "handle_ptr": true,
  "custom_records": {
    "update.microsoft.com": "127.0.0.1",
    "c2.malware.example": "10.0.0.5"
  }
}
```

---

## `http`

Fake HTTP server — returns a canned response to every request regardless of method or path.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the HTTP service. |
| `port` | int | `80` | TCP port to listen on. |
| `response_code` | int | `200` | HTTP status code to return. Common values: `200`, `404`, `302`. |
| `response_body` | string | `<html>…</html>` | HTTP response body (HTML string). Used only when `response_body_file` is not set. |
| `response_body_file` | string | `""` | Path to an HTML file to serve as the response body (e.g. `"assets/notthenet-page.html"`). Takes priority over `response_body`. |
| `server_header` | string | `"Apache/2.4.51 (Debian)"` | Value of the `Server:` response header. Change to mimic target infrastructure. |
| `log_requests` | bool | `true` | Log each HTTP request (method, path, client IP). |
| `response_delay_ms` | int | `0` | Artificial delay in milliseconds before each response. Values of 50–200 ms simulate realistic network latency and defeat timing-based sandbox detection. `0` = no delay. |
| `dynamic_responses` | bool | `true` | Enable the dynamic response engine. When a request path contains a recognisable file extension (`.exe`, `.dll`, `.pdf`, `.zip`, `.png`, etc.), the server returns a response with the correct MIME type and a minimal valid file stub (correct magic bytes/headers). Covers 70+ extensions. |
| `dynamic_response_rules` | array | `[]` | Custom regex-based response rules. Each rule is an object with `pattern` (regex matched against the request path), `mime` (MIME type), and `body` (Base64-encoded response body). Custom rules take priority over the built-in extension map. |
| `doh_sinkhole` | bool | `true` | Intercept DNS-over-HTTPS (DoH) queries. Detects requests by `Content-Type: application/dns-message` or the `/dns-query` path. Handles both GET (base64url `?dns=` parameter) and POST (raw wire-format body). Resolves all queries to `doh_redirect_ip`. |
| `doh_redirect_ip` | string | `"127.0.0.1"` | IP address to return for all intercepted DoH queries. |
| `websocket_sinkhole` | bool | `true` | Accept and sinkhole WebSocket upgrade requests. Completes the RFC 6455 handshake (101 Switching Protocols), drains up to 4 KB of incoming frames, logs a hex preview, then sends a clean close frame. Satisfies malware using WebSocket-based C2. |

---

## `https`

Fake HTTPS server with hardened TLS. Shares response configuration with HTTP.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the HTTPS service. |
| `port` | int | `443` | TCP port to listen on. |
| `cert_file` | string | `"certs/server.crt"` | Path to the PEM certificate. Auto-generated on first run if absent. |
| `key_file` | string | `"certs/server.key"` | Path to the PEM private key. Auto-generated on first run if absent. |
| `response_code` | int | `200` | HTTP status code. |
| `response_body` | string | `<html>…</html>` | Response body (HTML string). Used only when `response_body_file` is not set. |
| `response_body_file` | string | `""` | Path to an HTML file to serve (e.g. `"assets/notthenet-page.html"`). Takes priority over `response_body`. |
| `server_header` | string | `"Apache/2.4.51 (Debian)"` | `Server:` header value. |
| `log_requests` | bool | `true` | Log HTTPS requests. |
| `response_delay_ms` | int | `0` | Artificial delay in milliseconds before each response. Same as HTTP — 50–200 ms recommended to defeat timing-based sandbox detection. |
| `dynamic_responses` | bool | `true` | Enable the dynamic response engine (same behaviour as HTTP). |
| `dynamic_response_rules` | array | `[]` | Custom regex-based response rules (same format as HTTP). |
| `dynamic_certs` | bool | `true` | Enable per-domain TLS certificate forging. A Root CA is auto-generated at `certs/ca.crt` / `certs/ca.key`. On each TLS connection, the SNI hostname is read and a certificate with `CN=<hostname>` + wildcard SAN is forged on-the-fly, signed by the Root CA. Certificates are cached in a thread-safe LRU cache (max 500 entries). Install `certs/ca.crt` in the analysis VM's trust store for seamless HTTPS interception. |
| `doh_sinkhole` | bool | `true` | Intercept DNS-over-HTTPS queries inside the TLS tunnel (same behaviour as HTTP). |
| `doh_redirect_ip` | string | `"127.0.0.1"` | IP address to return for DoH queries over HTTPS. |
| `websocket_sinkhole` | bool | `true` | Accept and sinkhole WebSocket upgrades inside the TLS tunnel (same behaviour as HTTP). |

> **TLS details:** TLS 1.2 minimum. Protocols SSLv2, SSLv3, TLS 1.0, TLS 1.1 are disabled. Only ECDHE + AEAD cipher suites are accepted.

---

## `smtp`

Fake SMTP server — accepts connections, speaks ESMTP, optionally saves received emails to disk.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the SMTP service. |
| `port` | int | `25` | TCP port to listen on. |
| `hostname` | string | `"mail.example.com"` | Hostname used in EHLO/HELO response. |
| `banner` | string | `"220 mail.example.com ESMTP Postfix"` | The banner string sent on connection. |
| `save_emails` | bool | `true` | Save received email content to `logs/emails/` as `.eml` files (UUID filenames). Max 5 MB per email; total capped at 100 MB. |

---

## `pop3`

Minimal POP3 server. Reports an empty mailbox to keep clients happy.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the POP3 service. |
| `port` | int | `110` | TCP port. |
| `hostname` | string | `"mail.example.com"` | Hostname in the greeting banner. |

---

## `imap`

Minimal IMAP4rev1 server. Reports an empty INBOX.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the IMAP service. |
| `port` | int | `143` | TCP port. |
| `hostname` | string | `"mail.example.com"` | Hostname in the greeting banner. |

---

## `ftp`

Fake FTP server. Accepts uploads (saved with UUID filenames), always reports success.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the FTP service. |
| `port` | int | `21` | TCP control port. |
| `banner` | string | `"220 FTP Server Ready"` | FTP greeting banner. |
| `allow_uploads` | bool | `true` | If `true`, save uploaded files to `upload_dir`. If `false`, drain and discard uploads silently. |
| `upload_dir` | string | `"logs/ftp_uploads"` | Directory for uploaded files. Only used when `allow_uploads` is `true`. Max file: 50 MB. Total cap: 200 MB. |

> **Security note:** Active mode (PORT command) is disabled — it presents an SSRF risk. PASV only.

---

## `ntp`

NTP server — responds with current system time to defeat clock-skew sandbox detection.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the NTP service. |
| `port` | int | `123` | UDP port. |

---

## `irc`

Fake IRC server for capturing IRC-based botnet C2.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the IRC service. |
| `port` | int | `6667` | TCP port. |
| `hostname` | string | `"irc.example.com"` | IRC server hostname reported in welcome numerics. |
| `network` | string | `"IRCnet"` | IRC network name reported in `005 NETWORK=`. |
| `channel` | string | `"botnet"` | Default channel the server advertises in the welcome burst. |
| `motd` | string | `"Welcome to IRC."` | Message of the Day text. |

---

## `ircs`

TLS-wrapped IRC (implicit TLS on port 6697). Identical config keys to [`irc`](#irc).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the IRCS service. |
| `port` | int | `6697` | TCP port. |
| `hostname` | string | `"irc.example.com"` | IRC server hostname. |
| `network` | string | `"IRCnet"` | IRC network name. |
| `channel` | string | `"botnet"` | Default channel. |
| `motd` | string | `"Welcome to IRC."` | Message of the Day. |

---

## `tftp`

Fake TFTP server for capturing payload staging and exfiltration over UDP.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the TFTP service. |
| `port` | int | `69` | UDP port. |
| `allow_uploads` | bool | `true` | If `true`, save WRQ (write) uploads to `upload_dir`. |
| `upload_dir` | string | `"logs/tftp_uploads"` | Directory for uploaded files. UUID-prefixed names. Max 10 MB per file. |

---

## `telnet`

Fake BusyBox telnet shell for capturing Mirai-family botnet credential sprays.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the Telnet service. |
| `port` | int | `23` | TCP port. |
| `banner` | string | `"router login"` | Hostname shown in the login banner line. |
| `prompt` | string | `"# "` | Shell prompt string shown after successful login. |

---

## `socks5`

Fake SOCKS5 proxy that captures the true C2 destination inside CONNECT requests.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the SOCKS5 service. |
| `port` | int | `1080` | TCP port. |

---

## `icmp`

ICMP echo-request logger (raw socket). Works with iptables DNAT in `gateway` mode to make every ping appear to succeed.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the ICMP responder. No port — uses a raw socket. Requires root / `CAP_NET_RAW`. |

---

## `smtps`

TLS-wrapped SMTP (implicit TLS, port 465). Identical config keys to [`smtp`](#smtp).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the SMTPS service. |
| `port` | int | `465` | TCP port. |
| `hostname` | string | `"mail.example.com"` | SMTP hostname in banner and EHLO response. |
| `banner` | string | `"220 mail.example.com ESMTP Postfix"` | SMTP greeting banner. |
| `save_emails` | bool | `true` | Save received email bodies to `logs/emails/`. |

---

## `pop3s`

TLS-wrapped POP3 (implicit TLS, port 995). Identical config keys to [`pop3`](#pop3).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the POP3S service. |
| `port` | int | `995` | TCP port. |
| `hostname` | string | `"mail.example.com"` | POP3 server hostname. |

---

## `imaps`

TLS-wrapped IMAP (implicit TLS, port 993). Identical config keys to [`imap`](#imap).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the IMAPS service. |
| `port` | int | `993` | TCP port. |
| `hostname` | string | `"mail.example.com"` | IMAP server hostname. |

---

## `mysql`

Fake MySQL 5.7.x server for credential harvesting stealers (RedLine, Vidar, Raccoon).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the MySQL service. |
| `port` | int | `3306` | TCP port. |

---

## `mssql`

Fake Microsoft SQL Server for lateral movement and credential spray capture.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the MSSQL service. |
| `port` | int | `1433` | TCP port. |

---

## `rdp`

Fake RDP server for capturing ransomware operators, brute-force bots, and worm probes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the RDP service. |
| `port` | int | `3389` | TCP port. |

---

## `smb`

Fake SMB server for logging dialect negotiation and detecting EternalBlue probes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the SMB service. |
| `port` | int | `445` | TCP port. |

---

## `vnc`

Fake VNC server for capturing RAT password challenges and brute-force responses.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the VNC service. |
| `port` | int | `5900` | TCP port. |

---

## `redis`

Fake Redis server (RESP protocol) for capturing cryptominer C2 and webshell-planting attempts.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the Redis service. |
| `port` | int | `6379` | TCP port. |

---

## `ldap`

Fake LDAP server for capturing Active Directory enumeration (BloodHound, Mimikatz) and SimpleBind credentials.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the LDAP service. |
| `port` | int | `389` | TCP port. |

---

## `catch_all`

The TCP catch-all service receives all traffic redirected by iptables from unknown ports.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `redirect_tcp` | bool | `true` | Enable the TCP catch-all service and iptables redirect. |
| `tcp_port` | int | `9999` | Port the catch-all TCP server listens on. iptables redirects all other TCP traffic here. |
| `redirect_udp` | bool | `false` | Enable a UDP catch-all (drain + respond `OK`). Disabled by default as it can break legitimate UDP (NTP, etc.). |
| `udp_port` | int | `9998` | Port for the UDP catch-all service. |
| `excluded_ports` | array | `[21, 22, 23, 25, 53, 69, 80, 110, 123, 143, 389, 443, 445, 465, 993, 995, 1080, 1433, 3306, 3389, 5900, 6379, 6667, 6697, 9998, 9999]` | TCP ports that **bypass** the catch-all redirect. Always include `22` (SSH) so you don't lock yourself out. The default list excludes every dedicated-service port. |

---

## Custom DNS Records

The `dns.custom_records` object maps hostnames (lowercase) to IP addresses. These override the default `resolve_to` for specific names.

**Example use cases:**

```json
"custom_records": {
  "update.microsoft.com": "127.0.0.1",
  "windowsupdate.microsoft.com": "127.0.0.1",
  "c2.evil-domain.xyz": "10.0.0.100",
  "api.stripe.com": "127.0.0.1"
}
```

In the GUI, use the **Custom DNS Records** text box in the DNS config page:
```
update.microsoft.com = 127.0.0.1
c2.evil-domain.xyz = 10.0.0.100
```

---

## Example Configurations

### Minimal (DNS + HTTP only)

```json
{
  "general": { "bind_ip": "0.0.0.0", "redirect_ip": "127.0.0.1", "auto_iptables": true },
  "dns":  { "enabled": true,  "port": 53,  "resolve_to": "127.0.0.1" },
  "http": { "enabled": true,  "port": 80 },
  "https":{ "enabled": false },
  "smtp": { "enabled": false },
  "pop3": { "enabled": false },
  "imap": { "enabled": false },
  "ftp":  { "enabled": false },
  "catch_all": { "redirect_tcp": true, "tcp_port": 9999, "excluded_ports": [22] }
}
```

### Gateway Mode (intercept traffic from other VMs)

```json
{
  "general": {
    "bind_ip": "0.0.0.0",
    "redirect_ip": "192.168.100.1",
    "interface": "virbr0",
    "auto_iptables": true,
    "iptables_mode": "gateway"
  }
}
```

### Mimic a Specific Server

```json
{
  "http":  { "enabled": true, "server_header": "nginx/1.18.0 (Ubuntu)", "response_code": 200 },
  "https": { "enabled": true, "server_header": "nginx/1.18.0 (Ubuntu)", "response_code": 200 },
  "smtp":  { "enabled": true, "banner": "220 smtp.gmail.com ESMTP", "hostname": "smtp.gmail.com" }
}
```

### Full Interception (dynamic certs + dynamic responses + JSON logging)

```json
{
  "general": {
    "bind_ip": "0.0.0.0",
    "redirect_ip": "10.0.0.1",
    "interface": "eth0",
    "iptables_mode": "gateway",
    "json_logging": true,
    "json_log_file": "logs/events.jsonl",
    "tcp_fingerprint": true,
    "tcp_fingerprint_os": "windows"
  },
  "http": {
    "dynamic_responses": true,
    "doh_sinkhole": true,
    "websocket_sinkhole": true,
    "dynamic_response_rules": [
      { "pattern": "/update\\.php$", "mime": "application/octet-stream", "body": "TVqQ" }
    ]
  },
  "https": {
    "dynamic_responses": true,
    "dynamic_certs": true,
    "doh_sinkhole": true,
    "websocket_sinkhole": true
  }
}
```

---

## Dynamic Response Rules

The `dynamic_response_rules` array (available in both `http` and `https`) lets you define custom regex-based rules that take priority over the built-in extension map.

Each rule is an object with three keys:

| Key | Type | Description |
|-----|------|-------------|
| `pattern` | string | Python regex matched against the full request path (e.g. `"/update\\.php$"`). |
| `mime` | string | MIME type for the `Content-Type` header (e.g. `"application/octet-stream"`). |
| `body` | string | Base64-encoded response body. Decoded before sending. |

**Resolution order:** custom rules → extension map → fallback static response.

```json
"dynamic_response_rules": [
  {
    "pattern": "\\.config$",
    "mime": "application/xml",
    "body": "PD94bWwgdmVyc2lvbj0iMS4wIj8+Cjxjb25maWc+PC9jb25maWc+"
  },
  {
    "pattern": "/gate\\.php",
    "mime": "text/plain",
    "body": "T0s="
  }
]
```

---

## TCP/IP OS Fingerprint Profiles

When `general.tcp_fingerprint` is enabled, NotTheNet modifies low-level TCP/IP stack parameters on every listening socket so that responses mimic the chosen operating system. This defeats fingerprinting-based sandbox detection (e.g. Nmap OS scan, p0f).

| Profile | TTL | TCP Window Size | DF Bit | MSS |
|---------|-----|----------------|--------|-----|
| `windows` | 128 | 65535 | Set | 1460 |
| `linux` | 64 | 29200 | Set | 1460 |
| `macos` | 64 | 65535 | Set | 1460 |
| `solaris` | 255 | 49640 | Set | 1460 |

> **Linux only.** Uses Linux-specific `setsockopt` constants (`IP_TTL`, `TCP_WINDOW_CLAMP`, `IP_MTU_DISCOVER`, `TCP_MAXSEG`). Has no effect on other platforms.

---

## JSON Structured Event Logging

When `general.json_logging` is enabled, every intercepted request is written as a single JSON object per line to the configured `json_log_file` (default: `logs/events.jsonl`).

### Event Types

| Event Type | Source Service | Key Fields |
|-----------|---------------|------------|
| `dns_query` | DNS | `query_name`, `query_type`, `response_ip` |
| `http_request` | HTTP | `method`, `path`, `host`, `user_agent` |
| `doh_request` | HTTP/HTTPS | `query_name`, `method`, `response_ip` |
| `websocket_upgrade` | HTTP/HTTPS | `path`, `host` |
| `smtp_connection` | SMTP | `client_ip`, `commands` |
| `pop3_connection` | POP3 | `client_ip` |
| `imap_connection` | IMAP | `client_ip` |
| `ftp_connection` | FTP | `client_ip`, `commands` |
| `ftp_upload` | FTP | `filename`, `size` |
| `catch_all_tcp` | Catch-All | `client_ip`, `port`, `data_preview` |
| `catch_all_udp` | Catch-All | `client_ip`, `port`, `data_preview` |

### Integration with Analysis Pipelines

The JSONL format is directly ingestible by:
- **CAPEv2** — add the file as an auxiliary data source
- **Splunk** — use the `monitor` input with `sourcetype=_json`
- **ELK** — point Filebeat at the `.jsonl` file with JSON decoding enabled
- **jq** — `cat logs/events.jsonl | jq '.event'` for quick command-line filtering
