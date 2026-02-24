# Configuration Reference

All configuration is stored in `config.json` in the project root.  
The GUI exposes every field — you can also edit the JSON directly.

## Table of Contents

- [general](#general)
- [dns](#dns)
- [http](#http)
- [https](#https)
- [smtp](#smtp)
- [pop3](#pop3)
- [imap](#imap)
- [ftp](#ftp)
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
  "iptables_mode": "loopback"
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

## `catch_all`

The TCP catch-all service receives all traffic redirected by iptables from unknown ports.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `redirect_tcp` | bool | `true` | Enable the TCP catch-all service and iptables redirect. |
| `tcp_port` | int | `9999` | Port the catch-all TCP server listens on. iptables redirects all other TCP traffic here. |
| `redirect_udp` | bool | `false` | Enable a UDP catch-all (drain + respond `OK`). Disabled by default as it can break legitimate UDP (NTP, etc.). |
| `udp_port` | int | `9998` | Port for the UDP catch-all service. |
| `excluded_ports` | array | `[22, 53, 80, 443, 25, 110, 143, 21]` | TCP ports that **bypass** the catch-all redirect. Always include `22` (SSH) so you don't lock yourself out. |

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
