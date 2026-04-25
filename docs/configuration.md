# Configuration Reference

All configuration is stored in `config.json` in the project root.  
The GUI exposes every field — you can also edit the JSON directly.

## Table of Contents

- [general](#general)
- [dns](#dns)
- [dot](#dot)
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
- [victim](#victim)
- [Custom DNS Records](#custom-dns-records)
- [Example Configurations](#example-configurations)

---

## `general`

Global settings that apply to all services.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind_ip` | string | `"0.0.0.0"` | IP address all services listen on. Use `"0.0.0.0"` to listen on all interfaces, or a specific IP to restrict to one interface. For single-host testing, leave at default. For gateway mode with a separate victim VM, set to your lab interface IP (e.g. `"10.0.0.1"`). |
| `redirect_ip` | string | `"127.0.0.1"` | IP address returned by DNS for all queries. Should match the IP the victim machine reaches NotTheNet on — `127.0.0.1` for single-host, your lab interface IP (e.g. `"10.0.0.1"`) for gateway mode. |
| `interface` | string | `"eth0"` | Network interface to apply iptables rules to. **Critical: set this to your isolated/internal interface, not your real network adapter.** |
| `log_dir` | string | `"logs"` | Directory for log files. Relative paths are resolved from the project root. |
| `log_level` | string | `"INFO"` | Python logging level. One of: `DEBUG`, `INFO`, `WARNING`, `ERROR`. |
| `log_to_file` | bool | `true` | Whether to write logs to `logs/notthenet.log` (rotating, 10 MB × 5 files). |
| `auto_iptables` | bool | `true` | Automatically apply iptables NAT REDIRECT rules when services start, and remove them when stopped. |
| `iptables_mode` | string | `"gateway"` | How iptables rules are applied. `"loopback"` = OUTPUT chain (local-only). `"gateway"` = PREROUTING chain (intercept traffic from other hosts). See [Network & iptables](network.md). |
| `spoof_public_ip` | string | `""` | When set, HTTP/HTTPS requests to well-known public-IP-check services (`api.ipify.org`, `icanhazip.com`, `checkip.amazonaws.com`, `ifconfig.me`, `httpbin.org`, and 15+ others) return this IP as plain text or JSON instead of the normal response body. Defeats malware that queries these services to detect sandbox environments. Leave blank to disable. Example: `"93.184.216.34"`. |
| `json_logging` | bool | `true` | Enable structured JSON Lines event logging. Every intercepted request is written as a JSON object to the event log file — one line per event. Useful for automated pipelines (CAPEv2, Splunk, ELK). |
| `json_log_file` | string | `"logs/events.jsonl"` | Template base path for the JSON Lines event log. **Each session automatically creates a new session-labeled file** in the same directory: `events_YYYY-MM-DD_s1.jsonl`, `events_YYYY-MM-DD_s2.jsonl`, etc. The active session path is written back to config at runtime so the GUI JSON Events viewer always tails the current session. File is size-capped at 500 MB. |
| `drop_privileges` | bool | `true` | Drop from `root` to `drop_privileges_user`:`drop_privileges_group` after all ports are bound and iptables rules are applied. The `logs/` directory tree is `chown`'d to the target user before the drop so file saves, JSON exports, and the Open Logs button continue to work. |
| `drop_privileges_user` | string | `"nobody"` | Username to drop to when `drop_privileges` is `true`. |
| `drop_privileges_group` | string | `"nogroup"` | Group name to drop to when `drop_privileges` is `true`. |
| `process_masquerade` | bool | `true` | After startup, rename the process title to a kernel-thread-like string (e.g. `[kworker/u2:1-events]`) so it does not appear as `python3 notthenet.py` in `ps` or process monitors on the analysis host. Requires the `setproctitle` package (bundled in the offline installer). |
| `process_name` | string | `"[kworker/u2:1-events]"` | Process title used when `process_masquerade` is `true`. |
| `tcp_fingerprint` | bool | `true` | Enable TCP/IP OS fingerprint spoofing on all listening sockets. Modifies low-level TCP parameters so responses appear to come from the configured OS. Linux only. |
| `tcp_fingerprint_os` | string | `"windows"` | OS profile for TCP fingerprint spoofing. One of: `"windows"` (TTL=128, Win=65535), `"linux"` (TTL=64, Win=29200), `"macos"` (TTL=64, Win=65535), `"solaris"` (TTL=255, Win=49640). |
| `spoof_ttl` | int | `54` | When non-zero, adds an `iptables -t mangle` POSTROUTING rule that sets the TTL of all outgoing packets to this value. Makes traffic look like it traversed ~10 internet hops rather than coming from a directly-connected host (default Linux TTL=64). Valid range: 1–255. Requires the `xt_TTL` kernel module (`modprobe xt_TTL`); silently skipped if unavailable. Set to `0` to disable. |
| `auto_evict_services` | bool | `true` | When `true`, NotTheNet automatically stops conflicting system services (apache2, nginx, lighttpd, bind9, dnsmasq, systemd-resolved, exim4, postfix, smbd, nmbd, mariadb, mysql) before binding ports. Requires `systemctl` and root. Set to `false` to manage those services manually. |
| `auto_hardening` | bool | `true` | When `true`, automatically applies sysctl and iptables hardening on every Start: enables IP forwarding (`net.ipv4.ip_forward=1`), sets the FORWARD chain policy to ACCEPT, and writes `/etc/sysctl.d/99-notthenet.conf`. Settings are restored when NotTheNet stops. |
| `passthrough_subnets` | list[string] | `["10.10.10.0/24"]` | CIDR ranges whose **intra-LAN** traffic bypasses NotTheNet's DNAT redirects. Implemented as `iptables -t nat -I PREROUTING -s <cidr> -d <cidr> -j RETURN`. The match requires **both** source and destination inside the CIDR, so victim→Kali probes are still caught by NTN, but victim→victim traffic (e.g. WannaCry SMB lateral spread) passes straight through. In **gateway mode**, if this list is empty, NotTheNet auto-derives the LAN CIDR from the gateway interface IP at startup — so worm-style `/24` scans spread between victims out of the box without operator config. Set explicitly only if you need to allow additional subnets or override auto-derivation. **Sinkhole mode** (`iptables_mode: "loopback"`) does not auto-derive: the sinkhole is supposed to capture all traffic on the host. |

### Example

```json
"general": {
  "bind_ip": "10.0.0.1",
  "redirect_ip": "10.0.0.1",
  "interface": "vmbr1",
  "log_dir": "logs",
  "log_level": "INFO",
  "log_to_file": true,
  "auto_iptables": true,
  "auto_evict_services": true,
  "auto_hardening": true,
  "iptables_mode": "gateway",
  "json_logging": true,
  "json_log_file": "logs/events.jsonl",
  "tcp_fingerprint": true,
  "tcp_fingerprint_os": "windows",
  "spoof_ttl": 54,
  "drop_privileges": true,
  "drop_privileges_user": "nobody",
  "drop_privileges_group": "nogroup",
  "process_masquerade": true,
  "process_name": "[kworker/u2:1-events]"
}
```

---

## `dns`

Fake DNS server — resolves every query to `resolve_to`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the DNS service. |
| `port` | int | `53` | UDP + TCP port to listen on. |
| `resolve_to` | string | `"127.0.0.1"` | IP address returned for all A/AAAA queries. **In `gateway` mode**, if this is `"127.0.0.1"` (the default), NotTheNet automatically overrides it with the effective `redirect_ip` at startup — so malware following DNS-discovered targets connects to the NTN host rather than the victim's own loopback. Set an explicit non-loopback IP here to override that behaviour. |
| `ttl` | int | `300` | DNS TTL in seconds for synthesised records. |
| `handle_ptr` | bool | `true` | When `true`, PTR (reverse DNS) queries return a synthetic ISP-style hostname derived from the queried IP (e.g. `static-192-168-1-100.res.example.net`). When `false`, PTR queries get no answer. |
| `custom_records` | object | `{}` | Per-hostname overrides. Keys are lowercase hostnames; values are IP addresses. These take priority over all other resolver logic. See [Custom DNS Records](#custom-dns-records). |
| `nxdomain_entropy_threshold` | float | `3.2` | Shannon entropy threshold for DGA detection. Queries whose second-level domain has entropy **above** this value return NXDOMAIN. Set to `0` to disable. Useful to defeat malware that uses random-looking domains. **Raise to `4.0`** when analysing malware whose legitimate C2 hostnames are high-entropy (e.g. `.onion` addresses). |
| `nxdomain_label_min_length` | int | `8` | Minimum character length of the second-level domain label before DGA entropy evaluation is applied. Labels shorter than this are never DGA-filtered. |
| `public_response_ips` | array | `[]` | Pool of public-looking IP addresses to rotate through for A responses, instead of always returning `resolve_to`. Uses a stable hash of the queried name so the same domain always gets the same IP. Defeats sandbox-evasion heuristics that detect interceptors by checking for RFC-1918 response IPs. |
| `kill_switch_domains` | array | `[]` | Domains that always return NXDOMAIN, regardless of entropy. Subdomains also match. Use this to prevent malware from triggering its own kill switch — e.g. WannaCry exits if its kill-switch domain resolves. Adding it here ensures DNS fails and execution continues. |

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
  },
  "nxdomain_entropy_threshold": 3.2,
  "nxdomain_label_min_length": 8,
  "public_response_ips": [
    "142.250.80.1",
    "104.244.42.1",
    "151.101.1.140"
  ],
  "kill_switch_domains": [
    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
  ]
}
```

---

## `dot`

DNS-over-TLS server (RFC 7858). Shares all resolver logic with the plain DNS service.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable the DoT service. |
| `port` | int | `853` | TCP port to listen on. |
| `cert_file` | string | `"certs/server.crt"` | Path to the PEM certificate. Reuses the HTTPS cert by default. |
| `key_file` | string | `"certs/server.key"` | Path to the PEM private key. Reuses the HTTPS key by default. |
| `resolve_to` | string | `"127.0.0.1"` | IP address returned for all A/AAAA queries (inherited from DNS config at startup). |
| `ttl` | int | `300` | DNS TTL in seconds for synthesised records. |
| `handle_ptr` | bool | `true` | If `true`, PTR queries return a synthetic ISP-style hostname. |
| `custom_records` | object | `{}` | Per-hostname overrides (same format as `dns.custom_records`). |
| `nxdomain_entropy_threshold` | float | `3.2` | Shannon entropy threshold for DGA NXDOMAIN (0 = disabled). |
| `nxdomain_label_min_length` | int | `8` | Minimum SLD length for DGA evaluation. |
| `public_response_ips` | array | `[]` | Public IP pool for A responses (same as `dns.public_response_ips`). |

### Example

```json
"dot": {
  "enabled": true,
  "port": 853,
  "cert_file": "certs/server.crt",
  "key_file": "certs/server.key"
}
```

> **Note:** `resolve_to`, `ttl`, `handle_ptr`, `custom_records`, and the DGA/public-IP keys are populated automatically from the `dns` section at startup so you only need to set them here if you want DoT to behave differently from plain DNS.

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
| `doh_intercept` | bool | `true` | Intercept DNS-over-HTTPS (DoH) queries. Detects requests by `Content-Type: application/dns-message` or the `/dns-query` path. Handles both GET (base64url `?dns=` parameter) and POST (raw wire-format body). Resolves all queries to `doh_redirect_ip`. |
| `doh_redirect_ip` | string | `"127.0.0.1"` | IP address to return for all intercepted DoH queries. |
| `websocket_intercept` | bool | `true` | Intercept WebSocket upgrade requests. Completes the RFC 6455 handshake (101 Switching Protocols), drains up to 4 KB of incoming frames, logs a hex preview, then sends a clean close frame. Satisfies malware using WebSocket-based C2. |

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
| `doh_intercept` | bool | `true` | Intercept DNS-over-HTTPS queries inside the TLS tunnel (same behaviour as HTTP). |
| `doh_redirect_ip` | string | `"127.0.0.1"` | IP address to return for DoH queries over HTTPS. |
| `websocket_intercept` | bool | `true` | Intercept WebSocket upgrades inside the TLS tunnel (same behaviour as HTTP). |

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
| `mode` | string | `"sniff_and_drop"` | Use `"sniff_and_drop"` to send `RST` right after logging the `NEGOTIATE` packet (frees malware threads, enabling LAN lateral spread). Use `"tarpit"` to drain subsequent connections instead, maximizing telemetry per host at the cost of thread exhaustion on the malware side. |

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
    "doh_intercept": true,
    "websocket_intercept": true,
    "dynamic_response_rules": [
      { "pattern": "/update\\.php$", "mime": "application/octet-stream", "body": "" }
    ]
  },
  "https": {
    "dynamic_responses": true,
    "dynamic_certs": true,
    "doh_intercept": true,
    "websocket_intercept": true
  }
}
```

### WannaCry / Ransomware with embedded Tor client

This config bypasses WannaCry's kill switch, resolves its hardcoded `.onion` C2 addresses to the NTN interceptor, and serves fake Tor directory responses to maximise PCAP coverage.

```json
{
  "dns": {
    "kill_switch_domains": [
      "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    ],
    "nxdomain_entropy_threshold": 4.0,

    ---

    ## `victim`

    Victim connection settings used by the Preflight page for remote readiness checks.

    | Key | Type | Default | Description |
    |-----|------|---------|-------------|
    | `username` | string | `""` | Victim account name used by remote preflight checks. Domain users are supported (for example `LAB\\analyst`). |
    | `ip` | string | `""` | Victim IPv4 address. If empty and `auto_detect_ip=true`, preflight attempts ARP discovery on the configured interface. |
    | `auto_detect_ip` | bool | `true` | Auto-detect victim IP before remote checks by scanning ARP/neighbour entries. |
    | `subnet_mask` | int | `24` | CIDR mask used for ARP subnet scan (for example `24` for `/24`). |

    > Security note: victim passwords are entered in the GUI but are intentionally not persisted to `config.json`.

    ### Example

    ```json
    "victim": {
      "username": "analyst",
      "ip": "10.10.10.20",
      "auto_detect_ip": true,
      "subnet_mask": 24
    }
    ```
    "custom_records": {
      "gx7ekbenv2riucmf.onion": "10.10.10.1",
      "cwwnhwhlz52maqm7.onion": "10.10.10.1",
      "57g7spgrzlojinas.onion": "10.10.10.1",
      "xxlvbrloxvriy2c5.onion": "10.10.10.1",
      "76jdd2ir2embyv47.onion": "10.10.10.1"
    }
  },
  "http": {
    "dynamic_responses": true,
    "dynamic_response_rules": [
      { "pattern": "(?i)/tor/status-vote/current/consensus", "mime": "text/plain", "body": "network-status-version 3\nvalid-after 2026-01-01 00:00:00\n" },
      { "pattern": "(?i)/tor/server/authority", "mime": "text/plain", "body": "router FakeDirAuth 10.10.10.1 9001 0 0\n" },
      { "pattern": "(?i)/tor/keys/", "mime": "text/plain", "body": "dir-key-certificate-version 3\n" },
      { "pattern": "(?i)\\.onion", "mime": "application/octet-stream", "body": "{\"status\": \"ok\"}" }
    ]
  },
  "https": {
    "dynamic_certs": true,
    "dynamic_response_rules": [
      { "pattern": "(?i)/tor/status-vote/current/consensus", "mime": "text/plain", "body": "network-status-version 3\nvalid-after 2026-01-01 00:00:00\n" },
      { "pattern": "(?i)/tor/server/authority", "mime": "text/plain", "body": "router FakeDirAuth 10.10.10.1 9001 0 0\n" },
      { "pattern": "(?i)/tor/keys/", "mime": "text/plain", "body": "dir-key-certificate-version 3\n" },
      { "pattern": "(?i)\\.onion", "mime": "application/octet-stream", "body": "{\"status\": \"ok\"}" }
    ]
  },
  "smb": { "enabled": true }
}
```

> **Why `nxdomain_entropy_threshold: 4.0`?** WannaCry's `.onion` SLD labels have Shannon entropy of 3.3–3.9. The default threshold of 3.2 would DGA-filter them and return NXDOMAIN before the `custom_records` override could be applied. Raising the threshold to 4.0 ensures `custom_records` wins. Alternatively, set the threshold to `0` to disable DGA filtering entirely.

---

## Dynamic Response Rules

The `dynamic_response_rules` array (available in both `http` and `https`) lets you define custom regex-based rules that take priority over the built-in extension map.

Each rule is an object with three keys:

| Key | Type | Description |
|-----|------|-------------|
| `pattern` | string | Python regex matched against the full request path (e.g. `"/update\\.php$"`). |
| `mime` | string | MIME type for the `Content-Type` header (e.g. `"application/octet-stream"`). |
| `body` | string | Plain-text response body sent as-is. If omitted or empty, the built-in extension stub for the matched MIME type is used instead. |

**Resolution order:** custom rules → extension map → fallback static response.

```json
"dynamic_response_rules": [
  {
    "pattern": "\\.config$",
    "mime": "application/xml",
    "body": "<?xml version=\"1.0\"?><config></config>"
  },
  {
    "pattern": "/gate\\.php",
    "mime": "text/plain",
    "body": "OK"
  }
]
```

### Tor simulation rules

When analysing ransomware or malware that uses an embedded Tor client (e.g. WannaCry), you can fake directory authority responses to maximise traffic capture:

```json
"dynamic_response_rules": [
  {
    "pattern": "(?i)/tor/status-vote/current/consensus",
    "mime": "text/plain",
    "body": "network-status-version 3\nvalid-after 2026-01-01 00:00:00\nfresh-until 2026-01-01 01:00:00\nvalid-until 2026-01-01 03:00:00\n"
  },
  {
    "pattern": "(?i)/tor/server/authority",
    "mime": "text/plain",
    "body": "router FakeDirAuth 10.10.10.1 9001 0 0\nplatform Tor 0.4.8.9\nbandwidth 1073741824 1073741824 1073741824\n"
  },
  {
    "pattern": "(?i)/tor/keys/",
    "mime": "text/plain",
    "body": "dir-key-certificate-version 3\n"
  },
  {
    "pattern": "(?i)\\.onion",
    "mime": "application/octet-stream",
    "body": "{\"status\": \"ok\", \"msg_id\": 1}"
  }
]
```

> **Note:** The fake directory responses let you capture the full Tor bootstrap attempt and C2 bridge requests in your PCAP. The embedded Tor client will ultimately fail signature verification (expected), but all HTTP exchanges — including the ransom-key exchange attempt — will be visible.

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
