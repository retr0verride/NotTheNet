# NotTheNet — Fake Internet Simulator

<p align="center">
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/codeql.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/sca.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/sca.yml/badge.svg" alt="SCA"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/snyk.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/snyk.yml/badge.svg" alt="Snyk"></a>
  <a href="https://www.bestpractices.dev/projects/12084"><img src="https://img.shields.io/cii/summary/12084?label=openssf%20best%20practices" alt="OpenSSF Best Practices"></a>
  <a href="https://github.com/retr0verride/NotTheNet/releases/latest"><img src="https://img.shields.io/github/v/release/retr0verride/NotTheNet" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/retr0verride/NotTheNet" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
  <a href="https://github.com/retr0verride/NotTheNet/stargazers"><img src="https://img.shields.io/github/stars/retr0verride/NotTheNet?style=flat" alt="GitHub Stars"></a>
</p>

> **For malware analysis and sandboxed environments only.**  
> Never run on a production network or internet-connected interface.

NotTheNet simulates the internet for malware being analysed in an isolated environment. It solves the core problems of INetSim and FakeNet-NG — specifically DNS race conditions, service restart socket leaks, and opaque configuration — with a single clean Python application and a live GUI.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | System requirements, install steps, virtualenv setup |
| [Configuration](docs/configuration.md) | Full reference for every `config.json` field |
| [Usage](docs/usage.md) | GUI walkthrough, CLI/headless mode, command-line flags |
| [Services](docs/services.md) | DNS, DoT, HTTP/HTTPS, SMTP/S, POP3/S, IMAP/S, FTP, NTP, TFTP, IRC/TLS, Telnet, SOCKS5, VNC, RDP, SMB, Redis, MSSQL, MySQL, LDAP, ICMP, Catch-All, DoH/WS sinkhole, dynamic responses |
| [Network & iptables](docs/network.md) | Traffic redirection, loopback vs gateway mode, TCP/IP fingerprint spoofing |
| [Security Hardening](docs/security-hardening.md) | Lab isolation, interface binding, privilege model, OpenSSF practices |
| [Safe Detonation](docs/safe-detonation.md) | Proxmox snapshot workflow, KVM cloaking, artifact handling, detonation checklist |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |
| [Lab Setup: Proxmox + Kali + FlareVM](docs/lab-setup.md) | Isolated lab wiring, IP forwarding, detonation workflow |
| [Changelog](CHANGELOG.md) | Release history and migration notes |
| [Contributing](CONTRIBUTING.md) | How to report bugs, submit PRs, and run the test suite |

Man page available at [`man/notthenet.1`](man/notthenet.1) — install with `sudo notthenet-install.sh` or manually via `man ./man/notthenet.1`.

---

## Features

| Service / Feature | Details |
|---------|---------|
| **DNS** | Resolves every hostname to `redirect_ip`. PTR/rDNS, MX, TXT all handled. Per-host override records. DGA/canary-domain NXDOMAIN detection (Shannon entropy threshold). Public IP pool rotation to defeat single-IP heuristics. |
| **DNS-over-TLS (DoT)** | RFC 7858, port 853. Shares the same resolver, DGA detection, FCrDNS, and public IP pool as plain DNS. Reuses the HTTPS certificate. |
| **HTTP / HTTPS** | Configurable response code, body, and `Server:` header. TLS 1.2+ with ECDHE+AEAD ciphers only. HTTP/2 GOAWAY downgrade. Captive portal handlers for Android/ChromeOS/Apple/Windows. Hardened against timing-based sandbox detection. |
| **SMTP / SMTPS** | Captures outbound email to `logs/emails/` (UUID filenames, disk cap). SMTPS = implicit TLS port 465. STARTTLS in-place upgrade supported. |
| **POP3 / POP3S** | Minimal RFC 1939 state machine; satisfies poll-checkers. POP3S = implicit TLS port 995. STLS upgrade supported. |
| **IMAP / IMAPS** | Minimal RFC 3501 state machine; satisfies stealers that enumerate the inbox. IMAPS = implicit TLS port 993. STARTTLS supported. |
| **FTP** | Accepts uploads with UUID filenames, size-capped storage. Active (PORT) mode disabled (SSRF prevention). |
| **NTP** | UDP Stratum 2 server (port 123). Reference ID set to a real Stratum 1 IP. Satisfies malware that probes NTP before detonating. |
| **TFTP** | RFC 1350 RRQ/WRQ. Write requests saved to `logs/tftp_uploads/` with UUID prefix, 10 MB cap. |
| **IRC / IRC-TLS** | Full RFC 1459 registration burst, CAP negotiation, PRIVMSG/NOTICE logging. IRC-TLS (port 6697) wraps the same handler in TLS. Captures botnet C2. |
| **Telnet** | RFC 854 IAC negotiation, configurable device banner, accepts any credentials, simulates BusyBox root shell. Captures Mirai and IoT botnet command sequences. |
| **SOCKS5** | RFC 1928 proxy sinkhole (port 1080). Logs the real CONNECT destination host and port — highest-value C2 intelligence. Used by SystemBC, QakBot, Cobalt Strike. |
| **VNC** | RFB 003.008 handshake sinkhole (port 5900). Logs connection attempts. |
| **RDP** | TPKT/X.224 connection request banner (port 3389). Logs source IPs of RDP probes. |
| **SMB** | SMB2 NEGOTIATE banner (port 445). Logs SMB connection attempts from malware enumerating shares. |
| **Redis** | RESP protocol sinkhole (port 6379). Responds to PING/INFO/CONFIG; logs all commands. |
| **MSSQL** | TDS pre-login sinkhole (port 1433). Returns a valid server version banner. |
| **MySQL** | MySQL handshake sinkhole (port 3306). Returns a valid server greeting. |
| **LDAP** | LDAPv3 bind + search sinkhole (port 389). Returns `LDAP_SUCCESS` to bind and empty search results. |
| **ICMP Responder** | Raw socket ICMP echo responder. Malware that pings the gateway to confirm reachability gets replies. |
| **TCP Catch-All** | Receives any TCP connection redirected by iptables. Detects HTTP/TLS first-byte and responds appropriately. |
| **UDP Catch-All** | Optional UDP drain; silently logs all received datagrams. |
| **iptables manager** | Auto-applies NAT REDIRECT rules on start; snapshot/restore guarantees a clean state on stop even after a crash. |
| **Public-IP spoof** | 20+ well-known IP-check endpoints (`api.ipify.org`, `icanhazip.com`, `ip-api.com`, `ifconfig.me`, etc.) return a configurable fake residential IP. Defeats AgentTesla, FormBook, and other stealers. |
| **Response delay + jitter** | Per-ms artificial delay with random jitter on HTTP/HTTPS responses. Default 120 ± 80 ms (40–200 ms range) simulates realistic WAN latency; jitter defeats timing-based sandbox fingerprinting. |
| **Dynamic responses** | Extension-based response engine (70+ file types). Requests for `.exe`, `.dll`, `.pdf`, `.zip`, etc. return correct MIME types with valid file stubs. Custom regex rules supported. |
| **DNS-over-HTTPS sinkhole** | Intercepts DoH queries via GET and POST. Prevents malware from bypassing the fake DNS via `dns.google` or `cloudflare-dns.com`. |
| **WebSocket sinkhole** | Completes RFC 6455 handshake, drains up to 4 KB of frames, logs hex preview, sends clean close. Satisfies WebSocket-based C2. |
| **Dynamic TLS certs** | Auto-generated Root CA + per-domain cert forging via SNI. Each HTTPS connection gets a cert matching the requested hostname (with fake SCT extension). Install `certs/ca.crt` in the VM. |
| **TCP/IP fingerprint spoof** | Modifies TTL, TCP window size, DF bit, and MSS to mimic Windows, Linux, macOS, or Solaris. Defeats OS fingerprinting-based sandbox detection. |
| **JSON event logging** | Structured JSONL per-request logging. Pipeline-ready for CAPEv2, Splunk, ELK. GUI includes a live JSON Events viewer with search and filtering. |
| **Dark GUI** | Grouped sidebar, live colour-coded log panel with level filters, JSON Events viewer, zoom controls (70%–200%), tooltips on every field and button. |
| **Desktop integration** | App menu icon, pkexec/polkit privilege prompt — no terminal needed to launch. |
| **Privilege drop** | Binds privileged ports as root then immediately drops to `nobody:nogroup` after startup. Configurable. |
| **Process masquerade** | Renames the process to a kernel-thread-like title (e.g. `[kworker/u2:1-events]`) via `setproctitle` to hide from `ps`/process monitors on the analysis host. |
| **Lab hardening script** | `harden-lab.sh` stops conflicting services, blocks bridge↔management interface pivoting with iptables FORWARD DROP, and mounts `logs/` as `noexec` tmpfs in one command. |

---

## Requirements

- Kali Linux / Debian 12 / Ubuntu 22.04+
- Python 3.9+
- `python3-tk` (for GUI — pre-installed on Kali)
- Root access (for binding ports < 1024 and iptables)

---

## Installation

```bash
cd ~
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
sudo bash notthenet-install.sh
```

### Offline / Air-gapped install

For isolated labs with no internet access, build a self-contained installer on a Windows machine and transfer it via USB:

```powershell
# On Windows — builds notthenet-bundle.sh + NotTheNet-bundle.zip
.\make-bundle.ps1 -Zip
```

Then on Kali:

```bash
unzip NotTheNet-bundle.zip && cd NotTheNet
sudo bash notthenet-bundle.sh            # prompts: fresh install or update
sudo bash notthenet-bundle.sh --install  # skip prompt — always fresh
sudo bash notthenet-bundle.sh --update   # skip prompt — always update
```

See [docs/installation.md](docs/installation.md#offline--usb-install) for full details.

---

## Updating

```bash
cd NotTheNet
sudo bash update.sh
```

Pulls the latest code, reinstalls the package, and re-syncs the icon, desktop entry, and polkit action automatically.

---

## Uninstalling

After install, the uninstaller is available as a system command:

```bash
# Remove system files, keep repo/logs/certs
sudo notthenet-uninstall

# Remove everything
sudo notthenet-uninstall --purge
```

---

## Usage

### GUI (recommended)
```bash
sudo notthenet
```

### Headless / CLI
```bash
sudo notthenet --nogui --config config.json
```

### Custom config
```bash
sudo notthenet --config /etc/notthenet/mylab.json
```

---

## Configuration

All settings live in `config.json`. The GUI exposes every field.  
Key settings:

| Key | Description |
|-----|-------------|
| `general.redirect_ip` | IP all DNS queries resolve to (usually `127.0.0.1`) |
| `general.interface` | Network interface to apply iptables rules on |
| `general.auto_iptables` | Auto-manage iptables NAT rules |
| `general.spoof_public_ip` | Fake public IP returned to well-known IP-check services (e.g. `"93.184.216.34"`). Leave blank to disable. |
| `general.json_logging` | Enable structured JSON event logging to `json_log_file` (JSONL format). |
| `general.tcp_fingerprint` | Enable TCP/IP OS fingerprint spoofing (`tcp_fingerprint_os`: `windows`/`linux`/`macos`/`solaris`). |
| `http.dynamic_responses` | Enable extension-based MIME types + valid file stubs for 70+ extensions. |
| `http.doh_sinkhole` | Intercept DNS-over-HTTPS queries (GET + POST wire-format). |
| `http.websocket_sinkhole` | Accept and sinkhole WebSocket upgrade requests. |
| `https.dynamic_certs` | Forge per-domain TLS certs via auto-generated Root CA + SNI callback. |
| `dns.custom_records` | Per-hostname overrides: `{"c2.evil.com": "127.0.0.1"}` |
| `http.response_delay_ms` / `https.response_delay_ms` | Artificial delay in ms before each HTTP/HTTPS response (50–200 ms recommended to defeat timing detection). |
| `https.cert_file` / `key_file` | TLS cert paths (auto-generated if absent) |
| `catch_all.excluded_ports` | Ports to EXCLUDE from TCP catch-all (e.g. `[22]` for SSH) |

---

## Architecture

```
notthenet.py          ← Entry point + GUI (tkinter)
config.py             ← JSON config loader / saver / validator
service_manager.py    ← Orchestrates all services + iptables lifecycle
services/
  dns_server.py       ← DNS (UDP + TCP; DGA/NXDOMAIN; public IP pool; FCrDNS)
  dot_server.py       ← DNS-over-TLS (RFC 7858, port 853; shares DNS resolver)
  http_server.py      ← HTTP + HTTPS (dynamic certs, DoH/WS sinkhole, captive portal)
  mail_server.py      ← SMTP + SMTPS + POP3 + POP3S + IMAP + IMAPS
  ftp_server.py       ← FTP (PASV only; PORT/SSRF disabled)
  ntp_server.py       ← NTP (UDP Stratum 2)
  tftp_server.py      ← TFTP (RRQ/WRQ; UUID uploads; 10 MB cap)
  irc_server.py       ← IRC (RFC 1459, plaintext + TLS)
  telnet_server.py    ← Telnet (RFC 854; BusyBox shell simulation)
  socks5_server.py    ← SOCKS5 proxy (RFC 1928; logs real CONNECT destinations)
  icmp_responder.py   ← ICMP echo responder (raw socket)
  mysql_server.py     ← MySQL handshake sinkhole (port 3306)
  mssql_server.py     ← MSSQL TDS pre-login sinkhole (port 1433)
  rdp_server.py       ← RDP TPKT/X.224 banner sinkhole (port 3389)
  smb_server.py       ← SMB2 NEGOTIATE banner sinkhole (port 445)
  vnc_server.py       ← VNC RFB handshake sinkhole (port 5900)
  redis_server.py     ← Redis RESP sinkhole (port 6379)
  ldap_server.py      ← LDAPv3 bind + search sinkhole (port 389)
  catch_all.py        ← TCP/UDP catch-all (HTTP/TLS detection)
  doh_websocket.py    ← DoH + WebSocket sinkhole handlers (shared with HTTP/HTTPS)
  dynamic_response.py ← Extension→MIME map + valid file stub generator (70+ types)
network/
  iptables_manager.py ← NAT redirect rules, save/restore
  tcp_fingerprint.py  ← TCP/IP OS fingerprint spoofing (TTL, window, DF, MSS)
utils/
  cert_utils.py       ← RSA-4096 self-signed certs + Root CA + dynamic cert forging
  logging_utils.py    ← Log sanitization (CWE-117 prevention)
  json_logger.py      ← Structured JSON Lines event logger (thread-safe, size-capped)
  privilege.py        ← Root check + drop_privileges() helper (for future bind-then-drop)
  validators.py       ← Input validation for all external data
tests/
  test_config.py      ← Config load / get / set / save / reset
  test_logging_utils.py ← Log sanitization & injection prevention
  test_validators.py  ← Input validation for all public functions
```

---

## Testing

```bash
# From the project root (venv active)
pytest tests/ -v
```

86 tests cover `utils/validators`, `utils/logging_utils`, `config.py`, service connection caps, IRC session timeout, and JSON logger flush behaviour. All tests are pure-Python and require no network access, root, or external services.

The full pre-deployment gate (lint → type-check → security scan → tests → build) is run via:

```bash
# Linux
bash predeploy.sh

# Windows dev machine
.\predeploy.ps1
```

---

## Reporting Bugs & Feature Requests

Open an issue on the [GitHub Issue Tracker](https://github.com/retr0verride/NotTheNet/issues).  
For **security vulnerabilities**, see [SECURITY.md](SECURITY.md) — do not open a public issue.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide — fork, branch, code, test, PR.

---

## Security

See [SECURITY.md](SECURITY.md) for the full security policy and vulnerability reporting process.

Key hardening highlights:
- Subprocess calls: always `shell=False` — no shell injection possible
- Log output: all untrusted strings sanitized (ANSI/CRLF stripped)
- File saves: UUID filenames only — attacker never controls path
- TLS: minimum 1.2, ECDHE+AEAD ciphers, `OP_NO_SSLv2/3/TLSv1/1.1`
- Dynamic certs: hostname sanitised for path traversal; Root CA + per-domain keys at `0o600`
- Private key: written with mode `0o600`
- JSON log: 500 MB file-size cap; thread-safe singleton; no eval of logged data
- Privilege: runs as root scoped to the isolated interface; `bind_ip` limits exposure to the analysis adapter

---

## License

MIT — see `LICENSE`.
