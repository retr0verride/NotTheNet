<p align="center">
  <img src="assets/logo.svg" alt="NotTheNet — Fake Internet Simulator" width="480"/>
</p>

# NotTheNet — Fake Internet Simulator

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
| [Services](docs/services.md) | DNS, HTTP/HTTPS, SMTP, POP3, IMAP, FTP, Catch-All technical details |
| [Network & iptables](docs/network.md) | Traffic redirection, loopback vs gateway mode, manual rules |
| [Security Hardening](docs/security-hardening.md) | Lab isolation, interface binding, privilege model, OpenSSF practices |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |
| [Lab Setup: Proxmox + Kali + FlareVM](docs/lab-setup.md) | Isolated lab wiring, IP forwarding, detonation workflow |

Man page available at [`man/notthenet.1`](man/notthenet.1) — install with `sudo notthenet-install.sh` or manually via `man ./man/notthenet.1`.

---

## Features

| Service / Feature | Details |
|---------|---------|
| **DNS** | Resolves every hostname to your configured IP. PTR/rDNS handled cleanly. Per-host override records. |
| **HTTP/HTTPS** | Configurable response code, body, and `Server:` header. TLS 1.2+ with ECDHE+AEAD ciphers only. |
| **SMTP** | Accepts and archives email to `logs/emails/`. UUID filenames, disk cap enforced. |
| **POP3 / IMAP** | Minimal state machines that satisfy poll-checkers. Zero stored state. |
| **FTP** | Accepts uploads with UUID filenames, size-capped storage. Active (PORT) mode disabled (SSRF). |
| **TCP Catch-All** | Receives any TCP connection redirected by iptables; responds with `200 OK`. |
| **UDP Catch-All** | Optional UDP drain; responds with `OK`. |
| **iptables manager** | Auto-applies NAT REDIRECT rules; cleanly restores originals on stop. |
| **Public-IP spoof** | HTTP/HTTPS responses to 20+ well-known public-IP-check services (`api.ipify.org`, `icanhazip.com`, `checkip.amazonaws.com`, `ifconfig.me`, `httpbin.org`, and others) return a configurable fake IP. Defeats malware that queries these endpoints to detect sandbox environments. |
| **Response delay** | Per-millisecond artificial delay on HTTP/HTTPS responses. 50–200 ms simulates realistic network latency and defeats timing-based sandbox detection. |
| **Dark GUI** | Grouped sidebar, live colour-coded log panel with level filters, tooltips on every field and button. |
| **Desktop integration** | App menu icon, pkexec/polkit privilege prompt — no terminal needed to launch. |

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
  dns_server.py       ← dnslib-based DNS (UDP + TCP, all → redirect_ip)
  http_server.py      ← HTTP + HTTPS (hardened TLS)
  mail_server.py      ← SMTP + POP3 + IMAP
  ftp_server.py       ← FTP (PASV only, PORT disabled)
  catch_all.py        ← TCP/UDP catch-all
network/
  iptables_manager.py ← NAT redirect rules, save/restore
utils/
  cert_utils.py       ← RSA-4096 self-signed TLS cert generation
  logging_utils.py    ← Log sanitization (CWE-117 prevention)
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

70 tests cover `utils/validators`, `utils/logging_utils`, and `config.py`. All tests are pure-Python and require no network access, root, or external services.

The full pre-deployment gate (lint → type-check → security scan → tests → build) is run via:

```bash
# Linux
bash predeploy.sh

# Windows dev machine
.\predeploy.ps1
```

---

## Security

See [SECURITY.md](SECURITY.md) for the full security policy and vulnerability reporting process.

Key hardening highlights:
- Subprocess calls: always `shell=False` — no shell injection possible
- Log output: all untrusted strings sanitized (ANSI/CRLF stripped)
- File saves: UUID filenames only — attacker never controls path
- TLS: minimum 1.2, ECDHE+AEAD ciphers, `OP_NO_SSLv2/3/TLSv1/1.1`
- Private key: written with mode `0o600`
- Privilege: runs as root scoped to the isolated interface; `bind_ip` limits exposure to the analysis adapter

---

## License

MIT — see `LICENSE`.
