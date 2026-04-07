# NotTheNet — Fake Internet Simulator

<p align="center">
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/codeql.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/sca.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/sca.yml/badge.svg" alt="SCA"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/snyk.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/snyk.yml/badge.svg" alt="Snyk"></a>
  <a href="https://www.bestpractices.dev/projects/12084"><img src="https://www.bestpractices.dev/projects/12084/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/retr0verride/NotTheNet"><img src="https://api.securityscorecards.dev/projects/github.com/retr0verride/NotTheNet/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/retr0verride/NotTheNet/releases/latest"><img src="https://img.shields.io/github/v/release/retr0verride/NotTheNet" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/retr0verride/NotTheNet" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+">
  <a href="https://github.com/retr0verride/NotTheNet/stargazers"><img src="https://img.shields.io/github/stars/retr0verride/NotTheNet?style=flat" alt="GitHub Stars"></a>
</p>

> **For malware analysis and sandboxed environments only.**  
> Never run on a production network or internet-connected interface.

NotTheNet simulates the internet for malware being detonated in an isolated lab. It replaces INetSim and FakeNet-NG with a single Python application and a live GUI — no race conditions, no socket leaks, no opaque config files.

---

## Quick Start

```bash
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
sudo bash notthenet-install.sh
sudo notthenet
```

**Air-gapped / offline install** (build on Windows, copy via USB):
```powershell
.\make-bundle.ps1 -Zip     # → NotTheNet-bundle.zip
```
```bash
# On Kali — unzip and run
sudo bash notthenet-bundle.sh
```

---

## What It Does

- **27 fake services** running simultaneously: DNS, DoT, HTTP/S, SMTP/S, POP3/S, IMAP/S, FTP, NTP, TFTP, IRC, IRC-TLS, Telnet, SOCKS5, VNC, RDP, SMB, MySQL, MSSQL, Redis, LDAP, ICMP, TCP/UDP catch-all
- **Every DNS query resolves** to your Kali IP — with DGA/canary-domain NXDOMAIN detection and public-IP pool rotation
- **Dynamic TLS certs** — Root CA + per-SNI cert forging so HTTPS looks real; fake SCT extension included
- **DoH + DoT interception** — prevents malware from bypassing fake DNS via port 853 or HTTPS resolvers
- **Public-IP spoofing** — 20+ IP-check endpoints return a fake residential IP (defeats AgentTesla, FormBook, stealers)
- **TCP/IP fingerprint spoofing** — fakes TTL, window size, MSS to mimic Windows/Linux/macOS
- **Dynamic file responses** — 70+ MIME-correct file stubs (`.exe`, `.dll`, `.pdf`, `.zip`, …)
- **Response delay + jitter** — 120 ± 80 ms artificial latency defeats timing-based sandbox detection
- **Session-labeled JSON logs** — each Start creates `logs/events_YYYY-MM-DD_s1.jsonl`, `_s2.jsonl`, … automatically
- **iptables manager** — NAT REDIRECT on start; snapshot/restore for clean teardown on crash
- **Privilege drop** — binds ports as root then drops to `nobody:nogroup`; `logs/` is chown'd before the drop so exports keep working
- **Process masquerade** — process title set to `[kworker/u2:1-events]` to hide from `ps`
- **Dark GUI** — live colour-coded log, JSON Events viewer with search/filter, zoom controls, per-field tooltips
- **Preflight checks** — local readiness audit + remote victim validation/fixes via WMI/SMB before detonation
- **Lab hardening script** — `harden-lab.sh` stops conflicting services, blocks bridge↔management pivoting, mounts `logs/` as noexec tmpfs

---

## Requirements

- Kali Linux / Debian 12 / Ubuntu 22.04+
- Python 3.9+
- `python3-tk` (pre-installed on Kali)
- Root (for ports < 1024 and iptables)

---

## Usage

```bash
sudo notthenet                                    # GUI
sudo notthenet --nogui                            # headless / pipeline
sudo notthenet --preflight                        # local preflight report (no GUI)
sudo notthenet --config /path/to/mylab.json       # custom config
sudo notthenet --nogui --loglevel DEBUG           # verbose
```

---

## Docs

| Guide | |
|---|---|
| [Installation](docs/installation.md) | Install, update, uninstall, offline USB bundle |
| [Configuration](docs/configuration.md) | Every `config.json` field with examples |
| [Usage](docs/usage.md) | GUI walkthrough, CLI mode, analysis workflow |
| [Services](docs/services.md) | Per-service technical reference |
| [Network & iptables](docs/network.md) | Traffic redirection, loopback vs gateway, TTL mangle |
| [Security Hardening](docs/security-hardening.md) | Lab isolation, privilege model, OpenSSF practices |
| [Safe Detonation](docs/safe-detonation.md) | Proxmox snapshots, KVM cloaking, artifact handling |
| [Lab Setup](docs/lab-setup.md) | Proxmox + Kali + FlareVM wiring guide |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and fixes |
| [Changelog](CHANGELOG.md) | Full release history |

Man page: [`man/notthenet.1`](man/notthenet.1) — installed automatically by `notthenet-install.sh`.

---

## Testing

```bash
pytest tests/ -v    # 253 tests — pure Python, no root, no network required
```

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.  
See [CONTRIBUTING.md](CONTRIBUTING.md) to submit a PR.

- `shell=False` on all subprocess calls
- Log output sanitized (ANSI/CRLF stripped, CWE-117)
- File saves use UUID filenames — attacker never controls path
- TLS 1.2+, ECDHE+AEAD only; private keys at `0o600`
- 500 MB JSON log cap; no eval of logged data

---

## License

MIT — see [LICENSE](LICENSE).
