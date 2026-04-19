# NotTheNet — Fake Internet Simulator

<p align="center">
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/retr0verride/NotTheNet/actions/workflows/codeql.yml"><img src="https://github.com/retr0verride/NotTheNet/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/retr0verride/NotTheNet"><img src="https://api.securityscorecards.dev/projects/github.com/retr0verride/NotTheNet/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/retr0verride/NotTheNet/releases/latest"><img src="https://img.shields.io/github/v/release/retr0verride/NotTheNet" alt="Latest Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/retr0verride/NotTheNet" alt="License"></a>
</p>

<p align="center">
  <img src="assets/notthenet_screenshot.png" alt="NotTheNet GUI" width="720">
</p>

> **For malware analysis and sandboxed environments only.**  
> Never run on a production network or internet-connected interface.

NotTheNet simulates the internet for malware being detonated in an isolated lab. It replaces INetSim and FakeNet-NG with a single Python application and a live GUI — no race conditions, no socket leaks, no opaque config files.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Services (27)](#services-27)
- [Configuration — Twelve-Factor](#configuration--twelve-factor)
- [Health & Admin API](#health--admin-api)
- [Deployment](#deployment)
  - [Headless / Container](#headless--container-mode)
  - [Air-gapped USB bundle](#air-gapped--offline-install)
  - [systemd service](#systemd-service)
- [CI/CD Pipeline](#cicd-pipeline)
- [Security](#security)
- [SOC2 / ISO27001 Compliance Notes](#soc2--iso27001-compliance-notes)
- [Development](#development)

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

## Architecture

NotTheNet follows **Clean Architecture** (ports-and-adapters) with a strict dependency rule: inner layers never import from outer layers.

```
┌─────────────────────────────────────────────────────────┐
│  GUI / CLI (notthenet.py + gui/)          ← outer shell │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │  Infrastructure (infrastructure/)                │   │
│  │  DI container · EnvConfigStore · HealthServer   │   │
│  │  JsonlEventSink · ServiceRepoAdapter             │   │
│  │  CircuitBreaker · retry_with_backoff             │   │
│  │  OTel hooks · structured logging                 │   │
│  │                                                  │   │
│  │  ┌────────────────────────────────────────────┐  │   │
│  │  │  Application (application/)               │  │   │
│  │  │  ServiceOrchestrator                      │  │   │
│  │  │  HealthCheckService                       │  │   │
│  │  │  ConfigApplicationService                 │  │   │
│  │  │                                           │  │   │
│  │  │  ┌──────────────────────────────────────┐ │  │   │
│  │  │  │  Domain (domain/)                   │ │  │   │
│  │  │  │  Entities · Ports (interfaces)      │ │  │   │
│  │  │  │  Value Objects                      │ │  │   │
│  │  │  │  Zero external imports              │ │  │   │
│  │  │  └──────────────────────────────────────┘ │  │   │
│  │  └────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Layer contracts

| Layer | May import | Must NOT import |
|---|---|---|
| `domain/` | `typing`, `dataclasses`, `enum`, stdlib only | Everything else |
| `application/` | `domain/` only | `infrastructure/`, `services/`, `gui/` |
| `infrastructure/` | `application/`, `domain/`, stdlib, third-party | `gui/` |
| `services/` | `utils/`, `network/`, `config`, stdlib | `application/`, `domain/` (backward compat) |
| `gui/` | Everything | — |

### Dependency Injection

All application and infrastructure objects are wired in the single **composition root**:
[`infrastructure/di/container.py`](infrastructure/di/container.py).

```python
from infrastructure.di.container import Container

container = Container.build()
container.start()   # starts health server + all fake services
```

The `Container` constructor accepts any objects that satisfy the domain `Protocol`
interfaces — swap implementations without touching application logic.

### Domain Ports (interfaces)

| Port | File | Implemented by |
|---|---|---|
| `IConfigStore` | `domain/ports/config_store.py` | `EnvConfigStore` |
| `IEventSink` | `domain/ports/event_sink.py` | `JsonlEventSink` |
| `IServiceRepository` | `domain/ports/service_repo.py` | `ServiceRepoAdapter` |

### Resilience

- **Circuit Breaker** (`infrastructure/resilience/circuit_breaker.py`) — three-state
  CLOSED/OPEN/HALF-OPEN; configurable thresholds; thread-safe.
- **Retry with backoff** (`infrastructure/resilience/retry.py`) — exponential
  back-off + ±25% jitter; decorator or imperative call style.

---

## Services (27)

| Service | Port | Protocol | TLS |
|---|---|---|---|
| DNS | 53 | TCP+UDP | — |
| DoT | 853 | TCP | ✓ |
| HTTP | 80 | TCP | — |
| HTTPS | 443 | TCP | ✓ |
| SMTP | 25 | TCP | — |
| SMTPS | 465 | TCP | ✓ |
| POP3 | 110 | TCP | — |
| POP3S | 995 | TCP | ✓ |
| IMAP | 143 | TCP | — |
| IMAPS | 993 | TCP | ✓ |
| FTP | 21 | TCP | — |
| NTP | 123 | UDP | — |
| TFTP | 69 | UDP | — |
| IRC | 6667 | TCP | — |
| IRC-TLS | 6697 | TCP | ✓ |
| Telnet | 23 | TCP | — |
| SOCKS5 | 1080 | TCP | ✓ |
| ICMP | — | ICMP | — |
| Catch-all TCP | configurable | TCP | — |
| Catch-all UDP | configurable | UDP | — |
| MySQL | 3306 | TCP | — |
| MSSQL | 1433 | TCP | — |
| RDP | 3389 | TCP | — |
| SMB | 445 | TCP | — |
| VNC | 5900 | TCP | — |
| Redis | 6379 | TCP | — |
| LDAP | 389 | TCP | — |

---

## Configuration — Twelve-Factor

Config follows [12-Factor §III](https://12factor.net/config): environment variables override `config.json`.

Copy `.env.example` → `.env` and set the values for your deployment.
The `.env` file is in `.gitignore` and must never be committed.

| Env var | Overrides | Default |
|---|---|---|
| `NTN_CONFIG_PATH` | config file path | `config.json` |
| `NTN_BIND_IP` | `general.bind_ip` | `10.10.10.1` |
| `NTN_REDIRECT_IP` | `general.redirect_ip` | `10.10.10.1` |
| `NTN_SPOOF_PUBLIC_IP` | `general.spoof_public_ip` | — |
| `NTN_INTERFACE` | `general.interface` | `vmbr1` |
| `NTN_LOG_DIR` | `general.log_dir` | `logs` |
| `NTN_CERT_PATH` | `general.cert_path` | auto-generated |
| `NTN_KEY_PATH` | `general.key_path` | auto-generated |
| `NTN_DROP_PRIVS` | `general.drop_privileges` | `1` |
| `NTN_HEADLESS` | headless mode flag | `0` |
| `NTN_LOG_LEVEL` | logging level | `INFO` |
| `NTN_HEALTH_BIND` | health server bind | `127.0.0.1` |
| `NTN_HEALTH_PORT` | health server port | `8080` |
| `NTN_HEALTH_TOKEN` | admin endpoint token | — |
| `NTN_OTEL_ENABLED` | OpenTelemetry on/off | `0` |
| `NTN_OTEL_ENDPOINT` | OTLP/gRPC endpoint | `localhost:4317` |

---

## Health & Admin API

When running, a lightweight HTTP server (stdlib `http.server`, no Flask) binds to
`127.0.0.1:8080`.  Full OpenAPI 3.1 spec: [`openapi.yaml`](openapi.yaml).

| Endpoint | Auth | Description |
|---|---|---|
| `GET /health/live` | None | Liveness probe — always 200 while alive |
| `GET /health/ready` | None | Readiness probe — 200/503 based on core services |
| `GET /health/status` | `X-Admin-Token` | Full service status JSON |
| `GET /metrics` | None | Prometheus text format metrics |

**Security controls on the health endpoint:**
- Binds `127.0.0.1` by default (never `0.0.0.0` without an explicit firewall rule)
- Rate limiting: 60 req / 60 s per source IP (token bucket)
- `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`
- `hmac.compare_digest` for constant-time token comparison (prevents timing attacks)
- CORS configured via `NTN_HEALTH_CORS_ORIGINS`

---

## Deployment

### Headless / Container mode

```bash
# Pull and run
docker run --rm -it \
  --cap-add NET_ADMIN \
  --cap-add NET_BIND_SERVICE \
  -e NTN_HEADLESS=1 \
  -e NTN_BIND_IP=172.20.0.1 \
  -e NTN_REDIRECT_IP=172.20.0.1 \
  -e NTN_HEALTH_TOKEN=change-me \
  -v /path/to/config.json:/app/config.json:ro \
  -v /path/to/certs:/app/certs:ro \
  -v notthenet-logs:/app/logs \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/retr0verride/notthenet:latest
```

Build locally:
```bash
docker build --target runtime -t notthenet:local .
```

### Air-gapped / Offline Install

```powershell
# On Windows build host (has internet):
.\make-bundle.ps1 -Zip    # produces NotTheNet-bundle.zip
```

```bash
# Copy zip to USB, then on Kali (no internet needed):
sudo bash notthenet-bundle.sh
sudo notthenet
```

### systemd service

```bash
sudo cp assets/notthenet.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now notthenet
sudo journalctl -fu notthenet
```

The unit file sets `NTN_HEADLESS=1` and configures `ProtectHome`,
`ProtectSystem=strict`, and `CapabilityBoundingSet`.

---

## CI/CD Pipeline

The pipeline in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and PR:

| Stage | Tool | Gate |
|---|---|---|
| Style | `ruff` | Blocks merge |
| Type check | `mypy` | Informational |
| SAST | `bandit` | Blocks on HIGH findings; SARIF uploaded to GitHub Security |
| CVE scan | `pip-audit` | Blocks on known vulnerabilities |
| Tests | `pytest` | Blocks; ≥70% coverage required |
| Docker | `docker/build-push-action` | Multi-stage build; SBOM + provenance on push |
| Release | `softprops/action-gh-release` | Draft release created on `v*` tags |

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

- `shell=False` on all subprocess calls (no injection surface)
- All input sanitized at system boundaries (`utils/validators.py`)
- Log output ANSI/CRLF-stripped before write (CWE-117)
- TLS 1.2+, ECDHE+AEAD only; private key files at `0o600`
- 500 MB JSONL log cap; no eval of logged data
- TOCTOU-safe iptables snapshots (`O_CREAT|O_WRONLY|O_TRUNC, 0o600`)
- Per-SNI dynamic certs: temp key files deleted immediately after `load_cert_chain()`
- Privilege drop to `nobody:nogroup` after low-port bind
- `hmac.compare_digest` everywhere tokens are compared

---

## SOC2 / ISO27001 Compliance Notes

| Control | Implementation |
|---|---|
| CC6.1 — Logical access | `NTN_HEALTH_TOKEN` required on `/health/status`; admin port bound to loopback |
| CC6.6 — Vulnerability mgmt | `pip-audit` in CI on every PR; `bandit` SAST with SARIF upload |
| CC7.1 — Change management | All changes via PR; CI status checks required before merge |
| CC7.2 — Monitoring | Structured JSON logs → SIEM; `/metrics` for Prometheus scraping |
| CC8.1 — Change control | Multi-stage Docker with SBOM + provenance; signed images via GHCR |
| A.10.1 — Cryptographic policy | TLS 1.2+, ECDHE+AEAD, RSA-4096 CA, no MD5/SHA-1 |
| A.12.3 — Backup | `config.json` atomic save (`.tmp` + `os.replace`); log rotation 14 days |
| A.12.6 — Patch management | `pip-audit` + `pip install --upgrade` in CI and install scripts |
| A.14.2 — SSDLC | OWASP-aligned validators, sanitize_path anti-traversal, rate limiting |

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
sudo notthenet --headless                         # headless / container
sudo notthenet --nogui                            # headless (legacy alias)
sudo notthenet --config /path/to/mylab.json       # custom config
sudo NTN_LOG_LEVEL=DEBUG notthenet --headless     # verbose headless
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

## Development

```bash
pytest tests/ -v              # 253 tests — pure Python, no root, no network
ruff check .                  # lint
bandit -r . --exclude .venv   # SAST
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to submit a PR.

---

## License

MIT — see [LICENSE](LICENSE).
