<p align="center">
  <img src="../assets/logo.svg" alt="NotTheNet — Fake Internet Simulator" width="480"/>
</p>

# NotTheNet Documentation

Welcome to the NotTheNet documentation hub. NotTheNet is a fake internet simulator for malware analysis — a modern, easy-to-configure alternative to INetSim and FakeNet-NG.

---

## Contents

| Document | Description |
|----------|-------------|
| [Installation](installation.md) | System requirements, install steps, virtualenv setup |
| [Configuration](configuration.md) | Full reference for every `config.json` field |
| [Usage](usage.md) | GUI walkthrough, CLI/headless mode, command-line flags |
| [Services](services.md) | DNS, HTTP/HTTPS, SMTP, POP3, IMAP, FTP, Catch-All details |
| [Network & iptables](network.md) | How traffic redirection works, gateway vs loopback modes |
| [Security Hardening](security-hardening.md) | Lab network isolation, interface binding, privilege model |
| [Troubleshooting](troubleshooting.md) | Common errors and fixes |
| [Lab Setup: Proxmox + Kali + FlareVM](lab-setup.md) | Isolated lab wiring, IP forwarding, detonation workflow |
| [Development Setup](development.md) | VS Code on Kali/Windows, venv, predeploy checks, project structure |

Man page: [`man/notthenet.1`](../man/notthenet.1)

---

## Quick-Start (TL;DR)

**Option A — .deb package (recommended on Kali):**

```bash
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
bash build-deb.sh
sudo dpkg -i notthenet_*.deb
sudo notthenet
```

**Option B — install script:**

```bash
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
sudo bash notthenet-install.sh
sudo notthenet
```

> **Note:** Both options require cloning the repo first — there is no standalone download. The `.deb` is built locally from the source.

Then click **▶ Start**.

That's it. Every DNS query from the analysis machine now resolves to `127.0.0.1`, every HTTP/HTTPS request gets a `200 OK`, and all other TCP traffic hits the catch-all service.

---

## Why NotTheNet Instead of INetSim / FakeNet-NG?

| Issue | INetSim | FakeNet-NG | NotTheNet |
|-------|---------|-----------|-----------|
| DNS race on startup | Common | Occasional | None — DNS binds synchronously |
| Socket leak on restart | Yes (requires `kill -9`) | Occasionally | `SO_REUSEADDR` + clean shutdown |
| Python 3 support | Partial | Yes | Full (3.9+) |
| GUI configuration | No | No | Yes (Tkinter, no extra dep) |
| TLS 1.2+ only | No | No | Yes (configurable cipher list) |
| Privilege drop after bind | No | No | Runs as root; `pkexec` handles privilege for desktop launch |
| Catch-all port redirect | Via config file | Via config file | Auto iptables NAT |
| Log injection prevention | No | No | Yes (CWE-117 sanitised) |
| Single file to read | No | No | Each concern in one module |
