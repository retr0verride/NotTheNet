# Installation Guide

> If you're building an isolated lab from scratch, read [Lab Setup](lab-setup.md) first.

## Table of Contents

- [Requirements](#requirements)
- [Which method?](#which-method)
- [Method 1 — .deb package (recommended)](#method-1--deb-package-recommended)
- [Method 2 — Offline / USB bundle](#method-2--offline--usb-bundle)
- [Method 3 — Dev / script install](#method-3--dev--script-install)
- [Verifying the Install](#verifying-the-install)
- [Desktop Integration](#desktop-integration)

---

## Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11 / Ubuntu 20.04 | Kali Linux 2024+ |
| Python | 3.9 | 3.11+ |
| RAM | 128 MB | 256 MB |
| Disk | 50 MB | 200 MB (for captures) |
| Privileges | root | root |
| GUI toolkit | `python3-tk` | `python3-tk` |

| Platform | Status |
|----------|--------|
| Kali Linux 2024+ | ✅ Fully tested |
| Kali Linux 2023 | ✅ Supported |
| Debian 12 (Bookworm) | ✅ Supported |
| Ubuntu 22.04 / 24.04 | ✅ Supported |
| Ubuntu 20.04 | ⚠ Supported (Python 3.8 needs upgrade) |
| Parrot OS | ⚠ Should work, untested |
| macOS / Windows | ❌ No (requires Linux iptables) |

---

## Which method?

| Scenario | Use |
|---|---|
| Kali with internet | [Method 1 — .deb](#method-1--deb-package-recommended) |
| Air-gapped / USB lab | [Method 2 — offline bundle](#method-2--offline--usb-bundle) |
| Contributing / editing source | [Method 3 — dev script](#method-3--dev--script-install) |

---

## Method 1 — .deb package (recommended)

Installs to `/opt/notthenet/`. Clean uninstall via `apt`. Preferred for all end-user installs.

### Install

```bash
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet
bash build-deb.sh
sudo dpkg -i dist/notthenet_*.deb
sudo apt --fix-broken install   # only needed if dpkg reports missing deps
```

**What gets installed:**

| Path | Contents |
|------|----------|
| `/opt/notthenet/` | All project files + Python venv |
| `/usr/bin/notthenet` | CLI launcher |
| `/usr/local/bin/notthenet-gui` | Desktop icon launcher (via `pkexec`) |
| `/usr/share/applications/notthenet.desktop` | App menu entry |
| `/usr/share/icons/hicolor/` | SVG + 128 px PNG icon |
| `/usr/share/polkit-1/actions/` | Polkit action (named auth dialog) |
| `/usr/share/man/man1/notthenet.1.gz` | Man page |

### Upgrade

```bash
cd NotTheNet          # the repo you cloned during install
git pull origin main
bash build-deb.sh
sudo dpkg -i dist/notthenet_*.deb
```

`dpkg -i` on a newer `.deb` is an in-place upgrade — it replaces `/opt/notthenet/` and preserves `config.json`.

### Uninstall

```bash
sudo apt remove notthenet     # remove binaries, keep /opt/notthenet (config/certs/logs)
sudo apt purge notthenet      # remove everything including /opt/notthenet
```

Confirm iptables rules are gone:

```bash
sudo iptables -t nat -S | grep NOTTHENET   # should return nothing
```

---

## Method 2 — Offline / USB bundle

Use when your Kali machine has **no internet access** — the standard setup for an air-gapped analysis lab. Installs to `/opt/notthenet/`, same as the `.deb`.

### Install

**Step 1 — Build the bundle on Windows (internet-connected machine):**

```powershell
cd U:\NotTheNet
.\make-bundle.ps1 -SkipChecks
# Creates: dist\notthenet-bundle.sh + dist\NotTheNet-<ver>.zip
```

> `make-bundle.ps1` embeds all Python wheels. Kali needs no internet to install.

**Step 2 — Transfer to Kali** via USB, shared folder, or SCP.

**Step 3 — Install on Kali:**

```bash
unzip NotTheNet-*.zip
cd NotTheNet
sudo bash notthenet-bundle.sh --install
```

### Upgrade

Rebuild the bundle on Windows with the latest code, transfer, then:

```bash
sudo bash notthenet-bundle.sh --update   # preserves config/certs/logs
```

### Uninstall

```bash
sudo notthenet-uninstall            # remove system files, keep logs/certs
sudo notthenet-uninstall --purge    # remove everything
```

---

## Method 3 — Dev / script install

For contributors and anyone editing the source. Installs **in the cloned directory** (e.g. `~/NotTheNet/`), not `/opt/notthenet/`. The venv, config, and certs all stay in the repo clone.

> Not recommended for end users. Use Method 1 unless you're modifying the code.
> See [development.md](development.md) for the full contributor workflow.

### Install

```bash
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet
sudo bash notthenet-install.sh
```

### Upgrade

```bash
cd ~/NotTheNet
sudo bash update.sh
```

Backs up `config.json`, pulls the latest code, reinstalls the package, and restores your config. To see what new config keys were added:

```bash
diff config.json <(git show origin/main:config.json)
```

> Do **not** run `update.sh` on a `.deb` or bundle install — it expects the venv in the repo directory and will exit with an error.

### Uninstall

```bash
sudo notthenet-uninstall            # remove system files, keep logs/certs
sudo notthenet-uninstall --purge    # remove everything including the repo clone
```

> **Switching to `.deb` after a script install?** Uninstall first (above), then follow Method 1. Running `dpkg -i` on top of a script install leaves two conflicting launchers on `PATH`.

---

## Verifying the Install

After starting NotTheNet (`sudo notthenet`), run these from a second terminal:

```bash
# DNS — should return 127.0.0.1
dig @127.0.0.1 evil.com A +short

# HTTP — should print 200
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/

# HTTPS — -k accepts the self-signed cert
curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1/

# SMTP — should show a 220 greeting
echo "QUIT" | nc 127.0.0.1 25

# FTP — should show a 220 greeting
echo "QUIT" | nc 127.0.0.1 21
```

---

## Desktop Integration

All three install methods register a desktop entry so NotTheNet appears in the Kali app menu.

| File | What it does |
|------|-------------|
| `/usr/share/applications/notthenet.desktop` | App menu entry |
| `/usr/local/bin/notthenet-gui` | Launcher that calls `pkexec` for the password prompt |
| `/usr/share/polkit-1/actions/com.retr0verride.notthenet.policy` | Named polkit action |
| `/usr/share/icons/hicolor/scalable/apps/notthenet.svg` | SVG icon |
| `/usr/share/icons/hicolor/128x128/apps/notthenet.png` | 128 px PNG icon |

> A `~/Desktop` shortcut is not created automatically. To add one:
> ```bash
> cp /usr/share/applications/notthenet.desktop ~/Desktop/
> chmod +x ~/Desktop/notthenet.desktop
> ```


