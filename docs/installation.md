# Installation Guide

> If you're building an isolated lab from scratch, read [Lab Setup](lab-setup.md) first.

## Table of Contents

- [Requirements](#requirements)
- [Install (internet-connected Kali)](#install-internet-connected-kali)
  - [Option A — .deb package](#option-a--deb-package)
  - [Option B — install script](#option-b--install-script)
- [Offline / USB Install](#offline--usb-install)
- [Verifying the Install](#verifying-the-install)
- [Desktop Integration](#desktop-integration)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)
- [Manual Install (advanced)](#manual-install-advanced)

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

## Install (internet-connected Kali)

### Option A — .deb package

Installs cleanly to `/opt/notthenet/`, registers a `notthenet` CLI command, and adds an app-menu icon. Preferred for shared/multi-user installs.

```bash
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet
bash build-deb.sh
sudo dpkg -i notthenet_*.deb
```

If `dpkg` reports missing dependencies:

```bash
sudo apt --fix-broken install
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

**Remove:**

```bash
sudo apt remove notthenet        # keep config/certs in /opt/notthenet
sudo apt purge notthenet         # remove everything
```

---

### Option B — install script

Installs into the cloned directory. Easier to run from source, update via `git pull`, or run without root for development.

```bash
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet
sudo bash notthenet-install.sh
```

Then:

```bash
sudo notthenet          # GUI mode
sudo notthenet --nogui  # headless
```

> **Switching from script install to `.deb`?** The two methods install to different locations (`~/NotTheNet/` vs `/opt/notthenet/`) and register different launchers (`/usr/local/bin/notthenet` vs `/usr/bin/notthenet`). Running `sudo dpkg -i` on top of a script install leaves both in place and makes `sudo notthenet` hit whichever comes first in `PATH`. Uninstall first:
> ```bash
> sudo notthenet-uninstall
> ```
> Then follow the `.deb` steps above.

---

## Offline / USB Install

Use this when your Kali machine has **no internet access** — the standard setup for an air-gapped analysis lab.

### Step 1 — Build the bundle on Windows

```powershell
cd U:\NotTheNet
.\make-bundle.ps1 -SkipChecks
# Creates: dist\notthenet-bundle.sh + dist\NotTheNet-<ver>.zip
```

> `make-bundle.ps1` embeds all Python wheels into a self-contained installer script. Kali needs no internet to install.

### Step 2 — Transfer to Kali

Copy `NotTheNet-<ver>.zip` via USB, shared folder, or SCP.

### Step 3 — Install on Kali

```bash
unzip NotTheNet-*.zip
cd NotTheNet
sudo bash notthenet-bundle.sh
```

The installer asks whether to do a fresh install or update an existing one. Skip the prompt:

```bash
sudo bash notthenet-bundle.sh --install   # always fresh
sudo bash notthenet-bundle.sh --update    # always update, keep config/certs/logs
```

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

The install script and `.deb` both register a desktop entry so NotTheNet appears in the Kali app menu.

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

---

## Upgrading

```bash
cd ~/NotTheNet
sudo bash update.sh
```

The script backs up `config.json`, pulls the latest code, re-installs the package, and restores your config. Your settings are never overwritten.

To see what new config keys were added in a new release:

```bash
diff config.json <(git show origin/main:config.json)
```

---

## Uninstalling

```bash
sudo notthenet-uninstall            # remove system files, keep logs/certs
sudo notthenet-uninstall --purge    # remove everything
```

Or directly from the repo:

```bash
sudo bash notthenet-uninstall.sh
sudo bash notthenet-uninstall.sh --purge
```

For a `.deb` install you can also use apt:

```bash
sudo apt remove notthenet     # keep /opt/notthenet
sudo apt purge notthenet      # remove /opt/notthenet entirely
```

Confirm iptables rules are gone after uninstall:

```bash
sudo iptables -t nat -S | grep NOTTHENET
# should return nothing
```

---

## Manual Install (advanced)

For contributors or non-standard environments. Most users should use Option A or B above.

```bash
sudo apt-get install -y python3 python3-venv python3-tk iptables iproute2

cd NotTheNet
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Generate a self-signed TLS cert
mkdir -p certs
python3 - <<'EOF'
from utils.cert_utils import generate_self_signed_cert
generate_self_signed_cert(
    "certs/server.crt", "certs/server.key",
    common_name="notthenet.local",
    san_dns=["localhost", "notthenet.local"],
    san_ips=["127.0.0.1"],
    key_bits=4096,
)
EOF
chmod 600 certs/server.key

mkdir -p logs/emails logs/ftp_uploads
chmod 700 logs logs/emails logs/ftp_uploads

sudo .venv/bin/python notthenet.py
```