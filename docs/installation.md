# Installation Guide

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Install (Recommended)](#quick-install-recommended)
- [Manual Install](#manual-install)
- [Verifying the Install](#verifying-the-install)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11 / Ubuntu 20.04 | Kali Linux 2024+ |
| Python | 3.9 | 3.11+ |
| RAM | 128 MB | 256 MB |
| Disk | 50 MB | 200 MB (for captures) |
| Privileges | root (for ports < 1024 + iptables) | root |
| GUI toolkit | `python3-tk` | `python3-tk` |
| Network tools | `iptables`, `iproute2` | `iptables`, `iproute2` |

### Supported Platforms

| Platform | Status |
|----------|--------|
| Kali Linux 2024+ | ✅ Fully tested |
| Kali Linux 2023 | ✅ Supported |
| Debian 12 (Bookworm) | ✅ Supported |
| Ubuntu 22.04 / 24.04 | ✅ Supported |
| Ubuntu 20.04 | ⚠ Supported (Python 3.8 needs upgrade) |
| Parrot OS | ⚠ Should work, untested |
| macOS | ❌ No (uses Linux iptables) |
| Windows | ❌ No |

---

## Quick Install (Recommended)

```bash
# Clone the repository (run from your home directory)
cd ~
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet

# Run the install script as root
sudo bash notthenet-install.sh
```

The install script will:
1. Check Python version (3.9+ required)
2. Install system packages (`python3-venv`, `iptables`, `iproute2`, `openssl`)
3. Create a virtualenv at `./venv`
4. Install Python dependencies (`dnslib`, `cryptography`)
5. Generate a self-signed TLS certificate (`certs/server.crt` / `certs/server.key`)
6. Create log directories (`logs/`, `logs/emails/`, `logs/ftp_uploads/`)
7. Install a launcher at `/usr/local/bin/notthenet`
8. Install a clickable desktop icon (app menu + polkit password prompt)

After install:

```bash
sudo notthenet           # launch GUI from terminal
sudo notthenet --nogui   # headless mode
```

Or simply search for **NotTheNet** in the Kali application menu (or any GNOME/XFCE/KDE desktop) and click the icon — a graphical password prompt will appear via `pkexec`.

---

## Desktop Integration

`notthenet-install.sh` installs three things that make the app launchable from the desktop:

| File installed | Purpose |
|----------------|---------|
| `/usr/share/icons/hicolor/scalable/apps/notthenet.svg` | SVG icon (all sizes) |
| `/usr/share/icons/hicolor/128x128/apps/notthenet.png` | 128 px PNG icon |
| `/usr/share/applications/notthenet.desktop` | Desktop entry (app menu, dock) |
| `/usr/local/bin/notthenet-gui` | Wrapper that calls `pkexec` for the password prompt |
| `/usr/share/polkit-1/actions/com.retr0verride.notthenet.policy` | Named polkit action (descriptive auth dialog) |

### How privilege escalation works

When you click the icon, `notthenet-gui` is called, which executes:

```
pkexec /path/to/venv/bin/python notthenet.py
```

This causes the desktop to show a **graphical password prompt** with the message *"NotTheNet needs root access to bind privileged ports and manage iptables rules."*

If `pkexec` is not available, the wrapper falls back to `kdesudo` → `gksudo` → `xterm + sudo` in that order.

### Manual desktop entry (if not installed by script)

```bash
# If you installed manually (non-root) and want to add the desktop entry later:
sudo cp assets/notthenet.desktop /usr/share/applications/notthenet.desktop
sudo sed -i "s|NOTTHENET_EXEC_PLACEHOLDER|/usr/local/bin/notthenet-gui|" \
    /usr/share/applications/notthenet.desktop
sudo update-desktop-database /usr/share/applications
```

---

## Manual Install

If you prefer not to use the install script:

### 1. Install system dependencies

```bash
sudo apt-get install -y python3 python3-venv python3-tk iptables iproute2
```

### 2. Create and activate a virtualenv

```bash
cd NotTheNet
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python packages

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Generate a self-signed TLS certificate

```bash
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
```

### 5. Set correct permissions on the private key

```bash
chmod 600 certs/server.key
```

### 6. Create log directories

```bash
mkdir -p logs/emails logs/ftp_uploads
chmod 700 logs logs/emails logs/ftp_uploads
```

### 7. Run

```bash
sudo venv/bin/python notthenet.py
```

---

## Verifying the Install

After starting NotTheNet, verify each service is responding:

```bash
# DNS — should return 127.0.0.1 for any name
dig @127.0.0.1 evil.com A

# HTTP — should return 200 OK
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/

# HTTPS — should return 200 OK (skip cert verify for self-signed)
curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1/

# SMTP
echo "QUIT" | nc 127.0.0.1 25

# FTP
echo "QUIT" | nc 127.0.0.1 21
```

---

## Upgrading

### One-command update

A convenience script is included. Run it from anywhere inside the repo:

```bash
cd ~/NotTheNet
sudo bash update.sh
```

The script will:
1. Stop NotTheNet if it is running
2. Back up your local `config.json` if it has unsaved changes, pull, then restore it automatically
3. Pull the latest code from GitHub
4. Re-install the package (picks up dependency or entry-point changes)
5. Print the new version number

### Manual steps

If you prefer to do it yourself:

```bash
cd ~/NotTheNet

# 1. Pull latest changes
git pull origin master

# 2. Re-install (safe to run every time — no-op if nothing changed)
source venv/bin/activate
pip install -e . --quiet

# 3. Confirm the new version
python -c "import notthenet; print(notthenet.APP_VERSION)"
```

### Config file changes

New releases may add keys to `config.json`. Your existing config is never overwritten automatically. To see what changed:

```bash
diff config.json <(git show origin/master:config.json)
```

Copy any new keys you want into your local `config.json`, or delete it and let NotTheNet regenerate it with defaults on next launch.

---

## Uninstalling

Run the following from inside the project directory (or replace `$NOTTHENET_DIR`
with the full path to wherever you cloned it):

```bash
# Set this to wherever you cloned the repo
NOTTHENET_DIR="$(pwd)"   # if you are already inside the project directory

# ── 1. Flush any live iptables rules first (do this while the app is stopped) ─
sudo iptables -t nat -S | grep NOTTHENET | sed 's/^-A/-D/' | \
    while read -r rule; do sudo iptables -t nat $rule; done

# ── 2. Remove system launchers ────────────────────────────────────────────────
sudo rm -f /usr/local/bin/notthenet
sudo rm -f /usr/local/bin/notthenet-gui

# ── 3. Remove desktop integration ────────────────────────────────────────────
sudo rm -f /usr/share/applications/notthenet.desktop
sudo rm -f /usr/share/icons/hicolor/scalable/apps/notthenet.svg
sudo rm -f /usr/share/icons/hicolor/128x128/apps/notthenet.png
sudo rm -f /usr/share/polkit-1/actions/com.retr0verride.notthenet.policy

# ── 4. Remove the man page ────────────────────────────────────────────────────
sudo rm -f /usr/local/share/man/man1/notthenet.1.gz

# ── 5. Refresh system caches ─────────────────────────────────────────────────
sudo update-desktop-database -q /usr/share/applications 2>/dev/null || true
sudo gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
sudo mandb -q 2>/dev/null || true

# ── 6. Remove the pip package (if installed with pip install -e . or pip install) ─
"${NOTTHENET_DIR}/venv/bin/pip" uninstall -y notthenet 2>/dev/null || true
pip uninstall -y notthenet 2>/dev/null || true

# ── 7. Remove the project directory (logs, captures, venv, certs, and all) ───
# WARNING: this permanently deletes all captured emails, FTP uploads, TLS
# certificates, and logs stored inside the project folder.
cd "$(dirname "$NOTTHENET_DIR")" && rm -rf "$NOTTHENET_DIR"
```

> **Note:** If you cloned to a custom path, set `NOTTHENET_DIR` explicitly before
> running, e.g. `NOTTHENET_DIR=/opt/NotTheNet`.

To verify all iptables rules are gone after step 1:
```bash
sudo iptables -t nat -S | grep NOTTHENET
# Should return nothing
```
