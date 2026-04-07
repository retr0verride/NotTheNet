# Installation Guide

This guide covers every way to install NotTheNet on a Kali Linux (or Debian-based) machine. If you're building an isolated lab, start with the [Lab Setup](lab-setup.md) guide first — it walks you through the full environment before you get to installation.

## Table of Contents

- [System Requirements](#system-requirements)
- [.deb Package Install](#deb-package-install)
- [Quick Install (Script)](#quick-install-script)
- [Offline / USB Install](#offline--usb-install)
- [Manual Install](#manual-install)
- [Verifying the Install](#verifying-the-install)
- [Upgrading](#upgrading)
- [Uninstalling](#uninstalling)

---

## System Requirements

NotTheNet is lightweight — it runs comfortably on the same Kali VM you use for analysis.

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

## .deb Package Install

The easiest way to install on Kali Linux or any Debian-based system. A `.deb` package is like a Windows installer — it puts everything in the right place and can be cleanly uninstalled later.

```bash
# Download the source code
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet

# Build the .deb package from the source code
bash build-deb.sh

# Install the package (sudo = run as administrator)
sudo dpkg -i notthenet_2026.04.07-3_all.deb
```

`build-deb.sh` requires only `dpkg` (always present on Debian/Kali) and `rsync`.

If `dpkg` reports missing dependencies, run:

```bash
# This tells apt to find and install anything that was missing
sudo apt --fix-broken install
```

### What gets installed

| Path | Contents |
|------|----------|
| `/opt/notthenet/` | All project files + `venv/` (created by postinst) |
| `/usr/bin/notthenet` | CLI launcher |
| `/usr/bin/notthenet-uninstall` | Uninstall command |
| `/usr/local/bin/notthenet-gui` | Desktop icon launcher (via `pkexec`) |
| `/usr/share/applications/notthenet.desktop` | App menu entry |
| `/usr/share/icons/hicolor/` | Scalable SVG + 128 px PNG icon |
| `/usr/share/polkit-1/actions/` | Named polkit action for the auth dialog |
| `/usr/share/man/man1/notthenet.1.gz` | Man page |

### Removing the package

```bash
sudo apt remove notthenet        # remove, keep /opt/notthenet config/certs
sudo apt purge notthenet         # remove everything including /opt/notthenet
```

---

## Quick Install (Script)

```bash
# Download the source code into your home directory
cd ~
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet

# Run the install script (sudo = run as administrator)
sudo bash notthenet-install.sh
```

The install script handles everything automatically:

1. Checks your Python version (3.9 or newer required)
2. Installs system packages needed by NotTheNet (`python3-venv`, `iptables`, `iproute2`, `openssl`)
3. Creates a **virtual environment** (an isolated Python folder so NotTheNet's dependencies don't interfere with other tools on your system)
4. Installs Python dependencies (`dnslib` for DNS packet handling, `cryptography` for TLS certificates)
5. Generates a self-signed TLS certificate for the fake HTTPS server
6. Creates log directories (`logs/`, `logs/emails/`, `logs/ftp_uploads/`)
7. Installs a `notthenet` command you can run from anywhere
8. Installs an uninstall command (`notthenet-uninstall`)
9. Adds NotTheNet to your application menu with an icon

After install:

```bash
# Launch NotTheNet with the GUI
sudo notthenet

# Or run without a GUI (for SSH sessions or automation)
sudo notthenet --nogui
```

Or search for **NotTheNet** in your Kali application menu and click the icon — a password prompt will appear asking for your root password.

---

## Offline / USB Install

Use this when your Kali machine has **no internet access** — which is the recommended setup for a malware analysis lab. All Python dependencies are packed into a single shell script, so nothing needs to be downloaded on Kali.

### What you need

- A Windows machine with internet access (to prepare the bundle)
- A USB drive (or any way to copy a ~6 MB file to Kali)

### Step 1 — Build and deploy the bundle on Windows

On your Windows machine, open PowerShell in the `NotTheNet` project folder:

```powershell
# The all-in-one command: bumps version, runs checks, builds the bundle, copies to USB
.\ship.ps1

# Skip the lint/type checks (use when you just need a quick rebuild)
.\ship.ps1 -SkipPredeploy

# Force a specific USB drive letter if auto-detection picks the wrong one
.\ship.ps1 -Drive E:\
```

`ship.ps1` automatically finds your USB drive. If no USB is plugged in, it tells you.

If you only want the zip file (without copying to USB):

```powershell
.\make-bundle.ps1 -Zip
# Creates: NotTheNet-bundle.zip in the project folder
```

> **What's inside the bundle:** All Python packages that NotTheNet needs (dnslib, cryptography, cffi, pycparser) are embedded directly in the installer script. Kali does not need internet access to install them.

### Step 2 — Transfer to Kali

Copy `NotTheNet-bundle.zip` (or just `notthenet-bundle.sh`) to the Kali machine via USB, shared folder, or SCP.

### Step 3 — Install

```bash
# If you transferred the zip file, unzip it first:
unzip NotTheNet-bundle.zip
cd NotTheNet

# Run the offline installer
sudo bash notthenet-bundle.sh
```

The installer detects whether NotTheNet is already installed and asks if you want a fresh install or an update:

- **Fresh install** — sets up everything from scratch. The unzipped folder becomes your install directory.
- **Update** — copies new files into your existing install while keeping your settings (`config.json`), certificates (`certs/`), and logs (`logs/`).

You can also skip the prompt with a flag:

```bash
sudo bash notthenet-bundle.sh --install   # always fresh
sudo bash notthenet-bundle.sh --update    # always update
```

---

## Desktop Integration

The install script sets up NotTheNet so you can launch it like any other app — from the application menu, dock, or desktop.

| File installed | What it does |
|----------------|---------|
| `/usr/share/icons/hicolor/scalable/apps/notthenet.svg` | SVG icon (all sizes) |
| `/usr/share/icons/hicolor/128x128/apps/notthenet.png` | 128 px PNG icon |
| `/usr/share/applications/notthenet.desktop` | Desktop entry (app menu, dock) |
| `/usr/local/bin/notthenet-gui` | Wrapper that calls `pkexec` for the password prompt |
| `/usr/share/polkit-1/actions/com.retr0verride.notthenet.policy` | Named polkit action (descriptive auth dialog) |

> **Note:** The installer adds NotTheNet to the application menu only. A `~/Desktop` shortcut is **not** created automatically. To add one manually:
> ```bash
> cp /usr/share/applications/notthenet.desktop ~/Desktop/
> chmod +x ~/Desktop/notthenet.desktop
> ```

### How the password prompt works

NotTheNet needs root (administrator) access to listen on standard ports like 80 and 443 and to set up traffic redirection rules. When you click the app icon, a password dialog appears asking for your root password.

Behind the scenes, the launcher uses `pkexec` (a Linux tool for requesting administrator access with a graphical prompt). If `pkexec` is not available on your system, it falls back to other methods (`kdesudo` → `gksudo` → `xterm + sudo`).

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

If you prefer to set things up yourself instead of using the install script:

### 1. Install system dependencies

```bash
# python3-tk is the GUI toolkit; iptables handles traffic redirection;
# iproute2 provides the 'ip' command for network configuration
sudo apt-get install -y python3 python3-venv python3-tk iptables iproute2
```

### 2. Create and activate a virtual environment

A virtual environment keeps NotTheNet's Python packages separate from the rest of your system.

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

NotTheNet needs a TLS certificate for its fake HTTPS server. This creates a self-signed one (not trusted by browsers, but fine for intercepting malware traffic).

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
# Only the owner (root) should be able to read this file
chmod 600 certs/server.key
```

### 6. Create log directories

```bash
# NotTheNet stores intercepted emails and FTP uploads here
mkdir -p logs/emails logs/ftp_uploads
chmod 700 logs logs/emails logs/ftp_uploads
```

### 7. Run

```bash
sudo venv/bin/python notthenet.py
```

---

## Verifying the Install

After starting NotTheNet, run these quick tests to confirm each service is responding. Open a second terminal on Kali:

```bash
# Test DNS — should return 127.0.0.1 (meaning NotTheNet answered the query)
dig @127.0.0.1 evil.com A

# Test HTTP — should print "200" (meaning the fake web server is working)
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1/

# Test HTTPS — -k tells curl to accept the self-signed certificate
curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1/

# Test SMTP — should show a "220" greeting from the fake mail server
echo "QUIT" | nc 127.0.0.1 25

# Test FTP — should show a "220" greeting from the fake FTP server
echo "QUIT" | nc 127.0.0.1 21
```

---

## Upgrading

### One-command update

A convenience script handles the entire update process:

```bash
cd ~/NotTheNet
sudo bash update.sh
```

The script will:
1. Stop NotTheNet if it's currently running
2. Back up your `config.json` (your settings), pull the latest code, then restore your config
3. Reset any other modified files so the update can apply cleanly
4. Download the latest code from GitHub
5. Re-install the package (picks up any new dependencies)
6. Update the app menu icon, desktop entry, and other system files to match the new version
7. Re-apply lab hardening rules (if applicable)
8. Print the new version number

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

New versions may add settings to `config.json`. Your existing config is **never overwritten** — your settings are always preserved. To see what new settings were added:

```bash
diff config.json <(git show origin/master:config.json)
```

Copy any new keys you want into your local `config.json`, or delete it and let NotTheNet regenerate it with defaults on next launch.

---

## Uninstalling

An uninstall script is included in the repo. After running `notthenet-install.sh`, it is also available as a system command:

```bash
# Remove system files, keep the project directory (logs, certs, captures intact)
sudo notthenet-uninstall

# Remove everything including the project directory
sudo notthenet-uninstall --purge
```

Or run it directly from the repo if the system command isn't available:

```bash
sudo bash notthenet-uninstall.sh
sudo bash notthenet-uninstall.sh --purge
```

The script handles, in order:
1. Stopping any running NotTheNet process
2. Flushing all NotTheNet iptables rules
3. Removing CLI launchers (`/usr/local/bin/notthenet`, `notthenet-gui`)
4. Removing desktop integration (`.desktop`, icons, polkit action)
5. Removing the man page
6. Refreshing icon/desktop/man caches and restarting the XFCE panel
7. Uninstalling the pip package from the local venv
8. Removing `/opt/notthenet` (if installed via `.deb`)
9. **`--purge` only:** prompts for confirmation then deletes the project directory

### Removing a .deb install

```bash
sudo apt remove notthenet        # remove, keep /opt/notthenet config/certs
sudo apt purge notthenet         # remove everything including /opt/notthenet
```

### Verify iptables rules are gone

```bash
sudo iptables -t nat -S | grep NOTTHENET
# Should return nothing
```
