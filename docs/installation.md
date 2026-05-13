# Installation Guide

> If you're building an isolated lab from scratch, read the [Proxmox Lab Setup](lab-setup-proxmox.md) or [VirtualBox / VMware Lab Setup](lab-setup-vbox.md) guide first.

## Table of Contents

- [Requirements](#requirements)
- Install methods
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
| Python | 3.10 | 3.11+ |
| RAM | 128 MB | 256 MB |
| Disk | 50 MB | 200 MB (for captures) |
| Privileges | root | root |
| GUI toolkit | `python3-tk` | `python3-tk` |
| Python venv | `python3-venv` | `python3-venv` |

| Platform | Status |
|----------|--------|
| Kali Linux 2024+ | ✅ Fully tested |
| Kali Linux 2023 | ✅ Supported |
| Debian 12 (Bookworm) | ✅ Supported |
| Ubuntu 22.04 / 24.04 | ✅ Supported |
| Ubuntu 20.04 | ⚠ Supported (default Python 3.8 must be upgraded to 3.10+) |
| Parrot OS | ⚠ Should work, untested |
| macOS / Windows | ❌ No (requires Linux iptables) |

---

## Method 1 — .deb package (recommended)

Installs to `/opt/notthenet/`. Clean uninstall via `apt`. Preferred for all end-user installs.

> ⚠ **Do not clone into `/opt/notthenet/`.** That directory is the install target of the `.deb` and will be replaced by `dpkg -i`, leaving your shell with a stale CWD (`getcwd: cannot access parent directories`). Clone into your home directory instead.

### Install

```bash
cd ~
# If you have a previous clone, remove it first:
rm -rf NotTheNet
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet
bash build-deb.sh
sudo install -d -m 755 /usr/local/bin   # minimal Kali/WSL images may not have this path
sudo dpkg -i dist/notthenet_*.deb
sudo apt-get install -f         # installs any missing dependencies and completes configuration
```

If configuration fails with `notthenet.postinst: ... /usr/local/bin/notthenet-gui: No such file or directory`, run:

```bash
sudo install -d -m 755 /usr/local/bin
sudo dpkg --configure -a
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
cd ~/NotTheNet                # the repo you cloned during install
git pull origin main
rm -f dist/*.deb              # remove stale builds so the glob below is unambiguous
bash build-deb.sh
sudo dpkg -i dist/notthenet_*.deb
sudo apt-get install -f       # installs any missing dependencies and completes configuration
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

## Method 2 — Offline / USB install

Use when your Kali machine has **no internet access**. Download the `.deb` from GitHub Releases on any internet-connected machine and copy it to Kali.

### Download (on any internet-connected machine)

```bash
# Download the latest .deb from GitHub Releases:
curl -L -o notthenet_latest.deb \
  "$(curl -s https://api.github.com/repos/retr0verride/NotTheNet/releases/latest \
    | grep 'browser_download_url.*\.deb' | cut -d'"' -f4)"
```

Or grab it manually from [github.com/retr0verride/NotTheNet/releases/latest](https://github.com/retr0verride/NotTheNet/releases/latest).

### Transfer to Kali

Copy via USB, SCP, or shared folder.

```bash
# On Kali — install the .deb and its dependencies:
sudo install -d -m 755 /usr/local/bin
sudo dpkg -i notthenet_*.deb
sudo apt-get install -f
```

> `apt-get install -f` fetches `python3-venv` and any other missing dependencies from the Kali apt mirror. If the Kali apt mirror is also unavailable, install `python3-venv` from a pre-downloaded package before running `dpkg -i`.

### Upgrade

Download the new `.deb` from [releases](https://github.com/retr0verride/NotTheNet/releases/latest), copy to Kali, and re-run `dpkg -i`.

### Uninstall

```bash
sudo apt remove notthenet     # remove binaries, keep /opt/notthenet (config/certs/logs)
sudo apt purge notthenet      # remove everything including /opt/notthenet
```

---

## Method 3 — Dev / script install

For contributors and anyone editing the source. Installs **in the cloned directory** (e.g. `~/NotTheNet/`), not `/opt/notthenet/`. The venv, config, and certs all stay in the repo clone.

> Not recommended for end users. Use Method 1 unless you're modifying the code.
> See [development.md](development.md) for the full contributor workflow.

### Install

```bash
cd ~
# If you have a previous clone, remove it first:
rm -rf NotTheNet
git clone https://github.com/retr0verride/NotTheNet.git
cd NotTheNet
sudo bash notthenet-install.sh
```

### Upgrade

```bash
cd ~/NotTheNet
sudo bash update.sh
```

Backs up `config.json`, pulls the latest code, reinstalls the package, and restores your config. Any **new default keys** introduced by the release are deep-merged into your config (existing values are never overwritten); the script reports each key it added. To preview the diff yourself:

```bash
diff config.json <(git show origin/main:config.json)
```

> **`update.sh` works on `.deb` installs too.** When run on a system where the `notthenet` package is registered with `dpkg`, it pulls the latest source, rebuilds the `.deb`, backs up `/opt/notthenet/config.json`, runs `dpkg -i`, restores the user config, and merges any new default keys. The version is verified post-install (`dpkg-query -W` must equal `gui/widgets.py:APP_VERSION`) so silent build failures are caught.

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
| `/usr/share/polkit-1/actions/com.retr0verride.notthenet.policy` | Named polkit action — uses `auth_self` so polkit asks for the user's own password (matches `sudo`). `exec.path` matches `/usr/local/bin/notthenet-gui`. On GNOME/Wayland the launcher recovers `DISPLAY` from XWayland and sets `GDK_BACKEND=x11` automatically. |
| `/usr/share/icons/hicolor/scalable/apps/notthenet.svg` | SVG icon (hicolor theme) |
| `/usr/share/icons/hicolor/128x128/apps/notthenet.png` | 128 px PNG icon (hicolor theme) |
| `/usr/share/pixmaps/notthenet.svg` | Fallback icon for desktop environments that query pixmaps instead of hicolor |

> A `~/Desktop` shortcut is not created automatically. To add one:
> ```bash
> cp /usr/share/applications/notthenet.desktop ~/Desktop/
> chmod +x ~/Desktop/notthenet.desktop
> ```


