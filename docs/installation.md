# Installation Guide

> If you're building an isolated lab from scratch, read [Lab Setup](lab-setup.md) first.

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
cd ~/NotTheNet                # the repo you cloned during install
git pull origin main
rm -f dist/*.deb              # remove stale builds so the glob below is unambiguous
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

Use when your Kali machine has **no internet access**. The bundle embeds all required Python wheels so Kali never needs to reach PyPI.

> The bundle is built on your Windows machine from the cloned repo — it is not a download. If Kali has internet, use Method 1.

### Build (on Windows, internet-connected machine)

```powershell
cd U:\NotTheNet
git pull origin main
.\make-bundle.ps1 -SkipChecks
# Output: dist\NotTheNet-<ver>.zip  and  dist\notthenet-bundle.sh
```

### Transfer to Kali

Copy via USB, SCP, or shared folder. If using FAT32 USB, copy the zip to local disk first — FAT32 does not support symlinks required by the Python venv.

```bash
cp NotTheNet-*.zip ~/
cd ~
unzip NotTheNet-*.zip
```

### Install on Kali

```bash
cd ~/NotTheNet
sudo bash notthenet-bundle.sh --install
```

### Upgrade

Rebuild on Windows with the latest code, transfer, then:

```bash
sudo bash notthenet-bundle.sh --update   # preserves config.json, certs, logs
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
| `/usr/share/polkit-1/actions/com.retr0verride.notthenet.policy` | Named polkit action — `exec.path` matches `/usr/local/bin/notthenet-gui` so pkexec forwards `DISPLAY`/`XAUTHORITY` to the GUI |
| `/usr/share/icons/hicolor/scalable/apps/notthenet.svg` | SVG icon (hicolor theme) |
| `/usr/share/icons/hicolor/128x128/apps/notthenet.png` | 128 px PNG icon (hicolor theme) |
| `/usr/share/pixmaps/notthenet.svg` | Fallback icon for desktop environments that query pixmaps instead of hicolor |

> A `~/Desktop` shortcut is not created automatically. To add one:
> ```bash
> cp /usr/share/applications/notthenet.desktop ~/Desktop/
> chmod +x ~/Desktop/notthenet.desktop
> ```


