# Usage Guide

## Table of Contents

- [Launching the GUI](#launching-the-gui)
- [GUI Walkthrough](#gui-walkthrough)
  - [Toolbar](#toolbar)
  - [Service Sidebar](#service-sidebar)
  - [Configuration Panels](#configuration-panels)
  - [Live Log](#live-log)
- [Starting and Stopping Services](#starting-and-stopping-services)
- [Saving and Loading Configs](#saving-and-loading-configs)
- [Updating](#updating)
- [CLI / Headless Mode](#cli--headless-mode)
- [Command-Line Reference](#command-line-reference)
- [Running Multiple Configs](#running-multiple-configs)
- [Typical Malware Analysis Workflow](#typical-malware-analysis-workflow)

---

## Launching the GUI

NotTheNet must be run as **root** to bind privileged ports (53, 80, 443, 25, etc.) and manage iptables rules.

```bash
# If installed via notthenet-install.sh
sudo notthenet

# If running from the project directory directly
sudo venv/bin/python notthenet.py

# With a specific config file
sudo notthenet --config /path/to/my-lab.json
```

> **Kali tip:** You can also right-click the project folder in the file manager → "Open as Root" → run `venv/bin/python notthenet.py`.

---

## GUI Walkthrough

```
╔══════════════════════════════════════════════════════════════════════════╗
║▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ accent line ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓║
║  [Globe]  NotTheNet          │  ▶ Start  ■ Stop │ 💾 Save  📂 Load…      ║
║           2026.02.24-2 · Fake Internet Simulator │                      ║
╠══════════════════╦═══════════════════════════════════════════════════════╣
║  SERVICES        ║                                                       ║
║  ── CONFIG ────  ║         Configuration Panel                          ║
║  ⚙  General  ●  ║         (content changes per selected service)        ║
║  ── NETWORK ─── ║                                                       ║
║  ◈  DNS      ●  ║                                                       ║
║  ◈  HTTP     ●  ║                                                       ║
║  ◈  HTTPS    ●  ║                                                       ║
║  ◈  FTP      ●  ║                                                       ║
║  ── MAIL ──────  ║                                                       ║
║  ◈  SMTP     ●  ║                                                       ║
║  ◈  POP3     ●  ║                                                       ║
║  ◈  IMAP     ●  ║                                                       ║
║  ── FALLBACK ── ║                                                       ║
║  ◈  Catch-All ● ║                                                       ║
║  ── ANALYSIS ── ║                                                       ║
║  📊 JSON Events ║                                                       ║
╠══════════════════╩═══════════════════════════════════════════════════════╣
║  LIVE LOG     [DEBUG] [INFO] [WARNING] [ERROR]              [✕ Clear]   ║
║  10:23:01 [INFO]  notthenet.dns: DNS service started on 0.0.0.0:53      ║
║  10:23:01 [INFO]  notthenet.http: HTTP service started on 0.0.0.0:80    ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ● Running                              github.com/retr0verride/NotTheNet║
╚══════════════════════════════════════════════════════════════════════════╝
```

### Toolbar

The toolbar has three zones separated by dividers:

| Zone | Contents |
|------|----------|
| **Left — Brand** | Canvas-rendered globe+prohibition icon, "NotTheNet" wordmark, version and tagline |
| **Centre — Controls** | **▶ Start** (green), **■ Stop** (red), **💾 Save**, **📂 Load…** |
| **Right** | Zoom controls (**A−**, percentage label, **A+**), root warning label if not running as root |

A 2 px teal accent line runs along the very top of the toolbar.

| Button | Action |
|--------|--------|
| **▶ Start** | Applies all config panel values, starts all enabled services and iptables rules. Disabled while running. |
| **■ Stop** | Gracefully stops all services and removes iptables rules. |
| **💾 Save** | Saves current GUI values to `config.json` (or the `--config` path). |
| **📂 Load…** | Opens a file picker to load a different `.json` config file and rebuilds all panels. |
| **A−** | Decrease zoom by 15% (also `Ctrl+-`). Range: 70%–200%. |
| **A+** | Increase zoom by 15% (also `Ctrl+=`). Range: 70%–200%. |
| **Ctrl+0** | Reset zoom to 100%. |

All buttons change shade on hover. A `⚠ Not root` warning appears on the right if not running as root.

### Service Sidebar

Services are grouped into labelled categories:

| Group | Services |
|-------|---------|
| **CONFIG** | General settings |
| **NETWORK** | DNS, HTTP, HTTPS, FTP |
| **MAIL** | SMTP, POP3, IMAP |
| **FALLBACK** | Catch-All |
| **ANALYSIS** | JSON Events |

Click any row to open the configuration panel. The active row is highlighted with a darker background and bold text.

### Configuration Panels

Each panel maps directly to a section in `config.json`. All fields are validated when **▶ Start** is clicked. See the [Configuration Reference](configuration.md) for every field.

New fields in this release:

- **General panel:** JSON Logging (toggle + file path), TCP Fingerprint (toggle + OS profile dropdown)
- **HTTP panel:** Dynamic Responses (toggle), DoH Sinkhole (toggle + redirect IP), WebSocket Sinkhole (toggle), Dynamic Response Rules (JSON array editor)
- **HTTPS panel:** All of the above plus Dynamic Certificates (toggle)

> **Tip:** Hover over any field label, entry box, checkbox, toolbar button, or sidebar item for a tooltip explaining what it does and what values are accepted.

**DNS panel extras:** The "Custom DNS Records" text box accepts one record per line in the format:
```
hostname = ip_address
example.com = 127.0.0.1
c2.evil.xyz = 10.0.0.5
```

A hint label above the text box shows the expected format.

### Live Log

The log panel fills the lower portion of the window and is vertically resizable by dragging the sash. Lines are colour-coded:

| Colour | Level |
|--------|-------|
| White | INFO |
| Orange | WARNING |
| Red | ERROR |
| Grey | DEBUG |

**Level filter pills** (DEBUG / INFO / WARNING / ERROR) let you focus on a single log level — click a pill to show only that level, click it again to restore all output. The log is capped at 2,000 lines in the GUI display (the file log has no display limit). Click **✕ Clear** to wipe the display.

---

## Starting and Stopping Services

1. **Configure** — click each service in the sidebar, adjust fields as needed.
2. **Save** — hit **Save Config** to persist your settings.
3. **Start** — click **▶ Start**. The log will show each service binding. A new session-labeled JSON log file is created automatically (e.g. `logs/events_2026-04-01_s1.jsonl`).
4. **Verify** — run the test commands below.
5. **Detonate** — execute the malware sample in your isolated VM.
6. **Review** — check the live log, the JSON Events viewer, and the `logs/` directory. Each session's events are in their own dated file.
7. **Stop** — click **■ Stop** to cleanly restore iptables and shut down all services.

### Quick verification after Start

```bash
# Verify DNS
dig @127.0.0.1 anything-at-all.evil +short
# Expected: 127.0.0.1

# Verify HTTP
curl -I http://127.0.0.1/
# Expected: HTTP/1.1 200 OK

# Verify HTTPS
curl -Ik https://127.0.0.1/
# Expected: HTTP/1.1 200 OK

# Verify SMTP
nc 127.0.0.1 25
# Expected: 220 mail.notthenet.local ESMTP ...
```

---

## Saving and Loading Configs

You can maintain **multiple config files** for different analysis scenarios:

```
configs/
  banking-trojan.json      # high-fidelity HTTP mimicry
  ransomware.json          # DNS-heavy, catch-all everything
  default.json             # standard lab baseline
```

Load them from the GUI via **Load Config…** or from the command line:
```bash
sudo notthenet --config configs/banking-trojan.json
```

---

## CLI / Headless Mode

For automated pipelines, sandboxes without a display, or SSH sessions:

```bash
sudo notthenet --nogui --config config.json
```

On startup, an ASCII banner is printed to stdout:

```
  ███╗   ██╗ ██████╗ ████████╗    ████████╗██╗  ██╗███████╗    ███╗   ██╗███████╗████████╗
  ████╗  ██║██╔═══██╗╚══██╔══╝       ██║   ██║  ██║██╔════╝    ████╗  ██║██╔════╝╚══██╔══╝
  ██╔██╗ ██║██║   ██║   ██║          ██║   ███████║█████╗      ██╔██╗ ██║█████╗     ██║
  ██║╚██╗██║██║   ██║   ██║          ██║   ██╔══██║██╔══╝      ██║╚██╗██║██╔══╝     ██║
  ██║ ╚████║╚██████╔╝   ██║          ██║   ██║  ██║███████╗    ██║ ╚████║███████╗   ██║
  ╚═╝  ╚═══╝ ╚═════╝    ╚═╝          ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝
                            Fake Internet Simulator  ·  Malware Analysis
```

In headless mode:
- All output goes to stdout and `logs/notthenet.log`
- `SIGINT` (Ctrl+C) and `SIGTERM` trigger a clean shutdown with iptables restore
- Exit code `0` = clean stop; `1` = failed to start (check log)

### Scripted analysis example

```bash
#!/usr/bin/env bash
# Start NotTheNet, run the sample, stop and collect logs

sudo notthenet --nogui &
NTN_PID=$!
sleep 2   # Wait for services to bind

# Run the sample in your isolated VM (e.g. via SSH)
ssh analyst@192.168.100.20 "wine malware_sample.exe" &
sleep 60  # Let it run for 60 seconds

# Stop NotTheNet
kill -SIGTERM $NTN_PID
wait $NTN_PID

# Collect results
cp logs/notthenet.log analysis_$(date +%s).log
cp -r logs/emails emails_$(date +%s)/
```

---

## Command-Line Reference

```
usage: notthenet.py [-h] [--config CONFIG] [--nogui] [--loglevel LEVEL]

Fake internet simulator for malware analysis.

options:
  -h, --help            Show this help message and exit
  --config CONFIG       Path to JSON config file (default: config.json)
  --nogui               Run in headless/CLI mode without the GUI
  --loglevel LEVEL      Override log level: DEBUG, INFO, WARNING, ERROR
                        (default: value from config general.log_level)
```

### Examples

```bash
# GUI, default config
sudo notthenet

# GUI, custom config
sudo notthenet --config /opt/labs/ransomware.json

# Headless, verbose
sudo notthenet --nogui --loglevel DEBUG

# Headless, quiet (errors only)
sudo notthenet --nogui --loglevel ERROR --config configs/default.json
```

---

## Running Multiple Configs

Multiple NotTheNet instances cannot run simultaneously on the same ports. To switch configs:

1. Click **■ Stop** (or Ctrl+C in headless mode)
2. Click **Load Config…** and pick the new file
3. Click **▶ Start**

Or from the CLI:
```bash
# Running instance is stopped by SIGTERM
sudo notthenet --nogui --config configs/banking.json &
# ... analysis ...
kill %1

sudo notthenet --nogui --config configs/ransomware.json &
```

---

## Typical Malware Analysis Workflow

### Lab Setup Prerequisites

```
┌─────────────────────────┐        ┌─────────────────────────┐
│  Analysis Host (Kali)   │        │  Victim VM              │
│  NotTheNet running      │◄──────►│  Isolated network only  │
│  IP: 192.168.100.1      │        │  DNS: 192.168.100.1     │
│  iptables: gateway mode │        │  GW:  192.168.100.1     │
└─────────────────────────┘        └─────────────────────────┘
         virbr0 / host-only adapter
```

### Step-by-Step

1. **Snapshot the victim VM** before any execution.
2. Set the victim VM's DNS server to your Kali IP.
3. Set the victim VM's default gateway to your Kali IP (for gateway mode).
4. In NotTheNet config: set `interface` to your VM network adapter (e.g. `virbr0`), `iptables_mode` to `"gateway"`, and `redirect_ip` to your Kali IP.
5. **Check for kill-switch domains.** Many samples exit early if a specific domain resolves. Add known kill-switch domains to `dns.kill_switch_domains` so they return NXDOMAIN. Example (WannaCry): `"kill_switch_domains": ["iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]`.
6. **Check for high-entropy C2 domains.** If the sample uses `.onion` addresses or other high-entropy hostnames, either raise `dns.nxdomain_entropy_threshold` (e.g. to `4.0`) or add them explicitly to `dns.custom_records` pointing to your sinkhole IP.
7. Start NotTheNet.
8. Execute the malware sample in the victim VM.
9. Watch the live log for C2 callbacks, DNS lookups, email exfil attempts.
10. Stop NotTheNet and review `logs/`.
11. Revert the victim VM snapshot.

> See [Configuration → Example Configurations](configuration.md#wannacry--ransomware-with-embedded-tor-client) for a ready-made WannaCry config that bypasses the kill switch, maps `.onion` C2 addresses, and serves fake Tor directory responses.
