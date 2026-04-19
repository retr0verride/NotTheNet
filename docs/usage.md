# Usage Guide

This guide shows you how to use NotTheNet day-to-day — launching the GUI, configuring services, running malware analysis, and using headless (no-GUI) mode.

## Table of Contents

- [Launching the GUI](#launching-the-gui)
- [GUI Walkthrough](#gui-walkthrough)
  - [Toolbar](#toolbar)
  - [Service Sidebar](#service-sidebar)
  - [Configuration Panels](#configuration-panels)
  - [Live Log](#live-log)
- [Starting and Stopping Services](#starting-and-stopping-services)
- [Saving and Loading Configs](#saving-and-loading-configs)
- [Preflight Checks](#preflight-checks)
- [Updating](#updating)
- [CLI / Headless Mode](#cli--headless-mode)
- [Command-Line Reference](#command-line-reference)
- [Running Multiple Configs](#running-multiple-configs)
- [Typical Malware Analysis Workflow](#typical-malware-analysis-workflow)

---

## Launching the GUI

NotTheNet must be run as **root** (administrator) because standard internet ports like 53 (DNS), 80 (HTTP), and 443 (HTTPS) are restricted to root on Linux. It also needs root to set up traffic redirection rules.

```bash
# If you installed with the install script or .deb package:
sudo notthenet

# If running directly from the project folder:
sudo venv/bin/python notthenet.py

# To load a specific configuration file:
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
| **Left — Brand** | Globe icon, "NotTheNet" name, version number |
| **Centre — Controls** | **▶ Start** (green), **■ Stop** (red), **💾 Save**, **📂 Load…** |
| **Right** | Zoom controls (**A−** / **A+**), warning if not running as root |

A 2 px teal accent line runs along the very top of the toolbar.

| Button | What it does |
|--------|--------|
| **▶ Start** | Saves your settings, starts all enabled services, and sets up traffic redirection rules. Greyed out while running. |
| **■ Stop** | Stops all services and removes traffic redirection rules so your network goes back to normal. |
| **💾 Save** | Saves your current settings to `config.json` so they persist between sessions. |
| **📂 Load…** | Opens a file picker to load a different config file. |
| **A−** | Decrease text size by 15% (also `Ctrl+-`). Range: 70%–200%. |
| **A+** | Increase text size by 15% (also `Ctrl+=`). Range: 70%–200%. |
| **Ctrl+0** | Reset text size to 100%. |

All buttons change shade on hover. A `⚠ Not root` warning appears if you forgot to run with `sudo`.

### Service Sidebar

The left panel lists all services grouped by category. Click any row to open its settings.

| Group | Services |
|-------|---------|
| **CONFIG** | General settings, Preflight |
| **NETWORK** | DNS, HTTP, HTTPS, FTP |
| **MAIL** | SMTP, POP3, IMAP |
| **FALLBACK** | Catch-All |
| **ANALYSIS** | JSON Events |

Click any row to open the configuration panel. The selected row is highlighted.

### Configuration Panels

Each panel shows the settings for one service (or the General settings). These map directly to sections in `config.json`. All fields are checked for errors when you click **▶ Start**. See the [Configuration Reference](configuration.md) for a full description of every field.

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

The log panel fills the bottom of the window. You can drag the divider to make it taller or shorter. Each line is colour-coded by severity:

| Colour | Level | What it means |
|--------|-------|---------------|
| White | INFO | Normal activity (service started, request handled) |
| Orange | WARNING | Something unexpected but not broken |
| Red | ERROR | Something failed (port conflict, crash, etc.) |
| Grey | DEBUG | Detailed internal info (useful when troubleshooting) |

**Level filter pills** (DEBUG / INFO / WARNING / ERROR) let you show only one level at a time — click a pill to filter, click again to show all. The log display is capped at 2,000 lines (the file log is unlimited). Click **✕ Clear** to wipe the display.

---

## Starting and Stopping Services

1. **Configure** — click each service in the sidebar and adjust settings as needed.
2. **Save** — click **💾 Save** to persist your settings to disk.
3. **Start** — click **▶ Start**. Watch the log — you should see each service binding to its port. A new JSON log file is created automatically for each session (e.g. `logs/events_2026-04-01_s1.jsonl`).
4. **Verify** — run the quick test commands below to confirm services are responding.
5. **Detonate** — run your malware sample in the isolated victim VM.
6. **Review** — check the live log, the JSON Events tab, and the `logs/` folder. Each session gets its own log file.
7. **Stop** — click **■ Stop** to shut down all services and remove traffic redirection rules.

### Quick verification after Start

```bash
# Test DNS — should return 127.0.0.1
dig @127.0.0.1 anything-at-all.evil +short

# Test HTTP — should return "HTTP/1.1 200 OK"
curl -I http://127.0.0.1/

# Test HTTPS — -k ignores the self-signed certificate warning
curl -Ik https://127.0.0.1/

# Test SMTP — should show a "220" greeting
nc 127.0.0.1 25
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

## Preflight Checks

Preflight is a built-in diagnostic that verifies your Kali host and (optionally) the victim VM are ready for analysis. Think of it like a pre-flight checklist before takeoff.

- **GUI:** Open the **Preflight** page in the sidebar, then:
  - **Run Local Checks** — checks only the Kali host (config, ports, certs, hardening)
  - **Run All Checks** — checks Kali **and** the victim VM (via remote WMI)
  - **Fix Issues** — attempts to automatically fix problems found on the victim VM
- **CLI:** Run local checks from the terminal without launching the GUI:

```bash
sudo notthenet --preflight
```

The report checks your configuration, certificate files, network interface settings, port conflicts, lab hardening status, and whether the remote management tools (`impacket-wmiexec`, `smbclient`) are installed.

---

## CLI / Headless Mode

For running NotTheNet without a graphical display — useful for SSH sessions, automated pipelines, or systems without a desktop environment:

```bash
sudo notthenet --nogui --config config.json
```

In headless mode:
- All output goes to the terminal and `logs/notthenet.log`
- Press **Ctrl+C** to stop cleanly (services shut down and traffic rules are removed)
- Exit code `0` means clean stop; `1` means it failed to start (check the log for details)

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
- All output goes to the terminal and `logs/notthenet.log`
- Press **Ctrl+C** to stop cleanly (services shut down and traffic rules are removed)
- Exit code `0` means clean stop; `1` means it failed to start (check the log for details)

### Scripted analysis example

You can automate an entire analysis session with a shell script:

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
usage: notthenet.py [-h] [--config CONFIG] [--nogui] [--preflight] [--loglevel LEVEL]

Fake internet simulator for malware analysis.

options:
  -h, --help            Show this help message and exit
  --config CONFIG       Path to JSON config file (default: config.json)
  --nogui               Run in headless/CLI mode without the GUI
  --preflight           Run local preflight checks and exit
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

You cannot run two copies of NotTheNet at the same time (they would fight over the same ports). To switch between different configurations:

1. Click **■ Stop**
2. Click **📂 Load…** and pick the new config file
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

You need two machines connected by an isolated network — no real internet access for either:

```
┌─────────────────────────┐        ┌─────────────────────────┐
│  Analysis Host (Kali)   │        │  Victim VM (FlareVM)    │
│  NotTheNet running      │◄──────►│  Isolated network only  │
│  IP: 10.0.0.1           │        │  DNS: 10.0.0.1          │
│                         │        │  GW:  10.0.0.1          │
└─────────────────────────┘        └─────────────────────────┘
         vmbr1 (isolated virtual switch)
```

> **Need help setting this up?** See the [Lab Setup](lab-setup.md) guide for a complete walkthrough.

### Step-by-Step

1. **Snapshot the victim VM** before running anything (so you can revert to a clean state afterward).
2. Set the victim VM's **DNS server** to your Kali IP (e.g. `10.0.0.1`).
3. Set the victim VM's **default gateway** to your Kali IP (so all traffic routes through Kali).
4. In NotTheNet config: set `interface` to your lab network adapter (e.g. `eth0`), `iptables_mode` to `"gateway"`, and `redirect_ip` to your Kali IP.
5. **Check for kill-switch domains.** Some malware exits early if a specific domain resolves (famously, WannaCry checks `iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`). Add known kill-switch domains to `dns.kill_switch_domains` so they return NXDOMAIN ("not found").
6. **Check for high-entropy C2 domains.** If the malware uses random-looking domain names (like `.onion` addresses), raise `dns.nxdomain_entropy_threshold` to `4.0` or add them to `dns.custom_records`.
7. **Start** NotTheNet.
8. **Run** the malware sample in the victim VM.
9. **Watch** the live log for C2 callbacks, DNS lookups, and data exfiltration attempts.
10. **Stop** NotTheNet and review the `logs/` folder.
11. **Revert** the victim VM to its clean snapshot.

> See [Configuration → Example Configurations](configuration.md#wannacry--ransomware-with-embedded-tor-client) for a ready-made WannaCry config that bypasses the kill switch, maps `.onion` C2 addresses, and serves fake Tor directory responses.
