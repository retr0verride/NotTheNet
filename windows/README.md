# NotTheNet — Windows Edition

A Windows-native fake internet simulator for malware analysis. Like FakeNet, but with full protocol support and a live dashboard.

## Features

- **27 fake services** — DNS, DoT, HTTP/S, SMTP/S, POP3/S, IMAP/S, FTP, NTP, TFTP, IRC, Telnet, SOCKS5, VNC, RDP, SMB, MySQL, MSSQL, Redis, LDAP, ICMP, and more
- **No iptables required** — runs natively on Windows, binds to standard ports directly
- **GUI dashboard** — live log viewer with color coding, JSON events viewer, service status
- **JSON event logs** — each session creates `logs/events_YYYY-MM-DD_sN.jsonl` for analysis
- **No elevation required** (for ports > 1024) — can run from regular user account
- **Cross-platform Python** — same code runs on Windows, Linux, macOS

## Quick Start

### Prerequisites

- Windows 10/11 or Server 2019+
- Python 3.10+
- Administrator access (optional, required only for ports < 1024)

### Installation

```powershell
# Clone or extract NotTheNet
cd NotTheNet\windows

# Install Python dependencies
pip install -r requirements.txt

# Run in GUI mode
python notthenet.py

# Or run headless
$env:NTN_HEADLESS = "1"
python notthenet.py
```

### Configuration

Edit `config.json` to:
- Enable/disable services
- Change service ports
- Configure DNS resolution behavior
- Set response delays and spoofed IPs

### Running Services

The default configuration binds to:

| Service | Port |
|---------|------|
| DNS (UDP) | 53 |
| HTTP | 80 |
| HTTPS | 443 |
| FTP | 21 |
| SMTP | 25 |
| POP3 | 110 |
| IMAP | 143 |
| SSH (will add) | 22 |
| RDP | 3389 |
| SMB | 445 |

**Note:** Ports below 1024 on Windows require administrator access.

## Architecture

```
domain/          Pure business logic (platform-agnostic)
application/     Use-cases: orchestrator, health checks
infrastructure/  Windows adapters: logging, config, event sink
services/        Network protocol handlers
gui/             Tkinter dashboard
```

## Headless / Automation Mode

```powershell
# Run without GUI, expose health check on :8080
$env:NTN_HEADLESS = "1"
$env:NTN_LOG_LEVEL = "DEBUG"
python notthenet.py

# Check health
Invoke-WebRequest http://localhost:8080/health
```

## Configuration via Environment Variables

```powershell
$env:NTN_BIND_IP = "0.0.0.0"
$env:NTN_LOG_DIR = "C:\Temp\NotTheNet\logs"
$env:NTN_LOG_LEVEL = "DEBUG"
$env:NTN_SPOOF_PUBLIC_IP = "8.8.8.8"
python notthenet.py
```

## Event Logs

After each session, structured event logs are written to `logs/events_*.jsonl`:

```json
{"event_type": "service.start", "service": "dns", "success": true, "timestamp": 1234567890.0}
{"event_type": "service.start", "service": "http", "success": true, "timestamp": 1234567890.1}
```

Analyze logs with standard tools:

```powershell
Get-Content logs/events_*.jsonl | ConvertFrom-Json | Where-Object { $_.event_type -eq "service.start" }
```

## Differences from Linux Version

| Feature | Linux | Windows |
|---------|-------|---------|
| Traffic redirection | iptables / nftables | Direct port binding |
| Privilege dropping | yes (root→nobody) | N/A (UAC handles) |
| Process masquerading | setproctitle | N/A |
| Network interface selection | eth0 configurable | N/A |
| TTL mangle | iptables mangle table | TCP/IP fingerprinting only |

## Troubleshooting

### "Address already in use" errors

Port is already bound (another service or NotTheNet instance):

```powershell
# Find what's using port 53 (for DNS)
netstat -ano | Select-String ":53 "
# Kill the process
taskkill /PID <PID> /F
```

### "Access denied" when binding ports < 1024

You need administrator access:

```powershell
Start-Process powershell -Verb RunAs
# Then run NotTheNet in the new admin console
```

### GUI not starting

Try headless mode to verify the issue:

```powershell
$env:NTN_HEADLESS = "1"
python notthenet.py
```

## GUI Controls

- **Start** — Launch all enabled services
- **Stop** — Gracefully shut down all services
- **Restart [service]** — Restart a specific service
- **View Logs** — Open real-time event log viewer
- **Settings** — Edit config.json and reload

## License

MIT — see LICENSE file in the root directory.
