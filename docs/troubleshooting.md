# Troubleshooting Guide

Common problems and how to fix them. Each section starts with the **symptom** (what you see) and ends with the **fix**.

## Table of Contents

- [Services fail to bind ports](#services-fail-to-bind-ports)
- [DNS not resolving](#dns-not-resolving)
- [HTTP/HTTPS not responding](#httphttps-not-responding)
- [iptables rules not applied](#iptables-rules-not-applied)
- [Malware still reaching real internet](#malware-still-reaching-real-internet)
- [Hypervisor firewall blocking traffic (Proxmox / ESXi)](#hypervisor-firewall-blocking-traffic-proxmox--esxi)
- [Windows shows "No Internet" (NCSI failure)](#windows-shows-no-internet-ncsi-failure)
- [GUI won't start / Tkinter errors](#gui-wont-start--tkinter-errors)
- [TLS / certificate errors](#tls--certificate-errors)
- [High CPU or memory usage](#high-cpu-or-memory-usage)
- [Log file not created](#log-file-not-created)
- [Emails / FTP uploads not saved](#emails--ftp-uploads-not-saved)
- [iptables rules left behind after crash](#iptables-rules-left-behind-after-crash)
- [Python import errors](#python-import-errors)
- [Getting a debug trace](#getting-a-debug-trace)
- [DoH sinkhole not intercepting queries](#doh-sinkhole-not-intercepting-queries)
- [WebSocket connections not captured](#websocket-connections-not-captured)
- [Dynamic responses returning wrong type](#dynamic-responses-returning-wrong-type)
- [Dynamic TLS certs not working](#dynamic-tls-certs-not-working)
- [TCP fingerprint not applied](#tcp-fingerprint-not-applied)
- [JSON event log not created](#json-event-log-not-created)
- [Windows 7 victim — TLS connections fail or malware ignores HTTPS](#windows-7-victim--tls-connections-fail-or-malware-ignores-https)

---

## Services fail to bind ports

**Symptom:** The log shows `OSError: [Errno 13] Permission denied` or `[Errno 98] Address already in use`.

### Permission denied (Errno 13)

Ports below 1024 (like 53 for DNS, 80 for HTTP, 443 for HTTPS) require root access on Linux.

**Fix:** Run NotTheNet with `sudo`:
```bash
sudo notthenet
```

If you don't want to run as root, shift services to high ports and rely on iptables REDIRECT (which itself requires root, but doesn't need the service on a low port):
```json
"http": { "port": 8080 },
"https": { "port": 8443 }
```

### Address already in use (Errno 98)

Another program is already using that port.

**Automatic fix:** NotTheNet can automatically stop known conflicting services (like Apache or systemd-resolved) when it starts. This is enabled by default (`auto_evict_services: true`). Check the log for messages like `Stopping conflicting system service: apache2`.

**Manual fix — find and stop the conflicting program:**
```bash
# Find what's using port 53 (DNS):
sudo ss -tulpn | grep ':53'

# The most common culprit is systemd-resolved (a built-in DNS service on Ubuntu/Kali):
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
```

**For port 80/443 — web server running:**
```bash
sudo systemctl stop apache2
sudo systemctl stop nginx
```

**To disable auto-eviction** (if you want to manage conflicting services manually):
```json
"general": { "auto_evict_services": false }
```

---

## DNS not resolving

**Symptom:** `dig @127.0.0.1 evil.com` hangs or returns `connection refused`.

### Check that the DNS service is running

In the GUI, the DNS row in the sidebar should have a green dot. From the terminal:
```bash
sudo ss -tulpn | grep ':53'
# You should see two lines — one for UDP and one for TCP — with "python" as the process
```

### Check for systemd-resolved conflict (Ubuntu/Kali)

systemd-resolved is a built-in DNS service that may be occupying port 53. Check:
```bash
resolvectl status | head -5
# If you see "DNS Stub Listener: yes", it's blocking NotTheNet

# Fix: stop it and restart NotTheNet
sudo systemctl stop systemd-resolved
sudo notthenet
```

### Check if a firewall is blocking DNS

```bash
sudo iptables -L INPUT -n | grep 53
# If you see a DROP rule blocking port 53, add ACCEPT rules:
sudo iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
```

### dnslib not installed

If the log shows `DNS service cannot start: dnslib not installed`:
```bash
source .venv/bin/activate
pip install dnslib==0.9.25
```

---

## HTTP/HTTPS not responding

**Symptom:** `curl http://127.0.0.1/` times out or returns "connection refused".

First, check whether the service is actually listening:
```bash
sudo ss -tlpn | grep ':80'
sudo ss -tlpn | grep ':443'
```

Then test the ports directly (bypassing traffic redirection):
```bash
curl -v http://127.0.0.1:80/
curl -kv https://127.0.0.1:443/   # -k ignores the self-signed cert
```

If direct port tests work but browsing fails, the issue is with traffic redirection — see [iptables rules not applied](#iptables-rules-not-applied).

---

## iptables rules not applied

**Symptom:** The log shows `iptables rules cannot be applied` or you can't see any NOTTHENET rules.

```bash
# Check that iptables is installed:
which iptables
iptables --version

# On newer systems, iptables may need to use the "legacy" backend instead of nftables:
sudo update-alternatives --config iptables
# Select: iptables-legacy
```

**Check the interface name is correct:**
```bash
ip link show
# This lists all network interfaces (e.g. eth0, lo, vmbr1)
# Make sure the name in config.json matches exactly
```

**Verify rules were applied:**
```bash
sudo iptables -t nat -L OUTPUT --line-numbers -n | grep NOTTHENET
```

---

## Malware still reaching real internet

**Symptom:** The malware successfully connects to real C2 servers instead of NotTheNet.

### Some malware bypasses DNS entirely

If the malware has hard-coded IP addresses (instead of domain names), DNS interception won't help. You need the **catch-all** service to redirect those connections.

Test the catch-all from the victim:
```bash
nc -v 1.2.3.4 80
# Should connect to NotTheNet's catch-all, not the real 1.2.3.4
```

### Wrong interface

The most common cause: `general.interface` is set to the wrong network adapter. For example, it's set to `eth0` but victim traffic actually arrives on `vmbr1`.

```bash
# Watch live traffic to identify which interface the victim's packets arrive on:
sudo tcpdump -i any port 80 -n
```

### Block real internet explicitly

Add a blanket drop rule for traffic escaping to the real internet:
```bash
# Block everything except traffic to/from the analysis network
sudo iptables -A FORWARD -i virbr0 -o eth0 -j DROP
```

---

## Hypervisor firewall blocking traffic (Proxmox / ESXi)

**Symptom:** NotTheNet is running, traffic rules are set up, IP forwarding is on, but the victim VM can't reach anything. Traffic never arrives at Kali.

### Why this happens

Hypervisor-level firewalls (Proxmox firewall, VMware NSX) check packets **before** they reach the guest OS. When the victim sends a packet to `8.8.8.8`, the hypervisor sees the real destination and may drop it — even though Kali's iptables would redirect it to NotTheNet.

### Fix

**Disable the hypervisor firewall on both lab VMs.** The isolated bridge with no physical uplink already provides network containment — the hypervisor firewall adds no value in this setup.

**Proxmox:**
1. Select Kali VM → **Firewall** → **Options** → **Firewall: No**
2. Select FlareVM → **Firewall** → **Options** → **Firewall: No**

Disabling per-VM does not affect other VMs or your datacenter-level firewall.

**VMware / ESXi:**
- Ensure the port group security policy allows promiscuous mode, MAC address changes, and forged transmits if using a vSwitch.

### Verification

```bash
# On Kali — confirm traffic is now arriving
sudo tcpdump -i any -c 5 icmp
# Then ping 8.8.8.8 from the analysis VM — you should see packets
```

---

## Windows shows "No Internet" (NCSI failure)

**Symptom:** The Windows taskbar shows "No Internet access" even though DNS and HTTP work.

### Why this happens

Windows has a built-in connectivity checker called NCSI that runs two specific tests:

1. **HTTP test:** Fetches `http://www.msftconnecttest.com/connecttest.txt` and expects the exact text `Microsoft Connect Test`
2. **DNS test:** Resolves `dns.msftncsi.com` and expects the IP `131.107.255.255`

Both must pass for Windows to show "connected".

### NotTheNet handles this automatically

NotTheNet's built-in NCSI support fakes both responses. If it's still failing, test manually:
```bash
# From the analysis VM — test the HTTP probe
curl -s http://www.msftconnecttest.com/connecttest.txt
# Should return: Microsoft Connect Test

# Test the DNS probe
nslookup dns.msftncsi.com
# Should return: 131.107.255.255
```

If `curl` works but Windows still shows "No Internet", try:
```powershell
# On the analysis VM (PowerShell as Administrator)
# Force NCSI re-check
ipconfig /flushdns
# Disable and re-enable the network adapter
Get-NetAdapter | Restart-NetAdapter
```

---

## GUI won't start / Tkinter errors

**Symptom:** The password prompt appears but the GUI never opens.

This is a known issue with certain Linux desktop environments — the password tool (`pkexec`) strips display environment variables, so the program starts as root but can't open a window.

**Fix:** Re-run the install script to get the updated launcher:

```bash
sudo bash notthenet-install.sh
```

Then launch via the desktop icon or:

```bash
notthenet-gui
```

If that doesn't work, launch directly from a terminal with sudo:

```bash
sudo .venv/bin/python notthenet.py
```

---

**Symptom:** `ModuleNotFoundError: No module named 'tkinter'`

Tkinter is the Python GUI toolkit. On some systems it needs to be installed separately:

```bash
sudo apt-get install python3-tk

# Test that it works:
python3 -c "import tkinter; tkinter._test()"
```

**On a headless server (no display):**
```bash
# Use headless mode instead:
sudo notthenet --nogui
```

---

## TLS / certificate errors

**Symptom:** `ssl.SSLError: [SSL] PEM lib` or `No such file or directory: certs/server.crt`.

### Regenerate the certificate

The simplest fix is to delete the old certificates and let NotTheNet create new ones:

```bash
rm -f certs/server.crt certs/server.key
sudo notthenet   # will auto-generate new certs on startup
```

### Check key permissions

The private key must be readable by the process running NotTheNet:
```bash
ls -la certs/
# server.key should show: -rw------- 1 root root ...
# If not:
chmod 600 certs/server.key
```

### Wrong working directory

NotTheNet looks for certificate files relative to wherever you run it from. Always run from the project root:
```bash
cd /opt/NotTheNet
sudo notthenet
```

Or use absolute paths in `config.json`:
```json
"https": {
  "cert_file": "/opt/NotTheNet/certs/server.crt",
  "key_file": "/opt/NotTheNet/certs/server.key"
}
```

---

## High CPU or memory usage

**Symptom:** NotTheNet using >10% CPU or memory keeps growing.

### Malware is flooding the fake services

Some malware hammers its C2 server with rapid-fire requests. NotTheNet's thread pool (50 workers) prevents CPU runaway, but heavy logging can still stress the disk.

Reduce log verbosity:
```json
"general": { "log_level": "WARNING" }
```

### Check log file sizes

```bash
du -sh logs/
ls -lh logs/notthenet.log*
# Normal: under 50 MB total (5 × 10 MB rotation)
```

---

## Log file not created

**Symptom:** No `logs/notthenet.log` file after starting.

```bash
# Check the logs directory exists and is writable:
ls -la logs/

# If it doesn't exist, create it:
mkdir -p logs && chmod 700 logs

# Check that logging is enabled in your config:
grep log_to_file config.json
# Should show: "log_to_file": true
```

## Emails / FTP uploads not saved

**Symptom:** Receiving connections but no files in `logs/emails/` or `logs/ftp_uploads/`.

```bash
# Check directories exist
ls -la logs/emails/ logs/ftp_uploads/

# Check disk space
df -h .

# Check size caps haven't been hit (grep log)
grep "storage cap" logs/notthenet.log

# Check config
cat config.json | python3 -m json.tool | grep save_emails
cat config.json | python3 -m json.tool | grep allow_uploads
```

---

## iptables rules left behind after crash

If NotTheNet crashed without removing its iptables rules, connections may be silently redirected even when NotTheNet isn't running.

```bash
# Check for leftover rules
sudo iptables -t nat -L OUTPUT -n | grep NOTTHENET
sudo iptables -t nat -L PREROUTING -n | grep NOTTHENET

# Remove all NOTTHENET-tagged rules from OUTPUT
sudo iptables -t nat -S OUTPUT | grep NOTTHENET | while read rule; do
  sudo iptables -t nat $(echo $rule | sed 's/-A/-D/')
done

# Or restore from snapshot if present
sudo iptables-restore /tmp/notthenet_iptables_save.rules
```

---

## Python import errors

**Symptom:** `ModuleNotFoundError: No module named 'dnslib'` or similar.

```bash
# Ensure you're using the venv
source .venv/bin/activate
which python3   # should point to .venv/bin/python3

# Reinstall dependencies
pip install -r requirements.txt

# Run explicitly through venv
sudo .venv/bin/python notthenet.py
```

---

## Getting a debug trace

For any issue not covered above, run with maximum verbosity:

```bash
sudo notthenet --nogui --loglevel DEBUG 2>&1 | tee debug.log
```

Or in the GUI, set `Log Level` to `DEBUG` before clicking Start.

Include the relevant portion of `debug.log` when opening a GitHub issue.

---

## DoH sinkhole not intercepting queries

**Symptom:** Malware bypasses the fake DNS server by using DNS-over-HTTPS and resolves real IPs.

1. Confirm `doh_sinkhole` is `true` in both `http` and `https` config sections
2. Check the log for `DoH` entries — if no entries appear, the malware may be using a non-standard DoH endpoint
3. Verify the malware is sending `Content-Type: application/dns-message` or requesting `/dns-query`
4. Check `doh_redirect_ip` is set correctly (should match your NotTheNet host IP)

---

## WebSocket connections not captured

**Symptom:** Malware opens WebSocket connections but they don't appear in the log.

1. Confirm `websocket_sinkhole` is `true` in both `http` and `https` config sections
2. The WebSocket sinkhole only triggers on proper upgrade requests (`Connection: Upgrade`, `Upgrade: websocket`). If malware uses a non-standard handshake, it falls through to the normal HTTP handler
3. Check the log for `websocket_upgrade` events

---

## Dynamic responses returning wrong type

**Symptom:** Requests for `.exe` or `.dll` return HTML instead of a PE stub.

1. Confirm `dynamic_responses` is `true` in the relevant `http`/`https` config section
2. If you have custom `dynamic_response_rules`, check that regex patterns are valid (use Python `re` syntax)
3. Custom rules take priority — a broad custom rule may be matching before the extension map
4. Check the request path actually contains the extension (some malware uses extensionless paths)

---

## Dynamic TLS certs not working

**Symptom:** All HTTPS connections get the same self-signed cert instead of per-domain certs.

1. Confirm `https.dynamic_certs` is `true`
2. Check that `certs/ca.crt` and `certs/ca.key` exist — they are auto-generated on first start. If missing, restart NotTheNet
3. Check the log for SNI callback errors (set `log_level: DEBUG`)
4. The client must send an SNI hostname in the `ClientHello` — connections with no SNI get the default cert
5. To trust forged certs in the analysis VM, install `certs/ca.crt` in the trust store (see [Security Hardening](security-hardening.md))

---

## TCP fingerprint not applied

**Symptom:** `nmap -O` still identifies the host as Linux even with `tcp_fingerprint_os: "windows"`.

1. TCP fingerprint spoofing is **Linux only** — it has no effect on other platforms
2. Confirm `general.tcp_fingerprint` is `true` and `tcp_fingerprint_os` is set to a valid profile
3. Check the log for warnings about `setsockopt` failures (usually means the kernel doesn't support the option)
4. Nmap OS detection uses many heuristics — TCP fingerprint spoofing covers TTL, window size, DF bit, and MSS but cannot control all parameters. It is most effective against simpler fingerprinting checks

---

## Windows 7 victim — TLS connections fail or malware ignores HTTPS

**Symptom:** Port 443 hits appear in the log but no application data is captured; or malware (e.g. WannaCry) completes DNS and HTTP steps but silently skips HTTPS C2 callbacks.

**Cause:** Windows 7 does not enable TLS 1.2 in Schannel or WinHTTP by default. NotTheNet enforces `TLSv1.2` as its minimum, so the TLS handshake fails before any data is exchanged.

### Fix — enable TLS 1.2 on Windows 7 (run on the victim VM as Administrator)

```powershell
# Enable TLS 1.2 for Schannel (system-wide, covers malware that uses WinHTTP / wininet)
$tls12 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2'
New-Item -Path "$tls12\Client" -Force | Out-Null
New-Item -Path "$tls12\Server" -Force | Out-Null
Set-ItemProperty -Path "$tls12\Client" -Name Enabled       -Value 1 -Type DWord
Set-ItemProperty -Path "$tls12\Client" -Name DisabledByDefault -Value 0 -Type DWord
Set-ItemProperty -Path "$tls12\Server" -Name Enabled       -Value 1 -Type DWord
Set-ItemProperty -Path "$tls12\Server" -Name DisabledByDefault -Value 0 -Type DWord

# Enable TLS 1.2 for WinHTTP (covers .NET and some C2 frameworks)
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' `
    -Name DefaultSecureProtocols -Value 0x00000800 -Type DWord

# On 64-bit Windows 7 apply the WOW64 key too
if (Test-Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp') {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' `
        -Name DefaultSecureProtocols -Value 0x00000800 -Type DWord
}
```

Reboot the VM after applying, then take a new baseline snapshot.

> **Note:** Some malware (including WannaCry) uses its own bundled TLS/SSL stack (e.g. a statically linked OpenSSL) and ignores the Schannel registry entirely. In that case the fix above has no effect — the malware will still do its own TLS negotiation. WannaCry's HTTPS traffic to the kill-switch domain (`iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com`) uses a plain HTTP GET, not HTTPS, so this is not a blocker for capturing the kill-switch check. See [Configuration → WannaCry example](configuration.md#wannacry--ransomware-with-embedded-tor-client).

### Install the CA cert on Windows 7

Windows 7's `certutil` syntax is the same as later versions:

```powershell
# Copy ca.crt from Kali first (e.g. via NotTheNet's cert HTTP server on :8080)
certutil -addstore Root ca.crt
```

Or use the GUI: double-click `ca.crt` → **Install Certificate** → **Local Machine** → **Trusted Root Certification Authorities**.

---

## JSON event log not created

**Symptom:** `json_logging` is enabled but no `.jsonl` file appears.

1. Confirm `general.json_logging` is `true` in config.
2. Check the `logs/` directory exists and is writable. Each session creates a new file like `logs/events_2026-04-01_s1.jsonl` — the directory must exist before the first start.
3. Check disk space — the logger stops writing at 500 MB.
4. Check the main log for errors from `json_logger` (set `log_level: DEBUG`).

## JSON export fails — Permission denied

**Symptom:** Clicking **Export** or **Open File** in the JSON Events view shows "Permission denied" or "Cannot change to the directory".

This happens when `general.drop_privileges` is `true` (the default) and the dropped user (`nobody`) cannot write to the chosen export destination.

**Fix — export to the logs directory:** The export dialog opens directly in `logs/` where the dropped user already has write access (the service manager `chown`s it before dropping). Save the export file there.

**Fix — export to another location:** If you need to save elsewhere, ensure the target directory is writable by the drop user before clicking Start, or add it to the pre-drop chown list in `service_manager._prepare_dirs_for_drop()`.

**Fix — disable privilege drop:** Set `general.drop_privileges: false` if you want unrestricted filesystem access during the session (less secure but simpler for offline analysis hosts).
