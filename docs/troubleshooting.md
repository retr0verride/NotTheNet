# Troubleshooting Guide

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

---

## Services fail to bind ports

**Symptom:** Log shows `OSError: [Errno 13] Permission denied` or `[Errno 98] Address already in use`.

### Permission denied (Errno 13)

Port numbers below 1024 require root.

**Fix:**
```bash
sudo notthenet
# or
sudo venv/bin/python notthenet.py
```

If you don't want to run as root, shift services to high ports and rely on iptables REDIRECT (which itself requires root, but doesn't need the service on a low port):
```json
"http": { "port": 8080 },
"https": { "port": 8443 }
```

### Address already in use (Errno 98)

Another process is already using that port.

**Automatic fix:** NotTheNet automatically stops known conflicting services on startup when `auto_evict_services: true` (the default). Check the log for lines like `Stopping conflicting system service: apache2`.

**Manual fix — find and kill the conflicting process:**
```bash
# Find what's using port 53
sudo ss -tulpn | grep ':53'
sudo lsof -i :53

# Common culprit: systemd-resolved on Ubuntu/Kali
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Or change its stub listener port only
sudo sed -i 's/^#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```

**For port 80/443 — Apache/nginx running:**
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

### Check the service is running

In the GUI, the DNS dot should be green. In headless mode:
```bash
sudo ss -tulpn | grep ':53'
# Should show: udp   UNCONN 0  0  0.0.0.0:53  ...python
#              tcp   LISTEN 0  0  0.0.0.0:53  ...python
```

### Check systemd-resolved conflict (Ubuntu/Kali)

```bash
resolvectl status | head -5
# If "DNS Stub Listener: yes", it's occupying 127.0.0.53:53

sudo systemctl stop systemd-resolved
sudo notthenet    # restart NotTheNet
```

### Check firewall blocking DNS

```bash
sudo iptables -L INPUT -n | grep 53
# If a DROP rule is catching port 53, add an ACCEPT before it
sudo iptables -I INPUT 1 -p udp --dport 53 -j ACCEPT
sudo iptables -I INPUT 1 -p tcp --dport 53 -j ACCEPT
```

### dnslib not installed

```
ERROR: DNS service cannot start: dnslib not installed.
```
```bash
source venv/bin/activate
pip install dnslib==0.9.25
```

---

## HTTP/HTTPS not responding

**Symptom:** `curl http://127.0.0.1/` times out or returns connection refused.

```bash
# Check the service is listening
sudo ss -tlpn | grep ':80'
sudo ss -tlpn | grep ':443'

# Test directly (bypassing iptables)
curl -v http://127.0.0.1:80/
curl -kv https://127.0.0.1:443/
```

If the direct port test works but DNS-resolved URLs don't, the issue is with iptables redirect — see [iptables rules not applied](#iptables-rules-not-applied).

---

## iptables rules not applied

**Symptom:** Log shows `iptables rules cannot be applied` or rules aren't visible.

```bash
# Check if iptables is available
which iptables
iptables --version

# On newer systems, iptables may need the legacy backend
update-alternatives --config iptables
# Select: iptables-legacy

# Check for nftables conflict
systemctl status nftables
# If nftables is running and has rules, it may override iptables
```

**Check the interface name is correct:**
```bash
ip link show
# Lists: eth0, virbr0, lo, etc.
# Make sure config.interface matches one of these exactly
```

**Verify rules were applied:**
```bash
sudo iptables -t nat -L OUTPUT --line-numbers -n | grep NOTTHENET
```

---

## Malware still reaching real internet

**Symptom:** Malware successfully connects to real C2 servers instead of NotTheNet.

### Check DNS is being used

Some malware bypasses the system DNS and hard-codes IP addresses. If the sample uses hard-coded IPs, DNS interception won't help — you need iptables catch-all to redirect those connections.

Verify the catch-all is working:
```bash
nc -v 1.2.3.4 80   # from the victim machine
# Should connect to NotTheNet catch-all, not 1.2.3.4
```

### Check the interface

The most common cause: `general.interface` is set to `eth0` but the victim VM traffic arrives on `virbr0`. The iptables rule is applied to the wrong interface.

```bash
# Watch actual traffic to identify the correct interface
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

**Symptom:** NotTheNet is running, iptables rules are applied, `ip_forward=1`, but the analysis VM cannot ping or connect to any external IP. Traffic never arrives at Kali.

### Cause

Hypervisor-level firewalls (Proxmox VE firewall, VMware NSX, ESXi port groups) inspect packets **before** they reach the guest OS. When the analysis VM sends a packet to `8.8.8.8`, the hypervisor sees the real destination IP — not the DNAT'd address — and drops it if no matching ACCEPT rule exists.

This is true even if the VMs are on an isolated bridge with no physical uplink.

### Fix

**Recommended: Disable the hypervisor firewall on both lab VMs.** If the bridge has no physical uplink, network topology already provides containment — the firewall adds no value and breaks DNAT-based traffic interception.

**Proxmox:**
1. Select the Kali VM → **Firewall** → **Options** → set **Firewall: No**
2. Select the analysis VM → **Firewall** → **Options** → set **Firewall: No**

Security groups and firewall rules are only evaluated when the VM-level firewall is enabled. Disabling it per-VM does not affect other VMs or the datacenter-level firewall.

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

**Symptom:** Windows taskbar shows "No Internet access" on the network icon, even though DNS resolves and HTTP works.

### How Windows checks connectivity (NCSI)

Windows runs the Network Connectivity Status Indicator (NCSI) probe on every network change:

1. **HTTP probe:** `GET http://www.msftconnecttest.com/connecttest.txt` — expects body `Microsoft Connect Test`
2. **DNS probe:** resolves `dns.msftncsi.com` — expects `131.107.255.255`

Both must succeed for Windows to show "Internet access".

### NotTheNet handles this automatically

As of v2026.03.13-2, NotTheNet has built-in NCSI support:
- HTTP server responds with the correct body for `www.msftconnecttest.com` and `msftconnecttest.com`
- DNS server returns `131.107.255.255` for `dns.msftncsi.com`

If NCSI is still failing, verify:
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

**Symptom:** Password prompt appears (pkexec / polkit) but the GUI never opens afterward.

This is a known polkit issue — versions 0.106+ strip `DISPLAY` and `XAUTHORITY` from the
environment before launching the process, so the program starts as root but cannot connect
to the X display.

**Fix:** Re-run the install script to deploy the updated launcher that explicitly forwards the display environment:

```bash
sudo bash notthenet-install.sh
```

Then launch via the desktop icon or:

```bash
notthenet-gui
```

If you cannot re-run the install script, you can work around it by launching directly from a terminal with `sudo`:

```bash
sudo /path/to/venv/bin/python notthenet.py
```

---

**Symptom:** `ModuleNotFoundError: No module named 'tkinter'` or display errors.

```bash
# Install Tkinter (Kali/Debian)
sudo apt-get install python3-tk

# Verify
python3 -c "import tkinter; tkinter._test()"
```

**On headless server (no display):**
```bash
# Use headless mode
sudo notthenet --nogui

# Or set up a virtual display
sudo apt-get install xvfb
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 &
sudo notthenet
```

---

## TLS / certificate errors

**Symptom:** `ssl.SSLError: [SSL] PEM lib` or `No such file or directory: certs/server.crt`.

### Regenerate the certificate

```bash
rm -f certs/server.crt certs/server.key
sudo notthenet   # will auto-generate
```

Or manually:
```bash
source venv/bin/activate
python3 -c "
from utils.cert_utils import generate_self_signed_cert
generate_self_signed_cert('certs/server.crt', 'certs/server.key')
"
```

### Check key permissions

```bash
ls -la certs/
# server.key must be readable by the process user
chmod 600 certs/server.key
```

### Wrong working directory

NotTheNet resolves cert paths relative to the working directory. Always run from the project root:
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

**Symptom:** NotTheNet consuming >10% CPU or growing memory.

### Flooded with connections

Malware may be hammering the fake services. Check the log for thousands of rapid-fire requests. The bounded thread pool (50 workers) prevents CPU runaway, but log writes can still stress the disk.

Reduce log verbosity:
```json
"general": { "log_level": "WARNING" }
```

Or disable request logging:
```json
"http": { "log_requests": false },
"https": { "log_requests": false }
```

### Log file disk usage

```bash
du -sh logs/
ls -lh logs/notthenet.log*
# If > 50 MB total (5 × 10 MB), something is wrong with rotation
```

---

## Log file not created

**Symptom:** No `logs/notthenet.log` file after starting.

```bash
# Check the log directory exists and is writable
ls -la logs/
# If it doesn't exist:
mkdir -p logs && chmod 700 logs

# Check config
cat config.json | python3 -m json.tool | grep log
# "log_to_file" must be true
```

Also verify the user running NotTheNet has write permission to the `logs/` directory (NotTheNet runs as root, so this is only an issue if the directory was created with restrictive permissions by another user).

---

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
source venv/bin/activate
which python3   # should point to venv/bin/python3

# Reinstall dependencies
pip install -r requirements.txt

# Run explicitly through venv
sudo venv/bin/python notthenet.py
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
