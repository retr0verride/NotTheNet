# Troubleshooting Guide

## Table of Contents

- [Services fail to bind ports](#services-fail-to-bind-ports)
- [DNS not resolving](#dns-not-resolving)
- [HTTP/HTTPS not responding](#httphttps-not-responding)
- [iptables rules not applied](#iptables-rules-not-applied)
- [Malware still reaching real internet](#malware-still-reaching-real-internet)
- [GUI won't start / Tkinter errors](#gui-wont-start--tkinter-errors)
- [TLS / certificate errors](#tls--certificate-errors)
- [High CPU or memory usage](#high-cpu-or-memory-usage)
- [Log file not created](#log-file-not-created)
- [Emails / FTP uploads not saved](#emails--ftp-uploads-not-saved)
- [iptables rules left behind after crash](#iptables-rules-left-behind-after-crash)
- [Python import errors](#python-import-errors)
- [Getting a debug trace](#getting-a-debug-trace)

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

**Fix — find and kill the conflicting process:**
```bash
# Find what's using port 53
sudo ss -tulpn | grep ':53'
sudo lsof -i :53

# Common culprit: systemd-resolved on Ubuntu/Kali
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved

# Or change its port
sudo sed -i 's/^#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf
sudo systemctl restart systemd-resolved
```

**For port 80/443 — Apache/nginx running:**
```bash
sudo systemctl stop apache2
sudo systemctl stop nginx
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

## GUI won't start / Tkinter errors

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

Also verify the user running NotTheNet has write permission to the `logs/` directory after the privilege drop to `nobody`.

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
