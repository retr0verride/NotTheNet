# Safe Detonation Guide

A step-by-step checklist for safely running ("detonating") malware in a NotTheNet + Proxmox lab. Follow this every time you analyse a new sample.

> **"Detonation"** means intentionally executing a malware sample in a controlled environment so you can observe what it does.

---

## Pre-Flight Checklist

### 1. Take a Proxmox Snapshot (with RAM)

**Always snapshot your victim VM before running malware.** Including RAM lets you freeze and resume the VM mid-execution if needed.

```bash
# Run this on the Proxmox host (not inside a VM):
qm snapshot <VMID> pre-detonation --vmstate 1 --description "Clean state before sample X"

# Verify the snapshot was created:
qm listsnapshot <VMID>
```

> Replace `<VMID>` with your FlareVM's Proxmox VM ID (visible in the Proxmox sidebar, e.g. `200`).

### 2. Verify Network Isolation

Make sure the victim VM truly cannot reach the real internet.

On **Kali** (after running `harden-lab.sh` or with auto-hardening enabled):

```bash
# Check that forwarding between the lab bridge and management network is blocked:
iptables -L FORWARD -n | grep NOTTHENET_HARDEN
# You should see two DROP rules
```

On **FlareVM** (after NotTheNet is running):

```
REM These should all work (they hit NotTheNet's fake services):
ping 10.0.0.1
nslookup evil.com 10.0.0.1
curl http://www.msftconnecttest.com/connecttest.txt
```

### 3. Verify NotTheNet Config

Double-check these settings match your lab setup:

| Setting | Should be | Why |
|---------|-----------|-----|
| `bind_ip` | `10.0.0.1` (your Kali IP) | So NotTheNet only listens on the lab network, not other interfaces |
| `interface` | `eth0` (or whatever your lab NIC is) | Traffic rules are applied to this interface |
| `redirect_ip` | `10.0.0.1` | All intercepted traffic is sent here |
| `tcp_fingerprint` | `true` | Hides the fact that Kali (Linux) is answering instead of a real Windows/Mac server |
| `tcp_fingerprint_os` | `windows` | Match what the malware expects to see |

### 4. Verify Services Are Running

After starting NotTheNet (either click **▶ Start** in the GUI or run headless):

```bash
# Check which ports NotTheNet is listening on:
ss -tlnp | grep python   # TCP services
ss -ulnp | grep python   # UDP services

# You should see at least these key ports:
# :53 (DNS), :80 (HTTP), :443 (HTTPS), :25 (SMTP),
# :21 (FTP), :445 (SMB), :23 (Telnet), :9999 (Catch-all)
```

In the GUI, every enabled service should show a green dot in the sidebar.

---

## During Analysis

- **Watch the live log:** In the GUI, or tail the JSON event log in a terminal:
  ```bash
  # Shows new log entries as they appear, formatted for readability:
  tail -f logs/events_$(date +%Y-%m-%d)_s*.jsonl | python -m json.tool
  ```
- **Do NOT connect to the victim VM from the management network** (e.g. via RDP or VNC) during detonation — this creates cross-network traffic that may confuse the malware or reveal your real IP.
- Instead, use **Proxmox's built-in noVNC console** (accessible from the Proxmox web UI) to watch the victim.

---

## Post-Detonation: Handling Captured Artifacts

### 1. Stop NotTheNet

```bash
# Press Ctrl+C in headless mode, or click Stop in the GUI.
```

### 2. Secure the artifacts

Files captured by NotTheNet in `logs/emails/` and `logs/ftp_uploads/` **may contain live malware**. Handle them carefully.

```bash
cd /opt/NotTheNet

# Compress and password-protect before transferring anywhere.
# The password "infected" is a standard convention in malware research.
zip -P infected -r artifacts.zip logs/emails/ logs/ftp_uploads/ logs/events_*.jsonl

# Check what's in the zip without extracting:
unzip -l artifacts.zip

# Create a hash for chain-of-custody documentation:
sha256sum artifacts.zip > artifacts.zip.sha256
```

### 3. Transfer safely

```bash
# Copy to an analysis workstation via SCP (never unzip on a production machine):
scp artifacts.zip analyst@10.0.0.5:/secure/evidence/

# Or copy to a USB drive:
cp artifacts.zip /media/usb-evidence/
sync  # ensures the write is flushed to the USB before unplugging
```

### 4. Revert the victim VM to its clean snapshot

```bash
# Run on the Proxmox host:
qm rollback <VMID> pre-detonation

# Verify you're back to the clean state:
qm listsnapshot <VMID>
```

### 5. Clean up Kali logs

If you mounted `logs/` as tmpfs (RAM disk), they are automatically cleared on reboot. Otherwise:

```bash
# Delete captured emails and uploads from the previous session:
rm -rf logs/emails/* logs/ftp_uploads/*

# Clear the event log:
rm -f logs/events_$(date +%Y-%m-%d)_s*.jsonl
```

---

## Proxmox KVM Cloaking

Some malware checks if it's running inside a virtual machine and refuses to execute if it detects one. To defeat this, you can modify the Proxmox VM config to hide the virtualisation layer.

> **For the full step-by-step guide**, see [Lab Setup: Proxmox → Part 8: Anti-Detection Hardening](lab-setup-proxmox.md#part-8--anti-detection-hardening).

Here's a quick summary of the key settings to add to `/etc/pve/qemu-server/<VMID>.conf` on the Proxmox host:

```ini
# Hide the KVM hypervisor so malware can't detect it
args: -cpu host,kvm=off,hv_vendor_id=GenuineIntel

# Pass the real CPU model through (no "QEMU Virtual CPU" string)
cpu: host,hidden=1

# Make WMI report real hardware names instead of "QEMU"
smbios1: type=0,vendor=Dell Inc.,version=A11
smbios1: type=1,manufacturer=Dell Inc.,product=OptiPlex 7050,serial=ABC1234XYZ

# Disable memory ballooning (some malware detects this)
balloon: 0

# Use a modern chipset (the old i440fx is a known sandbox indicator)
machine: pc-q35-9.2
```

### Additional QEMU args (add to `args:` line)

```ini
args: -cpu host,kvm=off,hv_vendor_id=GenuineIntel,+hypervisor -smbios type=0,vendor="Dell Inc.",version=A11 -smbios type=1,manufacturer="Dell Inc.",product="OptiPlex 7050",serial=ABC1234XYZ,uuid=4c4c4544-0044-4810-8031-c2c04f333432
```

### Verify from inside the victim VM

```cmd
:: Should NOT say "Microsoft Hv" or "KVMKVMKVM"
wmic bios get manufacturer,serialnumber,version
wmic computersystem get manufacturer,model

:: Check for VM artifacts:
reg query "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions" 2>nul
reg query "HKLM\SOFTWARE\VMware, Inc.\VMware Tools" 2>nul
:: Both should return "ERROR: The system was unable to find the specified registry key"
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│                  SAFE DETONATION FLOW                   │
├─────────────────────────────────────────────────────────┤
│  1. qm snapshot <VMID> pre-det --vmstate 1             │
│  2. sudo bash harden-lab.sh --bridge vmbr1 --mgmt eth0 │
│  3. sudo python notthenet.py --nogui                    │
│  4. Start victim VM → deploy sample                     │
│  5. Monitor logs/events_$(date +%Y-%m-%d)_s*.jsonl         │
│  6. Stop NotTheNet                                      │
│  7. zip -P infected artifacts.zip logs/emails/ ...      │
│  8. qm rollback <VMID> pre-det                         │
│  9. sudo umount /opt/NotTheNet/logs                     │
└─────────────────────────────────────────────────────────┘
```
