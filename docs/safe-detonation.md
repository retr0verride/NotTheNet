# Safe Detonation Guide

Complete checklist for running malware safely in a NotTheNet + Proxmox lab.

---

## Pre-Flight Checklist

### 1. Proxmox Snapshot (RAM-inclusive)

**Always snapshot before detonation.** Include RAM so you can resume analysis mid-execution.

```bash
# From Proxmox host shell:
qm snapshot <VMID> pre-detonation --vmstate 1 --description "Clean state before sample X"

# Verify:
qm listsnapshot <VMID>
```

> Replace `<VMID>` with your Windows 7 victim VM ID (e.g., `101`).

### 2. Network Isolation Verification

On the **Kali host** (after running `harden-lab.sh`):

```bash
# Confirm bridge ↔ management forwarding is blocked:
iptables -L FORWARD -n | grep NOTTHENET_HARDEN
# Expected: two DROP rules (bridge→mgmt, mgmt→bridge)

# Confirm no real internet from victim subnet:
ip netns exec victim curl --max-time 3 https://1.1.1.1/
# Expected: timeout / connection refused
```

On the **Windows 7 victim** (after NotTheNet is running):

```
ping 10.10.10.1
:: Expected: Reply (ICMP responder)

nslookup evil.com 10.10.10.1
:: Expected: resolves to 10.10.10.1

curl http://www.msftconnecttest.com/connecttest.txt
:: Expected: "Microsoft Connect Test" (NCSI pass)
```

### 3. NotTheNet Config Verification

| Setting | Required Value | Why |
|---------|---------------|-----|
| `bind_ip` | `10.10.10.1` (gateway IP) | Prevents binding to management NIC |
| `interface` | `vmbr1` (isolated bridge) | iptables rules target this interface |
| `redirect_ip` | `10.10.10.1` | All traffic redirected to sinkhole |
| `drop_privileges` | `true` | Drop root after port binding |
| `process_masquerade` | `true` | Hide from process scanners |
| `tcp_fingerprint` | `true` | Spoof OS fingerprint |
| `tcp_fingerprint_os` | `windows` | Match victim OS expectation |

### 4. Services Check

After `sudo python notthenet.py --nogui`:

```bash
# All services should show green:
ss -tlnp | grep python   # TCP listeners
ss -ulnp | grep python   # UDP listeners

# Key ports:
# :53 (DNS), :80 (HTTP), :443 (HTTPS), :25 (SMTP),
# :21 (FTP), :445 (SMB), :23 (Telnet), :9999 (Catch-all)
```

---

## During Analysis

- **Monitor live:** Watch logs in the GUI or tail the JSON event log:
  ```bash
  tail -f logs/events.jsonl | python -m json.tool
  ```
- **Do NOT** access the victim VM via RDP/VNC from the management network during detonation — this creates cross-bridge traffic that may confuse the malware or leak your IP.
- Use Proxmox's built-in noVNC console (accessed via the Proxmox web UI) instead.

---

## Post-Detonation: Handling Hot Artifacts

### 1. Stop NotTheNet

```bash
# Ctrl+C (headless) or Stop button (GUI)
# Or: sudo systemctl stop notthenet
```

### 2. Secure the artifacts

Artifacts in `logs/emails/` and `logs/ftp_uploads/` **may contain live malware**.

```bash
cd /opt/NotTheNet

# Password-protect before moving off-host
zip -P infected -r artifacts.zip logs/emails/ logs/ftp_uploads/ logs/events.jsonl

# Verify contents without extracting
unzip -l artifacts.zip

# SHA256 manifest for chain of custody
sha256sum artifacts.zip > artifacts.zip.sha256
```

### 3. Transfer safely

```bash
# SCP to analysis workstation (never unzip on production systems)
scp artifacts.zip analyst@10.0.0.5:/secure/evidence/

# Or USB (write-only, no autorun):
cp artifacts.zip /media/usb-evidence/
sync
```

### 4. Revert the victim VM

```bash
# From Proxmox host:
qm rollback <VMID> pre-detonation

# Verify clean state:
qm listsnapshot <VMID>
```

### 5. Clean up Kali logs (if tmpfs mounted, this is automatic on reboot)

```bash
# If logs were on tmpfs:
sudo umount /opt/NotTheNet/logs  # automatic if using systemd unit

# If logs were on disk:
rm -rf logs/emails/* logs/ftp_uploads/*
> logs/events.jsonl
```

---

## Proxmox KVM Cloaking

Malware may detect KVM/QEMU and refuse to execute. Add these to your victim VM's Proxmox config file at `/etc/pve/qemu-server/<VMID>.conf`:

```ini
# ── Anti-VM detection ────────────────────────────────────────
# Hide the KVM hypervisor leaf (CPUID 0x40000000)
args: -cpu host,kvm=off,hv_vendor_id=GenuineIntel

# Disable hypervisor signature entirely
cpu: host,hidden=1

# Spoof SMBIOS to look like real hardware
smbios1: type=0,vendor=Dell Inc.,version=A11
smbios1: type=1,manufacturer=Dell Inc.,product=OptiPlex 7050,serial=ABC1234XYZ

# Disable QEMU ballooning (detected by some malware)
balloon: 0

# Set machine type to latest Q35 (hides older QEMU signatures)
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
│  5. Monitor logs/events.jsonl                           │
│  6. Stop NotTheNet                                      │
│  7. zip -P infected artifacts.zip logs/emails/ ...      │
│  8. qm rollback <VMID> pre-det                         │
│  9. sudo umount /opt/NotTheNet/logs                     │
└─────────────────────────────────────────────────────────┘
```
