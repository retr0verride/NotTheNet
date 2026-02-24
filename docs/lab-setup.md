# Lab Setup: Proxmox + Kali + FlareVM

Step-by-step guide for running NotTheNet in an isolated Proxmox lab with a Kali analysis host and a FlareVM Windows sandbox.

---

## 1. Proxmox Network Setup

Create an **isolated internal bridge** — no internet access, no gateway, no connection to your real LAN.

In Proxmox → **System → Network → Create → Linux Bridge**:

| Field | Value |
|-------|-------|
| Name | `vmbr1` |
| IP address | *(leave blank — layer 2 only)* |
| Gateway | *(leave blank)* |
| Comment | `NotTheNet lab` |

Do **not** set a gateway on this bridge. It is an isolated segment only.

---

## 2. Kali VM — NotTheNet Host

### VM network config

Add **two** NICs to the Kali VM:

| NIC | Bridge | Purpose |
|-----|--------|---------|
| `net0` | `vmbr0` | Internet / SSH access |
| `net1` | `vmbr1` | Isolated lab interface |

### Static IP on the lab interface

```bash
# Find the vmbr1 interface name (commonly eth1 or ens19)
ip link show

# Assign a static IP
sudo ip addr add 10.0.0.1/24 dev eth1
sudo ip link set eth1 up

# Make it persistent with nmcli
sudo nmcli con add type ethernet ifname eth1 ip4 10.0.0.1/24
```

### Install and run NotTheNet

```bash
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
sudo bash install.sh
sudo notthenet
```

### GUI — General settings

| Field | Value |
|-------|-------|
| Bind IP | `0.0.0.0` |
| Redirect IP | `10.0.0.1` |
| Interface | `eth1` *(your vmbr1 NIC)* |
| iptables mode | `gateway` |
| Auto iptables | ✔ enabled |

Click **▶ Start**.

> **Why `gateway` mode?** It applies rules to the `PREROUTING` chain, which intercepts traffic arriving *from other hosts* on the bridge. `loopback` mode only catches traffic from the Kali machine itself.

---

## 3. FlareVM — Windows Analysis Machine

### VM network config

Attach **only one** NIC: `vmbr1` (isolated bridge only — no internet).

### Static IP inside FlareVM

```
IP Address:  10.0.0.50
Subnet Mask: 255.255.255.0
Gateway:     10.0.0.1
DNS Server:  10.0.0.1
```

Setting both the gateway and DNS to `10.0.0.1` (Kali) routes all traffic through NotTheNet and ensures every DNS query is answered by the fake DNS service.

---

## 4. Enable IP Forwarding on Kali

iptables gateway mode requires IP forwarding to be active:

```bash
sudo sysctl -w net.ipv4.ip_forward=1

# To persist across reboots
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

---

## 5. Verify the Lab

From **FlareVM**, open PowerShell and run:

```powershell
# DNS — every hostname should resolve to 10.0.0.1
Resolve-DnsName evil-c2.com

# HTTP
Invoke-WebRequest http://anything.com -UseBasicParsing

# HTTPS (self-signed cert — expected)
Invoke-WebRequest https://anything.com -SkipCertificateCheck -UseBasicParsing

# SMTP
Test-NetConnection -ComputerName 10.0.0.1 -Port 25

# FTP
Test-NetConnection -ComputerName 10.0.0.1 -Port 21
```

All responses should come from Kali. Check the NotTheNet **Live Log** panel to confirm each connection is being received and logged.

### Verify iptables rules on Kali

```bash
sudo iptables -t nat -L -n -v | grep NOTTHENET
```

You should see `REDIRECT` rules for each active service port.

---

## 6. Detonate a Sample

1. **Snapshot FlareVM** before detonation:
   Proxmox → VM → Snapshots → **Take Snapshot**

2. **Transfer the sample** to FlareVM — use a temporary HTTP server on Kali:
   ```bash
   cd /path/to/samples
   python3 -m http.server 8080
   ```
   Then download from FlareVM:
   ```powershell
   Invoke-WebRequest http://10.0.0.1:8080/sample.exe -OutFile C:\sample.exe
   ```

3. **Execute the sample** on FlareVM.

4. **Monitor** the NotTheNet live log for:
   - DNS queries from the sample
   - HTTP/HTTPS C2 beaconing
   - SMTP exfiltration attempts
   - Catch-all hits on unusual ports

5. **Review logs** on Kali at `logs/notthenet.log`.

6. **Revert FlareVM** to the pre-detonation snapshot when done.

---

## Tips

- The **Catch-All** service absorbs any protocol NotTheNet doesn't explicitly handle — useful for C2 beaconing on non-standard ports. Make sure it is enabled.
- Use **Custom DNS Records** in the DNS panel to respond differently to specific hostnames (e.g. map a known C2 domain to a different IP).
- If FlareVM traffic is not being redirected, double-check that iptables mode is set to `gateway` (not `loopback`) and that IP forwarding is enabled.
- Saved emails land in `logs/emails/` and FTP uploads in `logs/ftp_uploads/` on Kali for post-analysis review.
