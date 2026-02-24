# Lab Walkthrough: NotTheNet + Kali + FlareVM on Proxmox

> **Goal:** Build a fully isolated malware analysis lab where all network traffic from a Windows sandbox (FlareVM) is transparently intercepted by NotTheNet running on Kali — no real internet reachable from the sample.

---

## How it fits together

```
┌──────────────────────────────────────────────────────┐
│                    Proxmox Host                      │
│                                                      │
│  ┌─────────────────────┐   ┌──────────────────────┐  │
│  │    Kali Linux VM    │   │    FlareVM (Win)     │  │
│  │                     │   │                      │  │
│  │  NotTheNet          │◄──│  Malware sample      │  │
│  │  10.0.0.1           │   │  10.0.0.50           │  │
│  │                     │   │  GW:  10.0.0.1       │  │
│  │  eth0 → vmbr0 (WAN) │   │  DNS: 10.0.0.1       │  │
│  │  eth1 → vmbr1 (lab) │   │  NIC: vmbr1 only     │  │
│  └─────────────────────┘   └──────────────────────┘  │
│            │                        │                 │
│       ─────┴────────────────────────┘                 │
│            vmbr1  ←  isolated, no gateway             │
└──────────────────────────────────────────────────────┘
```

Every DNS query, HTTP/S request, SMTP, FTP, or unknown TCP/UDP connection from FlareVM hits NotTheNet. FlareVM has no route to the real internet.

---

## Prerequisites

- Proxmox VE installed and accessible via the web UI
- Kali Linux ISO uploaded to Proxmox storage
- Windows 10/11 ISO uploaded to Proxmox storage
- At least **24 GB RAM** and **200 GB disk** free on the Proxmox host

---

## Step 1 — Create the isolated network bridge

In Proxmox: **Node → System → Network → Create → Linux Bridge**

| Field | Value |
|-------|-------|
| Name | `vmbr1` |
| IP address | *(blank)* |
| Gateway | *(blank)* |
| Autostart | ✔ |
| Comment | `NotTheNet lab` |

Click **Create** → **Apply Configuration**.

> `vmbr1` is a bare layer-2 switch with no IP and no gateway. Kali becomes the router for anything on this segment.

---

## Step 2 — Create and configure the Kali VM

### Create the VM

**Proxmox → Create VM:**

| Setting | Value |
|---------|-------|
| Name | `kali-notthenet` |
| ISO | Kali Linux |
| OS type | Linux 6.x |
| Disk | 40 GB+ |
| CPU | 2+ cores |
| RAM | 4 GB+ |
| Network (net0) | `vmbr0` — internet, for setup |

After creation, add a second NIC:
**VM → Hardware → Add → Network Device** → bridge `vmbr1`

### Install Kali

Boot the ISO and run a standard install. When done, eject the ISO:
**Hardware → CD/DVD Drive → Do not use any media**

### Assign a static IP to the lab interface

```bash
# Check which interface is vmbr1 (usually eth1 or ens19)
ip link show

# Add a persistent static IP
sudo nmcli con add type ethernet ifname eth1 con-name lab ip4 10.0.0.1/24
sudo nmcli con up lab

# Verify
ip addr show eth1
# Expected: inet 10.0.0.1/24
```

### Enable IP forwarding

Required for NotTheNet's `gateway` iptables mode to forward packets from FlareVM:

```bash
# Apply now
sudo sysctl -w net.ipv4.ip_forward=1

# Persist across reboots
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-notthenet.conf
sudo sysctl -p /etc/sysctl.d/99-notthenet.conf
```

### Install NotTheNet

```bash
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
sudo bash notthenet-install.sh
```

The installer sets up a virtualenv, installs dependencies, generates TLS certificates, and installs the desktop launcher.

### Configure and start NotTheNet

```bash
sudo notthenet
```

In the GUI, click **⚙ General** and set:

| Field | Value | Why |
|-------|-------|-----|
| Bind IP | `0.0.0.0` | Listen on all interfaces |
| Redirect IP | `10.0.0.1` | All DNS resolves to Kali |
| Interface | `eth1` | Your `vmbr1` NIC |
| iptables mode | `gateway` | Intercepts traffic from other hosts via PREROUTING |
| Auto iptables | ✔ | Rules applied/removed on start/stop |
| Log to file | ✔ | Saved to `logs/notthenet.log` |

Leave all services at their defaults. Make sure **Catch-All** is enabled — it catches anything not handled by a named service.

Click **💾 Save** → **▶ Start**.

The status indicator turns green. Confirm iptables rules are live:

```bash
sudo iptables -t nat -L PREROUTING -n -v | grep NOTTHENET
```

---

## Step 3 — Create and configure FlareVM

### Create the Windows VM

**Proxmox → Create VM:**

| Setting | Value |
|---------|-------|
| Name | `flarevm` |
| ISO | Windows 10/11 |
| OS type | Microsoft Windows |
| Disk | 100 GB+ |
| CPU | 4+ cores |
| RAM | 8–16 GB |
| **Network** | `vmbr1` **only** — no `vmbr0` |

> **Critical:** attaching only `vmbr1` means FlareVM has no path to the real internet — only to Kali.

### Install Windows

Boot the ISO. At the network screen choose:
**"I don't have internet"** → **"Continue with limited setup"**

Create a local account. Eject the ISO when done.

### Set a static IP

**Control Panel → Network and Sharing Center → Change adapter settings**

Right-click the NIC → **Properties → IPv4 → Properties:**

```
IP address:      10.0.0.50
Subnet mask:     255.255.255.0
Default gateway: 10.0.0.1
DNS server:      10.0.0.1
```

Verify:
```cmd
ping 10.0.0.1
```

### Install FlareVM

> FlareVM downloads hundreds of tools from the internet. You need to **temporarily add `vmbr0`** to the FlareVM VM for this step only.

**Add temporary internet:**
1. Proxmox → FlareVM → **Hardware → Add → Network Device** → `vmbr0`
2. Set that NIC to DHCP inside Windows and verify internet access

**Run the installer** (PowerShell as Administrator):

```powershell
Set-ExecutionPolicy Unrestricted -Force

$installer = "$env:TEMP\flarevm.ps1"
(New-Object Net.WebClient).DownloadFile(
    'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
    $installer
)
Unblock-File $installer
& $installer
```

Select your desired tools and wait 1–2 hours for completion.

**Remove the `vmbr0` NIC** when done:
Proxmox → FlareVM → **Hardware → select the vmbr0 NIC → Remove**

FlareVM now has no real internet access.

### Take a clean baseline snapshot

Proxmox → **flarevm → Snapshots → Take Snapshot**

| Field | Value |
|-------|-------|
| Name | `clean-baseline` |
| Description | `FlareVM installed, isolated, no samples` |

---

## Step 4 — Verify the lab

Run these from **FlareVM PowerShell** before detonating anything.

| Test | Command | Expected result |
|------|---------|----------------|
| Connectivity | `ping 10.0.0.1` | Replies from Kali |
| DNS | `Resolve-DnsName evil-c2.com` | Resolves to `10.0.0.1` |
| HTTP | `Invoke-WebRequest http://google.com -UseBasicParsing` | `200 OK` |
| HTTPS | `Invoke-WebRequest https://google.com -SkipCertificateCheck -UseBasicParsing` | `200 OK` |
| SMTP | `Test-NetConnection 10.0.0.1 -Port 25` | `TcpTestSucceeded: True` |
| FTP | `Test-NetConnection 10.0.0.1 -Port 21` | `TcpTestSucceeded: True` |
| Catch-All | `Test-NetConnection 10.0.0.1 -Port 4444` | `TcpTestSucceeded: True` |
| **Isolation** | `Test-NetConnection 8.8.8.8 -Port 53` | **Must FAIL / timeout** |

Check the NotTheNet live log after each test — every connection should appear with its service label and source IP.

> If the isolation test **succeeds**, FlareVM still has a real internet route. Re-check that `vmbr0` is not attached in Proxmox hardware.

---

## Step 5 — Detonation workflow

### 1. Transfer the sample

On **Kali:**
```bash
cd /path/to/samples
python3 -m http.server 8080
```

On **FlareVM:**
```powershell
Invoke-WebRequest http://10.0.0.1:8080/sample.exe -OutFile C:\Samples\sample.exe
```

Stop the server on Kali with `Ctrl+C`.

### 2. Snapshot before running

Proxmox → **flarevm → Snapshots → Take Snapshot** → name it `pre-detonation`

### 3. Start monitoring tools

Before executing the sample, open:

| Tool | What to watch |
|------|--------------|
| **Wireshark** | Raw packets — capture on the `10.0.0.x` NIC |
| **Process Monitor** | File system, registry, process creation |
| **Process Hacker** | Live process tree and memory |
| **x64dbg / x32dbg** | Debugging, if needed |

### 4. Execute and monitor

Run the sample. On Kali, the NotTheNet live log shows every network contact in real time — DNS queries, HTTP beacons, SMTP exfil attempts, and catch-all hits on unusual ports.

### 5. Collect artifacts

**On Kali:**
```bash
cat logs/notthenet.log      # full structured log
ls  logs/emails/            # SMTP captures
ls  logs/ftp_uploads/       # FTP uploads
```

**On FlareVM:** save Wireshark `.pcapng` and ProcMon `.pml` before reverting.

### 6. Revert

Proxmox → **flarevm → Snapshots → Rollback** → `clean-baseline`

---

## Custom DNS records

To map a specific C2 hostname to a chosen IP, open the **DNS panel** in NotTheNet and add entries to **Custom DNS Records:**

```
c2.evil-domain.com = 10.0.0.1
updates.malware.net = 10.0.0.1
```

One `hostname = ip` per line. These override the default catch-all resolution.

---

## Troubleshooting

**FlareVM traffic not being intercepted**
- Confirm iptables mode is `gateway` in NotTheNet General settings
- Check IP forwarding: `sysctl net.ipv4.ip_forward` → must be `1`
- Check rules exist: `sudo iptables -t nat -L PREROUTING -n -v | grep NOTTHENET`
- Check FlareVM gateway: `ipconfig` → Default Gateway must be `10.0.0.1`

**DNS not resolving to 10.0.0.1**
- Confirm FlareVM DNS is set to `10.0.0.1` (not auto/DHCP)
- Confirm the DNS service shows a green dot in the NotTheNet sidebar
- Test on Kali: `dig @127.0.0.1 test.com +short` → should return `127.0.0.1`

**NotTheNet won't start — port 53 in use**
```bash
sudo ss -tulpn | grep :53
sudo systemctl disable --now systemd-resolved
```
Then retry **▶ Start**.

**HTTPS cert errors in the sample**
Some malware performs certificate validation and drops the connection if it fails. This is expected behaviour — the connection still appears in the log. For deeper TLS interception, add NotTheNet's CA cert (`certs/ca.crt`) to the Windows trust store on FlareVM.

**FlareVM still has real internet**
Proxmox → flarevm → Hardware — confirm only `vmbr1` is listed. No VPN or proxy should be running inside the VM.


End-to-end guide for building an isolated malware analysis lab on Proxmox. Kali Linux runs NotTheNet as the fake internet provider. FlareVM is the Windows sandbox where samples are detonated. All traffic from FlareVM is transparently redirected to NotTheNet — no configuration changes needed on the sample itself.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   Proxmox Host                      │
│                                                     │
│  ┌──────────────────┐      ┌──────────────────────┐ │
│  │   Kali Linux VM  │      │     FlareVM (Win)    │ │
│  │                  │      │                      │ │
│  │  NotTheNet       │      │  Malware sample      │ │
│  │  10.0.0.1        │◄─────│  10.0.0.50           │ │
│  │                  │      │  GW: 10.0.0.1        │ │
│  │  eth0 → vmbr0    │      │  DNS: 10.0.0.1       │ │
│  │  eth1 → vmbr1    │      │  NIC: vmbr1 only     │ │
│  └──────────────────┘      └──────────────────────┘ │
│          │                          │                │
│     ┌────┴──────────────────────────┘                │
│     │         vmbr1 (isolated — no gateway)          │
│     │                                                │
│  ┌──┴───────┐                                        │
│  │  vmbr0   │ ← internet (Kali only, for setup)      │
└──┴──────────┴────────────────────────────────────────┘
```

All DNS queries, HTTP/HTTPS requests, SMTP, POP3, IMAP, FTP, and any other TCP/UDP traffic from FlareVM lands on NotTheNet running on Kali. FlareVM has **no route to the real internet**.

---

## Part 1 — Proxmox Network Setup

### 1.1 Create the isolated lab bridge

In Proxmox web UI: **Node → System → Network → Create → Linux Bridge**

| Field | Value |
|-------|-------|
| Name | `vmbr1` |
| IP address | *(leave blank)* |
| Subnet mask | *(leave blank)* |
| Gateway | *(leave blank)* |
| Autostart | ✔ |
| Comment | `NotTheNet isolated lab` |

Click **Create**, then **Apply Configuration**.

> Leave the IP fields blank. This bridge is a dumb layer-2 switch — Kali provides all addressing and routing on it.

---

## Part 2 — Kali VM Setup

### 2.1 Create the VM

Proxmox → **Create VM**:

| Setting | Value |
|---------|-------|
| Name | `kali-notthenet` |
| ISO | Kali Linux installer ISO (upload to local storage first) |
| OS type | Linux, kernel 6.x |
| Disk | 40 GB+ (for logs and captures) |
| CPU | 2+ cores |
| RAM | 4 GB+ |

**Network tab:**
- `net0` → `vmbr0` (your normal internet bridge) — for setup and SSH
- Add a second NIC after creation: `net1` → `vmbr1` (isolated lab)

To add the second NIC after creation: **VM → Hardware → Add → Network Device**, bridge `vmbr1`.

### 2.2 Install Kali

Boot the ISO and run a standard Kali install. When complete, remove the ISO from the VM's CD drive: **Hardware → CD/DVD Drive → Do not use any media**.

### 2.3 Configure the lab interface

Log in to Kali and identify both NICs:

```bash
ip link show
# Example output:
# 2: eth0: ... (this is vmbr0 — internet)
# 3: eth1: ... (this is vmbr1 — lab)
```

Assign a static IP to the lab interface persistently:

```bash
# Using nmcli (persistent across reboots)
sudo nmcli con add \
  type ethernet \
  ifname eth1 \
  con-name lab \
  ip4 10.0.0.1/24

sudo nmcli con up lab
```

Verify:
```bash
ip addr show eth1
# Should show: inet 10.0.0.1/24
```

### 2.4 Enable IP forwarding

NotTheNet's `gateway` iptables mode requires the kernel to forward packets between interfaces:

```bash
# Apply immediately
sudo sysctl -w net.ipv4.ip_forward=1

# Persist across reboots
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-notthenet.conf
sudo sysctl -p /etc/sysctl.d/99-notthenet.conf
```

### 2.5 Install NotTheNet

```bash
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
sudo bash notthenet-install.sh
```

The installer creates a virtualenv, installs Python dependencies, generates TLS certificates, installs the desktop launcher, and sets up polkit rules so you can launch with GUI elevation.

### 2.6 Configure NotTheNet

Launch the GUI:
```bash
sudo notthenet
# Or from the app menu: NotTheNet (uses pkexec for privilege prompt)
```

Click **⚙ General** in the sidebar and set:

| Field | Value | Notes |
|-------|-------|-------|
| Bind IP | `0.0.0.0` | Listen on all interfaces |
| Redirect IP | `10.0.0.1` | Kali's lab IP — all DNS resolves here |
| Interface | `eth1` | Your vmbr1 NIC name |
| iptables mode | `gateway` | PREROUTING — intercepts traffic from other hosts |
| Auto iptables | ✔ | Rules applied/removed automatically on start/stop |
| Log level | `INFO` | Increase to `DEBUG` for detailed per-packet logging |
| Log to file | ✔ | Written to `logs/notthenet.log` |

Configure individual services as needed (all can be left at defaults for basic analysis):

- **DNS** — leave `resolve_to` at `127.0.0.1`; it will be rewritten to `10.0.0.1` by iptables redirect
- **HTTP/HTTPS** — default `200 OK` response with a generic body is fine
- **Catch-All** — ensure it is enabled; this catches any ports not handled by a specific service

Click **💾 Save**, then **▶ Start**.

The status indicator turns green and the log shows each service binding. Confirm iptables rules were applied:

```bash
sudo iptables -t nat -L PREROUTING -n -v | grep NOTTHENET
```

---

## Part 3 — FlareVM Setup

FlareVM is Mandiant's Windows-based malware analysis distribution. It installs as a Chocolatey/PowerShell overlay on top of a plain Windows VM.

### 3.1 Create the Windows VM in Proxmox

Proxmox → **Create VM**:

| Setting | Value |
|---------|-------|
| Name | `flarevm` |
| ISO | Windows 10/11 installer ISO |
| OS type | Microsoft Windows |
| Disk | 100 GB+ (FlareVM tools are large) |
| CPU | 4+ cores |
| RAM | 8 GB+ (16 GB recommended) |
| **Network** | `vmbr1` **only** — no `vmbr0` |

> Attaching only `vmbr1` means FlareVM has **no path to the internet**, only to Kali. This is intentional and critical for containment.

### 3.2 Install Windows

Boot the ISO, install Windows. When the network setup screen appears and asks for a network: choose **"I don't have internet"** → **"Continue with limited setup"**. Create a local account (no Microsoft account required or possible with no internet).

After install, remove the ISO: **Hardware → CD/DVD → Do not use any media**.

### 3.3 Install VirtIO drivers (if needed)

If the VM shows poor disk/network performance, download the VirtIO ISO from the Proxmox mirrors, attach it, and run the VirtIO installer from it. For analysis VMs this is optional.

### 3.4 Set a static IP on FlareVM

Open **Control Panel → Network and Sharing Center → Change adapter settings**.

Right-click the NIC → **Properties → Internet Protocol Version 4 (TCP/IPv4) → Properties**:

```
○ Use the following IP address:

  IP address:    10.0.0.50
  Subnet mask:   255.255.255.0
  Default gateway: 10.0.0.1

○ Use the following DNS server addresses:

  Preferred DNS server: 10.0.0.1
```

Click **OK**. Verify connectivity to Kali:
```cmd
ping 10.0.0.1
```

### 3.5 Install FlareVM

> **Before running the FlareVM installer**, make sure NotTheNet is **running** on Kali. The installer downloads hundreds of tools over HTTP/HTTPS — all of those requests will hit NotTheNet's fake HTTP server and fail. You need **real internet access for the install**, so temporarily add `vmbr0` to the FlareVM VM just for this step.

**Temporary internet for FlareVM install:**
1. Proxmox → FlareVM → **Hardware → Add → Network Device** → bridge `vmbr0`
2. Inside FlareVM, set this second NIC to DHCP and verify you have internet
3. Proceed with FlareVM install
4. **After FlareVM finishes**: remove the `vmbr0` NIC from the VM hardware

**FlareVM install steps:**

Open PowerShell as Administrator on FlareVM:

```powershell
# Set execution policy
Set-ExecutionPolicy Unrestricted -Force

# (Optional) Disable Windows Defender — FlareVM does this automatically
# but you can pre-disable to avoid install interruptions

# Download and run the FlareVM installer
$installer = "$env:TEMP\flarevm.ps1"
(New-Object Net.WebClient).DownloadFile(
    'https://raw.githubusercontent.com/mandiant/flare-vm/main/install.ps1',
    $installer
)
Unblock-File $installer
& $installer
```

The installer opens a GUI letting you choose which tool packages to install. Select what you need for your analysis workflow (the defaults are a good starting point). Installation takes 1–2 hours depending on what you select.

When complete, **remove the `vmbr0` NIC** from FlareVM in Proxmox hardware settings. From this point on FlareVM has no real internet.

### 3.6 Take a clean baseline snapshot

Before detonating anything, snapshot FlareVM in a known-good state:

Proxmox → **flarevm → Snapshots → Take Snapshot**

| Field | Value |
|-------|-------|
| Name | `clean-baseline` |
| Description | `Pre-detonation — FlareVM installed, no samples` |
| Include RAM | Optional (faster rollback with RAM, larger snapshot without) |

---

## Part 4 — Full Lab Verification

Before detonating any samples, verify every layer of the lab is working.

### 4.1 Ping (basic connectivity)

From FlareVM CMD:
```cmd
ping 10.0.0.1
```
Expected: replies from Kali.

### 4.2 DNS

From FlareVM PowerShell:
```powershell
Resolve-DnsName evil-c2-domain.com
Resolve-DnsName updates.microsoft.com
Resolve-DnsName anything-at-all.xyz
```
Every query should return `10.0.0.1`. Check the NotTheNet DNS log entries appear in the live log.

### 4.3 HTTP

```powershell
Invoke-WebRequest http://google.com -UseBasicParsing
```
Expected: `200 OK` from NotTheNet's fake HTTP server. The `Server:` header will be whatever you configured (default: `nginx`).

### 4.4 HTTPS

```powershell
# -SkipCertificateCheck because the cert is self-signed
Invoke-WebRequest https://google.com -SkipCertificateCheck -UseBasicParsing
```
Expected: `200 OK`. The TLS handshake will succeed with NotTheNet's auto-generated certificate.

### 4.5 SMTP

```powershell
Test-NetConnection -ComputerName 10.0.0.1 -Port 25
```
Expected: `TcpTestSucceeded: True`.

### 4.6 FTP

```powershell
Test-NetConnection -ComputerName 10.0.0.1 -Port 21
```
Expected: `TcpTestSucceeded: True`.

### 4.7 Non-standard port (Catch-All)

```powershell
Test-NetConnection -ComputerName 10.0.0.1 -Port 4444
Test-NetConnection -ComputerName 10.0.0.1 -Port 8443
```
Expected: `TcpTestSucceeded: True` — caught by the TCP Catch-All service. These appear in the NotTheNet log as `catch_all` entries.

### 4.8 Confirm isolation (no real internet)

```powershell
# This should FAIL — no route to the real internet
Test-NetConnection -ComputerName 8.8.8.8 -Port 53
```
Expected: timeout / `TcpTestSucceeded: False`. If this succeeds, FlareVM still has a route to the real internet — re-check that `vmbr0` is not attached.

---

## Part 5 — Detonation Workflow

### 5.1 Transfer the sample to FlareVM

On **Kali**, serve the sample over HTTP:
```bash
cd /path/to/samples
python3 -m http.server 8080
```

On **FlareVM**, download it:
```powershell
Invoke-WebRequest http://10.0.0.1:8080/sample.exe -OutFile C:\Samples\sample.exe
```

Stop the Python server on Kali when done (`Ctrl+C`).

> Alternatively, use a Proxmox shared directory or attach a separate ISO with the sample — whichever fits your workflow.

### 5.2 Snapshot before detonation

Take a fresh snapshot immediately before running the sample so you can cleanly revert:

Proxmox → **flarevm → Snapshots → Take Snapshot** → name it `pre-detonation`

### 5.3 Set up monitoring tools on FlareVM

Before executing the sample, start your tooling:

| Tool | Purpose |
|------|---------|
| **Wireshark** | Capture raw network traffic on the lab NIC |
| **Process Monitor (ProcMon)** | File system, registry, process activity |
| **Process Hacker** | Live process tree and memory inspection |
| **x64dbg / x32dbg** | Dynamic debugging if needed |

Start a Wireshark capture on the lab NIC (the `10.0.0.x` interface) before execution.

### 5.4 Detonate

Execute the sample on FlareVM. Watch:

- **NotTheNet live log** (on Kali) — every DNS query, HTTP request, SMTP connection, or catch-all hit appears in real time, colour-coded by service
- **Wireshark** — raw packets for protocol-level detail
- **ProcMon** — filesystem and registry changes

### 5.5 Collect artifacts

**On Kali:**

```bash
# Full structured log
cat logs/notthenet.log

# Emails received (SMTP)
ls logs/emails/

# FTP uploads received
ls logs/ftp_uploads/
```

**On FlareVM:**
- Save the Wireshark `.pcapng`
- Save ProcMon `.pml`
- Dump any processes of interest with Process Hacker

### 5.6 Revert FlareVM

Proxmox → **flarevm → Snapshots → Rollback** to `clean-baseline` (or `pre-detonation`).

The VM is restored to a clean state, ready for the next sample.

---

## Part 6 — Custom DNS Records

If a sample uses a hardcoded C2 hostname, add a custom record in NotTheNet so it resolves to a specific IP (useful for routing to a separate listener or a different Kali port):

In the NotTheNet GUI → **DNS panel → Custom DNS Records**:
```
c2.evil-domain.com = 10.0.0.1
updates.malware.net = 10.0.0.1
```

One record per line, `hostname = ip` format. These take precedence over the default catch-all resolution.

---

## Troubleshooting

### FlareVM traffic not being intercepted

1. Confirm iptables mode is `gateway` (not `loopback`) in NotTheNet General settings
2. Confirm IP forwarding is enabled on Kali: `sysctl net.ipv4.ip_forward` should return `1`
3. Check iptables rules exist: `sudo iptables -t nat -L PREROUTING -n -v | grep NOTTHENET`
4. Confirm FlareVM's default gateway is `10.0.0.1`: `ipconfig` on FlareVM

### DNS queries not resolving to 10.0.0.1

- Confirm FlareVM DNS is set to `10.0.0.1` (not auto/DHCP)
- Confirm the DNS service is running in NotTheNet (green dot next to DNS in sidebar)
- Test from Kali itself: `dig @127.0.0.1 test.com +short` — should return `127.0.0.1`

### HTTPS certificate errors breaking the sample

Some malware validates TLS certificates and will abandon connections if the cert is wrong. This is expected — the sample will still appear in the log hitting port 443. For deeper HTTPS interception, configure the sample's trust store to include NotTheNet's CA (`certs/ca.crt`) or use a tool like mitmproxy in front of NotTheNet.

### NotTheNet won't start (port already in use)

```bash
# Find what is using port 53
sudo ss -tulpn | grep :53
# systemd-resolved commonly holds port 53 on Kali
sudo systemctl disable --now systemd-resolved
sudo systemctl stop systemd-resolved
```

Then retry **▶ Start** in NotTheNet.

### FlareVM still has real internet after removing vmbr0

Check Proxmox → flarevm → Hardware — confirm only `vmbr1` is attached. Also confirm no VPN client or proxy is running inside FlareVM.

