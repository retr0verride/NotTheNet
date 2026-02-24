# Lab Walkthrough: NotTheNet + Kali + FlareVM on Proxmox

> **Goal:** Build a fully isolated malware analysis lab where all network traffic from a Windows sandbox (FlareVM) is transparently intercepted by NotTheNet running on Kali — no real internet reachable from the sample.

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
```

Assign a static IP to the lab interface persistently:

```bash
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
```

### 2.4 Enable IP forwarding

NotTheNet's `gateway` iptables mode requires the kernel to forward packets between interfaces:

```bash
sudo sysctl -w net.ipv4.ip_forward=1

echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-notthenet.conf

sudo sysctl -p /etc/sysctl.d/99-notthenet.conf
```

### 2.5 Install NotTheNet

```bash
cd ~
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet

sudo bash notthenet-install.sh
```

The installer creates a virtualenv, installs Python dependencies, generates TLS certificates, installs the desktop launcher, and sets up polkit rules so you can launch with GUI elevation.

### 2.6 Configure NotTheNet

Launch the GUI:
```bash
sudo notthenet
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
Set-ExecutionPolicy Unrestricted -Force


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

From FlareVM (cmd or PowerShell — `nslookup` works on every Windows version):
```cmd
nslookup evil-c2-domain.com
nslookup updates.microsoft.com
nslookup anything-at-all.xyz
```
Every query should return `10.0.0.1`. Check the NotTheNet DNS log entries appear in the live log.

### 4.3 HTTP

From FlareVM (cmd or PowerShell — `curl.exe` is built into Windows 10+):
```cmd
curl.exe -i http://google.com
```
Expected: response starts with `HTTP/1.1 200 OK`. The `Server:` header will be whatever you configured (default: `Apache/2.4.51 (Debian)`).

### 4.4 HTTPS

```cmd
curl.exe -ik https://google.com
```
Expected: response starts with `HTTP/1.1 200 OK`. The TLS handshake will succeed with NotTheNet's auto-generated certificate.

### 4.5 SMTP

```cmd
curl.exe -s -m 5 telnet://10.0.0.1:25
```
Expected: the SMTP banner, e.g. `220 mail.example.com ESMTP Postfix` (matches whatever you set in the Banner field).

### 4.6 FTP

```cmd
curl.exe -s -m 5 telnet://10.0.0.1:21
```
Expected: the FTP banner, e.g. `220 FTP Server Ready` (matches whatever you set in the Banner field).

### 4.7 Non-standard port (Catch-All)

```cmd
curl.exe -s -m 5 telnet://10.0.0.1:4444
curl.exe -s -m 5 telnet://10.0.0.1:8443
```
Expected: `200 OK` — caught by the TCP Catch-All service. These appear in the NotTheNet log as `catch_all` entries.

### 4.8 Confirm isolation (no real internet)

```cmd
curl.exe -s -m 5 telnet://8.8.8.8:53
```
Expected: no output / command returns after 5 seconds. If a banner appears, FlareVM still has a route to the real internet — re-check that `vmbr0` is not attached.

---

## Part 5 — Wireshark Setup (Kali)

Kali is the gateway for all FlareVM traffic — every packet passes through `eth1` before NotTheNet processes it. Capturing on that interface gives a complete packet-level record of everything the sample sends, independent of what NotTheNet logs.

### 5.1 Install Wireshark / tshark

Wireshark and tshark are included in Kali by default. If missing:

```bash
sudo apt-get install -y wireshark tshark
```

To allow non-root GUI captures:

```bash
sudo dpkg-reconfigure wireshark-common

sudo usermod -aG wireshark $USER

newgrp wireshark
```

### 5.2 Live GUI capture

```bash
sudo wireshark &
```

Select interface **eth1** (`vmbr1`, the lab-side NIC) and click the blue shark fin to start. Useful display filters:

| Display filter | What it shows |
|----------------|---------------|
| `ip.src == 10.0.0.50` | All traffic originating from FlareVM |
| `dns` | Every DNS query and response |
| `http` | Plain HTTP streams |
| `tcp.port == 443` | HTTPS / TLS handshakes |
| `smtp \|\| pop \|\| imap` | Mail protocol traffic |
| `ftp \|\| ftp-data` | FTP control and data channels |
| `ip.src == 10.0.0.50 && !dns` | All non-DNS traffic from FlareVM |

### 5.3 Headless capture with tshark

`tshark` is better for long sessions — it writes directly to `.pcapng` without opening a GUI.

```bash
sudo tshark -i eth1 \
  -f "host 10.0.0.50" \
  -b filesize:102400 -b files:5 \
  -w ~/captures/flarevm-$(date +%Y%m%d-%H%M%S).pcapng
```

Stop with **Ctrl+C**. To target specific protocols only (smaller files):

```bash
sudo tshark -i eth1 \
  -f "host 10.0.0.50 and (port 53 or port 80 or port 443 or port 25 or port 21)" \
  -w ~/captures/flarevm-targeted.pcapng
```

### 5.4 Post-capture analysis with tshark

Extract useful fields from a saved capture without opening the GUI:

```bash
tshark -r ~/captures/flarevm.pcapng \
  -Y "http.request" \
  -T fields -e http.request.method -e http.host -e http.request.uri

tshark -r ~/captures/flarevm.pcapng \
  -Y "dns.flags.response == 0" \
  -T fields -e frame.time -e dns.qry.name

tshark -r ~/captures/flarevm.pcapng -q -z follow,tcp,ascii,0
```

### 5.5 Export the capture to a Windows machine

Serve the capture from Kali so it can be downloaded on any analysis workstation:

```bash
cd ~/captures
python3 -m http.server 8080
```

Browse to `http://10.0.0.1:8080/` from a Windows host, download the `.pcapng`, and open it in Wireshark or upload it to a service like [PacketTotal](https://packettotal.com). Stop the server when done (`Ctrl+C`).

---

## Part 6 — Detonation Workflow

### 6.1 Transfer the sample to FlareVM

On **Kali**, serve the sample over HTTP:
```bash
cd /path/to/samples
python3 -m http.server 8080
```

On **FlareVM**, download it:
```cmd
curl.exe -o C:\Samples\sample.exe http://10.0.0.1:8080/sample.exe
```

Stop the Python server on Kali when done (`Ctrl+C`).

> Alternatively, use a Proxmox shared directory or attach a separate ISO with the sample — whichever fits your workflow.

### 6.2 Snapshot before detonation

Take a fresh snapshot immediately before running the sample so you can cleanly revert:

Proxmox → **flarevm → Snapshots → Take Snapshot** → name it `pre-detonation`

### 6.3 Set up monitoring tools on FlareVM

Before executing the sample, start your tooling:

| Tool | Purpose |
|------|---------|
| **Wireshark** | Capture raw traffic on the FlareVM NIC (see also Part 5 for gateway capture on Kali) |
| **Process Monitor (ProcMon)** | File system, registry, process activity |
| **Process Hacker** | Live process tree and memory inspection |
| **x64dbg / x32dbg** | Dynamic debugging if needed |

Start a Wireshark capture on the lab NIC (the `10.0.0.x` interface) before execution. For a full gateway-level capture of all traffic leaving FlareVM, see **Part 5**.

### 6.4 Detonate

Execute the sample on FlareVM. Watch:

- **NotTheNet live log** (on Kali) — every DNS query, HTTP request, SMTP connection, or catch-all hit appears in real time, colour-coded by service
- **Wireshark** — raw packets for protocol-level detail
- **ProcMon** — filesystem and registry changes

### 6.5 Collect artifacts

**On Kali:**

```bash
cat logs/notthenet.log

ls logs/emails/

ls logs/ftp_uploads/
```

**On FlareVM:**
- Save the Wireshark `.pcapng`
- Save ProcMon `.pml`
- Dump any processes of interest with Process Hacker

### 6.6 Revert FlareVM

Proxmox → **flarevm → Snapshots → Rollback** to `clean-baseline` (or `pre-detonation`).

The VM is restored to a clean state, ready for the next sample.

---

## Part 7 — Custom DNS Records

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
- Test from Kali itself: `dig @127.0.0.1 test.com +short` — `@127.0.0.1` queries NotTheNet's DNS server directly; `+short` prints only the answer IP. Should return `127.0.0.1`

### HTTPS certificate errors breaking the sample

Some malware validates TLS certificates and will abandon connections if the cert is wrong. This is expected — the sample will still appear in the log hitting port 443. For deeper HTTPS interception, configure the sample's trust store to include NotTheNet's CA (`certs/ca.crt`) or use a tool like mitmproxy in front of NotTheNet.

### NotTheNet won't start (port already in use)

```bash
sudo ss -tulpn | grep :53

sudo systemctl disable --now systemd-resolved
```

Then retry **▶ Start** in NotTheNet.

### FlareVM still has real internet after removing vmbr0

Check Proxmox → flarevm → Hardware — confirm only `vmbr1` is attached. Also confirm no VPN client or proxy is running inside FlareVM.

