# Lab Setup: VirtualBox / VMware + Kali + Victim VM

> **Goal:** Build a fully isolated malware analysis lab on a Windows or Mac laptop using VirtualBox (free) or VMware Workstation (paid). All network traffic from a Windows victim VM is intercepted by NotTheNet running on Kali — so malware thinks it has internet access, but everything goes to your fake servers instead.

> **On a dedicated server or home lab PC?** Use the [Proxmox guide](lab-setup-proxmox.md) instead — Proxmox gives you better isolation, snapshots, and anti-detection options.

---

## ⚠️ Lab Safety — Read This Before You Start

This lab is built to run **real malware**. That's the whole point — and it means you need to take isolation seriously from the start.

> **Think of it like a BSL-2 lab.** The malware is the pathogen. Your VM is the containment. If you skip steps or make mistakes with the network config, the containment breaks — and the malware can reach your real network, your host machine, or anything else connected to it.

| ⚠️ Risk | How it happens | How to prevent it |
|---------|---------------|-------------------|
| **Malware reaches the real internet** | NAT NIC left attached to the victim VM | Remove the NAT adapter after setup; verify with Part 5 checklist |
| **Malware persists between sessions** | Not reverting to `clean-baseline` snapshot | Roll back after **every** session — no exceptions |
| **Sample spreads to your host** | Transferring files out of the VM carelessly | Only move files you explicitly need; scan anything leaving the lab |
| **VM escape** (rare but real) | Hypervisor exploit in the sample | Keep VirtualBox/VMware updated; be cautious with kernel-mode samples |
| **Destroying a real machine's security** | Running the Defender removal steps outside the lab | Those steps are only for the isolated victim VM — **never on a real machine** |

> **If you are not certain the victim VM has no real internet, do not detonate anything.** The checklist in Part 5 takes two minutes and will catch any misconfiguration.

---

## Which hypervisor?

Both work. Pick one and stick to it — don't mix.

| | VirtualBox | VMware Workstation / Fusion |
|---|---|---|
| **Cost** | Free | Paid ($0 for personal use with VMware Workstation Pro 17+) |
| **Platform** | Windows, Mac, Linux | Windows, Mac (Fusion), Linux |
| **Performance** | Good | Slightly better, especially on Apple Silicon |
| **Anti-detection** | Limited VM hiding options | More hardware spoof options |
| **Recommended for** | Learning, CTFs, tight budget | More realistic malware behavior |

This guide covers both. Steps that differ between them are labelled **[VirtualBox]** or **[VMware]**.

---

## Architecture Overview

```
Your physical machine (Windows/Mac)
├── Kali Linux VM
│     └── eth0 / enp0s3 → Internal Network "labnet"
│           IP: 10.0.0.1
│           NotTheNet running here
└── victim VM (Windows)
      └── NIC → Internal Network "labnet"
            IP: 10.0.0.50
            Gateway: 10.0.0.1
            DNS: 10.0.0.1
```

Both VMs share an [Internal Network](https://www.virtualbox.org/manual/topics/networkingdetails.html#network_internal) (VirtualBox) or [LAN Segment](https://docs.vmware.com/en/VMware-Workstation-Pro/17/com.vmware.ws.using.doc/GUID-C7E183BE-6B2E-4DBF-B3D8-77D5BA9B8DD5.html) (VMware) — a completely isolated virtual network with no connection to the real internet. Kali is the only gateway, so all victim traffic passes through it to NotTheNet.

---

## Part 1 — Create the Isolated Network

We need a virtual network that exists only between VMs — no path to the real internet. Both hypervisors support this but call it different things.

### [VirtualBox] — Internal Network

VirtualBox's **Internal Network** type is completely isolated: VMs on it can talk to each other, but nothing can reach outside the host and the host itself can't see in. It doesn't need to be created in advance — it exists the moment you name it on a NIC. We'll name ours `labnet`.

No action needed here — you'll select `Internal Network` and type `labnet` when configuring each VM's NIC in Parts 2 and 3.

### [VMware Workstation] — LAN Segment

VMware's **LAN Segments** are the equivalent — pure VM-to-VM, no host access. Create it before setting up the VMs:

1. **Edit → Virtual Network Editor** → **Add Network** → pick an unused slot (e.g. `VMnet2`), or from any VM: **Settings → Network Adapter → LAN Segments → Add** → name it `labnet`
2. The name `labnet` is just a label — use whatever you want, but use the same name on both VMs.

---

## Part 2 — Kali VM Setup

Kali is the interception point — it runs NotTheNet and acts as the fake gateway that all victim traffic flows through. By the end of this part, NotTheNet will be running and listening.

### 2.1 Download Kali

Download the **VirtualBox** or **VMware** pre-built image from [https://www.kali.org/get-kali/#kali-virtual-machines](https://www.kali.org/get-kali/#kali-virtual-machines). These are fully installed VMs — no ISO, no installer. Just unzip and import.

> Default credentials for the pre-built images: `kali` / `kali`. Change the password after first boot: `passwd`

### 2.2 Import the VM

**[VirtualBox]:**
- File → Import Appliance → select the `.ova` file → Import
- Or: just double-click the `.ova` file

**[VMware]:**
- File → Open → select the `.vmx` file (or the `.ova`)
- Click **I Copied It** if prompted about the VM UUID

### 2.3 Add a second NIC for the lab network

Kali needs two NICs:
- **NIC 1** — NAT (for internet access to install packages). This is already configured in the pre-built image.
- **NIC 2** — Internal Network / LAN Segment (for the isolated lab). Add this now.

**[VirtualBox]:**
1. Right-click the Kali VM → **Settings → Network → Adapter 2**
2. Check **Enable Network Adapter**
3. Attached to: **Internal Network**
4. Name: `labnet`
5. Click **OK**

**[VMware]:**
1. Right-click the Kali VM → **Settings → Add → Network Adapter**
2. Connection type: **LAN Segment**
3. Select `labnet`
4. Click **Finish**

### 2.4 Configure the lab NIC with a static IP

Boot the Kali VM. Find your network interface names:

```bash
ip link show
```

You'll have two: the NAT NIC (already has an IP) and the new lab NIC (no IP yet — typically `eth1` or `enp0s8`).

Assign a static IP to the lab NIC (replace `eth1` with your actual name):

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
# Should show: inet 10.0.0.1/24
```

> You do **not** set a gateway on this interface. Kali is the gateway — it doesn't have a gateway of its own for this network.

### 2.5 Install NotTheNet

With the NAT NIC still up (internet available):

```bash
cd ~
rm -rf NotTheNet
git clone https://github.com/retr0verride/NotTheNet
cd NotTheNet
bash build-deb.sh
sudo dpkg -i dist/notthenet_*.deb
```

After installation, you can disable the NAT NIC if you want to keep Kali fully isolated during analysis sessions — but it's not required. NotTheNet's iptables rules only affect traffic on the lab interface.

### 2.6 Configure NotTheNet

Launch:
```bash
sudo notthenet
```

Click **⚙ General** and set:

| Field | Value | Why |
|-------|-------|-----|
| Bind IP | `0.0.0.0` | Listen on all interfaces |
| Redirect IP | `10.0.0.1` | Kali's IP on the lab network — DNS resolves everything here |
| Interface | `eth1` | Your lab NIC name (the one on `labnet`) |
| iptables mode | `gateway` | Intercepts all traffic from the victim VM |
| Auto iptables | ✔ | Applies rules automatically on Start |

Click **💾 Save**.

---

## Part 3 — Windows Victim VM Setup

This is the sandbox where malware actually runs. A plain Windows 10 or 11 VM is all you need to observe what a sample does. **FlareVM is optional** — it adds dedicated analysis tools (debuggers, disassemblers, packet capture utilities), but you don't need it to get started. You can always add it later.

> **Class note:** We're intentionally making this VM as undefended as possible. That's not careless — it's the whole point. Malware behaves differently when it detects security tools. We want to see its real behavior, not the version it performs for an antivirus.

### 3.1 Create a Windows VM

You need a Windows 10 or 11 ISO. Microsoft offers free 90-day evaluation ISOs at [https://www.microsoft.com/en-us/evalcenter/](https://www.microsoft.com/en-us/evalcenter/).

**[VirtualBox]:**
1. **New** → Name: `victim-win`, Type: Windows, Version: Windows 10 (64-bit)
2. RAM: 4 GB minimum (8–16 GB if installing FlareVM)
3. Disk: 60 GB+ (100 GB if installing FlareVM)
4. Network: **do not add a NIC yet** — you'll configure it in step 3.2

**[VMware]:**
1. **Create a New Virtual Machine** → Typical → select the Windows ISO
2. RAM: 4 GB+, Disk: 60 GB+
3. Before finishing, **Customize Hardware** → remove or disconnect the default NIC — you'll add the right one in step 3.2

### 3.2 Set the victim VM's NIC to the isolated network

The victim VM gets **only one NIC** and it must be on the isolated lab network — no NAT, no internet.

**[VirtualBox]:**
1. VM Settings → Network → Adapter 1
2. Attached to: **Internal Network**
3. Name: `labnet`

**[VMware]:**
1. VM Settings → Network Adapter
2. Connection type: **LAN Segment** → select `labnet`

> This means Windows will show "No internet" during the OS install — that's correct and expected. When the installer asks about network, click "I don't have internet" → "Continue with limited setup" to create a local account.

### 3.3 Install Windows

Boot from the ISO and run a standard Windows install. At the network screen, choose **I don't have internet** → **Continue with limited setup** → create a local account. No Microsoft account needed.

### 3.4 Set a static IP on the victim VM

Windows Control Panel → **Network and Sharing Center → Change adapter settings** → right-click the NIC → **Properties → IPv4 → Properties**:

```
○ Use the following IP address:
  IP address:      10.0.0.50
  Subnet mask:     255.255.255.0
  Default gateway: 10.0.0.1

○ Use the following DNS server:
  Preferred DNS:   10.0.0.1
```

Verify:
```cmd
ping 10.0.0.1
```
You should get replies from Kali.

### 3.5 Remove Windows Defender and disable security hardening

**This step is not optional.** Windows Defender will detect and quarantine most real malware samples before they run — or silently kill network connections without any indication. If you detonate a sample without disabling Defender first, the malware appears to do nothing, when it has actually been killed at startup.

SmartScreen, UAC, and Virtualization-Based Security (VBS) have the same problem. In an isolated lab with no internet they provide no real protection, but they do interfere with analysis.

> **Credit:** The steps below use [**windows-defender-remover**](https://github.com/ionuttbara/windows-defender-remover) by [Ionuț Bară](https://github.com/ionuttbara). It removes Defender's AV engine, Security Center, SmartScreen, VBS, and related services in a single pass.

**Getting the tool onto the VM:** temporarily add a NAT NIC (same method used for FlareVM install in step 3.6 below), download the `.exe`, then remove the NAT NIC — or copy it from your host via shared folder.

1. Download `Defender.Remover.exe` from the [releases page](https://github.com/ionuttbara/windows-defender-remover/releases)
2. Copy it to the victim VM
3. Open PowerShell as Administrator and run:

```powershell
# Silent full removal — no interactive prompts; reboots automatically
.\Defender.Remover.exe /r
```

4. Reboot when prompted.

After rebooting, also disable UAC, SmartScreen, and Windows Firewall:

```powershell
# Disable UAC
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 0 -Type DWord

# Disable SmartScreen
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" `
    -Name "SmartScreenEnabled" -Value "Off"

# Disable Windows Firewall (safe — the isolated network provides containment)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

> These changes make the VM intentionally insecure. That's the point — malware needs to run without interference so you can observe what it actually does. Never apply these settings to a machine connected to the real internet.

### 3.6 (Optional) Install FlareVM

[FlareVM](https://github.com/mandiant/flare-vm) is a free collection of malware analysis tools built by Mandiant (now part of Google). It installs on top of Windows using a PowerShell + [Chocolatey](https://chocolatey.org/) script and adds hundreds of tools — debuggers, disassemblers, hex editors, network monitors. **Skip this if you just want to run samples and watch the NotTheNet log.** Come back later if you want to dig into a sample in depth.

FlareVM needs internet to download its tools (~10–15 GB). Temporarily add a second NIC with internet access to download everything, then remove it when done.

**[VirtualBox]:** VM Settings → Network → Adapter 2 → Attached to: **NAT** → OK. Boot.

**[VMware]:** VM Settings → Add → Network Adapter → NAT. Boot.

Inside Windows, open **PowerShell as Administrator**:

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

The installer shows a GUI where you pick which tools to install. The defaults are a good starting point. This takes 1–2 hours.

**After FlareVM finishes installing:** shut down the VM, remove the NAT NIC. Re-apply the static IP from step 3.4 (FlareVM may have switched to DHCP). Re-run the Defender removal and hardening steps from section 3.5 — FlareVM may re-enable some security components during install.

### 3.7 Take a clean snapshot

Before touching any malware samples, take a snapshot of the clean state:

**[VirtualBox]:** Machine → Take Snapshot → name it `clean-baseline`

**[VMware]:** VM → Snapshot → Take Snapshot → name it `clean-baseline`

You'll restore to this after each analysis session.

---

## Part 4 — Promiscuous Mode (multi-victim lateral movement)

By default, VirtualBox and VMware only deliver packets to the VM they're addressed to. If you're running two victim VMs and want to see one attacking the other (EternalBlue spread, etc.), you need promiscuous mode on the virtual NIC.

**[VirtualBox]:**
VM Settings → Network → Adapter 2 (the lab NIC) → Advanced → **Promiscuous Mode: Allow All**

**[VMware]:**
This is controlled at the virtual switch level. Go to **Edit → Virtual Network Editor** → select the LAN Segment network → check **Allow promiscuous mode** (if shown). On some VMware versions you may need to set it per-adapter in the VM's `.vmx` file:
```
ethernet1.noPromisc = "FALSE"
```

---

## Part 5 — Full Lab Verification

Run every check below before detonating anything. This confirms the isolation is actually working. A few minutes here prevents hours of debugging later when a sample doesn't behave as expected — and more importantly, it confirms malware cannot reach the real internet.

### 5.1 Ping

From the victim VM:
```cmd
ping 10.0.0.1
```
Expected: replies. If you get "Request timed out", Kali's lab NIC is misconfigured or on the wrong virtual network.

### 5.2 DNS

```cmd
nslookup anything.com
nslookup evil-c2.xyz
```
Every query should return `10.0.0.1`. If you see `8.8.8.8` or anything else, the victim VM's DNS setting is wrong.

### 5.3 HTTP

```cmd
curl.exe -i http://google.com
```
Expected: `HTTP/1.1 200 OK` — from NotTheNet, not from Google.

### 5.4 HTTPS

```cmd
curl.exe -ik https://google.com
```
Expected: `HTTP/1.1 200 OK` with a TLS cert from NotTheNet.

### 5.5 Confirm no real internet

```cmd
curl.exe -s -m 5 http://1.1.1.1
```
Expected: no response, timeout after 5 seconds. If you get a response, the victim VM still has a path to the internet — check that the NAT NIC is fully removed.

---

## Part 6 — Anti-Detection Hardening

Both VirtualBox and VMware leave fingerprints that malware checks for — vendor strings in [CPUID](https://en.wikipedia.org/wiki/CPUID), [SMBIOS](https://en.wikipedia.org/wiki/SMBIOS) manufacturer showing "VirtualBox" or "VMware Inc.", known MAC address prefixes, and unusually small RAM. These checks cause sophisticated malware to sleep, exit, or behave differently.

### [VirtualBox] Hardening

VirtualBox's anti-detection options are limited but worth applying.

**In VirtualBox settings (FlareVM VM must be shut down):**

1. **System → Motherboard:**
   - Chipset: **ICH9** (less recognizable than PIIX3)
   - Enable I/O APIC ✔

2. **System → Processor:**
   - Enable PAE/NX ✔
   - Enable Nested VT-x/AMD-V if available ✔

3. **Display → Screen:**
   - Video Memory: 128 MB
   - Check **Enable 3D Acceleration**

4. **Network → Adapter 1 (labnet) → Advanced:**
   - Adapter Type: **Intel PRO/1000 MT Desktop (82540EM)** — this is the most common and least suspicious
   - **Change the MAC address** — VirtualBox assigns MACs starting with `08:00:27:` which is an immediate flag. Change it to something in the Dell/Lenovo/HP OUI range, e.g. `B8:CA:3A:xx:xx:xx` (Dell)

**Command-line hardening (run on your host, not inside the VM):**

```bash
# Replace "FlareVM" with your exact VM name
VBoxManage modifyvm "FlareVM" --cpuidset 00000001 000306c3 02100800 7fbae3ff bfebfbff
VBoxManage setextradata "FlareVM" "VBoxInternal/Devices/efi/0/Config/DmiSystemProduct" "OptiPlex 7090"
VBoxManage setextradata "FlareVM" "VBoxInternal/Devices/efi/0/Config/DmiSystemVendor" "Dell Inc."
VBoxManage setextradata "FlareVM" "VBoxInternal/CPUM/HostCPUID/00000001/ecx" 0x7fbae3bf
```

> VirtualBox's VM-hiding options are fundamentally limited compared to Proxmox/VMware. For serious anti-detection work, switch to the Proxmox lab setup.

### [VMware Workstation] Hardening

VMware has better hiding options, mostly through `.vmx` file edits.

**Shut down the VM**, then open the `.vmx` file in a text editor (find it in the folder where the VM is stored). Add or modify these lines:

```ini
# Hide hypervisor from CPUID
cpuid.1.ecx = "----:----:----:----:----:----:--0-:----"
hypervisor.cpuid.v0 = "FALSE"

# Set a realistic BIOS/SMBIOS identity
SMBIOS.reflectHost = "FALSE"
SMBIOS.noOEMStrings = "TRUE"
smbios.manufacturer = "Dell Inc."
smbios.productName = "OptiPlex 7090"

# Disable VMware backdoor (used by VMware Tools for host communication — also fingerprinted)
isolation.tools.getPtrLocation.disable = "TRUE"
isolation.tools.setPtrLocation.disable = "TRUE"
isolation.tools.setVersion.disable = "TRUE"
isolation.tools.getVersion.disable = "TRUE"
monitor_control.disable_directexec = "FALSE"
monitor_control.disable_chksimd = "FALSE"
monitor_control.disable_ntreloc = "FALSE"
monitor_control.disable_selfmod = "FALSE"
monitor_control.disable_reloc = "FALSE"
monitor_control.disable_btinit = "FALSE"
monitor_control.disable_mlfences = "FALSE"
monitor_control.disable_l2ltlbflush = "FALSE"

# Realistic MAC prefix (Intel NIC)
ethernet0.addressType = "static"
ethernet0.address = "B8:CA:3A:DE:AD:01"
```

> Do **not** install VMware Tools on FlareVM. The Tools process (`vmtoolsd.exe`) is one of the first things malware checks for.

---

## Part 7 — Detonation Workflow

> ⚠️ **Before every detonation:** re-run the Part 5 isolation checklist and take a fresh `pre-detonation` snapshot. Never detonate on a VM you didn't just verify.

Start these tools on the victim VM **before** running the sample:

| Tool | What it shows |
|------|---------------|
| **[Wireshark](https://www.wireshark.org/)** | Every raw packet the malware sends and receives |
| **[Process Monitor (ProcMon)](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)** | File writes, registry changes, child processes — what the malware does to the OS |
| **[Process Hacker](https://processhacker.sourceforge.io/)** | Live process tree, network connections, memory — good for watching C2 beaconing in real time |
| **[x64dbg](https://x64dbg.com/) / x32dbg** | Step through the malware's code when you need to understand a specific function |

Transfer the sample from your host to FlareVM. The easiest way is a shared folder:

**[VirtualBox]:** Devices → Shared Folders → Add a folder from your host → check **Auto-mount**. The folder appears as a network drive in Windows.

**[VMware]:** VM → Settings → Options → Shared Folders → Add. Same result.

Run the sample. Watch the NotTheNet live log on Kali — every DNS query, HTTP request, and catch-all connection shows up in real time. After analysis, roll back to the `clean-baseline` snapshot.

---

## Troubleshooting

### FlareVM can't ping Kali

- Confirm both VMs are on the same Internal Network / LAN Segment with the same name
- Confirm Kali's lab NIC has IP `10.0.0.1` (`ip addr show`)
- Confirm FlareVM's static IP is `10.0.0.50` and gateway is `10.0.0.1` (`ipconfig /all`)
- Check that NotTheNet is started (`sudo notthenet` on Kali)

### DNS not resolving to 10.0.0.1

- Confirm FlareVM's DNS is manually set to `10.0.0.1` (not auto/DHCP)
- Confirm the DNS service is green in NotTheNet
- Test from Kali: `dig @127.0.0.1 test.com +short` — should return `127.0.0.1`

### FlareVM still has real internet

The NAT NIC is still attached. Shut down FlareVM, remove it from VM settings, reboot. Run `curl.exe -s -m 5 http://1.1.1.1` again to verify.

### NotTheNet won't start — port 53 in use

```bash
sudo systemctl disable --now systemd-resolved
sudo notthenet
```

### HTTPS certificate errors in the malware's traffic

Install NotTheNet's Root CA in Windows: copy `certs/ca.crt` from Kali to FlareVM (via shared folder), then double-click it → **Install Certificate → Local Machine → Trusted Root Certification Authorities → Finish**.
