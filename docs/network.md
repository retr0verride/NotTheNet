# Network & iptables Guide

This guide explains how NotTheNet intercepts network traffic from the malware sample and redirects it to its fake services. If you're new to Linux networking, this page will help you understand what's happening behind the scenes.

> **Key concept: iptables** — `iptables` is a built-in Linux firewall tool that can inspect and redirect network traffic. NotTheNet uses it to catch all traffic leaving the malware and route it to the appropriate fake service. You don't need to configure iptables yourself — NotTheNet does it automatically.

## Table of Contents

- [How Traffic Redirection Works](#how-traffic-redirection-works)
- [Loopback Mode vs Gateway Mode](#loopback-mode-vs-gateway-mode)
- [iptables Rules Explained](#iptables-rules-explained)
- [Manual Rule Management](#manual-rule-management)
- [Disabling auto_iptables](#disabling-auto_iptables)
- [Excluding Ports from Catch-All](#excluding-ports-from-catch-all)
- [Network Namespace Isolation (Advanced)](#network-namespace-isolation-advanced)
- [Common Network Configurations](#common-network-configurations)
- [TCP/IP OS Fingerprint Spoofing](#tcpip-os-fingerprint-spoofing)

---

## How Traffic Redirection Works

The core problem with older fake-internet tools (INetSim, FakeNet-NG) is a **race condition**: DNS answers come back before the fake service is ready, or DNS points to an address where nothing is listening. NotTheNet solves this by starting all services first, then enabling traffic redirection.

Here's what happens step by step when malware runs:

```
Malware makes DNS query for evil-c2.com
         │
         ▼
[iptables: redirect port 53 traffic to NotTheNet's DNS]
         │
         ▼
NotTheNet DNS server answers with 127.0.0.1
         │
         ▼
Malware connects to 127.0.0.1:80 (HTTP beacon)
         │
         ▼
[iptables: port 80 → NotTheNet's HTTP server]  ← already running, no race
         │
         ▼
NotTheNet HTTP server returns 200 OK

Malware connects to 127.0.0.1:4444 (custom C2 port)
         │
         ▼
[iptables: all other TCP → NotTheNet's catch-all on port 9999]
         │
         ▼
NotTheNet catch-all pretends to be whatever the malware expects
```

The key difference: **all services are running and listening before any traffic rules kick in**. There is no gap between DNS answers and service availability.

---

## Loopback Mode vs Gateway Mode

### Loopback Mode (default)

```json
"iptables_mode": "loopback"
```

Rules are applied to the `OUTPUT` chain — they affect traffic **originating from the local machine only**.

```
┌─────────────────────────────────────┐
│  Kali Host                          │
│                                     │
│  [Malware process]                  │
│       │                             │
│       ▼  OUTPUT chain               │
│  [iptables NAT redirect]            │
│       │                             │
│       ▼                             │
│  [NotTheNet services on 127.0.0.1]  │
└─────────────────────────────────────┘
```

**Use when:** Running malware directly on the Kali host (e.g. in a container, Wine, or native Linux malware).

### Gateway Mode

```json
"iptables_mode": "gateway"
```

Rules are applied to the `PREROUTING` chain — they affect traffic **arriving from other hosts** (requires IP forwarding enabled).

```
┌─────────────────────────┐      ┌─────────────────────────┐
│  Victim VM              │      │  Kali / NotTheNet Host  │
│  DNS: 192.168.100.1     │─────►│  PREROUTING redirect    │
│  GW:  192.168.100.1     │      │  NotTheNet services     │
└─────────────────────────┘      └─────────────────────────┘
```

**Use when:** Running malware in a separate VM and the Kali host acts as the gateway/router.

**Required additional setup for gateway mode:**

`net.ipv4.ip_forward` is **enabled automatically** by NotTheNet when gateway mode is active and restored to its previous value when services stop. No manual step needed.

```bash
# Masquerade (only needed if the victim VM also needs real internet access through Kali)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

And in `config.json`, set `redirect_ip` to Kali's IP on the isolated network (e.g. `10.0.0.1`), **not** `127.0.0.1`.

#### Intra-LAN passthrough (worm lateral spread)

In gateway mode, NotTheNet inserts a `RETURN` rule at the top of `PREROUTING` that exempts traffic where **both source and destination** are inside the lab CIDR:

```bash
iptables -t nat -I PREROUTING 2 -s 10.10.10.0/24 -d 10.10.10.0/24 -j RETURN -m comment --comment NOTTHENET
```

This is what allows WannaCry/NotPetya-style worms to spread between victims (`10.10.10.7 → 10.10.10.8:445`) instead of being trapped on the NTN host. Victim→Kali probes (`10.10.10.7 → 10.10.10.1:53`) still hit NTN's DNAT because Kali binds `0.0.0.0:*` and receives them directly without needing a redirect.

- **Auto-derived** from `general.interface` when `passthrough_subnets` is empty (e.g. interface IP `10.10.10.1/24` → passthrough `10.10.10.0/24`).
- Override or add additional subnets via `general.passthrough_subnets` in `config.json`.
- Disable entirely by setting `general.passthrough_subnets: []` and switching to `iptables_mode: "loopback"` (no auto-derive in sinkhole mode).

---

## iptables Rules Explained

You don't need to understand these rules to use NotTheNet — they are applied and removed automatically. This section is for anyone who wants to know what's happening under the hood.

When NotTheNet starts with `auto_iptables: true`, it creates rules like these (example for loopback mode):

```bash
# Redirect all DNS traffic (both TCP and UDP) to NotTheNet's DNS server
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53 -m comment --comment NOTTHENET
iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53 -m comment --comment NOTTHENET

# Redirect HTTP traffic
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 80 -m comment --comment NOTTHENET

# Redirect HTTPS traffic
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 443 -m comment --comment NOTTHENET

# Redirect SMTP (email) traffic
iptables -t nat -A OUTPUT -p tcp --dport 25 -j REDIRECT --to-ports 25 -m comment --comment NOTTHENET

# (same pattern for POP3, IMAP, FTP...)

# Skip SSH so you don't lose remote access to Kali
iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN -m comment --comment NOTTHENET

# Catch-all: every remaining TCP connection goes to port 9999
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 9999 -m comment --comment NOTTHENET
```

All rules are tagged with the comment `NOTTHENET` so they can be easily identified and cleaned up.

### Viewing active NotTheNet rules

To see which rules NotTheNet has currently applied:

```bash
# For loopback mode:
sudo iptables -t nat -L OUTPUT --line-numbers -n | grep NOTTHENET

# For gateway mode:
sudo iptables -t nat -L PREROUTING --line-numbers -n | grep NOTTHENET
```

---

## Manual Rule Management

NotTheNet automatically saves your existing iptables rules before adding its own. When you click Stop, it restores the original rules from the backup.

### If NotTheNet crashed without cleaning up

If NotTheNet was killed unexpectedly (power loss, `kill -9`, system crash), it may not have removed its rules. Here's how to fix that:

```bash
# Option 1: Restore from the automatic backup (if it exists)
sudo iptables-restore /tmp/notthenet_iptables_save.rules

# Option 2: Manually delete NotTheNet rules one by one
# First, list the rules with line numbers:
sudo iptables -t nat -L OUTPUT --line-numbers -n
# Find lines tagged NOTTHENET, then delete by line number:
sudo iptables -t nat -D OUTPUT <line_number>
```

### Nuclear option — flush all NAT rules

```bash
# WARNING: This removes ALL NAT rules, not just NotTheNet's.
# Only use this if Kali is dedicated to this lab and you have no other NAT rules.
sudo iptables -t nat -F
```

---

## Disabling auto_iptables

If you want to manage traffic redirection yourself (for advanced setups like network namespaces or custom firewall rules), you can turn off automatic rule management:

```json
"general": {
  "auto_iptables": false
}
```

In this mode, NotTheNet only starts the fake services. **You** are responsible for making sure traffic reaches them.

Example manual redirect for DNS only:

```bash
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
sudo iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
```

---

## Excluding Ports from Catch-All

The catch-all service is a "safety net" that catches all TCP/UDP traffic on ports that don't have a dedicated fake service. But some ports should be left alone — most importantly SSH, so you don't lose remote access to your Kali machine.

The `catch_all.excluded_ports` setting tells NotTheNet to skip redirection for specific ports.

**Always include port 22 (SSH)** to avoid locking yourself out:

```json
"catch_all": {
  "excluded_ports": [22, 53, 80, 443, 25, 110, 143, 21]
}
```

Other ports you might want to exclude:
- `5900` — VNC (if you use remote desktop to view the victim VM)
- `3389` — RDP (same reason)
- `2222` — alternate SSH
- Any port used by monitoring tools running alongside NotTheNet

---

## Network Namespace Isolation (Advanced)

> **This section is for advanced users.** If you're using the standard Proxmox lab setup described in [Lab Setup](lab-setup.md), you can skip this.

For maximum isolation, you can run malware inside a dedicated Linux network namespace where **all** traffic is controlled by NotTheNet. This is useful if you're running Linux malware directly on Kali without a separate VM.

```bash
# Create a network namespace
sudo ip netns add malware-analysis

# Create a veth pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns malware-analysis

# Configure addresses
sudo ip addr add 192.168.200.1/24 dev veth0
sudo ip netns exec malware-analysis ip addr add 192.168.200.2/24 dev veth1
sudo ip link set veth0 up
sudo ip netns exec malware-analysis ip link set veth1 up
sudo ip netns exec malware-analysis ip link set lo up
sudo ip netns exec malware-analysis ip route add default via 192.168.200.1

# Run NotTheNet on the host with interface=veth0, iptables_mode=gateway
# redirect_ip=192.168.200.1

# Run the malware in the namespace
sudo ip netns exec malware-analysis wine malware.exe
# or: sudo ip netns exec malware-analysis ./malware_elf

# Tear down
sudo ip netns del malware-analysis
```

---

## Common Network Configurations

Here are ready-to-use config snippets for common lab setups. Copy the one that matches your environment.

### Single Kali VM (no separate victim VM)

Running malware directly on Kali (e.g. via Wine or as a native Linux binary):

```json
{
  "general": {
    "bind_ip": "127.0.0.1",
    "redirect_ip": "127.0.0.1",
    "interface": "lo",
    "auto_iptables": true,
    "iptables_mode": "loopback"
  }
}
```

### Kali + Victim VM on VirtualBox Host-Only Network

Using VirtualBox with a host-only adapter (`vboxnet0`):

```json
{
  "general": {
    "bind_ip": "0.0.0.0",
    "redirect_ip": "192.168.56.1",
    "interface": "vboxnet0",
    "auto_iptables": true,
    "iptables_mode": "gateway"
  },
  "dns": {
    "resolve_to": "192.168.56.1"
  }
}
```

### Kali + Victim VM on libvirt/KVM Host-Only

Using libvirt/KVM with the default virtual bridge:

```json
{
  "general": {
    "bind_ip": "0.0.0.0",
    "redirect_ip": "192.168.122.1",
    "interface": "virbr0",
    "auto_iptables": true,
    "iptables_mode": "gateway"
  },
  "dns": {
    "resolve_to": "192.168.122.1"
  }
}
```

### Network Namespace (most isolated)

```json
{
  "general": {
    "bind_ip": "0.0.0.0",
    "redirect_ip": "192.168.200.1",
    "interface": "veth0",
    "auto_iptables": true,
    "iptables_mode": "gateway"
  },
  "dns": {
    "resolve_to": "192.168.200.1"
  }
}
```

---

## TCP/IP OS Fingerprint Spoofing

**File:** `network/tcp_fingerprint.py`  
**Config:** `general.tcp_fingerprint`, `general.tcp_fingerprint_os`

Some malware and network tools (like Nmap) can detect what operating system is running by examining low-level details in network packets — things like the TTL (time to live), TCP window size, and other fields that differ between Windows, Linux, and macOS. If the malware sees Linux-style packets but expects Windows, it may refuse to run.

When `tcp_fingerprint` is enabled, NotTheNet modifies these low-level values on every connection so responses look like they came from the configured OS.

### OS Profiles

| Profile | TTL | TCP Window Size | DF Bit | MSS |
|---------|-----|----------------|--------|-----|
| `windows` | 128 | 65535 | Set | 1460 |
| `linux` | 64 | 29200 | Set | 1460 |
| `macos` | 64 | 65535 | Set | 1460 |
| `solaris` | 255 | 49640 | Set | 1460 |

### Platform Limitation

TCP fingerprint spoofing only works on Linux (it uses Linux-specific socket options). On other platforms, it silently does nothing. Errors are logged as warnings but do not prevent services from starting.

### Verifying

```bash
# From the victim VM, scan NotTheNet with Nmap OS detection:
nmap -O 10.0.0.1
# The "OS details" line should match your configured profile

# Or check the TTL in a simple ping:
ping -c 1 10.0.0.1
# TTL should be 128 for "windows", 64 for "linux" or "macos"
```
