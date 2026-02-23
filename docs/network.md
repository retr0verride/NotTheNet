# Network & iptables Guide

## Table of Contents

- [How Traffic Redirection Works](#how-traffic-redirection-works)
- [Loopback Mode vs Gateway Mode](#loopback-mode-vs-gateway-mode)
- [iptables Rules Explained](#iptables-rules-explained)
- [Manual Rule Management](#manual-rule-management)
- [Disabling auto_iptables](#disabling-auto_iptables)
- [Excluding Ports from Catch-All](#excluding-ports-from-catch-all)
- [Network Namespace Isolation (Advanced)](#network-namespace-isolation-advanced)
- [Common Network Configurations](#common-network-configurations)

---

## How Traffic Redirection Works

NotTheNet solves the core problem of INetSim and FakeNet-NG: **DNS resolves before services are ready, or resolves to addresses that don't match where services are listening**.

NotTheNet's approach:

```
Malware makes DNS query for evil-c2.com
         │
         ▼
[iptables NAT: port 53 → 127.0.0.1:53]
         │
         ▼
NotTheNet DNS server returns 127.0.0.1
         │
         ▼
Malware connects to 127.0.0.1:80 (HTTP beacon)
         │
         ▼
[iptables NAT: port 80 → 127.0.0.1:80]  ← already bound, no race
         │
         ▼
NotTheNet HTTP server returns 200 OK

Malware connects to 127.0.0.1:4444 (custom C2 port)
         │
         ▼
[iptables NAT: all other TCP → 127.0.0.1:9999]
         │
         ▼
NotTheNet catch-all returns "200 OK"
```

The key difference: **all services are bound before iptables rules are applied**. There is no window between DNS resolution and service availability.

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

```bash
# Enable IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Make permanent
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Masquerade (if the victim VM needs internet access through Kali normally)
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

And in `config.json`, set `redirect_ip` to the Kali host's IP on the host-only adapter (e.g. `192.168.100.1`), not `127.0.0.1`.

---

## iptables Rules Explained

When NotTheNet starts with `auto_iptables: true`, it applies rules like these (example for loopback mode):

```
# Redirect DNS (TCP+UDP) to local DNS server
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53 -m comment --comment NOTTHENET
iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53 -m comment --comment NOTTHENET

# Redirect HTTP
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-ports 80 -m comment --comment NOTTHENET

# Redirect HTTPS
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 443 -m comment --comment NOTTHENET

# Redirect SMTP
iptables -t nat -A OUTPUT -p tcp --dport 25 -j REDIRECT --to-ports 25 -m comment --comment NOTTHENET

# (and POP3, IMAP, FTP similarly...)

# Exclude SSH from catch-all
iptables -t nat -A OUTPUT -p tcp --dport 22 -j RETURN -m comment --comment NOTTHENET

# Catch-all: redirect all remaining TCP → port 9999
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 9999 -m comment --comment NOTTHENET
```

All rules are tagged with the comment `NOTTHENET` for easy identification and bulk removal.

### Viewing active NotTheNet rules

```bash
sudo iptables -t nat -L OUTPUT --line-numbers -n | grep NOTTHENET
# or for gateway mode:
sudo iptables -t nat -L PREROUTING --line-numbers -n | grep NOTTHENET
```

---

## Manual Rule Management

NotTheNet saves existing iptables rules to `/tmp/notthenet_iptables_save.rules` before applying its own rules. On stop, it restores from this snapshot.

### If NotTheNet crashed without cleaning up

```bash
# Restore from snapshot (if it exists)
sudo iptables-restore /tmp/notthenet_iptables_save.rules

# OR manually delete NotTheNet rules one by one
sudo iptables -t nat -L OUTPUT --line-numbers -n
# Find NOTTHENET lines, then:
sudo iptables -t nat -D OUTPUT <line_number>
```

### Nuclear option — flush all NAT rules

```bash
# WARNING: removes ALL NAT rules, not just NotTheNet's
sudo iptables -t nat -F
```

---

## Disabling auto_iptables

If you prefer to manage routing manually (e.g. using network namespaces or a different firewall), set:

```json
"general": {
  "auto_iptables": false
}
```

In this mode, NotTheNet only starts the service listeners. You are responsible for ensuring traffic reaches them.

Example manual redirect for DNS only:

```bash
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
sudo iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
```

---

## Excluding Ports from Catch-All

The `catch_all.excluded_ports` list tells iptables to **skip** the catch-all redirect for specific ports. These connections pass through unmodified.

**Always include port 22 (SSH)** to avoid losing remote access:

```json
"catch_all": {
  "excluded_ports": [22, 53, 80, 443, 25, 110, 143, 21]
}
```

Other ports to consider excluding:
- `5900` — VNC (remote desktop to analysis VM)
- `3389` — RDP
- `2222` — alternate SSH
- Any port you're using for live monitoring tools

---

## Network Namespace Isolation (Advanced)

For maximum isolation, run the malware sample inside a dedicated network namespace where **all** traffic is handled by NotTheNet.

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

### Single Kali VM (no separate victim VM)

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
