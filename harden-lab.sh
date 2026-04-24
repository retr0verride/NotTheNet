#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NotTheNet — Lab Hardening Script
# Run as root on Kali before starting NotTheNet.
#
# Hardens the host by:
#   1. Stopping all conflicting services (apache2, nginx, bind9, etc.)
#   2. Creating iptables isolation rules (blocks bridge↔management pivoting)
#   3. Blocking lateral movement ports on the bridge (SMB/RDP/WMI/RPC/WinRM)
#      so malware can spread between victim VMs but cannot attack Kali itself.
#   4. Mounting logs/ as tmpfs with noexec,nosuid,nodev
#   5. Verifying network isolation
#
# Usage:
#   sudo bash harden-lab.sh --bridge vmbr1 --mgmt eth0 --gateway-ip 10.10.10.1 [--victim-subnet 10.10.10.0/24]
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults (override with flags) ────────────────────────────────────────
BRIDGE_IF="${BRIDGE_IF:-vmbr1}"
MGMT_IF="${MGMT_IF:-eth0}"
GATEWAY_IP="${GATEWAY_IP:-10.10.10.1}"
VICTIM_SUBNET="${VICTIM_SUBNET:-10.10.10.0/24}"
VICTIM_IP="${VICTIM_IP:-}"
LOG_DIR="${LOG_DIR:-$(dirname "$0")/logs}"
SKIP_MOUNT="${SKIP_MOUNT:-0}"

usage() {
    echo "Usage: $0 [--bridge IFACE] [--mgmt IFACE] [--gateway-ip IP] [--victim-subnet CIDR] [--victim-ip IP] [--log-dir PATH] [--skip-mount]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bridge)         BRIDGE_IF="$2";     shift 2 ;;
        --mgmt)           MGMT_IF="$2";       shift 2 ;;
        --gateway-ip)     GATEWAY_IP="$2";    shift 2 ;;
        --victim-subnet)  VICTIM_SUBNET="$2"; shift 2 ;;
        --victim-ip)      VICTIM_IP="$2";      shift 2 ;;
        --log-dir)        LOG_DIR="$2";       shift 2 ;;
        --skip-mount)     SKIP_MOUNT=1;       shift   ;;
        -h|--help)        usage ;;
        *)                echo "Unknown option: $1"; usage ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (sudo)."
    exit 1
fi

# ── Autodetect bridge / gateway when caller passed defaults ──────────────
# Lets `service_manager._apply_hardening` pass through unset values without
# pinning Proxmox-specific names that don't exist on Kali / cloud / WSL.
if [[ "$BRIDGE_IF" == "vmbr1" ]] && ! ip link show vmbr1 >/dev/null 2>&1; then
    detected_if="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    if [[ -n "$detected_if" ]]; then
        echo "[i] Bridge '$BRIDGE_IF' not found; using default-route interface '$detected_if'."
        BRIDGE_IF="$detected_if"
    fi
fi
if [[ "$GATEWAY_IP" == "10.10.10.1" ]] && ! ip -4 addr show | grep -q "inet 10\.10\.10\.1/"; then
    detected_ip="$(ip -4 -o addr show dev "$BRIDGE_IF" scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    if [[ -n "$detected_ip" ]]; then
        echo "[i] Gateway '$GATEWAY_IP' not assigned; using '$detected_ip' from $BRIDGE_IF."
        GATEWAY_IP="$detected_ip"
    fi
fi

echo "═══════════════════════════════════════════════════════"
echo "  NotTheNet Lab Hardening"
echo "  Bridge:        $BRIDGE_IF"
echo "  Management:    $MGMT_IF"
echo "  Gateway IP:    $GATEWAY_IP"
echo "  Victim subnet: $VICTIM_SUBNET"
echo "  Victim IP:     ${VICTIM_IP:-auto-detect from config.json}"
echo "═══════════════════════════════════════════════════════"

# ── 1. Stop conflicting services ──────────────────────────────────────────
echo ""
echo "[1/5] Stopping conflicting system services..."

SERVICES=(
    apache2 nginx lighttpd
    bind9 dnsmasq systemd-resolved
    exim4 postfix
    smbd nmbd
    mariadb mysql
)

for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  ✓ Stopping $svc"
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    fi
done

# Prevent systemd-resolved from re-binding :53 on next boot
if [ -f /etc/systemd/resolved.conf ]; then
    if ! grep -q "^DNSStubListener=no" /etc/systemd/resolved.conf; then
        echo "  → Disabling DNSStubListener in resolved.conf"
        sed -i 's/^#\?DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
    fi
fi

echo "  Done."

# ── 2. iptables / ip6tables isolation rules ──────────────────────────────
echo ""
echo "[2/5] Applying iptables isolation rules..."

# Purge ALL existing NOTTHENET_HARDEN rules (INPUT, FORWARD, any chain) in one atomic pass.
# This prevents rule stacking across re-runs and is instant regardless of rule count.
iptables-save 2>/dev/null | { grep -v 'NOTTHENET_HARDEN' || true; } | iptables-restore 2>/dev/null || true

# ── IPv6: block all forwarding on the bridge. ─────────────────────────────
# Malware that is IPv6-aware can bypass an IPv4-only sinkhole by routing
# traffic via the victim NIC's link-local or ULA IPv6 address.  Drop all
# IPv6 forwarding on the lab bridge so there is no escape route.
# NotTheNet does not currently provide IPv6 fake services, so this is a
# pure DROP — nothing useful is blocked that wasn't already unserviced.
if command -v ip6tables &>/dev/null; then
    ip6tables-save 2>/dev/null | { grep -v 'NOTTHENET_HARDEN' || true; } | ip6tables-restore 2>/dev/null || true
    ip6tables -I FORWARD 1 -i "$BRIDGE_IF" -j DROP \
        -m comment --comment "NOTTHENET_HARDEN: block IPv6 forward on lab bridge"
    ip6tables -I FORWARD 2 -o "$BRIDGE_IF" -j DROP \
        -m comment --comment "NOTTHENET_HARDEN: block IPv6 forward to lab bridge"
    ip6tables -A INPUT -i "$BRIDGE_IF" -j DROP \
        -m comment --comment "NOTTHENET_HARDEN: block IPv6 input from lab bridge"
    echo "  ✓ IPv6 FORWARD + INPUT on $BRIDGE_IF: BLOCKED (ip6tables)"
else
    echo "  ⚠ ip6tables not found — IPv6 forwarding NOT blocked"
fi

# ip_forward: set to 0 here so that if NTN hasn't started yet (or is running
# in loopback mode) there is no kernel-level escape route.  When NTN starts in
# gateway mode it writes ip_forward=1 itself and restores 0 on stop.  This
# line is therefore the safe baseline, not the final runtime value.
echo 0 > /proc/sys/net/ipv4/ip_forward
echo "  ✓ ip_forward: baseline 0 (NTN gateway mode will re-enable on start)"

# Allow intra-bridge forwarding (victim ↔ victim) BEFORE any DROP rules.
# Required when bridge-nf-call-iptables=1 routes bridged packets through
# iptables FORWARD.  Without this rule, if the FORWARD default policy is DROP
# (common after system hardening), victim-to-victim spread is silently blocked
# even though passthrough_subnets skips DNAT in PREROUTING.  Insert at
# position 1 so it beats all existing FORWARD rules.
iptables -I FORWARD 1 -i "$BRIDGE_IF" -o "$BRIDGE_IF" -j ACCEPT \
    -m comment --comment "NOTTHENET_HARDEN: allow intra-bridge fwd (victim spread)"
echo "  ✓ FORWARD $BRIDGE_IF → $BRIDGE_IF: ALLOWED (victim-to-victim spread)"

# Block ALL forwarding between bridge (victim network) and management NIC.
# Skip if bridge and mgmt are the same interface (single-NIC setups).
if [[ "$BRIDGE_IF" != "$MGMT_IF" ]]; then
    iptables -I FORWARD 2 -i "$BRIDGE_IF" -o "$MGMT_IF" -j DROP \
        -m comment --comment "NOTTHENET_HARDEN: block pivot bridge→mgmt"
    iptables -I FORWARD 3 -i "$MGMT_IF" -o "$BRIDGE_IF" -j DROP \
        -m comment --comment "NOTTHENET_HARDEN: block pivot mgmt→bridge"

    # Block NEW inbound connections from the analysis subnet on the management NIC.
    iptables -A INPUT -i "$MGMT_IF" -s 10.0.0.0/8 -m conntrack --ctstate NEW -j DROP \
        -m comment --comment "NOTTHENET_HARDEN: block analysis subnet on mgmt"

    echo "  ✓ FORWARD $BRIDGE_IF ↔ $MGMT_IF: BLOCKED"
    echo "  ✓ INPUT from 10.0.0.0/8 on $MGMT_IF: BLOCKED"
else
    echo "  -- Single-NIC setup (bridge=$BRIDGE_IF == mgmt=$MGMT_IF): skipping pivot/mgmt isolation rules"
fi

# ── Block lateral movement ports: victim subnet → Kali (vmbr1 INPUT) ─────
# Victims can still reach NotTheNet fake-internet ports (53,80,443,25,…) but
# cannot attack Kali via Windows exploitation channels.

# Auto-read victim IP from config.json if not provided via --victim-ip
if [[ -z "$VICTIM_IP" ]]; then
    _CFG="$(dirname "$0")/config.json"
    if [[ -f "$_CFG" ]]; then
        VICTIM_IP=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('victim',{}).get('ip',''))" "$_CFG" 2>/dev/null || true)
    fi
fi

# Validate victim IP (each octet 0-255)
_valid_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && \
    python3 -c "import sys; sys.exit(0 if all(0<=int(o)<=255 for o in sys.argv[1].split('.')) else 1)" "$1" 2>/dev/null; }

# Allow selected victim to reach Kali on WMI/DCOM/SMB ports (needed for Preflight checks).
# These ACCEPTs are inserted BEFORE the subnet-wide DROPs so they take precedence.
if [[ -n "$VICTIM_IP" ]] && _valid_ip "$VICTIM_IP"; then
    for _port in 135 139 445; do
        iptables -I INPUT 1 -i "$BRIDGE_IF" -s "$VICTIM_IP" \
            -p tcp --dport "$_port" -j ACCEPT \
            -m comment --comment "NOTTHENET_HARDEN: allow victim WMI/SMB -> Kali"
    done
    echo "  ✓ WMI/SMB INPUT from $VICTIM_IP: ALLOWED (Preflight checks)"
else
    echo "  -- No valid victim IP configured; skipping WMI/SMB ACCEPT rules"
fi

# Validate CIDR subnet
if ! [[ "$VICTIM_SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    echo "  ✗ Invalid VICTIM_SUBNET: $VICTIM_SUBNET — skipping lateral movement blocks"
else
    # 445 (SMB) and 3389 (RDP) are NOT blocked here — NotTheNet sinkholes both
    # via dedicated services.  Blocking them would drop DNAT-redirected victim
    # traffic before it reaches NTN's listener.  WinRM (5985/5986) and raw
    # WMI/NetBIOS (135/139/137/138) have no NTN sinkhole and are genuine
    # Kali-exploitation channels, so those remain blocked.
    # SSH (22) is also blocked: passthrough_subnets exempts victim→Kali:22 from
    # DNAT, so without this INPUT DROP, malware doing SSH lateral movement could
    # hit the real Kali SSH daemon directly.
    for _proto in tcp udp; do
        for _port in 22 135 139 5985 5986; do
            iptables -A INPUT -i "$BRIDGE_IF" -s "$VICTIM_SUBNET" \
                -p "$_proto" --dport "$_port" -j DROP \
                -m comment --comment "NOTTHENET_HARDEN: block lateral movement -> Kali"
        done
    done
    # NetBIOS name/datagram (UDP only)
    for _port in 137 138; do
        iptables -A INPUT -i "$BRIDGE_IF" -s "$VICTIM_SUBNET" \
            -p udp --dport "$_port" -j DROP \
            -m comment --comment "NOTTHENET_HARDEN: block lateral movement -> Kali"
    done

    echo "  ✓ Lateral movement ports (SSH/WMI/WinRM/NetBIOS) from $VICTIM_SUBNET: BLOCKED on $BRIDGE_IF"
    echo "  -- SMB/RDP (445/3389) NOT blocked: handled by NotTheNet sinkholes"
fi
echo "  Done."

# ── 3. Mount logs/ as tmpfs (noexec) ─────────────────────────────────────
echo ""
echo "[3/5] Securing logs directory..."

mkdir -p "$LOG_DIR"

if [[ "$SKIP_MOUNT" -eq 0 ]]; then
    # Unmount if already mounted as tmpfs
    if mountpoint -q "$LOG_DIR" 2>/dev/null; then
        echo "  → Already mounted as tmpfs, remounting..."
        umount "$LOG_DIR"
    fi

    mount -t tmpfs -o size=512M,noexec,nosuid,nodev,mode=0700 tmpfs "$LOG_DIR"
    echo "  ✓ $LOG_DIR mounted as tmpfs (noexec,nosuid,nodev,512M)"

    # Create subdirectories for artifacts
    mkdir -p "$LOG_DIR/emails" "$LOG_DIR/ftp_uploads"
    chmod 0700 "$LOG_DIR/emails" "$LOG_DIR/ftp_uploads"
else
    echo "  → Skipped (--skip-mount)"
fi

echo "  Done."

# ── 4. Verify isolation ──────────────────────────────────────────────────
echo ""
echo "[4/5] Verifying isolation..."

# Check bridge interface exists
if ip link show "$BRIDGE_IF" &>/dev/null; then
    echo "  ✓ Bridge interface $BRIDGE_IF exists"
else
    echo "  ✗ Bridge interface $BRIDGE_IF NOT FOUND — check Proxmox config"
fi

# Check gateway IP is assigned
if ip addr show "$BRIDGE_IF" 2>/dev/null | grep -q "$GATEWAY_IP"; then
    echo "  ✓ Gateway IP $GATEWAY_IP is assigned to $BRIDGE_IF"
else
    echo "  ⚠ Gateway IP $GATEWAY_IP not on $BRIDGE_IF — assign with:"
    echo "    ip addr add $GATEWAY_IP/24 dev $BRIDGE_IF"
fi

# Show iptables rules
echo ""
echo "  Active FORWARD rules (IPv4):"
iptables -L FORWARD -n --line-numbers 2>/dev/null | head -20
echo ""
echo "  Active INPUT rules (bridge, IPv4):"
iptables -L INPUT -n --line-numbers 2>/dev/null | grep -E "$BRIDGE_IF|NOTTHENET" | head -20
echo ""
if command -v ip6tables &>/dev/null; then
    echo "  Active FORWARD rules (IPv6):"
    ip6tables -L FORWARD -n --line-numbers 2>/dev/null | grep -E "$BRIDGE_IF|NOTTHENET" | head -10
fi
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Hardening complete. Start NotTheNet with:"
echo "    sudo python notthenet.py --nogui"
echo "═══════════════════════════════════════════════════════"
