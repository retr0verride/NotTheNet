#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# NotTheNet — Lab Hardening Script
# Run as root on Kali before starting NotTheNet.
#
# Hardens the host by:
#   1. Stopping all conflicting services (apache2, nginx, bind9, etc.)
#   2. Creating iptables isolation rules (blocks bridge↔management pivoting)
#   3. Mounting logs/ as tmpfs with noexec,nosuid,nodev
#   4. Verifying network isolation
#
# Usage:
#   sudo bash harden-lab.sh --bridge vmbr1 --mgmt eth0 --gateway-ip 10.10.10.1
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults (override with flags) ────────────────────────────────────────
BRIDGE_IF="${BRIDGE_IF:-vmbr1}"
MGMT_IF="${MGMT_IF:-eth0}"
GATEWAY_IP="${GATEWAY_IP:-10.10.10.1}"
LOG_DIR="${LOG_DIR:-$(dirname "$0")/logs}"
SKIP_MOUNT="${SKIP_MOUNT:-0}"

usage() {
    echo "Usage: $0 [--bridge IFACE] [--mgmt IFACE] [--gateway-ip IP] [--log-dir PATH] [--skip-mount]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bridge)     BRIDGE_IF="$2";   shift 2 ;;
        --mgmt)       MGMT_IF="$2";     shift 2 ;;
        --gateway-ip) GATEWAY_IP="$2";  shift 2 ;;
        --log-dir)    LOG_DIR="$2";     shift 2 ;;
        --skip-mount) SKIP_MOUNT=1;     shift   ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1"; usage ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "[!] This script must be run as root (sudo)."
    exit 1
fi

echo "═══════════════════════════════════════════════════════"
echo "  NotTheNet Lab Hardening"
echo "  Bridge:     $BRIDGE_IF"
echo "  Management: $MGMT_IF"
echo "  Gateway IP: $GATEWAY_IP"
echo "═══════════════════════════════════════════════════════"

# ── 1. Stop conflicting services ──────────────────────────────────────────
echo ""
echo "[1/4] Stopping conflicting system services..."

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

# ── 2. iptables isolation rules ───────────────────────────────────────────
echo ""
echo "[2/4] Applying iptables isolation rules..."

# Flush any existing NotTheNet hardening rules (idempotent re-run)
iptables -D FORWARD -i "$BRIDGE_IF" -o "$MGMT_IF" -j DROP 2>/dev/null || true
iptables -D FORWARD -i "$MGMT_IF" -o "$BRIDGE_IF" -j DROP 2>/dev/null || true
iptables -D INPUT   -i "$MGMT_IF" -s 10.0.0.0/8 -j DROP   2>/dev/null || true

# Block ALL forwarding between bridge (victim network) and management NIC
iptables -I FORWARD 1 -i "$BRIDGE_IF" -o "$MGMT_IF" -j DROP \
    -m comment --comment "NOTTHENET_HARDEN: block pivot bridge→mgmt"
iptables -I FORWARD 2 -i "$MGMT_IF" -o "$BRIDGE_IF" -j DROP \
    -m comment --comment "NOTTHENET_HARDEN: block pivot mgmt→bridge"

# Also block any traffic from the analysis subnet reaching the mgmt interface INPUT
iptables -A INPUT -i "$MGMT_IF" -s 10.0.0.0/8 -j DROP \
    -m comment --comment "NOTTHENET_HARDEN: block analysis subnet on mgmt"

# Ensure IP forwarding is on for the bridge (so NAT redirect works)
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "  ✓ FORWARD $BRIDGE_IF ↔ $MGMT_IF: BLOCKED"
echo "  ✓ INPUT from 10.0.0.0/8 on $MGMT_IF: BLOCKED"
echo "  Done."

# ── 3. Mount logs/ as tmpfs (noexec) ─────────────────────────────────────
echo ""
echo "[3/4] Securing logs directory..."

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
echo "[4/4] Verification..."

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
echo "  Active FORWARD rules:"
iptables -L FORWARD -n --line-numbers 2>/dev/null | head -20
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Hardening complete. Start NotTheNet with:"
echo "    sudo python notthenet.py --nogui"
echo "═══════════════════════════════════════════════════════"
