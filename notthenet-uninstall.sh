#!/usr/bin/env bash
# ============================================================================
# NotTheNet — Uninstall Script
# Removes everything installed by notthenet-install.sh or build-deb.sh
#
# Usage:
#   sudo bash notthenet-uninstall.sh            # remove system files, keep repo
#   sudo bash notthenet-uninstall.sh --purge    # also delete the project directory
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

PURGE=false
for arg in "$@"; do
    [[ "$arg" == "--purge" ]] && PURGE=true
done

# ── Privilege check ──────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash notthenet-uninstall.sh"

# ── 1. Stop any running NotTheNet process ────────────────────────────────────
if pgrep -f "notthenet" >/dev/null 2>&1; then
    info "Stopping running NotTheNet process..."
    pkill -f "notthenet" || true
    sleep 1
fi

# ── 2. Flush iptables rules added by NotTheNet ───────────────────────────────
info "Flushing NotTheNet iptables rules..."
for table in nat filter; do
    for chain in OUTPUT PREROUTING FORWARD INPUT; do
        while iptables -t "$table" -S "$chain" 2>/dev/null | grep -q "NOTTHENET"; do
            rule=$(iptables -t "$table" -S "$chain" | grep "NOTTHENET" | head -1)
            iptables -t "$table" $(echo "$rule" | sed 's/^-A/-D/') 2>/dev/null || break
        done
    done
done
info "iptables rules cleared"

# ── 3. Remove CLI launchers ───────────────────────────────────────────────────
for f in /usr/local/bin/notthenet /usr/local/bin/notthenet-gui /usr/bin/notthenet; do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        info "Removed $f"
    fi
done

# ── 4. Remove desktop integration ────────────────────────────────────────────
for f in \
    /usr/share/applications/notthenet.desktop \
    /usr/share/icons/hicolor/scalable/apps/notthenet.svg \
    /usr/share/icons/hicolor/128x128/apps/notthenet.png \
    /usr/share/polkit-1/actions/com.retr0verride.notthenet.policy; do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        info "Removed $f"
    fi
done

# ── 5. Remove man page ────────────────────────────────────────────────────────
for f in \
    /usr/local/share/man/man1/notthenet.1.gz \
    /usr/share/man/man1/notthenet.1.gz; do
    if [[ -f "$f" ]]; then
        rm -f "$f"
        info "Removed $f"
    fi
done

# ── 6. Refresh system caches ──────────────────────────────────────────────────
update-desktop-database -q /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
mandb -q 2>/dev/null || true
# Restart XFCE panel so it reloads the icon cache; prevents other panel icons
# from showing as white gear placeholders after the cache is rebuilt.
pgrep -x xfce4-panel >/dev/null && DISPLAY="${DISPLAY:-:0}" xfce4-panel --restart 2>/dev/null || true
info "System caches refreshed"

# ── 7. Remove pip package (script-install path) ───────────────────────────────
for pip_bin in "${SCRIPT_DIR}/venv/bin/pip" "${SCRIPT_DIR}/.venv/bin/pip"; do
    if [[ -f "$pip_bin" ]]; then
        "$pip_bin" uninstall -y notthenet 2>/dev/null || true
        info "pip package uninstalled via $pip_bin"
    fi
done

# ── 8. Remove /opt/notthenet (deb-install path) ───────────────────────────────
if [[ -d /opt/notthenet ]]; then
    info "Removing /opt/notthenet ..."
    chmod -R u+w /opt/notthenet
    rm -rf /opt/notthenet
    info "Removed /opt/notthenet"
fi

# ── 9. Optionally remove the project directory ────────────────────────────────
if $PURGE; then
    warn "Purging project directory: $SCRIPT_DIR"
    warn "This permanently deletes all logs, captured emails, FTP uploads, and certs."
    read -r -p "    Type YES to confirm: " confirm
    if [[ "$confirm" == "YES" ]]; then
        # chmod first: .git/objects files are 444 by default and cause
        # "Permission denied" with plain rm -rf even under sudo.
        chmod -R u+w "$SCRIPT_DIR"
        PARENT="$(dirname "$SCRIPT_DIR")"
        cd "$PARENT"
        rm -rf "$SCRIPT_DIR"
        info "Project directory removed."
    else
        warn "Purge cancelled — project directory kept."
    fi
else
    info "Project directory kept at $SCRIPT_DIR (run with --purge to remove it too)."
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NotTheNet uninstalled successfully.                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
