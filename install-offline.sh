#!/usr/bin/env bash
# ============================================================================
# NotTheNet — Offline / Air-Gap Install Script
# For Kali Linux (or any Debian/Ubuntu-based distro) with NO internet access.
#
# Prerequisites (prepared on an internet-connected Windows machine):
#   1. Run prepare-usb.ps1 to populate .\wheelhouse\ with Linux wheels.
#   2. Copy the entire NotTheNet folder to a FAT32 (or any) USB drive.
#   3. Mount the USB on the air-gapped Kali machine and run:
#        sudo bash install-offline.sh
#
# What this script does (same as notthenet-install.sh except pip is offline):
#   1. Checks Python 3.9+
#   2. Creates a virtualenv in ./venv
#   3. Installs pinned Python deps from ./wheelhouse (no network needed)
#   4. Generates a self-signed TLS certificate
#   5. Installs desktop icon, .desktop entry, polkit action
#   6. Creates /usr/local/bin/notthenet launcher
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
WHEEL_DIR="${SCRIPT_DIR}/wheelhouse"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some install steps will be skipped."
    warn "Re-run with: sudo bash install-offline.sh"
fi

# ── Wheelhouse check ──────────────────────────────────────────────────────────
if [[ ! -d "$WHEEL_DIR" ]] || [[ -z "$(ls -A "$WHEEL_DIR" 2>/dev/null)" ]]; then
    error "Wheelhouse not found or empty: $WHEEL_DIR
       On your internet-connected Windows machine, run:
         .\\prepare-usb.ps1
       Then copy the NotTheNet folder to this USB and retry."
fi
info "Wheelhouse found: $(ls "$WHEEL_DIR" | wc -l) file(s)"

# ── Python version check ──────────────────────────────────────────────────────
PYTHON=$(command -v python3 2>/dev/null || true)
[[ -z "$PYTHON" ]] && error "python3 not found. Install it with: apt install python3"

PYVER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYMAJ=$(echo "$PYVER" | cut -d. -f1)
PYMIN=$(echo "$PYVER" | cut -d. -f2)
if [[ $PYMAJ -lt 3 ]] || { [[ $PYMAJ -eq 3 ]] && [[ $PYMIN -lt 9 ]]; }; then
    error "Python 3.9+ required (found $PYVER)."
fi
info "Python $PYVER found at $PYTHON"

# ── System packages (no internet needed — these come from local apt cache) ────
# python3-venv and python3-dev may already be present on Kali.
# If apt can't find them offline, we skip gracefully.
info "Checking system packages (python3-venv, iptables, openssl)..."
if command -v apt-get &>/dev/null; then
    apt-get install -y --no-install-recommends \
        python3-venv python3-dev \
        iptables iproute2 \
        openssl \
        librsvg2-bin \
        2>/dev/null || warn "Some apt packages could not be installed (no local cache?)."
fi

# ── Virtualenv setup ──────────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv at $VENV_DIR..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

PIP="${VENV_DIR}/bin/pip"
VPYTHON="${VENV_DIR}/bin/python"

# Upgrade pip/setuptools/wheel from the wheelhouse if newer versions are there,
# otherwise use whatever came with the venv (no network call).
info "Upgrading pip/setuptools/wheel (offline)..."
"$PIP" install --quiet --upgrade --no-index --find-links "$WHEEL_DIR" \
    pip setuptools wheel 2>/dev/null || true

# ── Install Python dependencies from wheelhouse ───────────────────────────────
info "Installing Python dependencies from wheelhouse (offline)..."
"$PIP" install \
    --no-index \
    --find-links "$WHEEL_DIR" \
    -r "${SCRIPT_DIR}/requirements.txt"

# ── Generate self-signed TLS certificate ─────────────────────────────────────
CERT_DIR="${SCRIPT_DIR}/certs"
mkdir -p "$CERT_DIR"
chmod 750 "$CERT_DIR"

if [[ ! -f "${CERT_DIR}/server.crt" ]] || [[ ! -f "${CERT_DIR}/server.key" ]]; then
    info "Generating self-signed TLS certificate..."
    cd "$SCRIPT_DIR"
    "$VPYTHON" - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
from utils.cert_utils import generate_self_signed_cert
ok = generate_self_signed_cert(
    "certs/server.crt", "certs/server.key",
    common_name="notthenet.local",
    san_dns=["localhost", "notthenet.local", "*.notthenet.local"],
    san_ips=["127.0.0.1", "0.0.0.0"],
    key_bits=4096,
)
sys.exit(0 if ok else 1)
PYEOF
    info "Certificate generated: certs/server.crt"
else
    info "Existing certificate found; skipping generation."
fi

# ── Create log/upload directories ─────────────────────────────────────────────
for dir in "${SCRIPT_DIR}/logs" \
           "${SCRIPT_DIR}/logs/emails" \
           "${SCRIPT_DIR}/logs/ftp_uploads" \
           "${SCRIPT_DIR}/logs/tftp_uploads"; do
    mkdir -p "$dir"
    chmod 700 "$dir"
done

# ── Install man page ──────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    MAN_DIR="/usr/local/share/man/man1"
    mkdir -p "$MAN_DIR"
    gzip -c "${SCRIPT_DIR}/man/notthenet.1" > "${MAN_DIR}/notthenet.1.gz"
    mandb -q 2>/dev/null || true
    info "Man page installed."
fi

# ── Install icon ───────────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    ICON_SVG="${SCRIPT_DIR}/assets/notthenet-icon.svg"
    if [[ -f "$ICON_SVG" ]]; then
        ICON_SCALABLE="/usr/share/icons/hicolor/scalable/apps"
        mkdir -p "$ICON_SCALABLE"
        cp -f "$ICON_SVG" "${ICON_SCALABLE}/notthenet.svg"

        ICON_128="/usr/share/icons/hicolor/128x128/apps"
        mkdir -p "$ICON_128"
        if command -v rsvg-convert &>/dev/null; then
            rsvg-convert -w 128 -h 128 "$ICON_SVG" -o "${ICON_128}/notthenet.png"
        elif command -v convert &>/dev/null; then
            convert -background none -resize 128x128 "$ICON_SVG" "${ICON_128}/notthenet.png"
        else
            warn "No SVG→PNG converter found; skipping PNG icon."
        fi
        gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
        info "Icon installed."
    fi
fi

# ── Install .desktop file + GUI launcher ──────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    GUI_LAUNCHER="/usr/local/bin/notthenet-gui"
    sed \
        -e "s|VENV_PYTHON_PLACEHOLDER|${VENV_DIR}/bin/python|g" \
        -e "s|SCRIPT_PLACEHOLDER|${SCRIPT_DIR}/notthenet.py|g" \
        "${SCRIPT_DIR}/assets/notthenet-gui-launcher" > "$GUI_LAUNCHER"
    chmod 0755 "$GUI_LAUNCHER"

    DESKTOP_FILE="/usr/share/applications/notthenet.desktop"
    sed \
        -e "s|NOTTHENET_EXEC_PLACEHOLDER|/usr/local/bin/notthenet-gui|g" \
        "${SCRIPT_DIR}/assets/notthenet.desktop" > "$DESKTOP_FILE"
    chmod 0644 "$DESKTOP_FILE"
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
    info "Desktop entry installed."

    POLKIT_DIR="/usr/share/polkit-1/actions"
    if [[ -d "$POLKIT_DIR" ]]; then
        sed \
            -e "s|VENV_PYTHON_PLACEHOLDER|${VENV_DIR}/bin/python|g" \
            "${SCRIPT_DIR}/assets/com.retr0verride.notthenet.policy" \
            > "${POLKIT_DIR}/com.retr0verride.notthenet.policy"
        chmod 0644 "${POLKIT_DIR}/com.retr0verride.notthenet.policy"
        info "Polkit action installed."
    fi
fi

# ── Create /usr/local/bin launchers ───────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    LAUNCHER="/usr/local/bin/notthenet"
    cat > "$LAUNCHER" <<LAUNCHER_EOF
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python" "${SCRIPT_DIR}/notthenet.py" "\$@"
LAUNCHER_EOF
    chmod 0755 "$LAUNCHER"

    UNINSTALL_LAUNCHER="/usr/local/bin/notthenet-uninstall"
    cat > "$UNINSTALL_LAUNCHER" <<UNINSTALL_EOF
#!/usr/bin/env bash
exec bash "${SCRIPT_DIR}/notthenet-uninstall.sh" "\$@"
UNINSTALL_EOF
    chmod 0755 "$UNINSTALL_LAUNCHER"
    info "Launchers installed at /usr/local/bin/notthenet"
else
    warn "Skipping /usr/local/bin launcher (not root)."
    info "Usage: sudo ${VENV_DIR}/bin/python ${SCRIPT_DIR}/notthenet.py"
fi

# ── Final message ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NotTheNet installed successfully (offline)!        ║${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║   App menu:  Search 'NotTheNet' and click icon       ║${NC}"
echo -e "${GREEN}║   GUI:       sudo notthenet                          ║${NC}"
echo -e "${GREEN}║   Headless:  sudo notthenet --nogui                  ║${NC}"
echo -e "${GREEN}║   Man page:  man notthenet                           ║${NC}"
echo -e "${GREEN}║   Uninstall: sudo notthenet-uninstall                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
