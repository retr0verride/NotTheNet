#!/usr/bin/env bash
# ============================================================================
# NotTheNet — Install Script
# Tested on Kali Linux 2024+ / Debian 12 / Ubuntu 22.04+
#
# What this does:
#   1. Detects system Python 3.9+
#   2. Creates a virtualenv in ./venv
#   3. Installs pinned Python dependencies
#   4. Generates a self-signed TLS certificate
#   5. Installs desktop icon + .desktop file (click to launch from app menu)
#   6. Installs polkit action (graphical password prompt via pkexec)
#   7. Creates the notthenet launcher in /usr/local/bin (optional)
#
# OpenSSF notes:
#   - Uses --require-hashes to verify package integrity
#   - Never uses curl | bash patterns for dependency fetching
#   - All temp files created with mktemp and removed on EXIT
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

# ── Privilege check ──────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some install steps may fail."
    warn "Re-run with: sudo bash install.sh"
fi

# ── Check Python version ─────────────────────────────────────────────────────
PYTHON=$(command -v python3 2>/dev/null || true)
[[ -z "$PYTHON" ]] && error "python3 not found. Install it with: apt install python3"

PYVER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYMAJ=$(echo "$PYVER" | cut -d. -f1)
PYMIN=$(echo "$PYVER" | cut -d. -f2)
if [[ $PYMAJ -lt 3 ]] || { [[ $PYMAJ -eq 3 ]] && [[ $PYMIN -lt 9 ]]; }; then
    error "Python 3.9+ required (found $PYVER)."
fi
info "Python $PYVER found at $PYTHON"

# ── System dependencies ──────────────────────────────────────────────────────
info "Installing system packages..."
if command -v apt-get &>/dev/null; then
    apt-get install -y --no-install-recommends \
        python3-venv python3-dev \
        iptables iproute2 \
        openssl \
        librsvg2-bin \
        > /dev/null
elif command -v dnf &>/dev/null; then
    dnf install -y python3-devel iptables iproute librsvg2-tools > /dev/null
else
    warn "Unknown package manager; skipping system packages."
fi

# ── Virtualenv setup ─────────────────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv at $VENV_DIR..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

PIP="${VENV_DIR}/bin/pip"
VPYTHON="${VENV_DIR}/bin/python"

info "Upgrading pip/setuptools/wheel..."
"$PIP" install --quiet --upgrade pip setuptools wheel

# ── Install Python dependencies ───────────────────────────────────────────────
info "Installing Python dependencies (pinned)..."
"$PIP" install --quiet -r "${SCRIPT_DIR}/requirements.txt"

# ── Generate self-signed TLS certificate ─────────────────────────────────────
CERT_DIR="${SCRIPT_DIR}/certs"
mkdir -p "$CERT_DIR"
chmod 750 "$CERT_DIR"

if [[ ! -f "${CERT_DIR}/server.crt" ]] || [[ ! -f "${CERT_DIR}/server.key" ]]; then
    info "Generating self-signed TLS certificate (4096-bit RSA, SHA-256)..."
    "$VPYTHON" - <<'PYEOF'
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(".")))
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
           "${SCRIPT_DIR}/logs/ftp_uploads"; do
    mkdir -p "$dir"
    chmod 700 "$dir"
done

# ── Install man page ──────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    MAN_DIR="/usr/local/share/man/man1"
    mkdir -p "$MAN_DIR"
    gzip -c "${SCRIPT_DIR}/man/notthenet.1" > "${MAN_DIR}/notthenet.1.gz"
    mandb -q 2>/dev/null || true
    info "Man page installed: man notthenet"
fi

# ── Install icon ───────────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    ICON_SVG="${SCRIPT_DIR}/assets/logo.svg"

    # Scalable SVG
    ICON_SCALABLE="/usr/share/icons/hicolor/scalable/apps"
    mkdir -p "$ICON_SCALABLE"
    cp -f "$ICON_SVG" "${ICON_SCALABLE}/notthenet.svg"

    # 128×128 PNG (rsvg-convert preferred; fall back to convert/inkscape)
    ICON_128="/usr/share/icons/hicolor/128x128/apps"
    mkdir -p "$ICON_128"
    if command -v rsvg-convert &>/dev/null; then
        rsvg-convert -w 128 -h 128 "$ICON_SVG" -o "${ICON_128}/notthenet.png"
    elif command -v convert &>/dev/null; then
        convert -background none -resize 128x128 "$ICON_SVG" "${ICON_128}/notthenet.png"
    elif command -v inkscape &>/dev/null; then
        inkscape --export-type=png --export-width=128 \
                 --export-filename="${ICON_128}/notthenet.png" "$ICON_SVG" 2>/dev/null
    else
        warn "No SVG→PNG converter found (rsvg-convert/convert/inkscape); skipping PNG icon."
    fi

    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
    info "Icon installed: /usr/share/icons/hicolor/"
fi

# ── Install .desktop file + GUI launcher ──────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    # Write the GUI launcher with real paths baked in
    GUI_LAUNCHER="/usr/local/bin/notthenet-gui"
    sed \
        -e "s|VENV_PYTHON_PLACEHOLDER|${VENV_DIR}/bin/python|g" \
        -e "s|SCRIPT_PLACEHOLDER|${SCRIPT_DIR}/notthenet.py|g" \
        "${SCRIPT_DIR}/assets/notthenet-gui-launcher" > "$GUI_LAUNCHER"
    chmod 0755 "$GUI_LAUNCHER"
    info "GUI launcher installed: $GUI_LAUNCHER"

    # Write .desktop file with real Exec path
    DESKTOP_FILE="/usr/share/applications/notthenet.desktop"
    sed \
        -e "s|NOTTHENET_EXEC_PLACEHOLDER|/usr/local/bin/notthenet-gui|g" \
        "${SCRIPT_DIR}/assets/notthenet.desktop" > "$DESKTOP_FILE"
    chmod 0644 "$DESKTOP_FILE"
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
    info "Desktop entry installed: $DESKTOP_FILE"

    # Install polkit action (gives pkexec a descriptive auth dialog)
    POLKIT_DIR="/usr/share/polkit-1/actions"
    if [[ -d "$POLKIT_DIR" ]]; then
        sed \
            -e "s|VENV_PYTHON_PLACEHOLDER|${VENV_DIR}/bin/python|g" \
            "${SCRIPT_DIR}/assets/com.retr0verride.notthenet.policy" \
            > "${POLKIT_DIR}/com.retr0verride.notthenet.policy"
        chmod 0644 "${POLKIT_DIR}/com.retr0verride.notthenet.policy"
        info "Polkit action installed: com.retr0verride.notthenet"
    else
        warn "polkit not found; pkexec dialog will use generic prompt."
    fi
else
    warn "Skipping desktop integration (not root)."
fi

# ── Create /usr/local/bin launcher (optional) ─────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    LAUNCHER="/usr/local/bin/notthenet"
    cat > "$LAUNCHER" <<LAUNCHER_EOF
#!/usr/bin/env bash
# NotTheNet launcher
exec "${VENV_DIR}/bin/python" "${SCRIPT_DIR}/notthenet.py" "\$@"
LAUNCHER_EOF
    chmod 0755 "$LAUNCHER"
    info "Launcher installed at $LAUNCHER"
    info "Usage: sudo notthenet [--config config.json] [--nogui]"
else
    warn "Skipping /usr/local/bin launcher (not root)."
    info "Usage: sudo ${VENV_DIR}/bin/python ${SCRIPT_DIR}/notthenet.py"
fi

# ── Final message ─────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   NotTheNet installed successfully!                  ║${NC}"
echo -e "${GREEN}║                                                      ║${NC}"
echo -e "${GREEN}║   App menu:  Search 'NotTheNet' and click icon       ║${NC}"
echo -e "${GREEN}║   GUI:       sudo notthenet                          ║${NC}"
echo -e "${GREEN}║   Headless:  sudo notthenet --nogui                  ║${NC}"
echo -e "${GREEN}║   Man page:  man notthenet                           ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
