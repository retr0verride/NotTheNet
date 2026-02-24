#!/usr/bin/env bash
# ============================================================================
# NotTheNet — .deb package builder
#
# Run this on Kali / Debian to produce notthenet_<version>_all.deb
# Requires: dpkg-deb (part of dpkg, always present on Debian/Kali)
#
# Usage:
#   bash build-deb.sh
#   sudo dpkg -i notthenet_2026.02.24-1_all.deb
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2026.02.24-1"
PKG="notthenet"
ARCH="all"
DEB_NAME="${PKG}_${VERSION}_${ARCH}.deb"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

info "Staging directory: $STAGING"

# ── Directory structure ───────────────────────────────────────────────────────
install -dm755 "$STAGING/DEBIAN"
install -dm755 "$STAGING/opt/notthenet"
install -dm755 "$STAGING/usr/bin"
install -dm755 "$STAGING/usr/share/applications"
install -dm755 "$STAGING/usr/share/man/man1"
install -dm755 "$STAGING/usr/share/doc/${PKG}"
install -dm755 "$STAGING/usr/share/icons/hicolor/scalable/apps"

# ── Copy project files ────────────────────────────────────────────────────────
info "Copying project files to /opt/notthenet..."
rsync -a \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='*.egg-info' \
    --exclude='.vscode' \
    --exclude='build-deb.sh' \
    --exclude='*.deb' \
    --exclude='tests/' \
    "${SCRIPT_DIR}/" "$STAGING/opt/notthenet/"

# ── /usr/bin/notthenet CLI launcher ──────────────────────────────────────────
info "Creating /usr/bin/notthenet launcher..."
cat > "$STAGING/usr/bin/notthenet" << 'EOF'
#!/usr/bin/env bash
exec /opt/notthenet/venv/bin/python /opt/notthenet/notthenet.py "$@"
EOF
chmod 755 "$STAGING/usr/bin/notthenet"

# ── Man page ──────────────────────────────────────────────────────────────────
info "Installing man page..."
gzip -c "${SCRIPT_DIR}/man/notthenet.1" > "$STAGING/usr/share/man/man1/notthenet.1.gz"

# ── Desktop file ──────────────────────────────────────────────────────────────
info "Installing .desktop file..."
sed 's|NOTTHENET_EXEC_PLACEHOLDER|/usr/local/bin/notthenet-gui|g' \
    "${SCRIPT_DIR}/assets/notthenet.desktop" \
    > "$STAGING/usr/share/applications/notthenet.desktop"
chmod 644 "$STAGING/usr/share/applications/notthenet.desktop"

# ── Icon ──────────────────────────────────────────────────────────────────────
info "Installing icon..."
[[ -f "${SCRIPT_DIR}/assets/notthenet-icon.svg" ]] && \
    cp "${SCRIPT_DIR}/assets/notthenet-icon.svg" \
       "$STAGING/usr/share/icons/hicolor/scalable/apps/notthenet.svg"

# ── Doc ───────────────────────────────────────────────────────────────────────
gzip -c "${SCRIPT_DIR}/README.md" > "$STAGING/usr/share/doc/${PKG}/README.md.gz"

# ── DEBIAN/control ───────────────────────────────────────────────────────────
info "Writing DEBIAN/control..."
cat > "$STAGING/DEBIAN/control" << EOF
Package: ${PKG}
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: retr0verride <https://github.com/retr0verride>
Depends: python3 (>= 3.9), python3-venv, iptables, iproute2, openssl
Recommends: librsvg2-bin
Section: net
Priority: optional
Homepage: https://github.com/retr0verride/NotTheNet
Description: Fake Internet Simulator for malware analysis
 NotTheNet intercepts all outbound network traffic and responds with
 configurable fake services: DNS, HTTP/HTTPS, SMTP/POP3/IMAP, FTP,
 and a catch-all TCP/UDP listener.
 .
 Designed for Kali Linux malware analysis labs alongside FlareVM or
 similar analysis VMs. Replaces INetSim and FakeNet-NG with a
 Python-native, GUI-driven tool.
EOF

# ── DEBIAN/postinst ───────────────────────────────────────────────────────────
info "Writing DEBIAN/postinst..."
cat > "$STAGING/DEBIAN/postinst" << 'POSTINST'
#!/usr/bin/env bash
set -e
OPT=/opt/notthenet

# ── Python virtualenv + dependencies ─────────────────────────────────────────
echo "[*] Creating Python virtualenv..."
python3 -m venv "$OPT/venv"
"$OPT/venv/bin/pip" install --quiet --upgrade pip setuptools wheel
"$OPT/venv/bin/pip" install --quiet -r "$OPT/requirements.txt"
"$OPT/venv/bin/pip" install --quiet -e "$OPT" --no-deps

# ── TLS certificate ───────────────────────────────────────────────────────────
if [[ ! -f "$OPT/certs/server.crt" ]]; then
    echo "[*] Generating self-signed TLS certificate..."
    mkdir -p "$OPT/certs"
    chmod 750 "$OPT/certs"
    cd "$OPT"
    "$OPT/venv/bin/python" - << 'PYEOF'
import sys, os
sys.path.insert(0, '/opt/notthenet')
os.chdir('/opt/notthenet')
from utils.cert_utils import generate_self_signed_cert
generate_self_signed_cert(
    'certs/server.crt', 'certs/server.key',
    common_name='notthenet.local',
    san_dns=['localhost', 'notthenet.local', '*.notthenet.local'],
    san_ips=['127.0.0.1', '0.0.0.0'],
    key_bits=4096,
)
PYEOF
fi

# ── Log directories ───────────────────────────────────────────────────────────
mkdir -p "$OPT/logs/emails" "$OPT/logs/ftp_uploads"
chmod 700 "$OPT/logs"

# ── GUI launcher (/usr/local/bin/notthenet-gui) ───────────────────────────────
cat > /usr/local/bin/notthenet-gui << 'EOF'
#!/usr/bin/env bash
# NotTheNet GUI launcher (via pkexec for root privileges)
exec pkexec /opt/notthenet/venv/bin/python /opt/notthenet/notthenet.py "$@"
EOF
chmod 755 /usr/local/bin/notthenet-gui

# ── Polkit action ─────────────────────────────────────────────────────────────
if [[ -d /usr/share/polkit-1/actions ]]; then
    sed "s|VENV_PYTHON_PLACEHOLDER|/opt/notthenet/venv/bin/python|g" \
        "$OPT/assets/com.retr0verride.notthenet.policy" \
        > /usr/share/polkit-1/actions/com.retr0verride.notthenet.policy
    chmod 644 /usr/share/polkit-1/actions/com.retr0verride.notthenet.policy
fi

# ── Desktop icon (PNG rendered from SVG) ─────────────────────────────────────
if command -v rsvg-convert &>/dev/null && [[ -f "$OPT/assets/notthenet-icon.svg" ]]; then
    mkdir -p /usr/share/icons/hicolor/128x128/apps
    rsvg-convert -w 128 -h 128 "$OPT/assets/notthenet-icon.svg" \
        -o /usr/share/icons/hicolor/128x128/apps/notthenet.png 2>/dev/null || true
fi
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database -q /usr/share/applications 2>/dev/null || true
mandb -q 2>/dev/null || true
# Restart XFCE panel to reload icon cache and avoid gear-icon fallback
pgrep -x xfce4-panel >/dev/null && DISPLAY="${DISPLAY:-:0}" xfce4-panel --restart 2>/dev/null || true

# ── Uninstall launcher (/usr/bin/notthenet-uninstall) ────────────────────────
cat > /usr/bin/notthenet-uninstall << 'EOF'
#!/usr/bin/env bash
# NotTheNet uninstaller (deb install)
exec bash /opt/notthenet/notthenet-uninstall.sh "$@"
EOF
chmod 755 /usr/bin/notthenet-uninstall

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   NotTheNet installed successfully!                  ║"
echo "║                                                      ║"
echo "║   App menu:  Search 'NotTheNet' and click icon       ║"
echo "║   GUI:       sudo notthenet                          ║"
echo "║   Headless:  sudo notthenet --nogui                  ║"
echo "║   Man page:  man notthenet                           ║"
echo "║   Uninstall: sudo notthenet-uninstall                ║"
echo "╚══════════════════════════════════════════════════════╝"
POSTINST
chmod 755 "$STAGING/DEBIAN/postinst"

# ── DEBIAN/prerm ──────────────────────────────────────────────────────────────
cat > "$STAGING/DEBIAN/prerm" << 'PRERM'
#!/usr/bin/env bash
set -e
rm -f /usr/local/bin/notthenet-gui
rm -f /usr/bin/notthenet-uninstall
rm -f /usr/share/polkit-1/actions/com.retr0verride.notthenet.policy
rm -f /usr/share/man/man1/notthenet.1.gz
rm -f /usr/share/icons/hicolor/128x128/apps/notthenet.png
rm -f /usr/share/icons/hicolor/scalable/apps/notthenet.svg
rm -f /usr/share/applications/notthenet.desktop
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database -q /usr/share/applications 2>/dev/null || true
PRERM
chmod 755 "$STAGING/DEBIAN/prerm"

# ── DEBIAN/postrm ─────────────────────────────────────────────────────────────
cat > "$STAGING/DEBIAN/postrm" << 'POSTRM'
#!/usr/bin/env bash
set -e
# On purge, remove the installation directory completely
if [[ "$1" == "purge" ]]; then
    rm -rf /opt/notthenet
fi
POSTRM
chmod 755 "$STAGING/DEBIAN/postrm"

# ── Build ─────────────────────────────────────────────────────────────────────
info "Building ${DEB_NAME}..."
dpkg-deb --build --root-owner-group "$STAGING" "${SCRIPT_DIR}/${DEB_NAME}"

echo ""
echo -e "${GREEN}Built: ${DEB_NAME}${NC}"
echo ""
echo "Install:    sudo dpkg -i ${DEB_NAME}"
echo "Remove:     sudo apt remove notthenet"
echo "Purge:      sudo apt purge notthenet  (removes /opt/notthenet)"
