<#
.SYNOPSIS
    Generates a single self-contained install script for air-gapped Kali Linux.

.DESCRIPTION
    Downloads the required Linux Python wheels on this internet-connected
    Windows machine, then embeds them (base64) directly into a single bash
    script: notthenet-bundle.sh

    Workflow:
      1. Run this script on Windows:  .\make-bundle.ps1
      2. Copy the NotTheNet folder to your USB drive.
      3. On air-gapped Kali:  sudo bash /media/usb/NotTheNet/notthenet-bundle.sh

.PARAMETER Output
    Path for the generated bundle script. Default: .\notthenet-bundle.sh

.EXAMPLE
    .\make-bundle.ps1
    .\make-bundle.ps1 -Output D:\usb\NotTheNet\notthenet-bundle.sh
#>

[CmdletBinding()]
param(
    [string]$Output = ".\notthenet-bundle.sh",
    [switch]$Zip,
    [string]$ZipOutput = ""
)

$ErrorActionPreference = "Stop"
$GREEN  = "`e[32m"; $YELLOW = "`e[33m"; $RED = "`e[31m"; $NC = "`e[0m"
function info  { param($m) Write-Host "${GREEN}[*]${NC} $m" }
function warn  { param($m) Write-Host "${YELLOW}[!]${NC} $m" }
function fatal { param($m) Write-Host "${RED}[!]${NC} $m"; exit 1 }

if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    fatal "pip not found. Make sure Python is installed and in PATH."
}

# ── Download wheels into a temporary directory ────────────────────────────────
$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("notthenet_bundle_" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpDir | Out-Null

try {
    # dnslib — pure Python, platform-independent
    info "Downloading dnslib==0.9.26..."
    pip download dnslib==0.9.26 --dest $tmpDir --quiet
    if ($LASTEXITCODE -ne 0) { fatal "Failed to download dnslib." }

    # cryptography — binary wheel; try Python 3.13 first (Kali 2025+), then 3.12, 3.11
    $cryptoOk = $false
    $targets = @(
        @{ pyver = "313"; abi = "cp313"; plat = "manylinux_2_28_x86_64" },
        @{ pyver = "313"; abi = "cp313"; plat = "manylinux_2_17_x86_64" },
        @{ pyver = "312"; abi = "cp312"; plat = "manylinux_2_28_x86_64" },
        @{ pyver = "312"; abi = "cp312"; plat = "manylinux_2_17_x86_64" },
        @{ pyver = "311"; abi = "cp311"; plat = "manylinux_2_28_x86_64" },
        @{ pyver = "311"; abi = "cp311"; plat = "manylinux_2_17_x86_64" }
    )
    foreach ($t in $targets) {
        info "Downloading cryptography>=46.0.6 (cp$($t.pyver) / $($t.plat))..."
        pip download "cryptography>=46.0.6" `
            --platform $t.plat `
            --python-version $t.pyver `
            --implementation cp `
            --abi $t.abi `
            --only-binary :all: `
            --no-deps `
            --dest $tmpDir `
            --quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $cryptoOk = $true; break }
        warn "  Not available for that target, trying next..."
    }
    if (-not $cryptoOk) { fatal "Could not download a cryptography wheel for Linux x86_64." }

    # cffi — required by cryptography's pip metadata (declared dependency).
    # On Python 3.13, only cffi 2.0.0b1 ships binary wheels; cffi 1.x has none.
    # We download whatever is available and use --pre during offline install.
    $cffiOk = $false
    foreach ($t in $targets) {
        pip download "cffi>=1.14" `
            --platform $t.plat `
            --python-version $t.pyver `
            --implementation cp `
            --abi $t.abi `
            --only-binary :all: `
            --dest $tmpDir `
            --quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $cffiOk = $true; break }
    }
    if (-not $cffiOk) { fatal "Could not download a cffi wheel for Linux x86_64." }

    # setproctitle — binary wheel; needed for process masquerade feature
    $sptOk = $false
    foreach ($t in $targets) {
        info "Downloading setproctitle (cp$($t.pyver) / $($t.plat))..."
        pip download "setproctitle>=1.3" `
            --platform $t.plat `
            --python-version $t.pyver `
            --implementation cp `
            --abi $t.abi `
            --only-binary :all: `
            --no-deps `
            --dest $tmpDir `
            --quiet 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $sptOk = $true; break }
        warn "  Not available for that target, trying next..."
    }
    if (-not $sptOk) { warn "Could not download setproctitle -- process masquerade will be unavailable." }

    $wheels = @(Get-ChildItem -Path $tmpDir -Filter "*.whl")
    if ($wheels.Count -eq 0) { fatal "No wheels found after download." }
    info "Bundling $($wheels.Count) wheel(s):"
    $wheels | ForEach-Object { info "  $($_.Name)  ($([math]::Round($_.Length/1KB, 0)) KB)" }

    # ── Build the bundle shell script ─────────────────────────────────────────
    # All lines collected here; written at the end with LF-only endings.
    $out = [System.Collections.Generic.List[string]]::new()

    $out.Add(@'
#!/usr/bin/env bash
# ============================================================================
# NotTheNet — Self-Contained Offline Bundle
# Generated by make-bundle.ps1 — do not edit manually.
#
# This script contains the Python wheels it needs embedded as base64.
# Just copy the NotTheNet folder to a USB and on Kali run:
#   sudo bash notthenet-bundle.sh
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[!]${NC} $*" >&2; exit 1; }

# ── Privilege check ───────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    warn "Not running as root. Some install steps will be skipped."
    warn "Re-run with: sudo bash notthenet-bundle.sh"
fi

# ── FAT32 / noexec mount guard ────────────────────────────────────────────────
# Python venv requires symlink support (lib64 -> lib). FAT32 and some USB
# mount options (noexec, nosymlinks) will fail with "Operation not permitted".
# Detect this and tell the user to copy to their local disk first.
FSTYPE=$(stat -f -c "%T" "$SCRIPT_DIR" 2>/dev/null || echo "unknown")
if [[ "$FSTYPE" == "msdos" || "$FSTYPE" == "vfat" ]]; then
    error "You are running this script directly from a FAT32 USB drive.
       Python virtualenv requires symlink support, which FAT32 does not have.

       Copy the NotTheNet folder to your local disk first, then run:
         cp -r \"$SCRIPT_DIR\" ~/NotTheNet
         cd ~/NotTheNet
         sudo bash notthenet-bundle.sh"
fi
# Also test symlink creation directly as a fallback check
if ! ln -s /dev/null "$SCRIPT_DIR/.symlink_test" 2>/dev/null; then
    error "Cannot create symlinks in $SCRIPT_DIR (likely FAT32 or noexec mount).
       Copy the folder to your local disk first:
         cp -r \"$SCRIPT_DIR\" ~/NotTheNet
         cd ~/NotTheNet
         sudo bash notthenet-bundle.sh"
fi
rm -f "$SCRIPT_DIR/.symlink_test"

# ── Find an existing NotTheNet install ────────────────────────────────────────
# Greps the /usr/local/bin/notthenet launcher for the install path, then falls
# back to searching common locations.
find_existing_install() {
    local launcher="/usr/local/bin/notthenet"
    if [[ -f "$launcher" ]]; then
        local install_dir
        install_dir=$(grep -oP '(?<=exec ").*(?=/venv/bin/python)' "$launcher" 2>/dev/null || true)
        if [[ -n "$install_dir" ]] && [[ -f "${install_dir}/notthenet.py" ]]; then
            echo "$install_dir"; return
        fi
    fi
    for candidate in ~/NotTheNet /opt/NotTheNet /root/NotTheNet; do
        if [[ -f "${candidate}/notthenet.py" ]]; then
            echo "$candidate"; return
        fi
    done
}

# ── Mode selection ────────────────────────────────────────────────────────────
MODE=""
SKIP_HARDEN=0
for arg in "$@"; do
    case "$arg" in
        --install)      MODE="install" ;;
        --update)       MODE="update"  ;;
        --skip-harden)  SKIP_HARDEN=1  ;;
        --help|-h)
            echo "Usage: sudo bash notthenet-bundle.sh [--install|--update] [--skip-harden]"
            echo "  --install      Fresh install to this directory (default)"
            echo "  --update       Update an existing NotTheNet installation"
            echo "  --skip-harden  Skip lab hardening step"
            exit 0 ;;
    esac
done

if [[ -z "$MODE" ]]; then
    DETECTED=$(find_existing_install)
    if [[ -n "$DETECTED" ]]; then
        echo ""
        echo -e "${YELLOW}Existing NotTheNet install found at: ${DETECTED}${NC}"
        echo ""
        echo "  1) Update existing install  (preserves config.json, certs, logs)"
        echo "  2) Fresh install to: $SCRIPT_DIR"
        echo "  q) Quit"
        echo ""
        read -rp "Choice [1]: " _choice
        _choice="${_choice:-1}"
        case "$_choice" in
            1) MODE="update" ;;
            2) MODE="install" ;;
            *) echo "Aborted."; exit 0 ;;
        esac
    else
        MODE="install"
    fi
fi

# ── Extract embedded wheels to a temp dir ────────────────────────────────────
TMPWHEELS=$(mktemp -d)
trap 'rm -rf "$TMPWHEELS"' EXIT
info "Extracting bundled packages..."
'@)

    # Embed each wheel as a base64 heredoc
    foreach ($wheel in $wheels) {
        $bytes = [System.IO.File]::ReadAllBytes($wheel.FullName)
        $b64full = [System.Convert]::ToBase64String($bytes)

        # Split into 76-char lines (standard base64 line length)
        $b64lines = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $b64full.Length; $i += 76) {
            $b64lines.Add($b64full.Substring($i, [Math]::Min(76, $b64full.Length - $i)))
        }

        $marker = "WHL_" + ($wheel.Name -replace '[^a-zA-Z0-9]', '_')
        $out.Add("# Wheel: $($wheel.Name)")
        $out.Add("base64 -d > `"`$TMPWHEELS/$($wheel.Name)`" <<'$marker'")
        foreach ($line in $b64lines) { $out.Add($line) }
        $out.Add($marker)
        $out.Add("")
    }

    # Rest of the install logic (uses $TMPWHEELS as the wheelhouse)
    $out.Add(@'
info "Packages extracted."

# ── Update mode: rsync source into existing install, merge config ─────────────
if [[ "$MODE" == "update" ]]; then
    INSTALL_DIR=$(find_existing_install)
    if [[ -z "$INSTALL_DIR" ]]; then
        warn "No existing install found — switching to fresh install."
        MODE="install"
    else
        info "Updating existing install at: $INSTALL_DIR"

        # Stop any running instance
        if pgrep -f "notthenet.py" >/dev/null 2>&1; then
            info "Stopping running NotTheNet..."
            pkill -f "notthenet.py" || true
            sleep 1
        fi

        # Copy new source files; preserve user data in place
        info "Copying updated source files..."
        rsync -a \
            --exclude='config.json' \
            --exclude='certs/' \
            --exclude='logs/' \
            --exclude='venv/' \
            --exclude='.venv/' \
            --exclude='__pycache__/' \
            --exclude='*.pyc' \
            --exclude='notthenet-bundle.sh' \
            "${SCRIPT_DIR}/" "${INSTALL_DIR}/"

        # Merge any new default config keys into the user's existing config.json
        if [[ -f "${INSTALL_DIR}/config.json" ]] && [[ -f "${SCRIPT_DIR}/config.json" ]]; then
            python3 - "${INSTALL_DIR}/config.json" "${SCRIPT_DIR}/config.json" <<'MERGEPY'
import json, sys
with open(sys.argv[2]) as f:
    defaults = json.load(f)
with open(sys.argv[1]) as f:
    user = json.load(f)
changed = False
for section, keys in defaults.items():
    if section not in user or not isinstance(keys, dict):
        continue
    if not isinstance(user[section], dict):
        continue
    for key, val in keys.items():
        if key not in user[section]:
            user[section][key] = val
            changed = True
if changed:
    with open(sys.argv[1], "w") as f:
        json.dump(user, f, indent=2)
        f.write("\n")
    print("[*] Config migrated — new keys added")
else:
    print("[*] Config already up to date")
MERGEPY
        fi

        # Remember staging dir so we can clean it up after install
        STAGING_DIR="$SCRIPT_DIR"

        # Redirect remaining steps (venv refresh, certs, launchers) to existing dir
        SCRIPT_DIR="$INSTALL_DIR"
        VENV_DIR="${INSTALL_DIR}/venv"
        info "Source files updated — refreshing venv and system integration..."
    fi
fi

# ── Python version check ──────────────────────────────────────────────────────
PYTHON=$(command -v python3 2>/dev/null || true)
[[ -z "$PYTHON" ]] && error "python3 not found. Install with: apt install python3"
PYVER=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYMAJ=$(echo "$PYVER" | cut -d. -f1)
PYMIN=$(echo "$PYVER" | cut -d. -f2)
if [[ $PYMAJ -lt 3 ]] || { [[ $PYMAJ -eq 3 ]] && [[ $PYMIN -lt 9 ]]; }; then
    error "Python 3.9+ required (found $PYVER)."
fi
info "Python $PYVER found at $PYTHON"

# ── System packages ───────────────────────────────────────────────────────────
info "Checking system packages..."
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

info "Upgrading pip/setuptools/wheel (offline)..."
"$PIP" install --quiet --upgrade --no-index --find-links "$TMPWHEELS" \
    pip setuptools wheel 2>/dev/null || true

# ── Install Python dependencies from embedded wheels ─────────────────────────
info "Installing Python dependencies (offline)..."
"$PIP" install \
    --pre \
    --no-index \
    --find-links "$TMPWHEELS" \
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
    common_name="www.example.com",
    san_dns=["www.example.com", "example.com"],
    san_ips=["127.0.0.1", "0.0.0.0"],
    key_bits=4096,
)
sys.exit(0 if ok else 1)
PYEOF
    info "Certificate generated."
else
    info "Existing certificate found; skipping."
fi

# ── Create log/upload directories ─────────────────────────────────────────────
for dir in "${SCRIPT_DIR}/logs" \
           "${SCRIPT_DIR}/logs/emails" \
           "${SCRIPT_DIR}/logs/ftp_uploads" \
           "${SCRIPT_DIR}/logs/tftp_uploads"; do
    mkdir -p "$dir"
    chmod 700 "$dir"
done

# ── Fix ownership of user-writable files ──────────────────────────────────────
# The installer runs as root, so config.json and logs end up owned by root.
# chown them back to the real user so the app can write them whether launched
# via sudo, pkexec, or as the plain user.
# Resolve the real user: prefer $SUDO_USER (set by sudo), then logname.
_REAL_USER="${SUDO_USER:-}"
if [[ -z "$_REAL_USER" ]]; then
    _REAL_USER=$(logname 2>/dev/null || true)
fi
if [[ -n "$_REAL_USER" ]] && id "$_REAL_USER" &>/dev/null; then
    chown -R "${_REAL_USER}:" "${SCRIPT_DIR}/logs" 2>/dev/null || true
    [[ -f "${SCRIPT_DIR}/config.json" ]] && \
        chown "${_REAL_USER}:" "${SCRIPT_DIR}/config.json" 2>/dev/null || true
fi

# ── Install man page ──────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]] && [[ -f "${SCRIPT_DIR}/man/notthenet.1" ]]; then
    MAN_DIR="/usr/local/share/man/man1"
    mkdir -p "$MAN_DIR"
    gzip -c "${SCRIPT_DIR}/man/notthenet.1" > "${MAN_DIR}/notthenet.1.gz"
    mandb -q 2>/dev/null || true
    info "Man page installed."
fi

# ── Install icon and desktop entry ────────────────────────────────────────────
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
        fi
        gtk-update-icon-cache -q /usr/share/icons/hicolor 2>/dev/null || true
    fi

    GUI_LAUNCHER="/usr/local/bin/notthenet-gui"
    sed \
        -e "s|VENV_PYTHON_PLACEHOLDER|${VENV_DIR}/bin/python|g" \
        -e "s|SCRIPT_PLACEHOLDER|${SCRIPT_DIR}/notthenet.py|g" \
        "${SCRIPT_DIR}/assets/notthenet-gui-launcher" | tr -d '\r' > "$GUI_LAUNCHER"
    chmod 0755 "$GUI_LAUNCHER"

    DESKTOP_FILE="/usr/share/applications/notthenet.desktop"
    sed \
        -e "s|NOTTHENET_EXEC_PLACEHOLDER|/usr/local/bin/notthenet-gui|g" \
        "${SCRIPT_DIR}/assets/notthenet.desktop" | tr -d '\r' > "$DESKTOP_FILE"
    chmod 0644 "$DESKTOP_FILE"
    update-desktop-database -q /usr/share/applications 2>/dev/null || true

    # Install app icon so Icon=notthenet resolves correctly
    install -Dm644 "${SCRIPT_DIR}/assets/notthenet-icon.svg" \
        /usr/share/pixmaps/notthenet.svg
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true

    POLKIT_DIR="/usr/share/polkit-1/actions"
    if [[ -d "$POLKIT_DIR" ]]; then
        sed \
            -e "s|VENV_PYTHON_PLACEHOLDER|${VENV_DIR}/bin/python|g" \
            -e "s|NOTTHENET_GUI_PLACEHOLDER|${GUI_LAUNCHER}|g" \
            "${SCRIPT_DIR}/assets/com.retr0verride.notthenet.policy" \
            | tr -d '\r' > "${POLKIT_DIR}/com.retr0verride.notthenet.policy"
        chmod 0644 "${POLKIT_DIR}/com.retr0verride.notthenet.policy"
    fi
    info "Desktop integration installed."
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

# ── Lab hardening ──────────────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]] && [[ "${SKIP_HARDEN:-0}" -eq 0 ]]; then
    info "Running lab hardening (use --skip-harden to skip)..."
    _harden_args=()
    _cfg="${INSTALL_DIR:-$SCRIPT_DIR}/config.json"
    if [[ -f "$_cfg" ]] && command -v python3 &>/dev/null; then
        _bridge=$(python3 -c "import json; c=json.load(open('$_cfg')); print(c.get('general',{}).get('interface','vmbr1'))" 2>/dev/null || echo 'vmbr1')
        _gw=$(python3 -c "import json; c=json.load(open('$_cfg')); print(c.get('general',{}).get('redirect_ip','10.10.10.1'))" 2>/dev/null || echo '10.10.10.1')
        _harden_args+=("--bridge" "$_bridge" "--gateway-ip" "$_gw")
    fi
    bash "${INSTALL_DIR:-$SCRIPT_DIR}/harden-lab.sh" "${_harden_args[@]}" || warn "Hardening step failed — run manually: sudo bash harden-lab.sh"
elif [[ "${SKIP_HARDEN:-0}" -eq 1 ]]; then
    warn "Lab hardening skipped (--skip-harden). Run manually: sudo bash harden-lab.sh"
else
    warn "Not root — skipping lab hardening. Run manually: sudo bash harden-lab.sh"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
_VER=$(grep -oP '(?<=APP_VERSION = ")[^"]+' "${INSTALL_DIR:-$SCRIPT_DIR}/notthenet.py" 2>/dev/null || echo "unknown")
echo ""
if [[ "$MODE" == "update" ]]; then
echo -e "${GREEN}+------------------------------------------------------+${NC}"
echo -e "${GREEN}|   NotTheNet updated successfully!                    |${NC}"
echo -e "${GREEN}|   Version: ${_VER}$(printf '%*s' $((38 - ${#_VER})) '')|${NC}"
echo -e "${GREEN}|                                                      |${NC}"
echo -e "${GREEN}|   GUI:       sudo notthenet                          |${NC}"
echo -e "${GREEN}|   Headless:  sudo notthenet --nogui                  |${NC}"
echo -e "${GREEN}+------------------------------------------------------+${NC}"
# Clean up the staging directory from the USB/zip
if [[ -n "${STAGING_DIR:-}" ]] && [[ "$STAGING_DIR" != "$INSTALL_DIR" ]] && [[ -d "$STAGING_DIR" ]]; then
    cd / 2>/dev/null
    rm -rf "$STAGING_DIR"
fi
else
echo -e "${GREEN}+------------------------------------------------------+${NC}"
echo -e "${GREEN}|   NotTheNet installed successfully (offline)!        |${NC}"
echo -e "${GREEN}|   Version: ${_VER}$(printf '%*s' $((38 - ${#_VER})) '')|${NC}"
echo -e "${GREEN}|                                                      |${NC}"
echo -e "${GREEN}|   GUI:       sudo notthenet                          |${NC}"
echo -e "${GREEN}|   Headless:  sudo notthenet --nogui                  |${NC}"
echo -e "${GREEN}|   Uninstall: sudo notthenet-uninstall                |${NC}"
echo -e "${GREEN}+------------------------------------------------------+${NC}"
fi

_PREP_DIR="${INSTALL_DIR:-$SCRIPT_DIR}/assets"
_GW_IP=$(python3 -c "import json; c=json.load(open('${INSTALL_DIR:-$SCRIPT_DIR}/config.json')); print(c.get('general',{}).get('bind_ip','10.10.10.1'))" 2>/dev/null || echo '10.10.10.1')
if [[ -f "${_PREP_DIR}/prepare-victim.ps1" ]]; then
echo ""
echo -e "${YELLOW}+------------------------------------------------------+${NC}"
echo -e "${YELLOW}|  VICTIM PREP - run once on FlareVM (Admin PowerShell)|${NC}"
echo -e "${YELLOW}+------------------------------------------------------+${NC}"
echo -e "${YELLOW}  On Kali:${NC}"
echo -e "${YELLOW}    cd ${_PREP_DIR}${NC}"
echo -e "${YELLOW}    python3 -m http.server 8080${NC}"
echo ""
echo -e "${YELLOW}  On FlareVM (Admin PowerShell):${NC}"
echo -e "${YELLOW}    curl.exe -o C:\\prepare-victim.ps1 http://${_GW_IP}:8080/prepare-victim.ps1${NC}"
echo -e "${YELLOW}    Set-ExecutionPolicy Bypass -Scope Process -Force${NC}"
echo -e "${YELLOW}    & C:\\prepare-victim.ps1${NC}"
echo ""
echo -e "${YELLOW}  Then take a baseline snapshot.${NC}"
echo -e "${YELLOW}+------------------------------------------------------+${NC}"
fi
'@)

    # ── Write output file with LF line endings (critical for bash on Linux) ──
    # Strip all \r so PowerShell here-strings don't introduce CRLF endings.
    $content = ($out -join "`n").Replace("`r", "")
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $outFull = [System.IO.Path]::GetFullPath($Output)
    [System.IO.File]::WriteAllText($outFull, $content, $utf8NoBom)

    $outResolved = $Output
    $sizeMB = [math]::Round((Get-Item $Output).Length / 1MB, 1)
    info ""
    info "Bundle created: $outResolved  ($sizeMB MB)"
    info ""
    Write-Host "${GREEN}Next steps:${NC}"
    Write-Host "  1. Copy the NotTheNet folder to your USB drive."
    Write-Host "  2. On Kali:  sudo bash /media/usb/NotTheNet/notthenet-bundle.sh"
    Write-Host ""
    Write-Host "  Or use -Zip to create a ready-to-copy zip in one step:"
    Write-Host "    .\make-bundle.ps1 -Zip"

    # ── Optional zip ─────────────────────────────────────────────────────────
    $projectRoot = (Resolve-Path ".").Path
    if ($Zip) {
        $zipPath     = if ($ZipOutput) { [System.IO.Path]::GetFullPath($ZipOutput) } else { (Resolve-Path "..").Path.TrimEnd('\') + "\NotTheNet-bundle.zip" }
        $excludeDirs = @('.venv','.mypy_cache','.pytest_cache','.ruff_cache',
                         '__pycache__','build','dist','notthenet.egg-info','.git')

        info "Creating zip: $zipPath"
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

        $files = Get-ChildItem -Path $projectRoot -Recurse -File | Where-Object {
            $rel = $_.FullName.Substring($projectRoot.Length)
            $skip = $false
            foreach ($ex in $excludeDirs) {
                if ($rel -match "[/\\]$([regex]::Escape($ex))([/\\]|$)") { $skip = $true; break }
            }
            -not $skip
        }

        # Use ZipFile API directly to preserve directory structure.
        # Compress-Archive loses subdirectory paths when piped individual FileInfo objects.
        Add-Type -Assembly System.IO.Compression
        Add-Type -Assembly System.IO.Compression.FileSystem
        $zipStream = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $topFolder = Split-Path $projectRoot -Leaf   # "NotTheNet"
            foreach ($file in $files) {
                $entryName = "$topFolder/" + $file.FullName.Substring($projectRoot.Length + 1).Replace('\', '/')
                [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zipStream, $file.FullName, $entryName,
                    [System.IO.Compression.CompressionLevel]::Optimal) | Out-Null
            }
        } finally {
            $zipStream.Dispose()
        }
        $zipMB = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)
        info "Zip created: $zipPath  ($zipMB MB)"
        Write-Host ""
        Write-Host "${GREEN}Copy $zipPath to your USB drive.${NC}"
    }

} finally {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
}
