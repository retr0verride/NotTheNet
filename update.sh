#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# update.sh — pull the latest NotTheNet release and reinstall
# Run from anywhere inside the repo:  sudo bash update.sh
# -----------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── .deb install path: rebuild + reinstall + verify version ──────────────────
# update.sh is normally for dev/script installs (in-repo venv). When NotTheNet
# is installed via .deb, run the build-deb / dpkg -i flow instead and verify
# that the package version actually bumped (catches silent build failures).
if dpkg -l notthenet 2>/dev/null | grep -q '^ii'; then
    if [ "$EUID" -ne 0 ]; then
        echo "[!] .deb install detected — re-run with sudo:  sudo bash update.sh"
        exit 1
    fi
    echo "[*] .deb install detected — pulling latest source..."
    # Use `sudo -u` to git pull as the invoking user (avoids root-owning files in repo).
    SUDO_INVOKER="${SUDO_USER:-$(whoami)}"
    sudo -u "$SUDO_INVOKER" git pull origin main

    EXPECTED_VERSION=$(grep -oP 'APP_VERSION\s*=\s*"\K[^"]+' "${SCRIPT_DIR}/gui/widgets.py" 2>/dev/null) || {
        echo "[!] Could not extract APP_VERSION from gui/widgets.py — aborting."
        exit 1
    }
    INSTALLED_VERSION=$(dpkg-query -W -f='${Version}' notthenet 2>/dev/null || true)
    if [ "$EXPECTED_VERSION" = "$INSTALLED_VERSION" ]; then
        echo "[*] Already at $EXPECTED_VERSION — nothing to do."
        exit 0
    fi
    echo "[*] Building .deb (source=$EXPECTED_VERSION, installed=${INSTALLED_VERSION:-none})..."
    sudo -u "$SUDO_INVOKER" bash "${SCRIPT_DIR}/build-deb.sh"

    DEB_FILE="${SCRIPT_DIR}/dist/notthenet_${EXPECTED_VERSION}_all.deb"
    if [ ! -f "$DEB_FILE" ]; then
        echo "[!] Build did not produce expected deb at: $DEB_FILE"
        echo "    dist/ contents:"
        ls -la "${SCRIPT_DIR}/dist/" 2>/dev/null | sed 's/^/      /' || true
        exit 1
    fi

    # Back up user's live config before dpkg -i overwrites it. The deb ships
    # config.json inside /opt/notthenet/ without conffile protection, so a
    # plain reinstall would wipe operator customizations (bind_ip, ports,
    # passthrough_subnets, etc.). We restore + merge new default keys after.
    LIVE_CFG="/opt/notthenet/config.json"
    DEB_CFG_BACKUP=""
    if [ -f "$LIVE_CFG" ]; then
        DEB_CFG_BACKUP="$(mktemp)"
        cp "$LIVE_CFG" "$DEB_CFG_BACKUP"
        chmod 600 "$DEB_CFG_BACKUP"
        echo "[*] Backed up live config.json to $DEB_CFG_BACKUP (will restore + merge new defaults after install)"
    fi
    cleanup_deb_cfg_backup() {
        if [ -n "${DEB_CFG_BACKUP:-}" ] && [ -f "$DEB_CFG_BACKUP" ]; then
            rm -f "$DEB_CFG_BACKUP"
        fi
    }
    trap cleanup_deb_cfg_backup EXIT

    echo "[*] Installing $DEB_FILE..."
    dpkg -i "$DEB_FILE"

    NEW_INSTALLED=$(dpkg-query -W -f='${Version}' notthenet 2>/dev/null || true)
    if [ "$NEW_INSTALLED" != "$EXPECTED_VERSION" ]; then
        echo "[!] Version verification FAILED."
        echo "      Expected (source):  $EXPECTED_VERSION"
        echo "      Installed (dpkg):   ${NEW_INSTALLED:-none}"
        exit 1
    fi

    # Restore user config and merge any new default keys from the shipped
    # config.json. New keys get default values; existing user values are
    # never overwritten. Mirror of the dev-install merge (section 3b below).
    if [ -n "$DEB_CFG_BACKUP" ] && [ -f "$DEB_CFG_BACKUP" ]; then
        SHIPPED_CFG="$(cat "$LIVE_CFG" 2>/dev/null || true)"
        cp "$DEB_CFG_BACKUP" "$LIVE_CFG"
        chmod 644 "$LIVE_CFG"
        rm -f "$DEB_CFG_BACKUP"
        DEB_CFG_BACKUP=""
        if [ -n "$SHIPPED_CFG" ]; then
            python3 - "$SHIPPED_CFG" "$LIVE_CFG" << 'PYEOF'
import json, sys

defaults = json.loads(sys.argv[1])
cfg_path = sys.argv[2]
with open(cfg_path) as f:
    user = json.load(f)

added: list[str] = []
for section, keys in defaults.items():
    if section not in user:
        # New top-level section in the release: add it whole.
        user[section] = keys
        added.append(section)
        continue
    if not isinstance(keys, dict) or not isinstance(user[section], dict):
        continue
    for key, val in keys.items():
        if key not in user[section]:
            user[section][key] = val
            added.append(f"{section}.{key}")

if added:
    with open(cfg_path, "w") as f:
        json.dump(user, f, indent=2)
        f.write("\n")
    print(f"[*] Config migrated — added {len(added)} new key(s): {', '.join(added)}")
else:
    print("[*] Config restored — no new default keys to add")
PYEOF
        fi
        echo "[*] User config restored to $LIVE_CFG"
    fi

    echo "[*] Update complete — installed version $NEW_INSTALLED matches source."
    exit 0
fi

SKIP_HARDEN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-harden) SKIP_HARDEN=1; shift ;;
        *) break ;;
    esac
done

# ── 1. Stop NotTheNet if running ─────────────────────────────────────────────
if pgrep -f "notthenet" >/dev/null 2>&1; then
    echo "[*] Stopping running NotTheNet process..."
    pkill -f "notthenet" || true
    sleep 1
fi

# ── 2. Preserve user config.json across the pull ─────────────────────────────
CONFIG_BACKUP=""
# Cleanup trap: remove temp backup on any exit path so a failed pull never
# leaves credentials sitting in /tmp. Restore is handled explicitly below.
cleanup_config_backup() {
    if [ -n "${CONFIG_BACKUP:-}" ] && [ -f "$CONFIG_BACKUP" ]; then
        rm -f "$CONFIG_BACKUP"
    fi
}
trap cleanup_config_backup EXIT
if ! git diff --quiet config.json 2>/dev/null; then
    CONFIG_BACKUP="$(mktemp)"
    cp config.json "$CONFIG_BACKUP"
    echo "[*] Local config.json changes detected — backing up to $CONFIG_BACKUP"
    git checkout -- config.json
fi

# ── 3. Pull latest code ───────────────────────────────────────────────────────
# Discard local changes to any tracked files other than config.json so the
# pull can complete cleanly (config.json was already handled above).
OTHER_DIRTY=$(git diff --name-only 2>/dev/null | grep -v '^config\.json$' || true)
if [ -n "$OTHER_DIRTY" ]; then
    echo "[!] Discarding local changes to the following tracked files:"
    echo "$OTHER_DIRTY" | sed 's/^/    /'
    # xargs-safe: use git checkout -- with quoted names
    echo "$OTHER_DIRTY" | xargs git checkout --
fi

echo "[*] Pulling latest changes from GitHub..."
git pull origin main

# Restore user config if it was backed up
if [ -n "$CONFIG_BACKUP" ]; then
    cp "$CONFIG_BACKUP" config.json
    rm -f "$CONFIG_BACKUP"
    echo "[*] Restored your local config.json"
fi

# ── 3b. Merge new default config keys into user config ───────────────────────
# If a new release adds config keys, they won't be in the user's restored file.
# This deep-merges the repo defaults into the user config: new keys are added
# with their default values, existing user values are never overwritten.
DEFAULT_CFG="$(git show HEAD:config.json 2>/dev/null || true)"
if [ -n "$DEFAULT_CFG" ] && [ -f config.json ]; then
    python3 - "$DEFAULT_CFG" << 'PYEOF'
import json, sys

defaults = json.loads(sys.argv[1])
with open("config.json") as f:
    user = json.load(f)

added: list[str] = []
for section, keys in defaults.items():
    if section not in user:
        # New top-level section: add it whole.
        user[section] = keys
        added.append(section)
        continue
    if not isinstance(keys, dict) or not isinstance(user[section], dict):
        continue
    for key, val in keys.items():
        if key not in user[section]:
            user[section][key] = val
            added.append(f"{section}.{key}")

if added:
    with open("config.json", "w") as f:
        json.dump(user, f, indent=2)
        f.write("\n")
    print(f"[*] Config migrated — added {len(added)} new key(s): {', '.join(added)}")
else:
    print("[*] Config up to date — no new keys to add")
PYEOF
fi

# ── 4. Reinstall package (picks up any dependency / entry-point changes) ─────
if [ -d "venv" ]; then
    PYTHON="venv/bin/python"
    PIP="venv/bin/pip"
elif [ -d ".venv" ]; then
    PYTHON=".venv/bin/python"
    PIP=".venv/bin/pip"
else
    echo "[!] No virtual environment found (expected venv/ or .venv/)."
    echo "    Re-run notthenet-install.sh to set up the environment."
    exit 1
fi

echo "[*] Reinstalling package..."
"$PIP" install -e . --quiet

# ── 5. Re-sync system-installed assets (icon, desktop, polkit) ───────────────
# These live in /usr/share/ and are never touched by pip, so they go stale
# after an update unless we explicitly re-copy them.
if [[ $EUID -eq 0 ]]; then
    ICON_SVG="${SCRIPT_DIR}/assets/notthenet-icon.svg"

    # Scalable SVG icon
    if [[ -f "$ICON_SVG" ]]; then
        install -Dm644 "$ICON_SVG" /usr/share/icons/hicolor/scalable/apps/notthenet.svg

        # Re-render 128 px PNG if rsvg-convert is available
        if command -v rsvg-convert &>/dev/null; then
            install -d /usr/share/icons/hicolor/128x128/apps
            rsvg-convert -w 128 -h 128 "$ICON_SVG" \
                -o /usr/share/icons/hicolor/128x128/apps/notthenet.png
        fi

        gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
        # Restart XFCE panel so it reloads the icon cache; prevents other panel
        # icons from showing as white gears after the cache is rebuilt.
        # Use kill+relaunch instead of --restart to avoid a DBus error dialog
        # when the session bus address is not available under runuser.
        _panel_user="${SUDO_USER:-${LOGNAME:-$(logname 2>/dev/null || true)}}"
        if pgrep -x xfce4-panel >/dev/null && [[ -n "$_panel_user" ]]; then
            _disp=$(runuser -u "$_panel_user" -- bash -c 'echo ${DISPLAY:-:0}' 2>/dev/null || echo ':0')
            runuser -u "$_panel_user" -- env DISPLAY="$_disp" pkill -x xfce4-panel 2>/dev/null || true
            sleep 0.3
            runuser -u "$_panel_user" -- env DISPLAY="$_disp" xfce4-panel 2>/dev/null &
        fi
        echo "[*] Icon updated"
    fi

    # .desktop file
    if [[ -f "${SCRIPT_DIR}/assets/notthenet.desktop" ]]; then
        install -Dm644 "${SCRIPT_DIR}/assets/notthenet.desktop" \
            /usr/share/applications/notthenet.desktop
        sed -i "s|NOTTHENET_EXEC_PLACEHOLDER|${SCRIPT_DIR}/assets/notthenet-gui-launcher|g" /usr/share/applications/notthenet.desktop
        update-desktop-database -q /usr/share/applications 2>/dev/null || true
        echo "[*] Desktop entry updated"
    fi

    # polkit action
    if [[ -f "${SCRIPT_DIR}/assets/com.retr0verride.notthenet.policy" ]]; then
        install -Dm644 "${SCRIPT_DIR}/assets/com.retr0verride.notthenet.policy" \
            /usr/share/polkit-1/actions/com.retr0verride.notthenet.policy
        echo "[*] Polkit action updated"
    fi
else
    echo "[!] Not running as root — skipping system asset update (icon/desktop/polkit)."
    echo "    Re-run with sudo to also update the desktop icon."
fi

# ── 6. Re-run lab hardening ────────────────────────────────────────────────────
if [[ $EUID -eq 0 ]] && [[ "$SKIP_HARDEN" -eq 0 ]]; then
    echo "[*] Re-applying lab hardening..."
    _harden_args=()
    if [[ -f "${SCRIPT_DIR}/config.json" ]] && command -v python3 &>/dev/null; then
        _bridge=$(python3 -c "import json,sys; c=json.load(open('${SCRIPT_DIR}/config.json')); print(c.get('general',{}).get('interface','vmbr1'))" 2>/dev/null || echo 'vmbr1')
        _gw=$(python3 -c "import json,sys; c=json.load(open('${SCRIPT_DIR}/config.json')); print(c.get('general',{}).get('redirect_ip','10.10.10.1'))" 2>/dev/null || echo '10.10.10.1')
        _harden_args+=("--bridge" "$_bridge" "--gateway-ip" "$_gw")
    fi
    bash "${SCRIPT_DIR}/harden-lab.sh" "${_harden_args[@]}" || echo "[!] Hardening step failed — run manually: sudo bash harden-lab.sh"
elif [[ "$SKIP_HARDEN" -eq 1 ]]; then
    echo "[!] Lab hardening skipped (--skip-harden). Run manually: sudo bash harden-lab.sh"
else
    echo "[!] Not root — skipping lab hardening. Run manually: sudo bash harden-lab.sh"
fi

# ── 7. Show new version ───────────────────────────────────────────────────────
VERSION=$("$PYTHON" -c "import notthenet; print(notthenet.APP_VERSION)" 2>/dev/null || echo "unknown")
echo ""
echo "[✓] NotTheNet updated to version: $VERSION"
echo "    Start it with:  sudo notthenet"
echo ""

# ── 8. Remind user to re-push prepare-victim.ps1 to the victim ───────────────
_VICTIM_IP=$(python3 -c "import json; c=json.load(open('${SCRIPT_DIR}/config.json')); print(c.get('victim',{}).get('ip',''))" 2>/dev/null || true)
_VICTIM_USER=$(python3 -c "import json; c=json.load(open('${SCRIPT_DIR}/config.json')); print(c.get('victim',{}).get('username',''))" 2>/dev/null || true)
_PREP_SCRIPT="${SCRIPT_DIR}/assets/prepare-victim.ps1"

if [[ -f "$_PREP_SCRIPT" ]]; then
    if [[ -n "$_VICTIM_IP" && -n "$_VICTIM_USER" ]]; then
        echo "[i] prepare-victim.ps1 was updated. Push it to the victim:"
        echo "    smbclient //${_VICTIM_IP}/C\$ -U ${_VICTIM_USER}%PASSWORD -c 'put \"${_PREP_SCRIPT}\" \"Users\\\\${_VICTIM_USER}\\\\Desktop\\\\prepare-victim.ps1\"'"
        echo "    Then run it on the victim as Administrator."
    else
        echo "[i] prepare-victim.ps1 was updated. Copy it to the victim and re-run as Administrator."
        echo "    (Set victim.ip and victim.username in config.json for a ready-to-paste command.)"
    fi
fi
