#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# update.sh — pull the latest NotTheNet release and reinstall
# Run from anywhere inside the repo:  sudo bash update.sh
# -----------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── 1. Stop NotTheNet if running ─────────────────────────────────────────────
if pgrep -f "notthenet" >/dev/null 2>&1; then
    echo "[*] Stopping running NotTheNet process..."
    pkill -f "notthenet" || true
    sleep 1
fi

# ── 2. Preserve user config.json across the pull ─────────────────────────────
CONFIG_BACKUP=""
if ! git diff --quiet config.json 2>/dev/null; then
    CONFIG_BACKUP="$(mktemp)"
    cp config.json "$CONFIG_BACKUP"
    echo "[*] Local config.json changes detected — backing up to $CONFIG_BACKUP"
    git checkout -- config.json
fi

# ── 3. Pull latest code ───────────────────────────────────────────────────────
echo "[*] Pulling latest changes from GitHub..."
git pull origin master

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

changed = False
for section, keys in defaults.items():
    if section not in user:
        continue  # don't inject sections the user never had
    if not isinstance(keys, dict) or not isinstance(user[section], dict):
        continue
    for key, val in keys.items():
        if key not in user[section]:
            user[section][key] = val
            changed = True

if changed:
    with open("config.json", "w") as f:
        json.dump(user, f, indent=2)
        f.write("\n")
    print("[*] Config migrated — new default keys added to config.json")
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

# ── 6. Show new version ───────────────────────────────────────────────────────
VERSION=$("$PYTHON" -c "import notthenet; print(notthenet.APP_VERSION)" 2>/dev/null || echo "unknown")
echo ""
echo "[✓] NotTheNet updated to version: $VERSION"
echo "    Start it with:  sudo notthenet"
