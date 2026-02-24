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

# ── 5. Show new version ───────────────────────────────────────────────────────
VERSION=$("$PYTHON" -c "import notthenet; print(notthenet.APP_VERSION)" 2>/dev/null || echo "unknown")
echo ""
echo "[✓] NotTheNet updated to version: $VERSION"
echo "    Start it with:  sudo notthenet"
