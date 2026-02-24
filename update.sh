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

# ── 2. Pull latest code ───────────────────────────────────────────────────────
echo "[*] Pulling latest changes from GitHub..."
git pull origin master

# ── 3. Reinstall package (picks up any dependency / entry-point changes) ─────
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

# ── 4. Show new version ───────────────────────────────────────────────────────
VERSION=$("$PYTHON" -c "import notthenet; print(notthenet.APP_VERSION)" 2>/dev/null || echo "unknown")
echo ""
echo "[✓] NotTheNet updated to version: $VERSION"
echo "    Start it with:  sudo notthenet"
