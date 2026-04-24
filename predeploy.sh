#!/usr/bin/env bash
# predeploy.sh — thin wrapper around scripts/checks.py
# All check logic lives in scripts/checks.py (single source of truth, shared with CI).
set -euo pipefail
PYTHON="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
PYTHON="${PYTHON:-python3}"
exec "$PYTHON" scripts/checks.py "$@"
