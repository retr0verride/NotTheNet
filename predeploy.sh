#!/usr/bin/env bash
# predeploy.sh — run all checks before releasing NotTheNet
# Usage: bash predeploy.sh
set -euo pipefail

VENV_PYTHON="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
PYTHON="${VENV_PYTHON:-python3}"
PIP="${VENV_PYTHON:+$VIRTUAL_ENV/bin/pip}"
PIP="${PIP:-pip3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}  ✔ $1${NC}"; }
fail() { echo -e "${RED}  ✘ $1${NC}"; exit 1; }
step() { echo -e "\n${CYAN}── $1 ──${NC}"; }

# ── Install check tools if absent ────────────────────────────────────────────
step "Ensuring dev tools are installed"
$PIP install --quiet ruff mypy bandit pytest build 2>&1 | tail -1
pass "tools ready"

# ── Lint ─────────────────────────────────────────────────────────────────────
step "Lint (ruff)"
ruff check . && pass "ruff" || fail "ruff found issues"

# ── Type check ───────────────────────────────────────────────────────────────
step "Type check (mypy)"
mypy notthenet.py services/ network/ utils/ && pass "mypy" || fail "mypy found issues"

# ── Security scan ────────────────────────────────────────────────────────────
step "Security scan (bandit)"
bandit -c pyproject.toml -r notthenet.py services/ network/ utils/ && pass "bandit" || fail "bandit found issues"

# ── Tests ────────────────────────────────────────────────────────────────────
step "Tests (pytest)"
if [ -d tests ] && compgen -G "tests/test_*.py" > /dev/null 2>&1; then
    $PYTHON -m pytest tests/ -v && pass "pytest" || fail "tests failed"
else
    echo "  (no tests found — skipping)"
fi

# ── Build ────────────────────────────────────────────────────────────────────
step "Build package"
$PYTHON -m build --outdir dist/ && pass "build" || fail "build failed"

echo -e "\n${GREEN}All predeploy checks passed.${NC}"
