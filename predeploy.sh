#!/usr/bin/env bash
# predeploy.sh — run all checks before releasing NotTheNet (Linux/macOS dev)
# Matches CI pipeline exactly: lint → type → security → SCA → openapi → tests → version
# Usage: bash predeploy.sh
set -euo pipefail

VENV_PYTHON="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
PYTHON="${VENV_PYTHON:-python3}"
PIP="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/pip}"
PIP="${PIP:-pip3}"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}  ✔ $1${NC}"; }
fail() { echo -e "${RED}  ✘ $1${NC}"; exit 1; }
step() { echo -e "\n${CYAN}── $1 ──${NC}"; }
warn() { echo -e "${YELLOW}  ⚠ $1${NC}"; }

# ── Install check tools — pinned to match CI ─────────────────────────────────
step "Ensuring dev tools are installed (pinned versions)"
$PIP install --quiet \
    "ruff==0.15.2" \
    "bandit[toml]==1.9.4" \
    "bandit-sarif-formatter==1.1.1" \
    "pip-audit==2.10.0" \
    "mypy==1.19.1" \
    "pydantic==2.13.2" \
    "pydantic-settings==2.13.1" \
    "openapi-spec-validator==0.8.4" \
    "pytest==9.0.3" \
    "pytest-cov==7.1.0" \
    "pytest-timeout==2.4.0"
pass "tools ready"

# ── 1. Lint (ruff) ───────────────────────────────────────────────────────────
step "1/9  Lint (ruff)"
$PYTHON -m ruff check . && pass "ruff" || fail "ruff found issues"

# ── 2a. Type check — legacy (informational, non-blocking) ────────────────────
step "2a/9  Type check — legacy (mypy, informational)"
$PYTHON -m mypy notthenet.py services/ network/ utils/ || true
echo "  (informational — legacy code lacks strict annotations)"

# ── 2b. Type check — new layers (strict, blocking) ───────────────────────────
step "2b/9  Type check — new layers (mypy --strict)"
$PYTHON -m mypy domain/ application/ infrastructure/ \
    --strict \
    --ignore-missing-imports \
    --explicit-package-bases \
    && pass "mypy strict" || fail "mypy strict check failed on domain/application/infrastructure"

# ── 3. Security scan (bandit — HIGH severity, matches CI) ────────────────────
step "3/9  Security scan (bandit)"
bandit -r . \
    --exclude .venv,tests,tools \
    --severity-level high \
    && pass "bandit" || fail "bandit found HIGH severity issues"

# ── 4. SCA — dependency vulnerabilities ──────────────────────────────────────
step "4/9  SCA (pip-audit)"
sed '/--hash=sha256:/d' requirements.txt | sed 's/ \\$//' > /tmp/req_predeploy.txt
$PYTHON -m pip_audit --requirement /tmp/req_predeploy.txt --strict \
    && pass "pip-audit" || fail "pip-audit found vulnerabilities"

# ── 5. OpenAPI spec validation ────────────────────────────────────────────────
step "5/9  OpenAPI spec validation"
$PYTHON -m openapi_spec_validator openapi.yaml \
    && pass "openapi-spec-validator" || fail "openapi.yaml is invalid"

# ── 6. Tests (pytest — with coverage gate and timeout) ───────────────────────
step "6/9  Tests (pytest)"
if [ -d tests ] && compgen -G "tests/test_*.py" > /dev/null 2>&1; then
    $PYTHON -m pytest tests/ -v \
        --timeout=60 \
        --cov \
        --cov-fail-under=35 \
        && pass "pytest" || fail "tests failed"
else
    echo "  (no tests found — skipping)"
fi

# ── 7. Version consistency ────────────────────────────────────────────────────
step "7/9  Version consistency"
widget_ver=$(grep -oP 'APP_VERSION\s*=\s*"\K[^"]+' gui/widgets.py | head -1)
toml_ver=$(grep -oP '^version\s*=\s*"\K[^"]+' pyproject.toml | head -1)
if [ "$widget_ver" != "$toml_ver" ]; then
    fail "Version mismatch: gui/widgets.py=$widget_ver vs pyproject.toml=$toml_ver"
fi
if grep -qP '^APP_VERSION\s*=' notthenet.py; then
    fail "notthenet.py still has a local APP_VERSION assignment (should import from gui.widgets)"
fi
pass "all files at v$widget_ver"

# ── 8. CHANGELOG mentions current version ────────────────────────────────────
step "8/9  CHANGELOG check"
if [ -f CHANGELOG.md ]; then
    if grep -qF "$widget_ver" CHANGELOG.md; then
        pass "v$widget_ver in CHANGELOG.md"
    else
        warn "v$widget_ver not found in CHANGELOG.md"
    fi
else
    echo "  (no CHANGELOG.md — skipping)"
fi

# ── 9. Stale temp-cert check ──────────────────────────────────────────────────
step "9/9  Stale temp-cert check"
stale=$(find certs/ -name "_dyn_*" 2>/dev/null | head -5)
if [ -n "$stale" ]; then
    warn "stale dynamic cert files found in certs/:"
    echo "$stale" | while read -r f; do warn "  $f"; done
else
    pass "no stale _dyn_* cert files"
fi

echo -e "\n${GREEN}All predeploy checks passed.${NC}"
