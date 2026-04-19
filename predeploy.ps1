# predeploy.ps1 -- run all checks before releasing NotTheNet (Windows dev)
# Matches CI pipeline + GH badge checks: lint → type → security → SCA → tests → version
# Usage:  .\predeploy.ps1
$ErrorActionPreference = "Stop"

$Python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
$Pip    = if (Test-Path ".\.venv\Scripts\pip.exe")    { ".\.venv\Scripts\pip.exe"    } else { "pip"    }

function Step($msg) { Write-Host "`n-- $msg --" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red; exit 1 }

# Install check tools if absent
Step "Ensuring dev tools are installed"
& $Pip install --quiet ruff mypy bandit pytest pip-audit 2>&1 | Select-Object -Last 1
Pass "tools ready"

# ── 1. Lint (ruff) — matches CI + CodeQL badge ──────────────────────────────
Step "1/7  Lint (ruff)"
& $Python -m ruff check .
if ($LASTEXITCODE -ne 0) { Fail "ruff found issues" } else { Pass "ruff" }

# ── 2. Type check (mypy) — matches CI badge ─────────────────────────────────
Step "2/7  Type check (mypy)"
& $Python -m mypy notthenet.py services/ network/ utils/
if ($LASTEXITCODE -ne 0) { Fail "mypy found issues" } else { Pass "mypy" }

# ── 3. Security scan (bandit) — matches CI badge ────────────────────────────
Step "3/7  Security scan (bandit)"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$banditOut = & $Python -m bandit -c pyproject.toml -r notthenet.py services/ network/ utils/ 2>&1
$banditExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
$banditOut | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Write-Host
if ($banditExit -ne 0) { Fail "bandit found issues" } else { Pass "bandit" }

# ── 4. SCA — dependency vulnerabilities (matches SCA / Snyk badges) ─────────
Step "4/7  SCA (pip-audit)"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
# Audit the active venv directly -- requirements.txt hashes are Linux-only
# (deployment target is Kali), so re-installing on Windows fails hash checks.
& $Python -m pip_audit --skip-editable 2>&1 | Write-Host
$auditExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
if ($auditExit -ne 0) { Fail "pip-audit found vulnerabilities" } else { Pass "pip-audit" }

# ── 5. Tests (pytest) — matches CI badge ────────────────────────────────────
Step "5/7  Tests (pytest)"
if ((Test-Path "tests") -and (Get-ChildItem "tests\test_*.py" -ErrorAction SilentlyContinue)) {
    & $Python -m pytest tests/ -v
    if ($LASTEXITCODE -ne 0) { Fail "tests failed" } else { Pass "pytest" }
} else {
    Write-Host "  (no tests found -- skipping)"
}

# ── 6. Version consistency ──────────────────────────────────────────────────
Step "6/7  Version consistency"
$widgetVer = (Select-String -Path "gui\widgets.py" -Pattern 'APP_VERSION\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
$tomlVer   = (Select-String -Path "pyproject.toml" -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
if ($widgetVer -ne $tomlVer) {
    Fail "Version mismatch: gui/widgets.py=$widgetVer vs pyproject.toml=$tomlVer"
}
# notthenet.py should import, not define
$ntpyLine = Select-String -Path "notthenet.py" -Pattern '^APP_VERSION\s*=' -SimpleMatch
if ($ntpyLine) {
    Fail "notthenet.py still has a local APP_VERSION assignment (should import from gui.widgets)"
}
Pass "all files at v$widgetVer"

# ── 7. CHANGELOG mentions current version ───────────────────────────────────
Step "7/7  CHANGELOG check"
if (Test-Path "CHANGELOG.md") {
    $clMatch = Select-String -Path "CHANGELOG.md" -Pattern ([regex]::Escape($widgetVer))
    if (-not $clMatch) {
        Write-Host "  WARN: v$widgetVer not found in CHANGELOG.md" -ForegroundColor Yellow
    } else {
        Pass "v$widgetVer in CHANGELOG.md"
    }
} else {
    Write-Host "  (no CHANGELOG.md -- skipping)"
}

Write-Host "`nAll predeploy checks passed." -ForegroundColor Green
