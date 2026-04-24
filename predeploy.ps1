# predeploy.ps1 -- run all checks before releasing NotTheNet (Windows dev)
# Matches CI pipeline exactly: secrets → lint → type → security → SCA → openapi → shellcheck → placeholders → tests → version
# Usage:  .\predeploy.ps1
$ErrorActionPreference = "Stop"

$Python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
$Pip    = if (Test-Path ".\.venv\Scripts\pip.exe")    { ".\.venv\Scripts\pip.exe"    } else { "pip"    }

function Step($msg) { Write-Host "`n-- $msg --" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red; exit 1 }

# Install check tools — pinned to match CI
Step "Ensuring dev tools are installed (pinned versions)"
& $Pip install --quiet `
    "ruff==0.15.2" `
    "bandit[toml]==1.9.4" `
    "bandit-sarif-formatter==1.1.1" `
    "pip-audit==2.10.0" `
    "mypy==1.19.1" `
    "pydantic==2.13.2" `
    "pydantic-settings==2.13.1" `
    "openapi-spec-validator==0.8.4" `
    "pytest==9.0.3" `
    "pytest-cov==7.1.0" `
    "pytest-timeout==2.4.0" 2>&1 | Select-Object -Last 1
Pass "tools ready"

# ── 0. Secret scan (gitleaks) ────────────────────────────────────────────────
Step "0/12  Secret scan (gitleaks)"
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    gitleaks detect --source . --no-banner 2>&1 | Write-Host
    $glExit = $LASTEXITCODE
    $ErrorActionPreference = $prevEAP
    if ($glExit -ne 0) { Fail "gitleaks found secrets" } else { Pass "gitleaks" }
} else {
    Write-Host "  WARN: gitleaks not found — skipping (install from https://github.com/gitleaks/gitleaks/releases)" -ForegroundColor Yellow
}

# ── 1. Lint (ruff) ───────────────────────────────────────────────────────────
Step "1/12  Lint (ruff)"
& $Python -m ruff check .
if ($LASTEXITCODE -ne 0) { Fail "ruff found issues" } else { Pass "ruff" }

# ── 2a. Type check — legacy (informational, non-blocking) ───────────────────
Step "2a/12  Type check — legacy (mypy, informational)"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $Python -m mypy notthenet.py services/ network/ utils/ 2>&1 | Write-Host
$ErrorActionPreference = $prevEAP
Write-Host "  (informational — legacy code lacks strict annotations)"

# ── 2b. Type check — new layers (strict, blocking) ──────────────────────────
Step "2b/12  Type check — new layers (mypy --strict)"
& $Python -m mypy domain/ application/ infrastructure/ `
    --strict --ignore-missing-imports --explicit-package-bases
if ($LASTEXITCODE -ne 0) { Fail "mypy strict check failed on domain/application/infrastructure" } else { Pass "mypy strict" }

# ── 3. Security scan (bandit — HIGH severity, matches CI) ───────────────────
Step "3/12  Security scan (bandit)"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$banditOut = & $Python -m bandit -r . `
    --severity-level high 2>&1
$banditExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
$banditOut | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Write-Host
if ($banditExit -ne 0) { Fail "bandit found HIGH severity issues" } else { Pass "bandit" }

# ── 4. SCA — dependency vulnerabilities ─────────────────────────────────────
Step "4/12  SCA (pip-audit)"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
# Match CI: audit requirements.txt directly (venv audit misses transitive CVEs)
& $Python -m pip_audit --requirement requirements.txt --strict 2>&1 | Write-Host
$auditExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
if ($auditExit -ne 0) { Fail "pip-audit found vulnerabilities" } else { Pass "pip-audit" }

# ── 5. OpenAPI spec validation ───────────────────────────────────────────────
Step "5/12  OpenAPI spec validation"
& $Python -m openapi_spec_validator openapi.yaml
if ($LASTEXITCODE -ne 0) { Fail "openapi.yaml is invalid" } else { Pass "openapi-spec-validator" }

# ── 6. Shellcheck (shell script linting, mirrors CI) ─────────────────────────
Step "6/12  Shellcheck"
if (Get-Command shellcheck -ErrorAction SilentlyContinue) {
    $shFiles = Get-ChildItem -Recurse -Filter "*.sh" |
        Where-Object { $_.FullName -notmatch '\\\.(git|venv)\\' -and $_.Name -ne "notthenet-bundle.sh" }
    $prevEAP = $ErrorActionPreference; $ErrorActionPreference = "Continue"; $scExit = 0
    foreach ($f in $shFiles) {
        shellcheck --severity=warning $f.FullName 2>&1 | Write-Host
        if ($LASTEXITCODE -ne 0) { $scExit = 1 }
    }
    $ErrorActionPreference = $prevEAP
    if ($scExit -ne 0) { Fail "shellcheck found warnings/errors" } else { Pass "shellcheck" }
} else {
    Write-Host "  WARN: shellcheck not found — skipping (install via 'choco install shellcheck' or run predeploy.sh on Linux)" -ForegroundColor Yellow
}

# ── 7. Placeholder consistency audit (mirrors CI) ────────────────────────────
Step "7/12  Placeholder consistency audit"
$placeholders = Select-String -Path "assets\\*" -Pattern '[A-Z][A-Z_]*_PLACEHOLDER' -AllMatches |
    ForEach-Object { $_.Matches.Value } | Sort-Object -Unique
if (-not $placeholders) {
    Write-Host "  (no placeholders found in assets/ — skipping)"
} else {
    $auditFailed = $false
    foreach ($p in $placeholders) {
        foreach ($s in @("build-deb.sh", "notthenet-install.sh")) {
            if (-not (Select-String -Path $s -Pattern ([regex]::Escape("s|$p|")) -Quiet)) {
                Write-Host "  MISSING: $p not substituted in $s" -ForegroundColor Red
                $auditFailed = $true
            }
        }
    }
    if ($auditFailed) { Fail "placeholder substitution audit failed" } else { Pass "placeholder audit" }
}

# ── 8. Tests (pytest — with coverage gate and timeout) ──────────────────────
Step "8/12  Tests (pytest)"
if ((Test-Path "tests") -and (Get-ChildItem "tests\test_*.py" -ErrorAction SilentlyContinue)) {
    # TestCatchAllUDPLifecycle::test_start_stop is deselected: it passes in
    # isolation but fails under full-suite execution on Windows due to a port
    # collision with an earlier test's lingering socket (WinError 10013).
    & $Python -m pytest tests/ -v --timeout=60 --cov --cov-fail-under=35 `
        --deselect tests/test_catch_all.py::TestCatchAllUDPLifecycle::test_start_stop
    if ($LASTEXITCODE -ne 0) { Fail "tests failed" } else { Pass "pytest" }
} else {
    Write-Host "  (no tests found -- skipping)"
}

# ── 9. Version consistency ────────────────────────────────────────────────
Step "9/12  Version consistency"
$widgetVer = (Select-String -Path "gui\widgets.py" -Pattern 'APP_VERSION\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
$tomlVer   = (Select-String -Path "pyproject.toml" -Pattern '^version\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
if ($widgetVer -ne $tomlVer) {
    Fail "Version mismatch: gui/widgets.py=$widgetVer vs pyproject.toml=$tomlVer"
}
$ntpyLine = Select-String -Path "notthenet.py" -Pattern '^APP_VERSION\s*=' -SimpleMatch
if ($ntpyLine) {
    Fail "notthenet.py still has a local APP_VERSION assignment (should import from gui.widgets)"
}
Pass "all files at v$widgetVer"

# ── 10. CHANGELOG mentions current version ───────────────────────────────────
Step "10/12  CHANGELOG check"
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

# ── 11. pyproject.toml Python version floor ──────────────────────────────────────
Step "11/12  pyproject.toml version floor"
$pyMinMatch = Select-String -Path "pyproject.toml" -Pattern 'requires-python\s*=\s*"([^"]+)"' -ErrorAction SilentlyContinue
$pyMin = if ($pyMinMatch) { $pyMinMatch.Matches[0].Groups[1].Value } else { "" }
if ($pyMin -and $pyMin -match "3\.9") {
    Fail "pyproject.toml still targets Python 3.9 (EOL); update requires-python"
} else {
    Pass "Python version floor OK ($pyMin)"
}

# ── 12. Verify no temp cert/key files were left behind ────────────────────────
Step "12/12  Stale temp-cert check"
$stale = Get-ChildItem -Path "certs" -Filter "_dyn_*" -ErrorAction SilentlyContinue
if ($stale) {
    Write-Host "  WARN: stale dynamic cert files found in certs/:" -ForegroundColor Yellow
    $stale | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
} else {
    Pass "no stale _dyn_* cert files"
}

Write-Host "`nAll predeploy checks passed." -ForegroundColor Green
