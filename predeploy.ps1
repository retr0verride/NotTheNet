# predeploy.ps1 -- run all checks before releasing NotTheNet (Windows dev)
# Usage:  .\predeploy.ps1
$ErrorActionPreference = "Stop"

$Python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
$Pip    = if (Test-Path ".\.venv\Scripts\pip.exe")    { ".\.venv\Scripts\pip.exe"    } else { "pip"    }

function Step($msg) { Write-Host "`n-- $msg --" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "  PASS: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  FAIL: $msg" -ForegroundColor Red; exit 1 }

# Install check tools if absent
Step "Ensuring dev tools are installed"
& $Pip install --quiet ruff mypy bandit pytest build 2>&1 | Select-Object -Last 1
Pass "tools ready"

# Lint
Step "Lint (ruff)"
& $Python -m ruff check .
if ($LASTEXITCODE -ne 0) { Fail "ruff found issues" } else { Pass "ruff" }

# Type check
Step "Type check (mypy)"
& $Python -m mypy notthenet.py services/ network/ utils/
if ($LASTEXITCODE -ne 0) { Fail "mypy found issues" } else { Pass "mypy" }

# Security scan
Step "Security scan (bandit)"
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$banditOut = & $Python -m bandit -c pyproject.toml -r notthenet.py services/ network/ utils/ 2>&1
$banditExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
$banditOut | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Write-Host
if ($banditExit -ne 0) { Fail "bandit found issues" } else { Pass "bandit" }

# Tests
Step "Tests (pytest)"
if ((Test-Path "tests") -and (Get-ChildItem "tests\test_*.py" -ErrorAction SilentlyContinue)) {
    & $Python -m pytest tests/ -v
    if ($LASTEXITCODE -ne 0) { Fail "tests failed" } else { Pass "pytest" }
} else {
    Write-Host "  (no tests found -- skipping)"
}

# Build
Step "Build package"
$prevEAP2 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $Python -m build --outdir dist/ 2>&1 | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | Write-Host
$buildExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP2
if ($buildExit -ne 0) { Fail "build failed" } else { Pass "build" }

Write-Host "`nAll predeploy checks passed." -ForegroundColor Green
