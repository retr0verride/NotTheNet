# predeploy.ps1 — thin wrapper around scripts/checks.py
# All check logic lives in scripts/checks.py (single source of truth, shared with CI).
$ErrorActionPreference = "Stop"
$Python = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
& $Python scripts\checks.py @args
exit $LASTEXITCODE
