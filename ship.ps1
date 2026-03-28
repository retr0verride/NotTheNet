# ship.ps1 — Full release workflow for NotTheNet
# Runs predeploy checks, generates offline bundle, creates minimal zip, copies to USB.
#
# Usage:  .\ship.ps1
#         .\ship.ps1 -SkipPredeploy   (skip lint/type/test if you just bumped a hotfix)
#         .\ship.ps1 -Drive F:\        (force a specific drive letter)

param(
    [switch]$SkipPredeploy,
    [string]$Drive
)

$ErrorActionPreference = "Stop"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "    OK: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "    FAIL: $msg" -ForegroundColor Red; exit 1 }

# ── Bump version: YYYY.MM.DD-N (same day → N+1, new day → 1) ─────────────────
# Read from BOTH files and take the higher build number to avoid rollback when
# they drift (e.g. notthenet.py was manually bumped without updating pyproject.toml).
$pyprojectVer = (Select-String -Path pyproject.toml -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value
if (-not $pyprojectVer) { Fail "Could not read version from pyproject.toml" }

$appVerLine = (Select-String -Path notthenet.py -Pattern '^APP_VERSION\s*=\s*"(.+)"').Matches[0].Groups[1].Value
if (-not $appVerLine) { Fail "Could not read APP_VERSION from notthenet.py" }

# Normalise post-style (2026.3.19.post9) → dash-style (2026.03.19-9) for comparison
function ConvertTo-DashVer($v) {
    if ($v -match '^(\d{4})\.(\d{1,2})\.(\d{1,2})\.post(\d+)$') {
        return "{0}.{1:D2}.{2:D2}-{3}" -f $Matches[1], [int]$Matches[2], [int]$Matches[3], [int]$Matches[4]
    }
    return $v
}
$pyprojectVer = ConvertTo-DashVer $pyprojectVer
$appVerLine   = ConvertTo-DashVer $appVerLine

# Pick the higher build number among the two files
function Get-BuildNumber($v) {
    if ($v -match '^(\d{4}\.\d{2}\.\d{2})-(\d+)$') { return [int]$Matches[2] }
    return 0
}
$buildA = Get-BuildNumber $pyprojectVer
$buildB = Get-BuildNumber $appVerLine
$curVer = if ($buildB -gt $buildA) { $appVerLine } else { $pyprojectVer }
if ($buildB -gt $buildA) {
    Write-Host "    NOTE: notthenet.py ($appVerLine) was ahead of pyproject.toml ($pyprojectVer); using higher." -ForegroundColor Yellow
}

$today   = (Get-Date).ToString("yyyy.MM.dd")
if ($curVer -match '^(\d{4}\.\d{2}\.\d{2})-(\d+)$') {
    $verDate  = $Matches[1]
    $verBuild = [int]$Matches[2]
    if ($verDate -eq $today) {
        $ver = "$today-$($verBuild + 1)"
    } else {
        $ver = "$today-1"
    }
} else {
    $ver = "$today-1"
}

# Patch pyproject.toml
(Get-Content pyproject.toml) -replace "^version\s*=\s*`".*`"", "version = `"$ver`"" |
    Set-Content pyproject.toml

# Patch notthenet.py
(Get-Content notthenet.py) -replace '^APP_VERSION\s*=\s*".*"', "APP_VERSION = `"$ver`"" |
    Set-Content notthenet.py

Step "Shipping version $ver  (was $curVer)"

# ── Predeploy checks ──────────────────────────────────────────────────────────
if (-not $SkipPredeploy) {
    Step "Running predeploy checks"
    & .\predeploy.ps1
    if ($LASTEXITCODE -ne 0) { Fail "predeploy checks failed" }
    Pass "predeploy"
} else {
    Write-Host "    (predeploy skipped)" -ForegroundColor Yellow
}

# ── Offline bundle (wheels baked in) ─────────────────────────────────────────
Step "Building offline installer bundle"
& .\make-bundle.ps1 -Zip
if ($LASTEXITCODE -ne 0) { Fail "make-bundle.ps1 failed" }

# Locate the zip make-bundle.ps1 produced (relative to CWD)
$bundleSrc = Join-Path (Split-Path $PSScriptRoot -Parent) "NotTheNet-bundle.zip"
if (-not (Test-Path $bundleSrc)) {
    # Fallback: try the CWD parent (when run from repo root the zip lands one level up)
    $bundleSrc = Join-Path (Split-Path (Get-Location) -Parent) "NotTheNet-bundle.zip"
}
if (-not (Test-Path $bundleSrc)) { Fail "Cannot find NotTheNet-bundle.zip" }

# ── Detect USB drive ─────────────────────────────────────────────────────────
if ($Drive) {
    $usbRoot = $Drive.TrimEnd('\') + '\'
    if (-not (Test-Path $usbRoot)) { Fail "Specified drive $usbRoot not found" }
} else {
    $usb = Get-CimInstance Win32_DiskDrive -Filter "InterfaceType='USB'" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Get-CimAssociatedInstance $_ -ResultClassName Win32_DiskPartition |
                ForEach-Object { Get-CimAssociatedInstance $_ -ResultClassName Win32_LogicalDisk }
        } |
        Where-Object { $_.DriveType -eq 2 } |
        Select-Object -First 1
    if (-not $usb) { Fail "No USB drive detected. Plug one in or use -Drive <letter>:\" }
    $usbRoot = $usb.DeviceID + '\'
    Step "Detected USB drive: $usbRoot ($('{0:N1}' -f ($usb.FreeSpace/1GB)) GB free)"
}

$bundleDst = Join-Path $usbRoot "NotTheNet_${ver}_bundle.zip"
Move-Item -Force $bundleSrc $bundleDst
Pass "Bundle → $bundleDst ($( '{0:N1}' -f ((Get-Item $bundleDst).Length/1MB) ) MB)"

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "NotTheNet $ver shipped to $usbRoot" -ForegroundColor Green
Write-Host "  Bundle: NotTheNet_${ver}_bundle.zip" -ForegroundColor Green
