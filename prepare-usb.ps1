<#
.SYNOPSIS
    Prepares a USB drive (or the local folder) for air-gapped NotTheNet
    installation on Kali Linux.

.DESCRIPTION
    Downloads Linux-compatible Python wheels into .\wheelhouse\ so that
    install-offline.sh can install dependencies without internet access.

    Run this script ONCE on a Windows machine that has internet access,
    then copy the entire NotTheNet folder to the USB drive.

.PARAMETER WheelDir
    Destination folder for downloaded wheels. Default: .\wheelhouse

.EXAMPLE
    .\prepare-usb.ps1
    .\prepare-usb.ps1 -WheelDir D:\usb\NotTheNet\wheelhouse

.NOTES
    Kali Rolling 2024+ ships Python 3.12.
    Wheels are downloaded for Python 3.11 and 3.12 on Linux x86_64 to cover
    most lab setups. ARM64 (e.g. Kali on Raspberry Pi) is not covered here.
#>

[CmdletBinding()]
param(
    [string]$WheelDir = ".\wheelhouse"
)

$ErrorActionPreference = "Stop"

$GREEN  = "`e[32m"
$YELLOW = "`e[33m"
$RED    = "`e[31m"
$NC     = "`e[0m"

function info  { param($msg) Write-Host "${GREEN}[*]${NC} $msg" }
function warn  { param($msg) Write-Host "${YELLOW}[!]${NC} $msg" }
function fatal { param($msg) Write-Host "${RED}[!]${NC} $msg" -ForegroundColor Red; exit 1 }

# ── Sanity checks ────────────────────────────────────────────────────────────
if (-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    fatal "pip not found. Make sure Python is installed and in PATH."
}

New-Item -ItemType Directory -Force -Path $WheelDir | Out-Null
$WheelDir = (Resolve-Path $WheelDir).Path

info "Wheel destination: $WheelDir"
info "This may take a minute on first run..."

# ── dnslib — pure Python wheel (platform-independent) ────────────────────────
info "Downloading dnslib==0.9.26 (pure Python)..."
pip download dnslib==0.9.26 `
    --dest $WheelDir `
    --quiet
if ($LASTEXITCODE -ne 0) { fatal "Failed to download dnslib." }

# ── cryptography + deps — binary wheels for Linux x86_64 ─────────────────────
# Kali 2024+ (Debian bookworm-based) uses manylinux_2_28_x86_64.
# We download for both Python 3.11 and 3.12 to cover different Kali versions.

$platforms = @("manylinux_2_28_x86_64", "manylinux_2_17_x86_64")
$pyVersions = @("311", "312")

foreach ($pyver in $pyVersions) {
    foreach ($plat in $platforms) {
        info "Downloading cryptography>=44.0.1 for cp$pyver / $plat ..."
        pip download `
            --platform $plat `
            --python-version $pyver `
            --implementation cp `
            --abi "cp$pyver" `
            --only-binary :all: `
            "cryptography>=44.0.1" `
            --dest $WheelDir `
            --quiet 2>&1 | Out-Null
        # Non-fatal: a specific platform/version combo might not have a wheel;
        # the other combo will cover it.
    }
}

# Verify at least one cryptography wheel was downloaded
$cryptoWheels = Get-ChildItem -Path $WheelDir -Filter "cryptography-*" -ErrorAction SilentlyContinue
if (-not $cryptoWheels) {
    fatal "No cryptography wheel downloaded. Check your pip version and internet connection."
}

# ── Summary ───────────────────────────────────────────────────────────────────
$count = (Get-ChildItem -Path $WheelDir).Count
info ""
info "Done! $count file(s) in $WheelDir :"
Get-ChildItem -Path $WheelDir | Format-Table Name -HideTableHeaders

Write-Host ""
Write-Host "${GREEN}Next steps:${NC}"
Write-Host "  1. Copy the entire NotTheNet folder to your USB drive."
Write-Host "  2. On Kali, mount the USB and run:"
Write-Host "       cd /path/to/NotTheNet"
Write-Host "       sudo bash install-offline.sh"
