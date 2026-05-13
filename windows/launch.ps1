<#
.SYNOPSIS
    NotTheNet Windows Launcher — Start fake internet simulator

.DESCRIPTION
    Launches NotTheNet in either GUI or headless mode.

.PARAMETER Headless
    Run in headless mode (no GUI, exposes health endpoint on :8080)

.PARAMETER LogLevel
    Set log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

.EXAMPLE
    .\launch.ps1 -Headless -LogLevel DEBUG
#>

param(
    [switch]$Headless,
    [ValidateSet("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")]
    [string]$LogLevel = "INFO"
)

$ErrorActionPreference = "Stop"

# Ensure we're in the right directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# Check if requirements are installed
Write-Host "[*] Checking Python environment..." -ForegroundColor Cyan

try {
    python --version | Out-Null
}
catch {
    Write-Host "[!] Python not found. Please install Python 3.10+" -ForegroundColor Red
    Write-Host "[!] Download from: https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}

# Check if dependencies are installed
Write-Host "[*] Checking dependencies..." -ForegroundColor Cyan
python -c "import dnslib, cryptography" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Missing dependencies. Installing..." -ForegroundColor Yellow
    pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Failed to install dependencies" -ForegroundColor Red
        exit 1
    }
}

# Ensure logs directory exists
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

# Set environment variables
$env:NTN_LOG_LEVEL = $LogLevel

if ($Headless) {
    Write-Host "[*] Starting NotTheNet in HEADLESS mode..." -ForegroundColor Cyan
    Write-Host "[i] Health endpoint: http://localhost:8080/health" -ForegroundColor Green
    $env:NTN_HEADLESS = "1"
}
else {
    Write-Host "[*] Starting NotTheNet in GUI mode..." -ForegroundColor Cyan
}

Write-Host ""

# Launch
python notthenet.py

# Cleanup on exit
Write-Host "[*] NotTheNet stopped" -ForegroundColor Yellow
