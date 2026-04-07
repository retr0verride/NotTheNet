# ─────────────────────────────────────────────────────────────────────────────
# NotTheNet — Prepare Victim VM for Preflight
# Run as Administrator on FlareVM (one time, before taking baseline snapshot).
#
# What this does:
#   1. Disables Windows Firewall (all profiles)
#   2. Enables DCOM (required by WMI)
#   3. Sets LocalAccountTokenFilterPolicy (UAC remote admin fix)
#   4. Ensures WMI and RPC services are running and set to auto-start
#   5. Enables WMI firewall rules (belt-and-suspenders)
# ─────────────────────────────────────────────────────────────────────────────
#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

function Pass($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [!!] $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "  [--] $msg" -ForegroundColor Cyan }

Write-Host ""
Write-Host "════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  NotTheNet - Prepare Victim VM" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ── 1. Disable Windows Firewall ──────────────────────────────────────────────
Info "Disabling Windows Firewall (all profiles)..."
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    Pass "Windows Firewall disabled"
} catch {
    # Fallback for older Windows or if cmdlet is missing
    netsh advfirewall set allprofiles state off 2>$null
    if ($LASTEXITCODE -eq 0) { Pass "Windows Firewall disabled (netsh)" }
    else { Fail "Could not disable firewall: $_" }
}

# ── 2. Enable DCOM ───────────────────────────────────────────────────────────
Info "Enabling DCOM..."
$olePath = "HKLM:\SOFTWARE\Microsoft\Ole"
$current = (Get-ItemProperty -Path $olePath -Name EnableDCOM -ErrorAction SilentlyContinue).EnableDCOM
if ($current -eq "Y") {
    Pass "DCOM already enabled"
} else {
    Set-ItemProperty -Path $olePath -Name EnableDCOM -Value "Y" -Type String
    Pass "DCOM enabled"
}

# ── 3. LocalAccountTokenFilterPolicy (UAC remote admin) ─────────────────────
Info "Setting LocalAccountTokenFilterPolicy..."
$uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$current = (Get-ItemProperty -Path $uacPath -Name LocalAccountTokenFilterPolicy -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
if ($current -eq 1) {
    Pass "LocalAccountTokenFilterPolicy already set"
} else {
    Set-ItemProperty -Path $uacPath -Name LocalAccountTokenFilterPolicy -Value 1 -Type DWord
    Pass "LocalAccountTokenFilterPolicy set to 1"
}

# ── 4. Ensure WMI and RPC services are running ──────────────────────────────
Info "Checking WMI and RPC services..."
foreach ($svcName in @("Winmgmt", "RpcSs")) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Fail "$svcName service not found"
        continue
    }
    # Set to auto-start
    Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
    if ($svc.Status -ne "Running") {
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
        $svc = Get-Service -Name $svcName
    }
    if ($svc.Status -eq "Running") {
        Pass "$svcName is running (auto-start)"
    } else {
        Fail "$svcName status: $($svc.Status)"
    }
}

# ── 5. Enable WMI firewall rules (belt-and-suspenders) ──────────────────────
Info "Enabling WMI firewall rules..."
try {
    $rules = Get-NetFirewallRule -Group "Windows Management Instrumentation (WMI)" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Set-NetFirewallRule -Enabled True
        Pass "WMI firewall rules enabled ($($rules.Count) rules)"
    } else {
        Info "No WMI firewall rule group found (firewall is off -- OK)"
    }
} catch {
    netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=yes 2>$null
    if ($LASTEXITCODE -eq 0) { Pass "WMI firewall rules enabled (netsh)" }
    else { Info "Could not set WMI rules (firewall is off -- OK)" }
}

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Victim preparation complete." -ForegroundColor Green
Write-Host "  Take a baseline snapshot now." -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
