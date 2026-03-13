#Requires -RunAsAdministrator
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step { param([string]$msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-OK   { param([string]$msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Skip { param([string]$msg) Write-Host "[-] $msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$msg) Write-Host "[!] $msg" -ForegroundColor Red }

Write-Step "Patching SCSI disk Identifier..."
$scsiBase = "HKLM:\HARDWARE\DEVICEMAP\Scsi"
if (Test-Path $scsiBase) {
    $units = Get-ChildItem -Path $scsiBase -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "Logical Unit Id 0" }
    foreach ($u in $units) {
        $val = (Get-ItemProperty -Path $u.PSPath -Name "Identifier" -ErrorAction SilentlyContinue).Identifier
        if ($val -match "QEMU|VBOX|VMWARE|VIRTUAL") {
            Set-ItemProperty -Path $u.PSPath -Name "Identifier" -Value "SAMSUNG MZNLN256HAJQ-000H1"
            Write-OK "Patched: $($u.PSPath)"
        } else {
            Write-Skip "Already clean: $val"
        }
    }
} else {
    Write-Skip "SCSI devicemap key not found"
}

Write-Step "Patching SCSI disk SerialNumber..."
if (Test-Path $scsiBase) {
    $units = Get-ChildItem -Path $scsiBase -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq "Logical Unit Id 0" }
    foreach ($u in $units) {
        $snProp = Get-ItemProperty -Path $u.PSPath -Name "SerialNumber" -ErrorAction SilentlyContinue
        if ($null -eq $snProp) { Write-Skip "SerialNumber not present: $($u.PSPath)"; continue }
        $sn = $snProp.SerialNumber
        if ($sn -match "QM0|VBOX|VMWARE") {
            Set-ItemProperty -Path $u.PSPath -Name "SerialNumber" -Value "S4EWNX0N123456"
            Write-OK "SerialNumber patched: $($u.PSPath)"
        } else {
            Write-Skip "SerialNumber clean: $sn"
        }
    }
} else {
    Write-Skip "SCSI devicemap key not found"
}

Write-Step "Patching SystemBiosVersion..."
$sysKey = "HKLM:\HARDWARE\Description\System"
try {
    $bios = (Get-ItemProperty -Path $sysKey -Name "SystemBiosVersion" -ErrorAction Stop).SystemBiosVersion
    if ($bios -match "BOCHS|QEMU|VBOX|VMWARE") {
        Set-ItemProperty -Path $sysKey -Name "SystemBiosVersion" -Value "Dell Inc. 1.12.0, 11/15/2023"
        Write-OK "SystemBiosVersion patched"
    } else {
        Write-Skip "SystemBiosVersion clean: $bios"
    }
} catch {
    Write-Skip "SystemBiosVersion key not found"
}

Write-Step "Patching SystemBiosDate..."
try {
    $biosDate = (Get-ItemProperty -Path $sysKey -Name "SystemBiosDate" -ErrorAction Stop).SystemBiosDate
    # Match any date that looks like a hypervisor placeholder:
    # QEMU/BOCHS: "01/01/2011", "01/01/2006"
    # VirtualBox: "12/01/2006"
    # VMware: "01/01/2021" etc.
    # Rule: year before 2022 OR year starting with 1970-2020 is suspicious.
    # Simpler: just check for known-bad years / QEMU sentinel dates.
    $biosYear = ($biosDate -split "/")[-1]
    if ($biosDate -match "QEMU|VBOX|VMWARE" -or ($biosYear -match "^\d{4}$" -and [int]$biosYear -lt 2022)) {
        Set-ItemProperty -Path $sysKey -Name "SystemBiosDate" -Value "11/15/2023"
        Write-OK "SystemBiosDate patched (was $biosDate)"
    } else {
        Write-Skip "SystemBiosDate clean: $biosDate"
    }
} catch {
    Write-Skip "SystemBiosDate key not found"
}

Write-Step "Removing VM guest artifact keys..."
$artifactKeys = @(
    # VirtualBox
    "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions",
    "HKLM:\SOFTWARE\WOW6432Node\Oracle\VirtualBox Guest Additions",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxMouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxService",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxSF",
    "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxVideo",
    # VMware
    "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmhgfs",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmmouse",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmrawdsk",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmusbmouse",
    # Hyper-V / VMBUS (Proxmox can expose these when Hyper-V enlightenments are enabled)
    "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmicheartbeat",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmickvpexchange",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmicrdv",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmicshutdown",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmictimesync",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmicvss",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vmicguestinterface",
    "HKLM:\SYSTEM\CurrentControlSet\Services\vid"
)
foreach ($k in $artifactKeys) {
    if (Test-Path $k) {
        try {
            Remove-Item -Path $k -Recurse -Force
            Write-OK "Removed: $k"
        } catch {
            Write-Fail "Could not remove $k"
        }
    }
}

Write-Step "Patching SMBIOS manufacturer in registry..."
$compKey = "HKLM:\HARDWARE\DESCRIPTION\System\BIOS"
if (Test-Path $compKey) {
    $mfr = (Get-ItemProperty $compKey -Name "SystemManufacturer" -ErrorAction SilentlyContinue).SystemManufacturer
    if ($mfr -match "QEMU|innotek|VMware") {
        Set-ItemProperty $compKey -Name "SystemManufacturer" -Value "Dell Inc."
        Set-ItemProperty $compKey -Name "SystemProductName" -Value "OptiPlex 7090"
        Set-ItemProperty $compKey -Name "SystemFamily" -Value "Desktop"
        Set-ItemProperty $compKey -Name "SystemVersion" -Value "Not Specified"
        Set-ItemProperty $compKey -Name "BaseBoardManufacturer" -Value "Dell Inc."
        Set-ItemProperty $compKey -Name "BaseBoardProduct" -Value "0CXPYV"
        Write-OK "SMBIOS registry entries patched"
    } else {
        Write-Skip "Manufacturer already clean: $mfr"
    }
} else {
    Write-Skip "BIOS description key not found"
}

Write-Step "Backdating Windows install date..."
$cvKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$installDate = (Get-ItemProperty $cvKey -Name "InstallDate").InstallDate
$installDT = (Get-Date "1970-01-01").AddSeconds($installDate)
if ($installDT -gt (Get-Date).AddDays(-180)) {
    $backdateEpoch = [int][double]::Parse((Get-Date "2024-07-14").Subtract((Get-Date "1970-01-01")).TotalSeconds)
    Set-ItemProperty $cvKey -Name "InstallDate" -Value $backdateEpoch -Type DWord
    Write-OK "InstallDate backdated to 07/14/2024"
} else {
    $installDate2 = (Get-ItemProperty $cvKey -Name "InstallDate").InstallDate
    $installDT2 = (Get-Date "1970-01-01").AddSeconds($installDate2)
    Write-Skip "InstallDate already old: $installDT2"
}

Write-Step "Spoofing NIC MAC address OUI..."
# QEMU's default NIC OUI is 52:54:00 (Realtek paravirtual).
# Many sandbox detectors enumerate adapters and flag this prefix.
# We patch the NetworkAddress registry value which Windows uses to override
# the hardware MAC on the next interface init (takes effect after reboot).
$nicBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
if (Test-Path $nicBase) {
    $nics = Get-ChildItem -Path $nicBase -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' }
    foreach ($nic in $nics) {
        $desc = (Get-ItemProperty -Path $nic.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc
        $existingMac = (Get-ItemProperty -Path $nic.PSPath -Name "NetworkAddress" -ErrorAction SilentlyContinue).NetworkAddress
        # Only patch QEMU/VirtIO/vmxnet NICs that haven't already been spoofed
        if ($desc -match "QEMU|VirtIO|vmxnet|Red Hat" -and -not $existingMac) {
            # Dell/Intel OUI: D4:BE:D9 (Intel I219-LM, common on OptiPlex)
            # Last 3 octets randomised so each NIC gets a unique address
            $rand = "{0:X2}{1:X2}{2:X2}" -f (Get-Random -Max 256),(Get-Random -Max 256),(Get-Random -Max 256)
            $spoofedMac = "D4BED9$rand"
            Set-ItemProperty -Path $nic.PSPath -Name "NetworkAddress" -Value $spoofedMac -Type String -Force
            Write-OK "NIC '$desc' MAC → $($spoofedMac -replace '(.{2})(?=.)','`$1:')"
        } elseif ($existingMac) {
            Write-Skip "NIC '$desc' already has NetworkAddress override"
        } else {
            Write-Skip "NIC '$desc' OUI not flagged"
        }
    }
} else {
    Write-Skip "NIC class key not found"
}

Write-Step "Disabling VBS/DeviceGuard..."
$dgKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
$hgKey = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HyperGuard"
if (-not (Test-Path $dgKey)) { New-Item -Path $dgKey -Force | Out-Null }
if (-not (Test-Path $hgKey)) { New-Item -Path $hgKey -Force | Out-Null }
Set-ItemProperty -Path $dgKey -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $dgKey -Name "RequirePlatformSecurityFeatures" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $hgKey -Name "Enabled" -Value 0 -Type DWord -Force
Write-OK "VBS/DeviceGuard disabled"

Write-Step "Registering GhostFlare scheduled task..."
$taskName = "GhostFlare"
$scriptPath = $MyInvocation.MyCommand.Path
if (-not $scriptPath) { $scriptPath = "C:\Users\Proxmox\Desktop\ghost-flare.ps1" }
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Skip "Task '$taskName' already registered"
} else {
    $result = schtasks.exe /create /tn $taskName /tr "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" /sc ONLOGON /ru SYSTEM /rl HIGHEST /f 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Scheduled task '$taskName' created"
    } else {
        Write-Fail "Task creation failed: $result"
    }
}

Write-Host ""
Write-Host "Done. Reboot, idle 12+ min, then run pafish." -ForegroundColor Magenta
