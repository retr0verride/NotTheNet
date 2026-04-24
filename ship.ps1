# ship.ps1 -- Full release workflow for NotTheNet
# Runs predeploy checks, generates offline bundle installer + zip.
#
# Usage:  .\ship.ps1
#         .\ship.ps1 -SkipPredeploy   (skip lint/type/test if you just bumped a hotfix)

param(
    [switch]$SkipPredeploy,
    [switch]$SkipPush         # build only; don't commit/tag/push
)

$ErrorActionPreference = "Stop"

function Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Pass($msg) { Write-Host "    OK: $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "    FAIL: $msg" -ForegroundColor Red; exit 1 }

# -- Bump version: YYYY.MM.DD-N (same day -> N+1, new day -> 1) -----------------
# Read from BOTH files and take the higher build number to avoid rollback when
# they drift (e.g. gui/widgets.py was manually bumped without updating pyproject.toml).
# Note: notthenet.py imports APP_VERSION from gui.widgets -- it is not the source of truth.
$pyprojectVer = (Select-String -Path pyproject.toml -Pattern '^version\s*=\s*"(.+)"').Matches[0].Groups[1].Value
if (-not $pyprojectVer) { Fail "Could not read version from pyproject.toml" }

$appVerLine = (Select-String -Path gui/widgets.py -Pattern '^APP_VERSION\s*=\s*"(.+)"').Matches[0].Groups[1].Value
if (-not $appVerLine) { Fail "Could not read APP_VERSION from gui/widgets.py" }

# Normalise post-style (2026.3.19.post9) -> dash-style (2026.03.19-9) for comparison
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
    Write-Host "    NOTE: gui/widgets.py ($appVerLine) was ahead of pyproject.toml ($pyprojectVer); using higher." -ForegroundColor Yellow
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

# Patch pyproject.toml — match only the bare 'version = ...' key, not 'target-version'
(Get-Content pyproject.toml) -replace '(?<![-\w])\bversion\s*=\s*"[^"]*"', "version = `"$ver`"" |
    Set-Content pyproject.toml

# Patch gui/widgets.py
(Get-Content gui/widgets.py) -replace '^APP_VERSION\s*=\s*".*"', "APP_VERSION = `"$ver`"" |
    Set-Content gui/widgets.py

Step "Shipping version $ver  (was $curVer)"

# -- Predeploy checks ----------------------------------------------------------
if (-not $SkipPredeploy) {
    Step "Running predeploy checks"
    & .\predeploy.ps1
    if ($LASTEXITCODE -ne 0) { Fail "predeploy checks failed" }
    Pass "predeploy"
} else {
    Write-Host "    (predeploy skipped)" -ForegroundColor Yellow
}

# -- Offline bundle (wheels baked in) -----------------------------------------
# make-bundle.ps1 always writes dist\NotTheNet-<ver>.zip; -SkipChecks avoids
# re-running predeploy (we already ran it above).
Step "Building offline installer bundle"
& .\make-bundle.ps1 -SkipChecks -SkipRelease
if ($LASTEXITCODE -ne 0) { Fail "make-bundle.ps1 failed" }

# Locate the zip make-bundle.ps1 wrote to dist/
$distDir  = Join-Path (Get-Location) "dist"
$bundleDst = Join-Path $distDir "NotTheNet-${ver}.zip"
if (-not (Test-Path $bundleDst)) { Fail "Cannot find $bundleDst" }
Pass "Zip -> $bundleDst ($( '{0:N1}' -f ((Get-Item $bundleDst).Length/1MB) ) MB)"

# -- Summary -------------------------------------------------------------------
Write-Host ""
Write-Host "NotTheNet $ver ready in dist/" -ForegroundColor Green
Write-Host "  NotTheNet-${ver}.zip" -ForegroundColor Green
Write-Host ""
Write-Host "To create an ISO, add these files to your ISO tool (e.g. AnyBurn)." -ForegroundColor Yellow

# -- Commit, tag, push --------------------------------------------------------
if ($SkipPush) {
    Write-Host "`n(commit/tag/push skipped via -SkipPush)" -ForegroundColor Yellow
    exit 0
}

Step "Committing version bump"
# Stage only the files ship.ps1 mutates; never blanket-add (avoids sweeping in
# unrelated WIP changes).
git add pyproject.toml gui/widgets.py 2>&1 | Out-Null
$staged = (git diff --cached --name-only) -join ", "
if (-not $staged) {
    Write-Host "    (no version-bump changes to commit)" -ForegroundColor Yellow
} else {
    git commit -m "chore(release): $ver" | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "git commit failed" }
    Pass "committed: $staged"
}

Step "Tagging v$ver"
$tag = "v$ver"
if ((git tag -l $tag) -eq $tag) { Fail "tag $tag already exists locally -- bump the version or delete the tag" }
git tag -a $tag -m "Release $ver"
if ($LASTEXITCODE -ne 0) { Fail "git tag failed" }
Pass "tagged $tag"

Step "Pushing main + tag to origin"
git push origin main
if ($LASTEXITCODE -ne 0) { Fail "git push origin main failed" }
git push origin $tag
if ($LASTEXITCODE -ne 0) { Fail "git push origin $tag failed" }
Pass "pushed main and $tag"

Write-Host ""
Write-Host "Watch CI: https://github.com/retr0verride/NotTheNet/actions/workflows/ci.yml" -ForegroundColor Cyan
