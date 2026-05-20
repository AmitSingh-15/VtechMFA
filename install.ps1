<#
.SYNOPSIS
    Installs the VtechMFA Windows service on a client machine.

.DESCRIPTION
    Downloads the latest GitHub release of VtechMFA, verifies it, installs to
    %ProgramFiles%\VtechMFA, registers it as a Windows service, and starts it.

    Once installed the service auto-updates itself from this repo's GitHub Releases
    every 6 hours.

.EXAMPLE
    # Run as Administrator. One-liner install:
    iwr -useb https://raw.githubusercontent.com/AmitSingh-15/VtechMFA/main/install.ps1 | iex

.EXAMPLE
    # Install a specific version
    & ([scriptblock]::Create((iwr -useb https://raw.githubusercontent.com/AmitSingh-15/VtechMFA/main/install.ps1))) -Version v1.1.0
#>
[CmdletBinding()]
param(
    [string]$Version = "latest",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "VtechMFA"),
    [string]$Repo = "AmitSingh-15/VtechMFA"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }
function Fail($msg)       { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# --- Admin check (self-elevate if not elevated) ---------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warn2 "Not elevated. Re-launching as Administrator..."
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) {
        # When piped from iwr|iex there is no script file. Tell the user what to do.
        Fail "Please run from an elevated PowerShell:`n`n  Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command `"iwr -useb https://raw.githubusercontent.com/$Repo/main/install.ps1 | iex`"'"
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$scriptPath,"-Version",$Version,"-InstallDir",$InstallDir,"-Repo",$Repo)
    exit
}

# --- TLS 1.2 (PS 5.1 default is too old for GitHub) -----------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

Write-Step "Installing VtechMFA from $Repo"

# --- Find release ---------------------------------------------------------------
$apiUrl = if ($Version -eq "latest") {
    "https://api.github.com/repos/$Repo/releases/latest"
} else {
    "https://api.github.com/repos/$Repo/releases/tags/$Version"
}
Write-Step "Looking up release: $Version"
try {
    $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "VtechMFA-Installer" }
} catch {
    Fail "Could not fetch release info: $_"
}
$tag = $release.tag_name
Write-Ok  "Found release $tag"

$zipAsset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
$shaAsset = $release.assets | Where-Object { $_.name -like "*.sha256" } | Select-Object -First 1
if (-not $zipAsset) { Fail "Release $tag has no .zip asset." }

# --- Download -------------------------------------------------------------------
$tmp = Join-Path $env:TEMP ("VtechMFA-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
$zipPath = Join-Path $tmp $zipAsset.name

Write-Step "Downloading $($zipAsset.name) ($([math]::Round($zipAsset.size/1KB,1)) KB)"
Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
Write-Ok "Downloaded to $zipPath"

if ($shaAsset) {
    Write-Step "Verifying SHA256"
    $shaText = (Invoke-WebRequest -Uri $shaAsset.browser_download_url -UseBasicParsing).Content
    $expected = ($shaText -split '\s+')[0].Trim().ToLower()
    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) {
        Fail "SHA256 mismatch. Expected $expected, got $actual."
    }
    Write-Ok "SHA256 verified"
} else {
    Write-Warn2 "No .sha256 asset found - skipping verification"
}

# --- Stop existing service (if any) ---------------------------------------------
$svcName = "VtechMFADeviceAuthService"
$existing = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "Stopping existing service"
    try {
        Stop-Service -Name $svcName -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
    } catch {
        Write-Warn2 "Could not stop existing service cleanly: $_"
    }
}

# --- Extract --------------------------------------------------------------------
Write-Step "Installing to $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
Write-Ok "Files installed"

# --- Register service -----------------------------------------------------------
$exe = Join-Path $InstallDir "VtechMFA.exe"
if (-not (Test-Path $exe)) { Fail "Expected $exe to exist after extraction." }

# If the service already exists, --install will fail on `sc create`. Delete first.
if ($existing) {
    Write-Step "Removing previous service registration"
    & sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 1
}

Write-Step "Registering service"
$p = Start-Process -FilePath $exe -ArgumentList "--install" -NoNewWindow -Wait -PassThru
if ($p.ExitCode -ne 0) {
    Fail "VtechMFA.exe --install exited with code $($p.ExitCode)"
}

# --- Verify ---------------------------------------------------------------------
Start-Sleep -Seconds 3
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if (-not $svc) { Fail "Service did not register." }
Write-Ok "Service status: $($svc.Status)"

if ($svc.Status -ne "Running") {
    Write-Warn2 "Service is not Running yet - it may still be starting. Check: Get-Service $svcName"
}

# --- Smoke test the endpoint ----------------------------------------------------
Write-Step "Probing https://127.0.0.1:5002/health"
try {
    Start-Sleep -Seconds 2
    $resp = Invoke-RestMethod -Uri "https://127.0.0.1:5002/health" -TimeoutSec 5
    Write-Ok "Health: $($resp | ConvertTo-Json -Compress)"
} catch {
    Write-Warn2 "Health probe failed (service may still be initializing): $_"
}

# --- Cleanup --------------------------------------------------------------------
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "VtechMFA $tag installed successfully." -ForegroundColor Green
Write-Host "  Install dir : $InstallDir"
Write-Host "  Endpoint    : https://127.0.0.1:5002/device-info"
Write-Host "  Logs        : C:\ProgramData\VtechMFA\logs\service.log"
Write-Host "  Config      : C:\ProgramData\VtechMFA\config.json"
Write-Host ""
Write-Host "Auto-update runs every 6h. Force a check: `"$exe`" --check-update"
