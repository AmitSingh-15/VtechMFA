<#
.SYNOPSIS
    Uninstalls the VtechMFA Windows service.

.EXAMPLE
    iwr -useb https://raw.githubusercontent.com/AmitSingh-15/VtechMFA/main/uninstall.ps1 | iex
#>
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "VtechMFA"),
    [switch]$KeepData,        # If set, leaves C:\ProgramData\VtechMFA alone
    [switch]$KeepCert         # If set, leaves the LocalMachine\Root cert alone
)

$ErrorActionPreference = "Stop"
$svcName = "VtechMFADeviceAuthService"

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    $msg" -ForegroundColor Yellow }
function Fail($msg)       { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

# --- Admin check ---------------------------------------------------------------
$identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail "Must run from an elevated PowerShell."
}

# --- Stop + remove service -----------------------------------------------------
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Step "Stopping service"
    try { Stop-Service -Name $svcName -Force -ErrorAction Stop; Start-Sleep -Seconds 2 } catch { Write-Warn2 $_ }

    $exe = Join-Path $InstallDir "VtechMFA.exe"
    if (Test-Path $exe) {
        Write-Step "Running $exe --uninstall"
        Start-Process -FilePath $exe -ArgumentList "--uninstall" -NoNewWindow -Wait | Out-Null
    } else {
        Write-Step "Deleting service via sc.exe"
        & sc.exe delete $svcName | Out-Null
    }
    Write-Ok "Service removed"
} else {
    Write-Warn2 "Service not found (already uninstalled?)"
}

# --- Remove URL ACL + SSL binding ----------------------------------------------
Write-Step "Releasing port 5002 bindings"
& netsh.exe http delete sslcert ipport=127.0.0.1:5002 2>$null | Out-Null
& netsh.exe http delete urlacl url=https://127.0.0.1:5002/ 2>$null | Out-Null
Write-Ok "Port bindings cleared"

# --- Remove install dir --------------------------------------------------------
if (Test-Path $InstallDir) {
    Write-Step "Removing $InstallDir"
    Remove-Item -Recurse -Force $InstallDir
    Write-Ok "Install dir removed"
}

# --- Remove data dir -----------------------------------------------------------
$dataDir = Join-Path $env:ProgramData "VtechMFA"
if (-not $KeepData -and (Test-Path $dataDir)) {
    Write-Step "Removing $dataDir (logs, config, staging)"
    Remove-Item -Recurse -Force $dataDir
    Write-Ok "Data dir removed"
}

# --- Remove cert from trusted root + my -----------------------------------------
if (-not $KeepCert) {
    Write-Step "Removing VtechMFA cert from LocalMachine\Root and LocalMachine\My"
    foreach ($storeName in @("My","Root")) {
        try {
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
            $store.Open("ReadWrite")
            $toRemove = $store.Certificates | Where-Object { $_.FriendlyName -eq "VtechMFA-Localhost-HTTPS" }
            foreach ($c in $toRemove) { $store.Remove($c) }
            $store.Close()
        } catch { Write-Warn2 "Cert removal from $storeName failed: $_" }
    }
    Write-Ok "Certs removed"
}

Write-Host ""
Write-Host "VtechMFA uninstalled." -ForegroundColor Green
