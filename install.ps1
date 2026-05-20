<#
.SYNOPSIS
    Installs the VtechMFA Windows service on a client machine.

.DESCRIPTION
    Downloads the latest GitHub release of VtechMFA, verifies it, installs to
    %ProgramFiles%\VtechMFA, registers it as a Windows service, and starts it.

    Once installed the service auto-updates itself from this repo's GitHub Releases
    every 6 hours.

    Safe to run via `iex` (does not call `exit` from script scope, so it cannot kill
    the host PowerShell window). If not elevated when invoked via `iex`, the script
    saves itself to %TEMP% and re-launches via -File so the current shell stays open.

.EXAMPLE
    iwr -useb https://raw.githubusercontent.com/AmitSingh-15/VtechMFA/main/install.ps1 | iex
#>

# IMPORTANT: do not put a `param(...)` at top level when this script is intended to be
# piped through `iex`. We accept config via env vars instead.
#   $env:VTECHMFA_VERSION     (default: "latest")
#   $env:VTECHMFA_INSTALL_DIR (default: %ProgramFiles%\VtechMFA)
#   $env:VTECHMFA_REPO        (default: AmitSingh-15/VtechMFA)

& {
    $ErrorActionPreference = "Stop"

    $Version    = if ($env:VTECHMFA_VERSION)     { $env:VTECHMFA_VERSION }     else { "latest" }
    $InstallDir = if ($env:VTECHMFA_INSTALL_DIR) { $env:VTECHMFA_INSTALL_DIR } else { Join-Path $env:ProgramFiles "VtechMFA" }
    $Repo       = if ($env:VTECHMFA_REPO)        { $env:VTECHMFA_REPO }        else { "AmitSingh-15/VtechMFA" }

    function Write-Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
    function Write-Ok($msg)    { Write-Host "    $msg" -ForegroundColor Green }
    function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

    # --- Admin check -----------------------------------------------------------
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Warn2 "Not elevated. Saving script to temp and re-launching as Administrator..."
        $tmpScript = Join-Path $env:TEMP ("VtechMFA-install-" + [Guid]::NewGuid().ToString("N") + ".ps1")
        try {
            # Re-download a fresh copy so we don't rely on $MyInvocation (unreliable under iex).
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/$Repo/main/install.ps1" -OutFile $tmpScript
            Start-Process powershell.exe -Verb RunAs -ArgumentList @(
                "-NoProfile","-ExecutionPolicy","Bypass","-File",$tmpScript
            )
            Write-Host "Elevated installer launched in a new window. This shell will stay open." -ForegroundColor Green
        } catch {
            Write-Host "ERROR: could not relaunch as admin: $_" -ForegroundColor Red
            Write-Host "Please open an elevated PowerShell and run the install command there."
        }
        return
    }

    # --- TLS 1.2 ---------------------------------------------------------------
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    Write-Step "Installing VtechMFA from $Repo"

    # --- Find release ----------------------------------------------------------
    $apiUrl = if ($Version -eq "latest") {
        "https://api.github.com/repos/$Repo/releases/latest"
    } else {
        "https://api.github.com/repos/$Repo/releases/tags/$Version"
    }
    Write-Step "Looking up release: $Version"
    try {
        $release = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "VtechMFA-Installer" }
    } catch {
        Write-Host "ERROR: could not fetch release info from $apiUrl" -ForegroundColor Red
        Write-Host "Details: $_" -ForegroundColor Red
        return
    }
    $tag = $release.tag_name
    Write-Ok  "Found release $tag"

    $zipAsset = $release.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
    $shaAsset = $release.assets | Where-Object { $_.name -like "*.sha256" } | Select-Object -First 1
    if (-not $zipAsset) {
        Write-Host "ERROR: release $tag has no .zip asset." -ForegroundColor Red
        return
    }

    # --- Download --------------------------------------------------------------
    $tmp = Join-Path $env:TEMP ("VtechMFA-install-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    $zipPath = Join-Path $tmp $zipAsset.name

    Write-Step "Downloading $($zipAsset.name) ($([math]::Round($zipAsset.size/1KB,1)) KB)"
    try {
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Host "ERROR: download failed: $_" -ForegroundColor Red
        return
    }
    Write-Ok "Downloaded to $zipPath"

    if ($shaAsset) {
        Write-Step "Verifying SHA256"
        try {
            $shaText = (Invoke-WebRequest -Uri $shaAsset.browser_download_url -UseBasicParsing).Content
            $expected = ($shaText -split '\s+')[0].Trim().ToLower()
            $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
            if ($expected -ne $actual) {
                Write-Host "ERROR: SHA256 mismatch. Expected $expected, got $actual." -ForegroundColor Red
                return
            }
            Write-Ok "SHA256 verified"
        } catch {
            Write-Warn2 "SHA256 verification failed: $_ (continuing)"
        }
    } else {
        Write-Warn2 "No .sha256 asset found - skipping verification"
    }

    # --- Stop existing service (if any) ----------------------------------------
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

    # --- Extract ---------------------------------------------------------------
    Write-Step "Installing to $InstallDir"
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }
    try {
        Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
    } catch {
        Write-Host "ERROR: extraction failed: $_" -ForegroundColor Red
        return
    }
    Write-Ok "Files installed"

    # --- Register service ------------------------------------------------------
    $exe = Join-Path $InstallDir "VtechMFA.exe"
    if (-not (Test-Path $exe)) {
        Write-Host "ERROR: expected $exe to exist after extraction." -ForegroundColor Red
        return
    }

    if ($existing) {
        Write-Step "Removing previous service registration"
        & sc.exe delete $svcName | Out-Null
        Start-Sleep -Seconds 1
    }

    Write-Step "Registering service"
    $p = Start-Process -FilePath $exe -ArgumentList "--install" -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        Write-Host "ERROR: VtechMFA.exe --install exited with code $($p.ExitCode)" -ForegroundColor Red
        return
    }

    # --- Verify ---------------------------------------------------------------
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Write-Host "ERROR: service did not register." -ForegroundColor Red
        return
    }
    Write-Ok "Service status: $($svc.Status)"

    if ($svc.Status -ne "Running") {
        Write-Warn2 "Service is not Running yet - it may still be starting. Check: Get-Service $svcName"
    }

    # --- Smoke test ------------------------------------------------------------
    Write-Step "Probing https://127.0.0.1:5002/health"
    try {
        Start-Sleep -Seconds 2
        $resp = Invoke-RestMethod -Uri "https://127.0.0.1:5002/health" -TimeoutSec 5
        Write-Ok "Health: $($resp | ConvertTo-Json -Compress)"
    } catch {
        Write-Warn2 "Health probe failed (service may still be initializing): $_"
    }

    # --- Cleanup --------------------------------------------------------------
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "VtechMFA $tag installed successfully." -ForegroundColor Green
    Write-Host "  Install dir : $InstallDir"
    Write-Host "  Endpoint    : https://127.0.0.1:5002/device-info"
    Write-Host "  Logs        : C:\ProgramData\VtechMFA\logs\service.log"
    Write-Host "  Config      : C:\ProgramData\VtechMFA\config.json"
    Write-Host ""
    Write-Host "Auto-update runs every 6h. Force a check: `"$exe`" --check-update"
}
