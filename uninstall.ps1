<#
.SYNOPSIS
    Uninstalls the VtechMFA Windows service.

.DESCRIPTION
    Safe to run via `iex` (does not call `exit` from script scope, so it cannot kill
    the host PowerShell window).

    Config via env vars:
      $env:VTECHMFA_INSTALL_DIR  (default: %ProgramFiles%\VtechMFA)
      $env:VTECHMFA_KEEP_DATA    (set to "1" to preserve C:\ProgramData\VtechMFA)
      $env:VTECHMFA_KEEP_CERT    (set to "1" to preserve the cert in Trusted Root)

.EXAMPLE
    iwr -useb https://raw.githubusercontent.com/AmitSingh-15/VtechMFA/main/uninstall.ps1 | iex
#>

& {
    $ErrorActionPreference = "Stop"

    $InstallDir = if ($env:VTECHMFA_INSTALL_DIR) { $env:VTECHMFA_INSTALL_DIR } else { Join-Path $env:ProgramFiles "VtechMFA" }
    $KeepData   = $env:VTECHMFA_KEEP_DATA -eq "1"
    $KeepCert   = $env:VTECHMFA_KEEP_CERT -eq "1"
    $Repo       = if ($env:VTECHMFA_REPO)        { $env:VTECHMFA_REPO }        else { "AmitSingh-15/VtechMFA" }
    $svcName    = "VtechMFADeviceAuthService"

    function Write-Step($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
    function Write-Ok($msg)    { Write-Host "    $msg" -ForegroundColor Green }
    function Write-Warn2($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

    # --- Admin check -----------------------------------------------------------
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin   = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Warn2 "Not elevated. Saving script to temp and re-launching as Administrator..."
        $tmpScript = Join-Path $env:TEMP ("VtechMFA-uninstall-" + [Guid]::NewGuid().ToString("N") + ".ps1")
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/$Repo/main/uninstall.ps1" -OutFile $tmpScript
            Start-Process powershell.exe -Verb RunAs -ArgumentList @(
                "-NoProfile","-ExecutionPolicy","Bypass","-File",$tmpScript
            )
            Write-Host "Elevated uninstaller launched in a new window. This shell will stay open." -ForegroundColor Green
        } catch {
            Write-Host "ERROR: could not relaunch as admin: $_" -ForegroundColor Red
            Write-Host "Please open an elevated PowerShell and run the uninstall command there."
        }
        return
    }

    # --- Stop + remove service -------------------------------------------------
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

    # --- Remove URL ACL + SSL binding -----------------------------------------
    Write-Step "Releasing port 5002 bindings"
    & netsh.exe http delete sslcert ipport=127.0.0.1:5002 2>$null | Out-Null
    & netsh.exe http delete urlacl url=https://127.0.0.1:5002/ 2>$null | Out-Null
    Write-Ok "Port bindings cleared"

    # --- Remove install dir ---------------------------------------------------
    if (Test-Path $InstallDir) {
        Write-Step "Removing $InstallDir"
        try {
            Remove-Item -Recurse -Force $InstallDir
            Write-Ok "Install dir removed"
        } catch {
            Write-Warn2 "Could not fully remove $InstallDir : $_"
        }
    }

    # --- Remove data dir ------------------------------------------------------
    $dataDir = Join-Path $env:ProgramData "VtechMFA"
    if (-not $KeepData -and (Test-Path $dataDir)) {
        Write-Step "Removing $dataDir (logs, config, staging)"
        try {
            Remove-Item -Recurse -Force $dataDir
            Write-Ok "Data dir removed"
        } catch {
            Write-Warn2 "Could not fully remove $dataDir : $_"
        }
    }

    # --- Remove cert ----------------------------------------------------------
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
}
