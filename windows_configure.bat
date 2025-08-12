@echo off
REM ================================================
REM   ClamAV & OpenSSH Setup Script (PowerShell)
REM   Author: Koosha Yeganeh
REM   Description: Installs and configures ClamAV,
REM                sets up OpenSSH, and switches
REM                default shell to PowerShell.
REM ================================================

:: Force running in PowerShell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& {
    Write-Host '--- Starting ClamAV Setup ---' -ForegroundColor Cyan

    # 1. Create ClamAV database folder
    New-Item -ItemType Directory -Path 'C:\Program Files\ClamAV\database' -Force | Out-Null

    # 2. Copy configuration samples
    Copy-Item 'C:\Program Files\ClamAV\conf_examples\clamd.conf.sample' 'C:\Program Files\ClamAV\clamd.conf' -Force
    Copy-Item 'C:\Program Files\ClamAV\conf_examples\freshclam.conf.sample' 'C:\Program Files\ClamAV\freshclam.conf' -Force

    # 3. Modify clamd.conf to disable Example line
    (Get-Content 'C:\Program Files\ClamAV\clamd.conf') |
        ForEach-Object { $_ -replace '^(Example)', '#Example' } |
        Set-Content 'C:\Program Files\ClamAV\clamd.conf'

    # 4. Copy daily.cvd to ClamAV database
    if (Test-Path '.\daily.cvd') {
        Copy-Item '.\daily.cvd' 'C:\Program Files\ClamAV\database' -Force
        Write-Host 'daily.cvd copied successfully.' -ForegroundColor Green
    } else {
        Write-Host 'daily.cvd not found in script folder.' -ForegroundColor Yellow
    }

    Write-Host '--- ClamAV Setup Complete ---' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '--- Starting OpenSSH Setup ---' -ForegroundColor Cyan

    # 5. Navigate to OpenSSH folder
    Set-Location 'C:\Program Files\OpenSSH'

    # 6. Install OpenSSH service
    powershell.exe -ExecutionPolicy Bypass -File 'install-sshd.ps1'

    # 7. Change SSH port (example: 4444)
    $sshdConfig = 'C:\Program Files\OpenSSH\sshd_config'
    if (!(Test-Path $sshdConfig)) {
        $sshdConfigDefault = 'C:\Program Files\OpenSSH\sshd_config_default'
        if (Test-Path $sshdConfigDefault) { Copy-Item $sshdConfigDefault $sshdConfig -Force }
    }
    (Get-Content $sshdConfig) |
        ForEach-Object { $_ -replace '^#?Port\s+\d+', 'Port 4444' } |
        Set-Content $sshdConfig

    # 8. Open firewall for SSH port
    New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True `
        -Direction Inbound -Protocol TCP -Action Allow -LocalPort 4444

    # 9. Start and enable SSH service
    net start sshd
    Set-Service sshd -StartupType Automatic

    Write-Host '--- OpenSSH Setup Complete ---' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Switching default shell to PowerShell...' -ForegroundColor Cyan

    # 10. Set PowerShell as default shell for SSH
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

    Write-Host '--- Setup Finished ---' -ForegroundColor Green
}"


