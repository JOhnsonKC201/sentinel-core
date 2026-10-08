# ==============================================================================
# SentinelCore Antivirus - Automated Installer & Desktop Integrator
# Sets up Desktop Shortcut, Start Menu entry, Startup Guard, and PATH integration
# ==============================================================================

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Installing SentinelCore Personal Antivirus       " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$RepoDir = "C:\Users\johns\sentinel-core"
$PythonExe = (Get-Command python.exe).Source
$WScriptExe = "$env:WINDIR\System32\wscript.exe"

Write-Host "[*] Python runtime located: $PythonExe" -ForegroundColor Green
Write-Host "[*] SentinelCore Root:      $RepoDir" -ForegroundColor Green

# 1. Install CLI wrapper to .local/bin
$LocalBin = "$env:USERPROFILE\.local\bin"
if (-not (Test-Path $LocalBin)) {
    New-Item -ItemType Directory -Path $LocalBin -Force | Out-Null
}
Copy-Item "$RepoDir\scripts\sentinel.cmd" "$LocalBin\sentinel.cmd" -Force
Write-Host "[+] Installed CLI command 'sentinel' into $LocalBin\sentinel.cmd" -ForegroundColor Green

# 2. Create WScript Shell COM Object for shortcuts
$WshShell = New-Object -ComObject WScript.Shell

# 3. Create Desktop Shortcut: "SentinelCore Antivirus"
$DesktopDir = [Environment]::GetFolderPath("Desktop")
$DesktopShortcutPath = Join-Path $DesktopDir "SentinelCore Antivirus.lnk"
$Shortcut = $WshShell.CreateShortcut($DesktopShortcutPath)
$Shortcut.TargetPath = $PythonExe
$Shortcut.Arguments = "`"$RepoDir\scripts\run-sentinel.py`" --web"
$Shortcut.WorkingDirectory = $RepoDir
$Shortcut.Description = "SentinelCore Personal Antivirus & Security Dashboard"
$Shortcut.IconLocation = "$env:WINDIR\System32\SecurityAndMaintenance_Error.ico,0"
$Shortcut.Save()
Write-Host "[+] Created Desktop Shortcut: $DesktopShortcutPath" -ForegroundColor Green

# 4. Create Start Menu Shortcut
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "SentinelCore"
if (-not (Test-Path $StartMenuDir)) {
    New-Item -ItemType Directory -Path $StartMenuDir -Force | Out-Null
}
$StartMenuShortcutPath = Join-Path $StartMenuDir "SentinelCore Antivirus.lnk"
$StartShortcut = $WshShell.CreateShortcut($StartMenuShortcutPath)
$StartShortcut.TargetPath = $PythonExe
$StartShortcut.Arguments = "`"$RepoDir\scripts\run-sentinel.py`" --web"
$StartShortcut.WorkingDirectory = $RepoDir
$StartShortcut.Description = "SentinelCore Personal Antivirus & Security Dashboard"
$StartShortcut.IconLocation = "$env:WINDIR\System32\SecurityAndMaintenance_Error.ico,0"
$StartShortcut.Save()
Write-Host "[+] Created Start Menu Shortcut: $StartMenuShortcutPath" -ForegroundColor Green

# 5. Create Startup Shortcut (Optional auto-start on boot)
$StartupDir = [Environment]::GetFolderPath("Startup")
$StartupShortcutPath = Join-Path $StartupDir "SentinelCore Background Shield.lnk"
$StartupShortcut = $WshShell.CreateShortcut($StartupShortcutPath)
$StartupShortcut.TargetPath = $WScriptExe
$StartupShortcut.Arguments = "`"$RepoDir\scripts\start-sentinel-background.vbs`""
$StartupShortcut.WorkingDirectory = $RepoDir
$StartupShortcut.Description = "SentinelCore Silent Background Real-Time Shield"
$StartupShortcut.Save()
Write-Host "[+] Configured Windows Auto-Start Shield: $StartupShortcutPath" -ForegroundColor Green

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host "       SentinelCore Installation Completed Successfully!   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "You can now run SentinelCore in multiple ways:"
Write-Host "  1. Double-click the 'SentinelCore Antivirus' shortcut on your Desktop" -ForegroundColor Yellow
Write-Host "  2. Type 'sentinel web' in any terminal to open the Web UI" -ForegroundColor Yellow
Write-Host "  3. Type 'sentinel' in any terminal for interactive CLI console" -ForegroundColor Yellow
Write-Host "  4. Type 'sentinel scan <path>' to scan any folder on demand" -ForegroundColor Yellow
Write-Host "  5. Type 'sentinel start' / 'sentinel stop' to manage background shields" -ForegroundColor Yellow
