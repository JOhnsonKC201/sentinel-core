# ==============================================================================
# SentinelCore Antivirus - Clean Uninstaller
# Removes Desktop Shortcut, Start Menu entry, Startup Guard, and PATH integration
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Yellow
Write-Host "         Uninstalling SentinelCore Integration            " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Yellow

# 1. Remove Desktop Shortcut
$DesktopDir = [Environment]::GetFolderPath("Desktop")
$DesktopShortcut = Join-Path $DesktopDir "SentinelCore Antivirus.lnk"
if (Test-Path $DesktopShortcut) {
    Remove-Item $DesktopShortcut -Force
    Write-Host "[+] Removed Desktop shortcut." -ForegroundColor Green
}

# 2. Remove Start Menu Shortcut
$StartMenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "SentinelCore"
if (Test-Path $StartMenuDir) {
    Remove-Item $StartMenuDir -Recurse -Force
    Write-Host "[+] Removed Start Menu entry." -ForegroundColor Green
}

# 3. Remove Startup Shortcut
$StartupDir = [Environment]::GetFolderPath("Startup")
$StartupShortcut = Join-Path $StartupDir "SentinelCore Background Shield.lnk"
if (Test-Path $StartupShortcut) {
    Remove-Item $StartupShortcut -Force
    Write-Host "[+] Removed Startup auto-launch entry." -ForegroundColor Green
}

# 4. Remove CLI wrapper
$LocalBinCmd = "$env:USERPROFILE\.local\bin\sentinel.cmd"
if (Test-Path $LocalBinCmd) {
    Remove-Item $LocalBinCmd -Force
    Write-Host "[+] Removed sentinel.cmd from PATH." -ForegroundColor Green
}

Write-Host "`n[+] SentinelCore integration removed cleanly." -ForegroundColor Green
