# Installs the built SentinelCore app for the current user, the same way the
# Inno Setup installer does: %LOCALAPPDATA%\Programs\SentinelCore, a Start menu
# shortcut, and (unless -NoStartup) a sign-in entry that starts it in the tray.
#
# Use this where Smart App Control blocks the unsigned Setup.exe; the app
# bundle itself runs. Build first with scripts\build-installer.ps1.
param(
    [switch]$NoStartup,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Bundle = Join-Path $Root "dist\SentinelCore"
$AppDir = Join-Path $env:LOCALAPPDATA "Programs\SentinelCore"
$Exe = Join-Path $AppDir "SentinelCore.exe"
$MenuDir = Join-Path ([Environment]::GetFolderPath("Programs")) "SentinelCore"
$RunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

function Stop-RunningApp {
    Get-Process SentinelCore -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $Exe } | Stop-Process -Force
    Start-Sleep -Milliseconds 500
}

if ($Uninstall) {
    Stop-RunningApp
    Remove-ItemProperty -Path $RunKey -Name "SentinelCore" -ErrorAction SilentlyContinue
    if (Test-Path $MenuDir) { Remove-Item $MenuDir -Recurse -Force }
    if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force }
    Write-Host "[+] SentinelCore removed. Quarantine vault and settings stay in $env:ProgramData\SentinelCore." -ForegroundColor Green
    return
}

if (-not (Test-Path (Join-Path $Bundle "SentinelCore.exe"))) {
    throw "No build found at $Bundle. Run scripts\build-installer.ps1 first."
}

Stop-RunningApp
if (Test-Path $AppDir) { Remove-Item $AppDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
Copy-Item -Path (Join-Path $Bundle "*") -Destination $AppDir -Recurse -Force
Write-Host "[+] Installed to $AppDir" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path $MenuDir | Out-Null
$Shell = New-Object -ComObject WScript.Shell
$Link = $Shell.CreateShortcut((Join-Path $MenuDir "SentinelCore.lnk"))
$Link.TargetPath = $Exe
$Link.WorkingDirectory = $AppDir
$Link.Description = "SentinelCore endpoint protection"
$Link.Save()
Write-Host "[+] Start menu shortcut created" -ForegroundColor Green

if ($NoStartup) {
    Remove-ItemProperty -Path $RunKey -Name "SentinelCore" -ErrorAction SilentlyContinue
} else {
    Set-ItemProperty -Path $RunKey -Name "SentinelCore" -Value "`"$Exe`" --minimized"
    Write-Host "[+] Starts in the tray when you sign in" -ForegroundColor Green
}

Start-Process $Exe
Write-Host "[+] SentinelCore is running. Uninstall with: scripts\install-app.ps1 -Uninstall" -ForegroundColor Green
