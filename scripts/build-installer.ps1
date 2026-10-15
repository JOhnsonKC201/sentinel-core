# Builds dist\SentinelCore-Setup-<version>.exe: tests, PyInstaller bundle, integrity baseline, installer.
param(
    [string]$Version = "0.1.0",
    [switch]$SkipTests
)

# Native tools (pip, PyInstaller, ISCC) log to stderr, which Windows PowerShell
# 5.1 turns into errors under "Stop". Every native call is checked through
# $LASTEXITCODE instead, and cmdlets opt in with -ErrorAction Stop.
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $PSScriptRoot
$Venv = Join-Path $Root ".venv"
$Python = Join-Path $Venv "Scripts\python.exe"
$Build = Join-Path $Root "build"

function Step($text) { Write-Host "`n[*] $text" -ForegroundColor Cyan }

Step "Preparing build environment"
if (-not (Test-Path $Python)) {
    python -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create $Venv" }
}
& $Python -m pip install --disable-pip-version-check -q -r (Join-Path $Root "requirements-dev.txt")
if ($LASTEXITCODE -ne 0) { throw "Dependency install failed" }

if (-not $SkipTests) {
    Step "Running the test suite"
    & $Python -m pytest (Join-Path $Root "tests") -q -p no:cacheprovider
    if ($LASTEXITCODE -ne 0) { throw "Tests failed; not building an installer from a red tree" }
}

Step "Generating icon and integrity baseline"
New-Item -ItemType Directory -Force -Path $Build -ErrorAction Stop | Out-Null
& $Python (Join-Path $Root "packaging\make_icon.py") (Join-Path $Build "SentinelCore.ico")
if ($LASTEXITCODE -ne 0) { throw "Icon generation failed" }
# The bundle ships the same .py files, so a baseline of the source tree is the
# baseline of the installed app.
$Manifest = Join-Path $Build "integrity_manifest.json"
& $Python -c "import sys; sys.path.insert(0, r'$Root'); from sentinel_guard.integrity_guard import IntegrityGuard; IntegrityGuard(base_dir=r'$Root', manifest_path=r'$Manifest').generate_and_save_baseline()"
if ($LASTEXITCODE -ne 0) { throw "Integrity baseline failed" }

Step "Bundling with PyInstaller"
& $Python -m PyInstaller --noconfirm --clean --distpath (Join-Path $Root "dist") --workpath (Join-Path $Build "pyinstaller") (Join-Path $Root "packaging\SentinelCore.spec")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

Step "Building the installer"
$Iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Iscc) { throw "Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup" }
& $Iscc "/DAppVersion=$Version" (Join-Path $Root "packaging\SentinelCore.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed" }

$Setup = Join-Path $Root "dist\SentinelCore-Setup-$Version.exe"
Write-Host "`n[+] Installer ready: $Setup" -ForegroundColor Green
