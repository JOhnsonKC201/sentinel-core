# Unified Build Script for SentinelCore Components
param (
    [switch]$Release = $true,
    [switch]$SkipDriver = $false
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Building SentinelCore Security Suite             " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check Toolchain Requirements
Write-Host "`n[1/4] Auditing toolchain environments..." -ForegroundColor Yellow
$CargoPath = Get-Command cargo -ErrorAction SilentlyContinue
$GoPath = Get-Command go -ErrorAction SilentlyContinue
$MSBuildPath = Get-Command msbuild -ErrorAction SilentlyContinue

Write-Host " - Cargo (Rust): $(if ($CargoPath) { $CargoPath.Source } else { 'NOT FOUND' })"
Write-Host " - Go Compiler:  $(if ($GoPath) { $GoPath.Source } else { 'NOT FOUND' })"
Write-Host " - MSBuild (WDK): $(if ($MSBuildPath) { $MSBuildPath.Source } else { 'NOT FOUND' })"

# 2. Build User-Mode Rust Crates
Write-Host "`n[2/4] Compiling Rust Core Crates (sentinel-daemon)..." -ForegroundColor Yellow
if (Test-Path "$RootDir\crates\Cargo.toml") {
    $CargoArgs = @("build")
    if ($Release) { $CargoArgs += "--release" }
    Push-Location "$RootDir\crates"
    cargo @CargoArgs
    Pop-Location
} else {
    Write-Host " [!] crates/Cargo.toml scaffolded for upcoming wave." -ForegroundColor DarkGray
}

# 3. Build Go Behavioral Telemetry
Write-Host "`n[3/4] Compiling Go Telemetry Daemon (sentinel-telemetry)..." -ForegroundColor Yellow
if (Test-Path "$RootDir\services\sentinel-telemetry\go.mod") {
    Push-Location "$RootDir\services\sentinel-telemetry"
    go build -o "$RootDir\bin\sentinel-telemetry.exe" .
    Pop-Location
} else {
    Write-Host " [!] services/sentinel-telemetry scaffolded for upcoming wave." -ForegroundColor DarkGray
}

# 4. Build C/C++ Minifilter Driver
Write-Host "`n[4/4] Compiling Windows Minifilter Driver (sentinel-filter.sys)..." -ForegroundColor Yellow
if (-not $SkipDriver -and (Test-Path "$RootDir\drivers\sentinel-filter\sentinel-filter.vcxproj")) {
    if ($MSBuildPath) {
        Push-Location "$RootDir\drivers\sentinel-filter"
        msbuild /p:Configuration=Release /p:Platform=x64 sentinel-filter.vcxproj
        Pop-Location
    } else {
        Write-Warning "MSBuild not found in PATH. Open Developer Command Prompt for VS to compile driver."
    }
} else {
    Write-Host " [!] drivers/sentinel-filter scaffolded for upcoming wave." -ForegroundColor DarkGray
}

Write-Host "`n[+] Build pipeline check completed successfully." -ForegroundColor Green
