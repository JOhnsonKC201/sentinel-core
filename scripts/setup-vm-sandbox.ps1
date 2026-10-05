# Hyper-V Isolation Sandbox Setup for SentinelCore Kernel Minifilter
# Run in Administrator PowerShell to provision the isolated kernel testbed

param (
    [string]$VmName = "SentinelTestBed-Win11",
    [string]$SwitchName = "Default Switch",
    [int64]$MemoryBytes = 4GB,
    [string]$VhdPath = "C:\Hyper-V\Virtual Hard Disks\SentinelTestBed.vhdx"
)

$ErrorActionPreference = "Stop"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   Provisioning Isolated Hyper-V Kernel Sandbox: $VmName  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Verify Hyper-V feature is enabled
$HyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue
if ($HyperVFeature -and $HyperVFeature.State -ne "Enabled") {
    Write-Warning "Hyper-V is not enabled on this host. Run: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All"
}

# 2. Check if VM already exists
$ExistingVM = Get-VM -Name $VmName -ErrorAction SilentlyContinue
if ($ExistingVM) {
    Write-Host "[*] Virtual Machine '$VmName' already exists." -ForegroundColor Yellow
} else {
    Write-Host "[*] Creating new Generation 2 Virtual Machine..." -ForegroundColor Green
    if (Test-Path $VhdPath) {
        New-VM -Name $VmName -MemoryStartupBytes $MemoryBytes -Generation 2 -VHDPath $VhdPath -SwitchName $SwitchName
    } else {
        New-VM -Name $VmName -MemoryStartupBytes $MemoryBytes -Generation 2 -NewVHDPath $VhdPath -NewVHDSizeBytes 64GB -SwitchName $SwitchName
    }
}

# 3. Configure VM security and test-signing parameters
Write-Host "[*] Configuring VM settings for driver debugging..." -ForegroundColor Green
Set-VM -Name $VmName -ProcessorCount 4 -StaticMemory -MemoryStartupBytes $MemoryBytes
Set-VMFirmware -Name $VmName -EnableSecureBoot Off

Write-Host "`n[+] Sandbox Provisioning Steps for inside the VM:" -ForegroundColor Cyan
Write-Host "  1. Boot VM and install Windows 11 Enterprise"
Write-Host "  2. Open elevated Command Prompt inside VM and execute:"
Write-Host "     bcdedit /set testsigning on" -ForegroundColor Yellow
Write-Host "     bcdedit /set nointegritychecks on" -ForegroundColor Yellow
Write-Host "     bcdedit /debug on" -ForegroundColor Yellow
Write-Host "     bcdedit /dbgsettings net hostip:<HOST_IP> port:50000 key:1.2.3.4" -ForegroundColor Yellow
Write-Host "  3. Shutdown VM and take clean snapshot:"
Write-Host "     Checkpoint-VM -Name '$VmName' -SnapshotName 'CleanBaseline'" -ForegroundColor Yellow
Write-Host "`n[+] Kernel driver testing is now fully isolated from host OS." -ForegroundColor Green
