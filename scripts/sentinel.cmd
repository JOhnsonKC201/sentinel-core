@echo off
setlocal

if "%~1"=="" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py"
    goto :eof
)

if /i "%~1"=="web" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --web
    goto :eof
)

if /i "%~1"=="gui" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --web
    goto :eof
)

if /i "%~1"=="start" (
    wscript "C:\Users\johns\sentinel-core\scripts\start-sentinel-background.vbs"
    echo [+] SentinelCore Real-Time Shield started in background.
    echo [*] Web Management Dashboard is live at: http://127.0.0.1:8765
    goto :eof
)

if /i "%~1"=="stop" (
    powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*run-sentinel.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Host ('[+] Terminated Sentinel PID: ' + $_.ProcessId) }"
    goto :eof
)

if /i "%~1"=="scan" (
    if "%~2"=="" (
        echo [!] Usage: sentinel scan ^<path^>
        goto :eof
    )
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --scan "%~2"
    goto :eof
)

if /i "%~1"=="status" (
    powershell -NoProfile -Command "try { $s = Invoke-RestMethod 'http://127.0.0.1:8765/api/status' -TimeoutSec 2; Write-Host '[+] Real-Time Shield: ' $s.status -ForegroundColor Green; Write-Host '[*] Reputation Cache: ' $s.reputation_cache_size 'signatures'; Write-Host '[*] Quarantine Vault: ' $s.active_quarantined_threats 'threats isolated'; Write-Host '[*] Events Inspected: ' $s.fs_events_processed 'I/O events' } catch { Write-Host '[*] Sentinel background shield not running. Launching interactive console...' -ForegroundColor Yellow; python 'C:\Users\johns\sentinel-core\scripts\run-sentinel.py' }"
    goto :eof
)

python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" %*
