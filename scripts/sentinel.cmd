@echo off
setlocal

if "%~1"=="" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py"
    goto :eof
)

if /i "%~1"=="gui" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --gui
    goto :eof
)

if /i "%~1"=="start" (
    wscript "C:\Users\johns\sentinel-core\scripts\start-sentinel-background.vbs"
    echo [+] SentinelCore Real-Time Shield started in background.
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

if /i "%~1"=="autorun" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --autorun
    goto :eof
)

if /i "%~1"=="net" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --net
    goto :eof
)

if /i "%~1"=="procs" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --procs
    goto :eof
)

if /i "%~1"=="integrity" (
    python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" --integrity
    goto :eof
)

python "C:\Users\johns\sentinel-core\scripts\run-sentinel.py" %*
