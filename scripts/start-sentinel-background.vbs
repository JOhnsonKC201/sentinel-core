' SentinelCore Silent Background Launcher
' Starts pythonw scripts/run-sentinel.py --daemon in the background without a console window

Set WshShell = CreateObject("WScript.Shell")
strCommand = """C:\Users\johns\AppData\Local\Programs\Python\Python313\pythonw.exe"" ""C:\Users\johns\sentinel-core\scripts\run-sentinel.py"" --daemon"
WshShell.Run strCommand, 0, False
Set WshShell = Nothing
