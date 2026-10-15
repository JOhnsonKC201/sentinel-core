; Inno Setup script for SentinelCore. Build with scripts/build-installer.ps1,
; which passes AppVersion and the PyInstaller output folder.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef DistDir
  #define DistDir "..\dist\SentinelCore"
#endif

[Setup]
AppId={{6B1E9F0C-3A57-4E8B-9C3D-5E2B7A41C0D9}
AppName=SentinelCore
AppVersion={#AppVersion}
AppPublisher=SentinelCore
AppPublisherURL=https://github.com/JOhnsonKC201/sentinel-core
DefaultDirName={localappdata}\Programs\SentinelCore
DefaultGroupName=SentinelCore
DisableProgramGroupPage=yes
; Per-user install: no admin prompt. Quarantine data lives in ProgramData.
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=SentinelCore-Setup-{#AppVersion}
SetupIconFile=..\build\SentinelCore.ico
UninstallDisplayIcon={app}\SentinelCore.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
RestartApplications=no

[Tasks]
Name: "startup"; Description: "Start SentinelCore when I sign in (keeps real-time protection on)"; GroupDescription: "Protection:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "{#DistDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\SentinelCore"; Filename: "{app}\SentinelCore.exe"
Name: "{group}\Uninstall SentinelCore"; Filename: "{uninstallexe}"
Name: "{userdesktop}\SentinelCore"; Filename: "{app}\SentinelCore.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "SentinelCore"; ValueData: """{app}\SentinelCore.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\SentinelCore.exe"; Description: "Open SentinelCore now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop the running app (it lives in the tray) so its files can be removed.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM SentinelCore.exe"; Flags: runhidden; RunOnceId: "StopSentinelCore"

[UninstallDelete]
; The integrity baseline is regenerated at runtime if missing; remove it with the app.
Type: filesandordirs; Name: "{app}\_internal\data"

[Messages]
FinishedLabel=SentinelCore is installed. Your quarantine vault and settings are kept in %ProgramData%\SentinelCore, and stay there if you uninstall.
