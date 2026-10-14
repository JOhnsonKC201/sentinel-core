"""
Desktop Notification & Alert Dispatcher for SentinelCore
Displays Windows desktop notifications and logs security events.
"""

import os
import subprocess
import time
from typing import Optional

def notify_threat_blocked(title: str, message: str, threat_path: str = ""):
    """Dispatches a Windows toast/balloon notification and appends to alert log."""
    print(f"\n[!] ==================== SECURITY THREAT BLOCKED ====================")
    print(f"[!] Alert:   {title}")
    print(f"[!] Detail:  {message}")
    if threat_path:
        print(f"[!] Path:    {threat_path}")
    print(f"[!] Status:  Neutralized and isolated to Quarantine Vault.")
    print(f"[!] ==================================================================\n")

    # Append to local audit log
    log_dir = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "SentinelCore")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "threats.log")
    
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] [THREAT_NEUTRALIZED] {title} - {message} ({threat_path})\n")

    _show_toast(title, message)


# The toast text is attacker controlled (file and process names), so it is
# handed to PowerShell through environment variables and read as data. It is
# never pasted into the script, where "$(...)" would execute.
CREATE_NO_WINDOW = 0x08000000
TOAST_SCRIPT = (
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
    "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
    "$textNodes = $template.GetElementsByTagName('text'); "
    "$textNodes.Item(0).AppendChild($template.CreateTextNode($env:SENTINEL_TOAST_TITLE)) > $null; "
    "$textNodes.Item(1).AppendChild($template.CreateTextNode($env:SENTINEL_TOAST_MESSAGE)) > $null; "
    "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('SentinelCore Antivirus').Show($toast)"
)


def _show_toast(title: str, message: str):
    env = dict(os.environ, SENTINEL_TOAST_TITLE=title, SENTINEL_TOAST_MESSAGE=message)
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", TOAST_SCRIPT],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError:
        pass
