"""
Heuristic Multi-Signal Risk Analyzer for SentinelCore
Performs deep static heuristic inspection on scripts, Office documents, and executables.
Computes a composite threat risk score (0-100) based on malicious API imports,
obfuscation indicators, and macro execution vectors.
"""

import os
import re
import zipfile
from typing import Dict, List, Any

# Dangerous Windows API imports used in process injection and memory hollowing
DANGEROUS_APIS = {
    b"VirtualAllocEx": 15,
    b"WriteProcessMemory": 20,
    b"CreateRemoteThread": 25,
    b"NtUnmapViewOfSection": 30,
    b"QueueUserAPC": 20,
    b"SetWindowsHookEx": 15,
    b"AdjustTokenPrivileges": 15,
    b"IsDebuggerPresent": 5,
    b"OpenProcess": 10
}

# Suspicious Script & PowerShell Keywords
SCRIPT_INDICATORS = [
    (re.compile(rb"downloadstring\s*\(", re.IGNORECASE), "PowerShell.DownloadString", 30),
    (re.compile(rb"invoke-expression|iex\s+", re.IGNORECASE), "PowerShell.InvokeExpression", 25),
    (re.compile(rb"\[System\.Convert\]::FromBase64String", re.IGNORECASE), "PowerShell.Base64Decode", 20),
    (re.compile(rb"WScript\.Shell|Shell\.Application", re.IGNORECASE), "Script.ShellExecution", 20),
    (re.compile(rb"URLDownloadToFile", re.IGNORECASE), "Script.UrlDownload", 25),
    (re.compile(rb"AutoOpen|Workbook_Open|Document_Open", re.IGNORECASE), "Office.AutoExecMacro", 35),
    (re.compile(rb"cmd\.exe\s+/c\s+powershell", re.IGNORECASE), "ProcessChain.CmdToPowerShell", 25)
]

class HeuristicAnalyzer:
    def __init__(self):
        pass

    def analyze_bytes(self, data: bytes, filename: str = "") -> Dict[str, Any]:
        """Calculates composite heuristic risk score and indicators."""
        score = 0
        indicators: List[str] = []

        # 1. Check for dangerous Win32 API imports
        for api, weight in DANGEROUS_APIS.items():
            if api in data:
                score += weight
                indicators.append(f"DangerousApi({api.decode('ascii')})")

        # 2. Check for suspicious scripting and macro execution patterns
        for pattern, tag, weight in SCRIPT_INDICATORS:
            if pattern.search(data):
                score += weight
                indicators.append(tag)

        # 3. Check for Malicious Office Macro in ZIP container (e.g. .docm, .xlsm)
        if data[:4] == b"PK\x03\x04":
            score += self._inspect_zip_macro(data, indicators)

        score = min(score, 100)

        risk_level = "CLEAN"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        elif score > 0:
            risk_level = "LOW"

        return {
            "score": score,
            "risk_level": risk_level,
            "is_suspicious": score >= 50,
            "indicators": indicators
        }

    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            return {"score": 0, "risk_level": "CLEAN", "is_suspicious": False, "indicators": []}

        try:
            with open(file_path, "rb") as f:
                header = f.read(2 * 1024 * 1024)  # 2MB inspection window
            return self.analyze_bytes(header, os.path.basename(file_path))
        except Exception:
            return {"score": 0, "risk_level": "CLEAN", "is_suspicious": False, "indicators": []}

    def _inspect_zip_macro(self, data: bytes, indicators: List[str]) -> int:
        """Inspects OpenXML zip structures for embedded VBA projects."""
        added_score = 0
        try:
            import io
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for name in zf.namelist():
                    if "vbaProject.bin" in name or "vbaData.xml" in name:
                        indicators.append("Office.EmbeddedVbaMacroBinary")
                        added_score += 40
                        break
        except Exception:
            pass
        return added_score
