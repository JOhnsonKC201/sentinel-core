"""
Trust checks that keep SentinelCore from acting on legitimate software.

* is_protected_system_path: files under %SystemRoot% belong to Windows. They
  are mostly catalog signed, cannot be removed without admin rights anyway,
  and killing them (winlogon.exe, SearchProtocolHost.exe) breaks the session.
* has_valid_signature: an embedded Authenticode signature that verifies. The
  entropy and heuristic tiers are guesses, and a signed installer is exactly
  the packed, high-entropy kind of file they misjudge.
"""

import ctypes
import os
from ctypes import wintypes

_SYSTEM_ROOT = os.path.normcase(os.path.abspath(os.environ.get("SystemRoot", r"C:\Windows")))


def is_protected_system_path(path: str) -> bool:
    candidate = os.path.normcase(os.path.abspath(path))
    try:
        return os.path.commonpath([candidate, _SYSTEM_ROOT]) == _SYSTEM_ROOT
    except ValueError:  # different drives
        return False


class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


class _WinTrustFileInfo(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.POINTER(_GUID))]


class _WinTrustData(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", wintypes.LPVOID),
                ("pSIPClientData", wintypes.LPVOID), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(_WinTrustFileInfo)), ("dwStateAction", wintypes.DWORD),
                ("hWVTStateData", wintypes.HANDLE), ("pwszURLReference", wintypes.LPCWSTR),
                ("dwProvFlags", wintypes.DWORD), ("dwUIContext", wintypes.DWORD),
                ("pSignatureSettings", wintypes.LPVOID)]


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))
_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000  # never block a scan on the network
_INVALID_HANDLE_VALUE = wintypes.HWND(-1)

try:
    _wintrust = ctypes.WinDLL("wintrust")
    _wintrust.WinVerifyTrust.argtypes = (wintypes.HWND, ctypes.POINTER(_GUID), ctypes.POINTER(_WinTrustData))
    _wintrust.WinVerifyTrust.restype = ctypes.c_long
except OSError:  # not Windows
    _wintrust = None


def has_valid_signature(path: str) -> bool:
    """True when the file carries an embedded Authenticode signature that verifies."""
    if _wintrust is None or not os.path.isfile(path):
        return False
    file_info = _WinTrustFileInfo(ctypes.sizeof(_WinTrustFileInfo), path, None, None)
    data = _WinTrustData()
    data.cbStruct = ctypes.sizeof(_WinTrustData)
    data.dwUIChoice = _WTD_UI_NONE
    data.fdwRevocationChecks = _WTD_REVOKE_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _WTD_STATEACTION_VERIFY
    data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL
    action = _GUID.from_buffer_copy(_WINTRUST_ACTION_GENERIC_VERIFY_V2)
    try:
        result = _wintrust.WinVerifyTrust(_INVALID_HANDLE_VALUE, ctypes.byref(action), ctypes.byref(data))
    finally:
        data.dwStateAction = _WTD_STATEACTION_CLOSE
        _wintrust.WinVerifyTrust(_INVALID_HANDLE_VALUE, ctypes.byref(action), ctypes.byref(data))
    return result == 0
