"""
One SentinelCore window per Windows session.

The app starts hidden at login, so a second launch from the Start menu must
not start a second set of shields. It signals the running copy to show its
window through a named event, then exits.
"""

import ctypes
from ctypes import wintypes
from typing import Optional

ERROR_ALREADY_EXISTS = 183
WAIT_OBJECT_0 = 0
MUTEX_NAME = "Local\\SentinelCoreDesktopApp"
SHOW_EVENT_NAME = "Local\\SentinelCoreDesktopShow"

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
_kernel32.CreateMutexW.restype = wintypes.HANDLE
_kernel32.CreateEventW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR)
_kernel32.CreateEventW.restype = wintypes.HANDLE
_kernel32.SetEvent.argtypes = (wintypes.HANDLE,)
_kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
_kernel32.WaitForSingleObject.restype = wintypes.DWORD
_kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)


class SingleInstance:
    def __init__(self, mutex_name: str = MUTEX_NAME, event_name: str = SHOW_EVENT_NAME):
        self._mutex = _kernel32.CreateMutexW(None, False, mutex_name)
        self.is_primary = ctypes.get_last_error() != ERROR_ALREADY_EXISTS
        # Auto-reset event: one WaitForSingleObject consumes one show request.
        self._show_event: Optional[int] = _kernel32.CreateEventW(None, False, False, event_name)

    def ask_primary_to_show(self):
        if self._show_event:
            _kernel32.SetEvent(self._show_event)

    def show_requested(self) -> bool:
        if not self._show_event:
            return False
        return _kernel32.WaitForSingleObject(self._show_event, 0) == WAIT_OBJECT_0

    def release(self):
        for handle in (self._show_event, self._mutex):
            if handle:
                _kernel32.CloseHandle(handle)
        self._show_event = None
        self._mutex = None
