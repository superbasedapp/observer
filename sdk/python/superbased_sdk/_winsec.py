"""Windows file security for the SDK-held key file (ruling R4), standard
library ``ctypes`` only, loaded only on Windows.

- ``owner_is_current_user(path)``: the reader's check that the file's owner
  SID is this process's user SID.
- ``set_owner_only(path, directory=False)``: what ``setup`` applies after it
  writes the file (and its folder): the owner set to the current user (a
  file an elevated process creates can be owned by ``BUILTIN\Administrators``,
  which the readers refuse) and a protected DACL granting full control to the
  user, SYSTEM and Administrators only. ``setup``'s writer then reads the
  owner back (``store.windows_write_decision``).

Every function returns None (or False) instead of raising when the Windows
API is not there or fails; the caller decides (the reader refuses).
"""

from __future__ import annotations

import sys
from typing import Any, Optional

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1  # TokenUser
SDDL_REVISION_1 = 1


def _api() -> Any:
    if sys.platform != "win32":
        raise OSError("not Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PSID = ctypes.c_void_p
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(PSID), ctypes.POINTER(PSID), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, PSID, PSID, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [PSID, PSID]
    advapi32.EqualSid.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [PSID, ctypes.POINTER(wintypes.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    return ctypes, wintypes, advapi32, kernel32


class _UserSid:
    """This process's user SID (a buffer kept alive while it is used)."""

    def __init__(self) -> None:
        ctypes, wintypes, advapi32, kernel32 = _api()
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(token)):
            raise OSError("OpenProcessToken failed")
        try:
            size = wintypes.DWORD(0)
            advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
            if not size.value:
                raise OSError("GetTokenInformation gave no size")
            self._buf = ctypes.create_string_buffer(size.value)
            if not advapi32.GetTokenInformation(token, TOKEN_USER_CLASS, self._buf, size, ctypes.byref(size)):
                raise OSError("GetTokenInformation failed")
        finally:
            kernel32.CloseHandle(token)
        # TOKEN_USER starts with SID_AND_ATTRIBUTES, whose first member is the PSID.
        self.sid = ctypes.c_void_p.from_buffer(self._buf).value

    def string(self) -> str:
        ctypes, wintypes, advapi32, kernel32 = _api()
        out = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(self.sid, ctypes.byref(out)):
            raise OSError("ConvertSidToStringSidW failed")
        try:
            return str(out.value)
        finally:
            kernel32.LocalFree(ctypes.cast(out, ctypes.c_void_p))


def owner_is_current_user(path: str) -> Optional[bool]:
    """True or False; None when it cannot be told."""
    try:
        ctypes, wintypes, advapi32, kernel32 = _api()
        owner = ctypes.c_void_p()
        sd = ctypes.c_void_p()
        rc = advapi32.GetNamedSecurityInfoW(
            path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(owner), None, None, None, ctypes.byref(sd)
        )
        if rc != 0:
            return None
        try:
            user = _UserSid()
            return bool(advapi32.EqualSid(owner, user.sid))
        finally:
            kernel32.LocalFree(sd)
    except Exception:  # noqa: BLE001
        return None


def set_owner_only(path: str, directory: bool = False) -> bool:
    """Replace the DACL of ``path`` with a protected one: full control for
    this user, SYSTEM and Administrators, nothing inherited. True on
    success."""
    try:
        ctypes, wintypes, advapi32, kernel32 = _api()
        user = _UserSid()
        sid = user.string()
        flags = "OICI" if directory else ""
        sddl = f"D:P(A;{flags};FA;;;{sid})(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
        sd = ctypes.c_void_p()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, ctypes.byref(sd), None):
            return False
        try:
            present = wintypes.BOOL()
            defaulted = wintypes.BOOL()
            dacl = ctypes.c_void_p()
            if not advapi32.GetSecurityDescriptorDacl(sd, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
                return False
            what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
            rc = advapi32.SetNamedSecurityInfoW(path, SE_FILE_OBJECT, what, user.sid, None, dacl, None)
            return rc == 0
        finally:
            kernel32.LocalFree(sd)
    except Exception:  # noqa: BLE001
        return False
