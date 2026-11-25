"""Writing and removing the SDK-held key file (plan 3.4, SDKQS-4). Setup is
its only writer; the runtime SDK only reads it (``_credfile``).

The write is atomic and owner-only: the folders setup creates are 0700, the
key goes to a temporary file in the same folder opened with ``O_CREAT |
O_EXCL | O_NOFOLLOW`` and mode 0600, fsynced, restricted to this user on
Windows (a protected DACL: the user, SYSTEM and Administrators), then
renamed over the target. The result is read back with the runtime's own
reader, so a file the SDK would refuse is never reported as stored.
"""

from __future__ import annotations

import os
import secrets as _random
from typing import List, Optional, Sequence, Tuple, Union

from .. import _credfile


class StoreError(Exception):
    """A write or a removal failed; the message never carries the key."""


# Windows (ruling R4): the readers refuse a file whose owner SID is not the
# current user, and an elevated process's files can be owned by
# BUILTIN\Administrators. The writer sets the owner and the DACL, reads the
# owner back, and decides from those facts, walked top-down:
# (security set, owner read back: True is this user, False another, None
# unknown, ANY any) -> the refusal ("" keeps the file).
ELEVATED_HINT = "run setup from a normal (not elevated) prompt, as the user whose apps will read the key"
ANY = "any"
WINDOWS_WRITE_ROWS: Tuple[Tuple[bool, Union[bool, None, str], str], ...] = (
    (False, ANY, "cannot set this user as the owner of {path} and restrict it to them; " + ELEVATED_HINT),
    (True, True, ""),
    (True, False, "{path} is still owned by another account (an elevated prompt's files can be owned by Administrators); " + ELEVATED_HINT),
    (True, None, "cannot read back the owner of {path}; " + ELEVATED_HINT),
)


def windows_write_decision(security_set: bool, owner_is_user: Optional[bool], path: str) -> str:
    """Why a Windows write must be refused ("" when the file may stay)."""
    for set_ok, owner, why in WINDOWS_WRITE_ROWS:
        if set_ok == security_set and (owner == ANY or owner is owner_is_user):
            return why.format(path=path)
    return f"cannot secure {path}; " + ELEVATED_HINT


def lines(key: str, gateway_url: str, destination: str, dashboard_url: str, expires_at: str) -> List[str]:
    """The file's lines in setup's order (fixtures/setup/sdk-credential-file.json)."""
    out = [key, f"{_credfile.GATEWAY_FIELD}={gateway_url}", f"{_credfile.DESTINATION_FIELD}={destination}"]
    if dashboard_url:
        out.append(f"{_credfile.DASHBOARD_FIELD}={dashboard_url}")
    if expires_at:
        out.append(f"{_credfile.EXPIRES_FIELD}={expires_at}")
    return out


def _make_dirs(path: str) -> None:
    """Create the missing folders above ``path``, each 0700."""
    missing = []
    d = os.path.dirname(os.path.abspath(path))
    while d and not os.path.isdir(d):
        missing.append(d)
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    for d in reversed(missing):
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        if os.name == "nt":
            from .. import _winsec

            _winsec.set_owner_only(d, directory=True)
        else:
            os.chmod(d, 0o700)


def write(path: str, file_lines: Sequence[str]) -> _credfile.Record:
    """Write the file atomically; the record the runtime reads back."""
    if not path:
        raise StoreError("there is no SDK-held key file path on this computer")
    data = ("\n".join(file_lines) + "\n").encode("ascii")
    if len(data) > _credfile.MAX_BYTES:
        raise StoreError("the SDK key record is larger than 4096 bytes")
    try:
        _make_dirs(path)
    except OSError as exc:
        raise StoreError(f"cannot create the folder for {path}: {exc.strerror or type(exc).__name__}") from None
    folder = os.path.dirname(os.path.abspath(path))
    tmp = os.path.join(folder, f".{os.path.basename(path)}.{_random.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(tmp, flags, 0o600)
    except OSError as exc:
        raise StoreError(f"cannot write {path}: {exc.strerror or type(exc).__name__}") from None
    try:
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        if os.name == "nt":
            from .. import _winsec

            security_set = _winsec.set_owner_only(tmp)
            why = windows_write_decision(security_set, _winsec.owner_is_current_user(tmp) if security_set else None, path)
            if why:
                raise StoreError(why)
        else:
            os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except StoreError:
        _unlink(tmp)
        raise
    except OSError as exc:
        _unlink(tmp)
        raise StoreError(f"cannot write {path}: {exc.strerror or type(exc).__name__}") from None
    if os.name != "nt":
        try:
            dfd = os.open(folder, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    rec = _credfile.read(path)
    if not rec.usable:
        raise StoreError(f"{path} was written but the SDK would not use it: {rec.error or '; '.join(rec.warnings) or 'unknown'}")
    return rec


def _unlink(p: str) -> None:
    try:
        os.unlink(p)
    except OSError:
        pass


def remove(path: str) -> bool:
    """Remove the file (a link itself, never what it points at). True when
    it was there and is gone."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise StoreError(f"cannot remove {path}: {exc.strerror or type(exc).__name__}") from None
    return True
