"""The SDK-held credential file (plan 3.4, SDKQS-4; contract
destination.md section 6a).

``setup`` writes it (and nothing else does); every SDK reads it. It holds the
member's SDK key and where it goes, so an app on a machine with no Observer
can send online with no environment variable. The path is per user, never
inside a project:

- ``SUPERBASED_CREDENTIAL_FILE`` when set (another user, a test);
- Windows: ``%LOCALAPPDATA%\\superbased\\sdk-credential``;
- elsewhere: ``$XDG_CONFIG_HOME/superbased/sdk-credential``, else
  ``~/.config/superbased/sdk-credential``.

The format is the machine file's (section 6): the first line
``<key_id>.<secret>``, then ``name=value`` lines (``gateway_url``,
``destination``, ``dashboard_url``, ``expires_at``; unknown names ignored), at
most 4096 bytes. The read rules are one table (``REFUSALS``): no symlink or
reparse point, a regular file, owner-only on unix (``mode & 0o077 == 0``),
owned by this user, and on Windows (ruling R4) under this user's own
``%LOCALAPPDATA%``.

The key never leaves this module except in ``Record.key``, which no repr,
message or diagnostic carries.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

ENV_PATH = "SUPERBASED_CREDENTIAL_FILE"
DIR_NAME = "superbased"
FILE_NAME = "sdk-credential"
MAX_BYTES = 4096
EXPIRY_WARN_DAYS = 14

GATEWAY_FIELD = "gateway_url"
DESTINATION_FIELD = "destination"
DASHBOARD_FIELD = "dashboard_url"
EXPIRES_FIELD = "expires_at"
# The order setup writes the fields in (fixtures/setup/sdk-credential-file.json).
FIELDS = (GATEWAY_FIELD, DESTINATION_FIELD, DASHBOARD_FIELD, EXPIRES_FIELD)
DESTINATIONS = ("online", "both")

POSIX = "posix"
WINDOWS = "windows"


def platform_of(os_name: str = os.name) -> str:
    return WINDOWS if os_name == "nt" else POSIX


def default_path(env: Mapping[str, str], *, platform: Optional[str] = None, home: Optional[str] = None) -> Tuple[str, str]:
    """(path, problem). ``problem`` is set (and ``path`` "") only when the
    platform's base folder is unknown (Windows with no ``LOCALAPPDATA``, or
    no home folder)."""
    override = (env.get(ENV_PATH) or "").strip()
    if override:
        return override, ""
    plat = platform or platform_of()
    if plat == WINDOWS:
        base = (env.get("LOCALAPPDATA") or "").strip()
        if not base:
            return "", "LOCALAPPDATA is not set, so there is no SDK-held key file"
        return _join(plat, base, DIR_NAME, FILE_NAME), ""
    xdg = (env.get("XDG_CONFIG_HOME") or "").strip()
    if xdg and xdg.startswith("/"):  # the XDG spec ignores a relative value
        return _join(plat, xdg, DIR_NAME, FILE_NAME), ""
    h = home if home is not None else _home()
    if not h:
        return "", "no home folder, so there is no SDK-held key file"
    return _join(plat, h, ".config", DIR_NAME, FILE_NAME), ""


def _join(plat: str, *parts: str) -> str:
    if plat == WINDOWS:
        import ntpath

        return ntpath.join(*parts)
    import posixpath

    return posixpath.join(*parts)


def _home() -> str:
    try:
        return os.path.expanduser("~") if os.path.expanduser("~") != "~" else ""
    except Exception:  # noqa: BLE001
        return ""


def path(env: Optional[Mapping[str, str]] = None) -> str:
    """The SDK-held file's path here ("" when the platform has none)."""
    return default_path(os.environ if env is None else env)[0]


# --- the read rules ----------------------------------------------------------------


@dataclass(frozen=True)
class FileFacts:
    """What the reader learned about the file before opening it."""

    platform: str = POSIX
    exists: bool = True
    symlink: bool = False
    reparse_point: bool = False  # Windows: a link, junction or other reparse point
    regular: bool = True
    mode: int = 0o600  # unix permission bits
    owned_by_user: Optional[bool] = True  # None: could not tell
    under_local_appdata: Optional[bool] = None  # Windows only; None: not checked
    size: int = 128  # bytes (the tests' default is an ordinary small file)


# The closed refusal vocabulary (credential-file-cases.json ``reasons``).
SYMLINK = "symlink"
NOT_REGULAR = "not_regular"
MODE = "mode"
OWNER = "owner"
TOO_LARGE = "too_large"
EMPTY = "empty"
BAD_KEY_LINE = "bad_key_line"
BAD_NAME_LINE = "bad_name_line"
REPARSE_POINT = "reparse_point"
OUTSIDE_LOCALAPPDATA = "outside_localappdata"

# (platforms, refused when, reason, why). Walked top-down; the first hit refuses.
REFUSALS: Tuple[Tuple[Tuple[str, ...], Callable[[FileFacts], bool], str, str], ...] = (
    ((POSIX, WINDOWS), lambda f: f.symlink, SYMLINK, "is a symlink"),
    ((WINDOWS,), lambda f: f.reparse_point, REPARSE_POINT, "is a reparse point (a link or junction)"),
    ((POSIX, WINDOWS), lambda f: not f.regular, NOT_REGULAR, "is not a regular file"),
    ((POSIX,), lambda f: bool(f.mode & 0o077), MODE, "is readable by other users (chmod 600)"),
    ((POSIX, WINDOWS), lambda f: f.owned_by_user is False, OWNER, "is owned by another user"),
    ((WINDOWS,), lambda f: f.owned_by_user is None, OWNER, "has an owner that could not be confirmed as this user"),
    ((WINDOWS,), lambda f: f.under_local_appdata is not True, OUTSIDE_LOCALAPPDATA, "is not under this user's %LOCALAPPDATA%"),
    ((POSIX, WINDOWS), lambda f: f.size > MAX_BYTES, TOO_LARGE, "is larger than 4096 bytes"),
    ((POSIX, WINDOWS), lambda f: f.size == 0, EMPTY, "is empty"),
)


def refusal(facts: FileFacts) -> str:
    """Why the file must not be read ("" when it may)."""
    return refusal_reason(facts)[1]


def refusal_reason(facts: FileFacts) -> Tuple[str, str]:
    """(reason, why) of the first refusal row that applies, else ("", "")."""
    for platforms, hit, reason, why in REFUSALS:
        if facts.platform in platforms and hit(facts):
            return reason, why
    return "", ""


# --- the record ------------------------------------------------------------------------


@dataclass(frozen=True)
class Record:
    """One read of the SDK-held file. ``state`` is ``absent``, ``refused``
    (``error`` says why; nothing else is set) or ``valid``. ``usable`` means
    a key and a gateway address that may receive it."""

    path: str = ""
    state: str = "absent"
    reason: str = ""  # refused: the closed reason (``REFUSALS`` and the format rules)
    key_id: str = ""
    gateway_url: str = ""
    destination: str = ""
    dashboard_url: str = ""
    expires_at: str = ""
    error: str = ""
    warnings: Tuple[str, ...] = ()
    ignored: Tuple[str, ...] = ()  # the field lines read but not used (a bad value)
    key: str = field(default="", repr=False, compare=False)

    @property
    def usable(self) -> bool:
        return self.state == VALID and bool(self.key and self.gateway_url)

    def expired(self, now: Optional[datetime] = None) -> bool:
        t = parse_time(self.expires_at)
        return t is not None and t <= (now or datetime.now(timezone.utc))

    def describe(self) -> Dict[str, Any]:
        """The non-secret facts (diagnostics(), setup --status)."""
        return {
            "path": self.path,
            "state": self.state,
            "key_id": self.key_id,
            "gateway_url": self.gateway_url,
            "destination": self.destination,
            "dashboard_url": self.dashboard_url,
            "expires_at": self.expires_at,
            "error": self.error,
        }


ABSENT = "absent"
REFUSED = "refused"
VALID = "valid"


def parse(raw: bytes, where: str = "the SDK-held key file") -> Tuple[str, Dict[str, str], str]:
    """(key, fields, error) of the file's bytes under section 6's format.
    ``fields`` holds every ``name=value`` line (the last one of a name
    wins); a malformed file is an error and yields no key. CRLF line ends
    read as LF."""
    key, fields, reason = parse_reason(raw)
    if reason:
        return "", {}, f"{where} is not one key line followed by name=value lines ({reason}); refused"
    return key, fields, ""


def parse_reason(raw: bytes) -> Tuple[str, Dict[str, str], str]:
    """(key, fields, reason): reason is ``too_large``, ``empty``,
    ``bad_key_line`` or ``bad_name_line`` for a malformed file, else ""."""
    if len(raw) > MAX_BYTES:
        return "", {}, TOO_LARGE
    if not raw:
        return "", {}, EMPTY
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return "", {}, BAD_KEY_LINE
    text = text.replace("\r\n", "\n")
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    key = lines[0]
    key_id, dot, secret = key.partition(".")
    if not dot or not key_id or not secret or any(c.isspace() for c in key):
        return "", {}, BAD_KEY_LINE
    fields: Dict[str, str] = {}
    for line in lines[1:]:
        name, eq, value = line.partition("=")
        if not eq or not name:
            return "", {}, BAD_NAME_LINE
        fields[name] = value.strip()
    return key, fields, ""


def record_from(path: str, key: str, fields: Mapping[str, str]) -> Record:
    """The record of a parsed file: each field checked on its own (a bad
    one is ignored with a warning, the key stays)."""
    from ._destination import gateway_problem

    warnings: List[str] = []
    ignored: List[str] = []
    gateway = fields.get(GATEWAY_FIELD, "")
    if gateway:
        problem = gateway_problem(gateway)
        if problem:
            warnings.append(f"{path} names a gateway address that is not usable ({problem}); the key in it is not used")
            ignored.append(GATEWAY_FIELD)
            gateway = ""
    else:
        warnings.append(f"{path} names no gateway address; the key in it is not used (run setup again)")
    raw_dest = fields.get(DESTINATION_FIELD)
    dest = (raw_dest or "").strip().lower()
    if raw_dest is not None and dest not in DESTINATIONS:
        warnings.append(f"{path} names destination {raw_dest!r}, which is not online or both; ignored")
        ignored.append(DESTINATION_FIELD)
        dest = ""
    dashboard = fields.get(DASHBOARD_FIELD, "")
    if dashboard and dashboard_problem(dashboard):
        warnings.append(f"{path} names a dashboard address that is not an https base ({dashboard!r}); ignored")
        ignored.append(DASHBOARD_FIELD)
        dashboard = ""
    expires = fields.get(EXPIRES_FIELD, "")
    if expires and parse_time(expires) is None:
        warnings.append(f"{path} names an expires_at that is not an RFC 3339 time ({expires!r}); ignored")
        ignored.append(EXPIRES_FIELD)
        expires = ""
    return Record(
        path=path,
        state=VALID,
        key_id=key.partition(".")[0],
        gateway_url=gateway.rstrip("/"),
        destination=dest,
        dashboard_url=dashboard.rstrip("/"),
        expires_at=expires,
        warnings=tuple(warnings),
        ignored=tuple(ignored),
        key=key,
    )


def dashboard_problem(url: str) -> str:
    """'' when ``url`` is an https base with a host, no user info, query or
    fragment (a dashboard address is only ever a link: never a place the
    key goes)."""
    from urllib.parse import urlsplit

    try:
        u = urlsplit(url)
        host = u.hostname or ""
    except ValueError:
        return "not a URL"
    if u.scheme != "https" or not host:
        return "not https"
    if u.username is not None or u.password is not None or u.query or u.fragment or u.path not in ("", "/"):
        return "not a base address"
    return ""


def parse_time(value: str) -> Optional[datetime]:
    """An RFC 3339 time (``Z`` or an offset), or None."""
    v = (value or "").strip()
    if not v:
        return None
    if v.endswith(("Z", "z")):
        v = v[:-1] + "+00:00"
    # Python before 3.11 takes only 3 or 6 fraction digits; Go writes up to 9.
    m = re.match(r"^(.*T\d\d:\d\d:\d\d)\.(\d+)(.*)$", v)
    if m:
        v = m.group(1) + "." + (m.group(2) + "000000")[:6] + m.group(3)
    try:
        t = datetime.fromisoformat(v)
    except ValueError:
        return None
    if t.tzinfo is None:
        return None
    return t


def expiry_warning(rec: Record, now: Optional[datetime] = None) -> str:
    """A diagnostic from 14 days before ``expires_at`` ("" otherwise)."""
    t = parse_time(rec.expires_at)
    if t is None:
        return ""
    now = now or datetime.now(timezone.utc)
    left = t - now
    fix = "run `uvx superbased-sdk setup --online --replace` (or `npx @superbased/sdk setup --online --replace`)"
    if left.total_seconds() <= 0:
        return f"the SDK key in {rec.path} expired at {rec.expires_at}; {fix}"
    if left.days < EXPIRY_WARN_DAYS:
        return f"the SDK key in {rec.path} expires at {rec.expires_at} (in {max(1, left.days)} day(s)); {fix}"
    return ""


# --- reading -----------------------------------------------------------------------------


def read(file_path: str, *, env: Optional[Mapping[str, str]] = None) -> Record:
    """Read the SDK-held file at ``file_path`` under the platform's rules.
    A missing file is ``absent`` (no warning); a refused one carries why."""
    if not file_path:
        return Record(path="", state=ABSENT)
    plat = platform_of()
    facts = _facts(file_path, plat, os.environ if env is None else env)
    if not facts.exists:
        return Record(path=file_path, state=ABSENT)
    reason, why = refusal_reason(facts)
    if reason:
        return Record(path=file_path, state=REFUSED, reason=reason, error=f"the SDK-held key file {file_path} {why}; refused")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(file_path, flags)
        with os.fdopen(fd, "rb") as f:
            raw = f.read(MAX_BYTES + 1)
    except OSError as exc:
        return Record(
            path=file_path,
            state=REFUSED,
            reason=NOT_REGULAR,
            error=f"cannot read the SDK-held key file {file_path}: {exc.strerror or type(exc).__name__}",
        )
    key, fields, reason = parse_reason(raw)
    if reason:
        return Record(
            path=file_path,
            state=REFUSED,
            reason=reason,
            error=f"the SDK-held key file {file_path} is not one key line followed by name=value lines ({reason}); refused",
        )
    return record_from(file_path, key, fields)


def _facts(file_path: str, plat: str, env: Mapping[str, str]) -> FileFacts:
    try:
        st = os.lstat(file_path)
    except FileNotFoundError:
        return FileFacts(platform=plat, exists=False)
    except OSError:
        return FileFacts(platform=plat, exists=False)
    reparse = bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    if plat == WINDOWS:
        owned = _windows_owner_is_user(file_path)
        under = _under(file_path, (env.get("LOCALAPPDATA") or "").strip())
    else:
        getuid = getattr(os, "getuid", None)
        owned = (st.st_uid == getuid()) if getuid is not None else None
        under = None
    return FileFacts(
        platform=plat,
        exists=True,
        symlink=stat.S_ISLNK(st.st_mode),
        reparse_point=reparse if plat == WINDOWS else False,
        regular=stat.S_ISREG(st.st_mode),
        mode=stat.S_IMODE(st.st_mode),
        owned_by_user=owned,
        under_local_appdata=under,
        size=st.st_size,
    )


def _under(file_path: str, base: str) -> bool:
    if not base:
        return False
    try:
        f = os.path.normcase(os.path.realpath(file_path))
        b = os.path.normcase(os.path.realpath(base))
    except (OSError, ValueError):
        return False
    return f.startswith(b.rstrip("\\/") + os.sep)


def _windows_owner_is_user(file_path: str) -> Optional[bool]:
    """True when the file's owner SID is this process's user SID; None when
    it cannot be told (the reader then refuses)."""
    if sys.platform != "win32":
        return None
    try:
        from . import _winsec

        return _winsec.owner_is_current_user(file_path)
    except Exception:  # noqa: BLE001
        return None
