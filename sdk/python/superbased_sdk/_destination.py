"""Where the SDK sends data: ``local`` (the machine), ``online`` (the org or
SaaS gateway) or ``both`` (plan D18; contract
docs/plans/plane-a-sdk-buildout/contracts/destination.md).

``resolve()`` turns the settings, the environment and (when needed) the
machine's loopback discovery answer into a ``Plan``: the export targets, the
admit() target and the control-API bases. ``both`` means two independent
exporters, so a down destination never blocks the other, and it never depends
on the machine's org push tiers.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from . import _http
from ._config import DEFAULT_ENDPOINT, TRACES_PATH, Destination, Settings, parse_kv_list

LOG = logging.getLogger("superbased_sdk")

LOCAL = "local"
ONLINE = "online"
BOTH = "both"
VALUES = (LOCAL, ONLINE, BOTH)

DEFAULT_NODE_URL = "http://127.0.0.1:8081"
DISCOVERY_PATH = "/api/sdk/destination"
DISCOVERY_TIMEOUT = 0.5  # seconds, one attempt (contract section 4)
ADMISSION_PATH = "/api/obs/admission/check"
SDK_ADMIT_PATH = "/v1/sdk/admit"

_LOCAL_HEADER_ENVS = ("OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS")


@dataclass(frozen=True)
class Plan:
    """The resolved destination. ``exporters`` is what init() builds; the
    rest serves admit(), scores, prompts and experiments."""

    destination: str = LOCAL
    source: str = "default"  # argument | env | machine | default
    exporters: Tuple[Destination, ...] = ()
    node_url: str = DEFAULT_NODE_URL  # the machine's dashboard API (loopback)
    gateway_url: str = ""  # the org gateway base ("" when unknown)
    online_ready: bool = False  # gateway URL and credential both present
    admit_url: str = ""
    # This machine's admission check (loopback), whatever the destination:
    # where admit() goes when the org answers "admission off" under both.
    machine_admit_url: str = ""
    degraded: str = ""  # what is missing for the chosen destination, "" when nothing
    warnings: Tuple[str, ...] = ()
    notes: Tuple[str, ...] = ()  # informational (no machine answered discovery)
    signed_in: Optional[bool] = None  # from discovery; None when not asked
    credential_source: str = ""  # argument | env | file | ""
    # The online credential. Never logged, never in diagnostics, never sent to
    # the machine or to any host but gateway_url.
    _key: str = field(default="", repr=False, compare=False)

    def online_headers(self) -> Dict[str, str]:
        return {"Authorization": "Bearer " + self._key} if self._key else {}

    @property
    def local_enabled(self) -> bool:
        return self.destination in (LOCAL, BOTH) or (self.destination == ONLINE and not self.online_ready)

    @property
    def online_enabled(self) -> bool:
        return self.destination in (ONLINE, BOTH) and self.online_ready

    def summary(self) -> Dict[str, Any]:
        return {
            "destination": self.destination,
            "destination_source": self.source,
            "destinations": [{"name": d.name, "endpoint": d.endpoint} for d in self.exporters],
            "gateway_url": self.gateway_url,
            "degraded": self.degraded,
            "warnings": list(self.warnings),
            "notes": list(self.notes),
            "signed_in": self.signed_in,
            "credential_source": self.credential_source,
        }


# --- discovery -------------------------------------------------------------------

_cache_lock = threading.Lock()
_cache: Dict[str, Tuple[Optional[Dict[str, Any]], str]] = {}


def discover(node_url: str, fetch: Optional[Callable[..., _http.Response]] = None) -> Tuple[Optional[Dict[str, Any]], str]:
    """(body, error) of the machine's discovery route, cached per process.
    Only a loopback ``node_url`` is asked (the answer names a local file)."""
    with _cache_lock:
        if node_url in _cache:
            return _cache[node_url]
    if not _http.is_loopback_url(node_url):
        out: Tuple[Optional[Dict[str, Any]], str] = (None, f"SUPERBASED_NODE_URL {node_url} is not a loopback address; destination discovery skipped")
    else:
        resp = (fetch or _http.request)("GET", _http.join(node_url, DISCOVERY_PATH), timeout=DISCOVERY_TIMEOUT)
        if resp.status != 200:
            out = (None, f"machine destination discovery failed: {resp.describe()}")
        elif not isinstance(resp.body, dict) or resp.body.get("api_version") != 1:
            out = (None, "machine destination discovery answered an unknown api_version")
        else:
            out = (resp.body, "")
    with _cache_lock:
        _cache[node_url] = out
    return out


def reset_cache() -> None:
    with _cache_lock:
        _cache.clear()


# --- credential file ---------------------------------------------------------------


CREDENTIAL_GATEWAY_FIELD = "gateway_url"


def read_credential_file(path: str) -> Tuple[str, str]:
    """(compound, error); see ``read_credential_record``."""
    key, _gateway, err = read_credential_record(path)
    return key, err


def read_credential_record(path: str) -> Tuple[str, str, str]:
    """(compound, gateway, error). Unix rules (contract section 6): no
    symlink, no group/other permission bits, owned by this user. The first
    line is ``<key_id>.<secret>``; each further line is ``name=value``, where
    ``gateway_url`` names the only address the key is sent to (review E-04:
    the address comes from this owner-only file, never from the discovery
    answer). Unknown names are ignored; a gateway that is not https (or
    http to this machine) is refused."""
    if not path:
        return "", "", ""
    if os.name == "nt":
        return "", "", "credential files are not read on Windows; set SUPERBASED_API_KEY"
    try:
        st = os.lstat(path)
    except OSError as exc:
        return "", "", f"cannot read the SDK credential file: {exc.strerror or exc}"
    if stat.S_ISLNK(st.st_mode):
        return "", "", "the SDK credential file is a symlink; refused"
    if not stat.S_ISREG(st.st_mode):
        return "", "", "the SDK credential file is not a regular file; refused"
    if st.st_mode & 0o077:
        return "", "", "the SDK credential file is readable by other users; refused (chmod 600)"
    getuid = getattr(os, "getuid", None)
    if getuid is not None and st.st_uid != getuid():
        return "", "", "the SDK credential file is owned by another user; refused"
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as f:
            raw = f.read(4097)
    except OSError as exc:
        return "", "", f"cannot read the SDK credential file: {exc.strerror or exc}"
    bad = "the SDK credential file is not one key line followed by name=value lines; refused"
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return "", "", bad
    if len(raw) > 4096:
        return "", "", bad
    if text.endswith("\n"):
        text = text[:-1]
    lines = text.split("\n")
    key = lines[0]
    key_id, dot, secret = key.partition(".")
    if not dot or not key_id or not secret or any(c.isspace() for c in key):
        return "", "", bad
    gateway = ""
    for line in lines[1:]:
        name, eq, value = line.partition("=")
        if not eq or not name:
            return "", "", bad
        if name == CREDENTIAL_GATEWAY_FIELD:
            gateway = value.strip()
    if gateway:
        problem = gateway_problem(gateway)
        if problem:
            return key, "", f"the SDK credential file names a gateway address that is not usable ({problem}); it is ignored"
    return key, gateway.rstrip("/"), ""


def gateway_problem(url: str) -> str:
    """'' when ``url`` is a usable gateway base for the key: https (or http to
    a loopback host), a host, no user info, query, fragment or path."""
    from urllib.parse import urlsplit

    try:
        u = urlsplit(url)
        host = u.hostname or ""
    except ValueError:
        return f"{url!r} is not a URL"
    if u.scheme not in ("http", "https") or not host:
        return f"{url!r} is not an http(s) address with a host"
    if u.username is not None or u.password is not None:
        return f"{url!r} carries a user name or password"
    if u.query or u.fragment or u.path not in ("", "/"):
        return f"{url!r} is not a base address"
    if u.scheme != "https" and not _http.is_loopback_url(url):
        return f"{url!r} is plain http to a remote host"
    return ""


def _loopback_local_info(local: Mapping[str, Any], warnings: List[str]) -> Dict[str, Any]:
    """The discovery answer's local URLs, keeping only loopback ones (review
    E-04): a machine's receiver and admission check are on this machine, so a
    remote address there is not the machine speaking."""
    out = dict(local)
    for k in ("otlp_traces_url", "admission_url"):
        v = out.get(k)
        if isinstance(v, str) and v and not _http.is_loopback_url(v):
            warnings.append(f"the machine's discovery answer names a non-loopback {k} ({v}); ignored")
            out.pop(k)
    return out


# --- resolution ---------------------------------------------------------------------


def _first(*vals: Optional[str]) -> str:
    for v in vals:
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


def _valid(value: str, origin: str, warnings: List[str]) -> str:
    v = value.strip().lower()
    if not v:
        return ""
    if v not in VALUES:
        warnings.append(f"destination {value!r} from {origin} is not local, online or both; ignored")
        return ""
    return v


def resolve(
    settings: Settings,
    env: Mapping[str, str],
    *,
    explicit_destination: Optional[str] = None,
    explicit_endpoint: Optional[str] = None,
    explicit_headers: Optional[Mapping[str, str]] = None,
    explicit_api_key: Optional[str] = None,
    fetch: Optional[Callable[..., _http.Response]] = None,
) -> Plan:
    """The destination plan for ``settings`` (contract sections 3, 5, 6, 7)."""
    warnings: List[str] = []
    notes: List[str] = []
    dest = _valid(explicit_destination or "", "init(destination=)", warnings)
    source = "argument" if dest else ""
    if not dest:
        dest = _valid(env.get("SUPERBASED_DESTINATION", ""), "SUPERBASED_DESTINATION", warnings)
        source = "env" if dest else ""

    node_url = settings.node_url.rstrip("/") or DEFAULT_NODE_URL
    gateway = _first(settings.org_url)
    key, key_source = "", ""
    if settings.api_key:
        key, key_source = settings.api_key, ("argument" if explicit_api_key else "env")

    # Ask the machine only when something is still unknown: the destination,
    # the gateway or credential of an online/both, or the receiver of a
    # local/both the app named no endpoint for (a machine on other ports
    # advertises its own; live finding L-01).
    need_machine = (
        not dest
        or (dest in (ONLINE, BOTH) and (not gateway or not key))
        or (dest in (LOCAL, BOTH) and not _local_endpoint_named(explicit_endpoint, env, dest))
    )
    found: Optional[Dict[str, Any]] = None
    if need_machine and settings.discover:
        found, err = discover(node_url, fetch)
        if err:
            notes.append(err)
    signed_in: Optional[bool] = None
    local_info: Mapping[str, Any] = {}
    if found is not None:
        signed_in = bool(found.get("signed_in"))
        local_raw, online_raw = found.get("local"), found.get("online")
        local_info = _loopback_local_info(local_raw if isinstance(local_raw, dict) else {}, warnings)
        online: Dict[str, Any] = online_raw if isinstance(online_raw, dict) else {}
        for w in found.get("warnings") or ():
            if isinstance(w, str) and w:
                warnings.append("machine: " + w)
        if not dest:
            dest = _valid(str(found.get("destination") or ""), "the machine", warnings)
            source = "machine" if dest else ""
        # Where the key goes comes from the owner-only key file, never from
        # the discovery answer (review E-04): discovery only names the file.
        if dest != LOCAL and (not key or not gateway) and online.get("credential_present") and isinstance(online.get("credential_file"), str):
            fkey, fgateway, ferr = read_credential_record(online["credential_file"])
            if not key and fkey:
                key, key_source = fkey, "file"
            if not gateway:
                gateway = fgateway
            if ferr:
                warnings.append(ferr)
    if not dest and found is None and gateway and key:
        # No machine to ask, and the app was given a gateway and a credential
        # explicitly (a production app): send online rather than to a
        # loopback receiver that is not there.
        dest, source = ONLINE, "inferred"
    if not dest:
        dest, source = LOCAL, "default"

    online_ready = bool(gateway and key)
    degraded = ""
    if dest in (ONLINE, BOTH) and not online_ready:
        missing = " and ".join(m for m, ok in (("the gateway address", gateway), ("an SDK credential", key)) if not ok)
        fix = "run `observer sdk sign-in`, or set SUPERBASED_ORG_URL and SUPERBASED_API_KEY"
        if dest == ONLINE:
            degraded = f"destination online is missing {missing}: nothing is exported ({fix})"
        else:
            degraded = f"destination both is missing {missing}: exporting to this machine only ({fix})"
    if local_info and local_info.get("enabled") is False and dest in (LOCAL, BOTH):
        warnings.append("observability is off on this machine, so it refuses local spans (turn it on in the dashboard Settings)")

    exporters: List[Destination] = []
    timeout = settings.export_timeout
    if dest in (LOCAL, BOTH):
        endpoint, named = _local_endpoint(explicit_endpoint, env, dest, local_info)
        hdrs: Dict[str, str] = {}
        if dest == LOCAL:
            for name in _LOCAL_HEADER_ENVS:
                hdrs.update(parse_kv_list(env.get(name)))
        hdrs.update(parse_kv_list(env.get("SUPERBASED_OTLP_HEADERS")))
        if explicit_headers:
            hdrs.update({str(k): str(v) for k, v in explicit_headers.items()})
        # The credential never goes to the machine, and never to an endpoint
        # from OTEL_EXPORTER_OTLP_* (an app exporting to another vendor must
        # not leak the superbased key there). Only a remote collector the app
        # named itself (endpoint= or SUPERBASED_OTLP_ENDPOINT) carries it.
        if settings.api_key and named and not _http.is_loopback_url(endpoint) and not any(h.lower() == "authorization" for h in hdrs):
            hdrs["Authorization"] = "Bearer " + settings.api_key
        exporters.append(Destination(endpoint, tuple(sorted(hdrs.items())), timeout, name=LOCAL))
    if dest in (ONLINE, BOTH) and online_ready:
        hdrs = parse_kv_list(env.get("SUPERBASED_OTLP_HEADERS"))
        if explicit_headers:
            hdrs.update({str(k): str(v) for k, v in explicit_headers.items()})
        # The SDK credential always wins on the gateway: any user or env
        # Authorization header, whatever its case, is replaced (review FR-S04).
        for name in [h for h in hdrs if h.lower() == "authorization"]:
            del hdrs[name]
        hdrs["Authorization"] = "Bearer " + key
        exporters.append(Destination(gateway.rstrip("/") + TRACES_PATH, tuple(sorted(hdrs.items())), timeout, name=ONLINE))

    machine_admit_url = str(local_info.get("admission_url") or "") or node_url + ADMISSION_PATH
    if dest in (ONLINE, BOTH) and online_ready:
        admit_url = gateway.rstrip("/") + SDK_ADMIT_PATH
    else:
        admit_url = machine_admit_url
    return Plan(
        destination=dest,
        source=source,
        exporters=tuple(exporters),
        node_url=node_url,
        gateway_url=gateway.rstrip("/"),
        online_ready=online_ready,
        admit_url=admit_url,
        machine_admit_url=machine_admit_url,
        degraded=degraded,
        warnings=tuple(warnings),
        notes=tuple(notes),
        signed_in=signed_in,
        credential_source=key_source,
        _key=key,
    )


def _local_endpoint_named(explicit: Optional[str], env: Mapping[str, str], dest: str) -> bool:
    """Whether the app named the local destination's endpoint itself, so the
    machine's advertised receiver is not needed (the first rungs of
    ``_local_endpoint``)."""
    if explicit or _first(env.get("SUPERBASED_OTLP_ENDPOINT")):
        return True
    return dest == LOCAL and bool(_first(env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"), env.get("OTEL_EXPORTER_OTLP_ENDPOINT")))


def _local_endpoint(explicit: Optional[str], env: Mapping[str, str], dest: str, local_info: Mapping[str, Any]) -> Tuple[str, bool]:
    """(endpoint, named): explicit > SUPERBASED_OTLP_ENDPOINT > (destination
    local only) the standard OTEL_EXPORTER_OTLP_* > the machine's advertised
    receiver > the built-in loopback receiver. ``named`` is True only for the
    first two, the endpoints the app named for superbased itself."""
    if explicit:
        return explicit, True
    val = _first(env.get("SUPERBASED_OTLP_ENDPOINT"))
    if val:
        return val, True
    if dest == LOCAL:
        val = _first(env.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
        if val:
            return val, False
        base = _first(env.get("OTEL_EXPORTER_OTLP_ENDPOINT"))
        if base:
            return base.rstrip("/") + TRACES_PATH, False
    advertised = local_info.get("otlp_traces_url")
    if isinstance(advertised, str) and advertised:
        return advertised, False
    return DEFAULT_ENDPOINT, False


_logged_lock = threading.Lock()
_logged: set = set()


def log_once(plan: Plan) -> None:
    """Write each degraded reason and warning (WARNING) and note (INFO) to the
    ``superbased_sdk`` logger once per process."""
    rows = [(logging.WARNING, m) for m in ((plan.degraded,) if plan.degraded else ()) + plan.warnings]
    rows += [(logging.INFO, m) for m in plan.notes]
    for level, msg in rows:
        with _logged_lock:
            if msg in _logged:
                continue
            _logged.add(msg)
        LOG.log(level, "superbased_sdk: %s", msg)


def reset_for_tests() -> None:
    reset_cache()
    with _logged_lock:
        _logged.clear()
