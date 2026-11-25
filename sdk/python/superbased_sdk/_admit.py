"""``admit()``: the input-admission pre-flight check. Standard library only.

Never raises into the host. Any failure (transport, timeout, HTTP error, a body
that is not a JSON object, a field of the wrong type) yields a degraded
Verdict that admits (fail open, the default) or denies (``fail_closed=True``).
"""

from __future__ import annotations

import json
import logging
import os
import socket
import threading
import time
from typing import Any, Dict, Mapping, Optional, Tuple

from . import _http, _planrefusal

DEFAULT_ADMISSION_ENDPOINT = "http://127.0.0.1:8081/api/obs/admission/check"
SDK_ADMIT_PATH = "/v1/sdk/admit"

# The client waits longer than the server's judge budget (10 s) so it does not
# fail open on a request the server would still decide. A server that
# advertises a recommended timeout (the ``recommended_client_timeout_ms`` body
# field or the ``X-SBO-Recommended-Timeout-Ms`` header, sent by both the org
# SDK control API and the local node) overrides this for later calls.
DEFAULT_ADMIT_TIMEOUT = 12.0

# The advertised-timeout names, canonical first. The second of each pair is
# the pre-release spelling, still read so an older server keeps working.
TIMEOUT_HEADERS = ("X-SBO-Recommended-Timeout-Ms", "X-Superbased-Admit-Timeout-Ms")
TIMEOUT_FIELDS = ("recommended_client_timeout_ms", "recommended_timeout_ms")

# Client-side degraded reasons (``Verdict.degraded``). The server may send its
# own values (for example a judge outage); those pass through unchanged.
UNAVAILABLE = "admission-unavailable"  # 403 / 404: admission off or not permitted
TIMEOUT = "client-timeout"
TRANSPORT = "client-transport"
HTTP_ERROR = "client-http-error"
BAD_RESPONSE = "client-bad-response"
# The organization answered with mode "off": it has no admission policy, so
# it made no decision (live finding L-05, ruling D29). Under destination both
# the SDK then asks this machine; otherwise the verdict is degraded.
ADMISSION_OFF = "admission-off"

_advertised_lock = threading.Lock()
_advertised: Dict[str, float] = {}


def _str(d: Mapping[str, Any], key: str) -> str:
    v = d.get(key)
    return v if isinstance(v, str) else ""


def _int(d: Mapping[str, Any], key: str) -> int:
    v = d.get(key)
    if isinstance(v, bool):
        return 0
    if isinstance(v, (int, float)):
        return int(v)
    return 0


class Verdict:
    """The result of an ``admit()`` check.

    ``allowed`` is what the app should honour. In ``observe`` mode the server
    always returns ``allowed=True`` and records the shadow verdict; in
    ``enforce`` mode it returns the real decision (``ask``/``deny`` give
    ``allowed=False``; ``flag`` still admits). ``enforce_decision`` previews
    what enforce mode would decide.

    ``degraded`` is empty for a clean decision. A client-side failure sets it
    to one of ``admission-unavailable`` (HTTP 403/404), ``client-timeout``,
    ``client-transport``, ``client-http-error`` or ``client-bad-response``;
    ``http_status`` and ``error`` carry the detail. ``verdict_id`` is the
    server's id for the recorded verdict, when it returns one.
    ``plan_refusal`` is set when the org's plan refused the check (a
    ``PlanRefusalError``: its message and ``upgrade_url`` say why and where
    to fix it); the verdict is degraded as for any other refusal.
    """

    __slots__ = (
        "allowed",
        "decision",
        "severity",
        "criterion",
        "reason",
        "mode",
        "judge_used",
        "degraded",
        "enforce_decision",
        "latency_ms",
        "verdict_id",
        "http_status",
        "error",
        "plan_refusal",
    )

    def __init__(self, data: Optional[Mapping[str, Any]] = None, **overrides: Any) -> None:
        d: Mapping[str, Any] = data if isinstance(data, Mapping) else {}
        allowed = d.get("allowed", True)
        self.allowed: bool = allowed if isinstance(allowed, bool) else False
        self.decision: str = _str(d, "decision") or ("allow" if self.allowed else "deny")
        self.severity: str = _str(d, "severity")
        self.criterion: str = _str(d, "criterion")
        self.reason: str = _str(d, "reason")
        self.mode: str = _str(d, "mode")
        ju = d.get("judge_used")
        self.judge_used: bool = ju if isinstance(ju, bool) else False
        self.degraded: str = _str(d, "degraded")
        self.enforce_decision: str = _str(d, "enforce_decision")
        self.latency_ms: int = _int(d, "latency_ms")
        vid = d.get("verdict_id", d.get("id"))
        self.verdict_id: str = str(vid) if isinstance(vid, (str, int)) and not isinstance(vid, bool) else ""
        self.http_status: int = 0
        self.error: str = ""
        self.plan_refusal: Optional[_planrefusal.PlanRefusalError] = None
        for k, v in overrides.items():
            setattr(self, k, v)

    def to_dict(self) -> Dict[str, Any]:
        out = {k: getattr(self, k) for k in self.__slots__}
        out["plan_refusal"] = self.plan_refusal.to_dict() if self.plan_refusal is not None else None
        return out

    def __repr__(self) -> str:
        return (
            f"Verdict(allowed={self.allowed}, decision={self.decision!r}, "
            f"enforce_decision={self.enforce_decision!r}, degraded={self.degraded!r}, "
            f"reason={self.reason!r})"
        )


def _degraded(
    cause: str,
    *,
    fail_closed: bool,
    http_status: int = 0,
    error: str = "",
    started: float,
    plan_refusal: Optional["_planrefusal.PlanRefusalError"] = None,
) -> Verdict:
    return Verdict(
        None,
        allowed=not fail_closed,
        decision="deny" if fail_closed else "allow",
        reason="admission check unavailable" if fail_closed else "",
        degraded=cause,
        http_status=http_status,
        error=error[:300],
        latency_ms=int((time.monotonic() - started) * 1000),
        plan_refusal=plan_refusal,
    )


# --- saying so when admit() could not decide (review E-39) -------------------------
#
# admit() fails open (the contract), but never silently: every degraded
# verdict is counted for diagnostics(), and one WARNING per cause per minute
# names the cause and the fix. TypeScript does the same (console.warn).

LOG = logging.getLogger("superbased_sdk")
DEGRADED_LOG_INTERVAL = 60.0

# (cause, lowest status, highest status, what to fix, where): the first
# matching row wins; a 0..999 range matches any status; where is "machine"
# (the check went to a machine's admission path), "" for any address.
# TypeScript has the same table.
_FIXES: Tuple[Tuple[str, int, int, str, str], ...] = (
    (
        UNAVAILABLE,
        404,
        404,
        "this machine has no admission check: update Observer (a current machine answers allow while no admission policy is set), or turn admission on",
        "machine",
    ),
    (HTTP_ERROR, 300, 399, "the address redirects, and admit() never follows a redirect (the key must not move hosts): use the final URL", ""),
    (HTTP_ERROR, 401, 401, "the SDK key was refused: check api_key / SUPERBASED_API_KEY, or sign in again", ""),
    (UNAVAILABLE, 403, 403, "the key may not run admission checks, or admission is off for this app", ""),
    (UNAVAILABLE, 404, 404, "no admission check at this address: point org_url / SUPERBASED_ORG_URL at the AI Apps gateway (not the dashboard), or turn admission on", ""),
    (HTTP_ERROR, 429, 429, "the server is rate limiting admission checks", ""),
    (HTTP_ERROR, 0, 999, "the admission server answered with an error", ""),
    (TIMEOUT, 0, 999, "no answer within the timeout: raise timeout=, or check the server", ""),
    (TRANSPORT, 0, 999, "nothing answered at this address: check the URL and that Observer is running", ""),
    (BAD_RESPONSE, 0, 999, "the address did not answer like an admission check: check the URL", ""),
    (ADMISSION_OFF, 0, 999, "your organization has no admission policy for AI Apps (mode off): ask an admin to turn admission on, or use destination both so this machine's policy applies", ""),
)


def _where(url: str) -> str:
    """scheme://host[:port]/path of a URL: no user info, no query."""
    try:
        from urllib.parse import urlsplit

        u = urlsplit(url)
        host = u.hostname or ""
        if u.port:
            host = f"{host}:{u.port}"
        return f"{u.scheme}://{host}{u.path}"
    except Exception:  # noqa: BLE001
        return "the admission address"


def degraded_fix(cause: str, status: int, url: str = "") -> str:
    """What to fix for a degraded verdict ("" for a server-side reason). url
    is the address the check went to: a machine's admission path selects the
    machine's rows."""
    machine = _is_machine_admission(url)
    for c, lo, hi, fix, where in _FIXES:
        if c == cause and lo <= status <= hi and (not where or (where == "machine") == machine):
            return fix
    return ""


def _is_machine_admission(url: str) -> bool:
    """Whether url is a machine's admission check (its path)."""
    try:
        from urllib.parse import urlsplit

        from ._destination import ADMISSION_PATH

        return urlsplit(url).path.rstrip("/").endswith(ADMISSION_PATH)
    except Exception:  # noqa: BLE001
        return False


class _AdmitStats:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.degraded = 0
        self.last_error = ""
        self.last_error_at = 0.0
        self.logged_at: Dict[str, float] = {}


STATS = _AdmitStats()


def note_degraded(v: Verdict, url: str) -> None:
    """Count a degraded verdict and warn once a minute per cause."""
    try:
        status = v.http_status if isinstance(v.http_status, int) else 0
        detail = f"HTTP {status}" if status else (v.error or v.degraded)
        fix = degraded_fix(v.degraded, status, url)
        refusal = v.plan_refusal
        if refusal is not None:
            # The org's plan refused it: its own words and where to fix it.
            fix = f"{' '.join(refusal.message.split())} (upgrade: {refusal.upgrade_url})"
            _planrefusal.note(refusal)
        verdict = "denied (fail_closed)" if not v.allowed else "admitted (fail open)"
        where = f" from {_where(url)}" if url else ""
        msg = f"admit() got no decision{where} ({v.degraded}: {detail}); the message was {verdict}" + (f". Fix: {fix}" if fix else "")
        key = f"{v.degraded}:{status}"
        now = time.time()
        with STATS.lock:
            STATS.degraded += 1
            STATS.last_error = msg[:500]
            STATS.last_error_at = now
            last = STATS.logged_at.get(key, 0.0)
            due = now - last >= DEGRADED_LOG_INTERVAL
            if due:
                STATS.logged_at[key] = now
        if due:
            LOG.warning("superbased_sdk: %s", msg)
    except Exception:  # noqa: BLE001 - reporting never breaks admit()
        pass


def snapshot() -> Dict[str, Any]:
    with STATS.lock:
        return {
            "admission_degraded": STATS.degraded,
            "admission_last_error": STATS.last_error,
            "admission_last_error_at": STATS.last_error_at,
        }


# Where the admit URL came from decides whether a credential may ride along.
# PLAN_ORG is the org chosen by init()'s destination (online or both), the
# one origin whose "admission off" answer may fall back to the machine.
ORG, PLAN_ORG, EXPLICIT, MACHINE = "org", "plan-org", "explicit", "machine"


def _resolve_url(endpoint: Optional[str], org_url: Optional[str], env: Mapping[str, str]) -> Tuple[str, str, str]:
    """(url, origin, init key): explicit ``endpoint``, ``org_url`` +
    /v1/sdk/admit, ``$SUPERBASED_ADMISSION_ENDPOINT``, then the destination
    plan of ``init()`` (contract destination.md section 8: the org when the
    destination is online or both and usable, else this machine), then
    ``$SUPERBASED_ORG_URL`` + /v1/sdk/admit, then the local machine.

    The init key is ``init()``'s credential (its ``api_key``, the env, or the
    machine's credential file), "" before init. The caller sends it only to
    an org origin or a remote explicit endpoint, as TypeScript does (review
    E-76: an explicit ``org_url`` used to drop it)."""
    from . import _plan

    plan = _plan()
    init_key = plan._key if plan is not None else ""
    if endpoint:
        return endpoint, EXPLICIT, init_key
    if org_url:
        return org_url.rstrip("/") + SDK_ADMIT_PATH, ORG, init_key
    val = (env.get("SUPERBASED_ADMISSION_ENDPOINT") or "").strip()
    if val:
        return val, EXPLICIT, init_key
    if plan is not None and plan.admit_url:
        if plan.online_enabled and plan.gateway_url and plan.admit_url.startswith(plan.gateway_url):
            return plan.admit_url, PLAN_ORG, init_key
        return plan.admit_url, MACHINE, ""
    org = (env.get("SUPERBASED_ORG_URL") or "").strip()
    if org:
        return org.rstrip("/") + SDK_ADMIT_PATH, ORG, init_key
    return DEFAULT_ADMISSION_ENDPOINT, MACHINE, ""


def _scope_values() -> Dict[str, Any]:
    """The per-request identity in effect (propagate_attributes / identify)."""
    try:
        from ._context import get_current_attributes

        return get_current_attributes()
    except Exception:  # noqa: BLE001
        return {}


def _init_identity() -> Dict[str, str]:
    """init()'s process-wide tenant, user and session (empty before init)."""
    try:
        from . import settings

        s = settings()
        if s is None:
            return {}
        return {"tenant": s.tenant or "", "user": s.user or "", "session_id": s.session_id or ""}
    except Exception:  # noqa: BLE001
        return {}


def _advertised_timeout(url: str) -> Optional[float]:
    with _advertised_lock:
        return _advertised.get(url)


def _first_present(get: Any, names: Any) -> Any:
    """The first value ``get(name)`` returns that is not None."""
    for n in names:
        v = get(n)
        if v is not None:
            return v
    return None


def _remember_timeout(url: str, raw: Any) -> None:
    try:
        ms = float(raw)
    except (TypeError, ValueError):
        return
    if isinstance(raw, bool) or not (100 <= ms <= 120_000):
        return
    with _advertised_lock:
        _advertised[url] = ms / 1000.0


def _service_name(env: Mapping[str, str]) -> str:
    """The ``service.name`` the app's spans carry, which service-scoped
    budget caps match on: the resource of the provider holding the SDK's
    spans (init()), else of the registered provider, else the configured
    name (SUPERBASED_SERVICE_NAME, OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES,
    custom-app). OpenTelemetry's ``unknown_service`` default is no name."""
    try:
        from opentelemetry import trace

        from . import _PROVIDER

        provider = _PROVIDER if _PROVIDER is not None else trace.get_tracer_provider()
        name = (getattr(getattr(provider, "resource", None), "attributes", None) or {}).get("service.name")
        if isinstance(name, str) and name.strip() and not name.startswith("unknown_service"):
            return name.strip()
    except Exception:  # noqa: BLE001
        pass
    try:
        from ._config import resolve_service_name

        return resolve_service_name(None, env)
    except Exception:  # noqa: BLE001
        return ""


def _current_trace_id() -> str:
    try:
        from opentelemetry import trace

        ctx = trace.get_current_span().get_span_context()
        if ctx is not None and ctx.is_valid:
            return format(ctx.trace_id, "032x")
    except Exception:  # noqa: BLE001
        pass
    return ""


def _stamp_span(v: Verdict) -> None:
    """Record the verdict on the current span (if any), so the trace shows
    what admission decided and which verdict row it was."""
    try:
        from opentelemetry import trace

        sp = trace.get_current_span()
        if not sp.is_recording():
            return
        sp.set_attribute("sbo.admission.allowed", v.allowed)
        sp.set_attribute("sbo.admission.decision", v.decision)
        if v.verdict_id:
            sp.set_attribute("sbo.admission.verdict_id", v.verdict_id)
        if v.degraded:
            sp.set_attribute("sbo.admission.degraded", v.degraded)
    except Exception:  # noqa: BLE001
        pass


def admit(
    message: str,
    *,
    tenant: Optional[str] = None,
    user: Optional[str] = None,
    session: Optional[str] = None,
    trace_id: Optional[str] = None,
    request_id: Optional[str] = None,
    endpoint: Optional[str] = None,
    org_url: Optional[str] = None,
    api_key: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
    fail_closed: Optional[bool] = None,
) -> Verdict:
    """Check an incoming user message against the app's admission policy
    BEFORE running the agent, and get an allow/flag/ask/deny verdict::

        v = superbased_sdk.admit(user_message, user="alice", session="s1")
        if not v.allowed:
            return v.reason  # or route to a human on `ask`

    Endpoint, first match: ``endpoint`` (a full URL); ``org_url`` +
    ``/v1/sdk/admit``; ``$SUPERBASED_ADMISSION_ENDPOINT``; the destination
    ``init()`` resolved (the org gateway when it is ``online`` or ``both`` and
    usable, else this machine); ``$SUPERBASED_ORG_URL`` + ``/v1/sdk/admit``;
    the local node (``http://127.0.0.1:8081/api/obs/admission/check``).

    Credential: ``api_key``, else ``init()``'s key or ``$SUPERBASED_API_KEY``,
    is sent as ``Authorization: Bearer`` only to an org address or a remote
    explicit endpoint (an explicit ``api_key`` also goes to a loopback one),
    never to this machine's own routes; ``headers`` adds or overrides other
    headers. Redirects are never followed.

    ``timeout`` (seconds) defaults to the server-advertised recommended
    timeout once one has been seen, else 12 s, and bounds the whole exchange
    (connect, headers and body). ``fail_closed`` (or
    ``$SUPERBASED_ADMISSION_FAIL_CLOSED=1``) denies when no decision could be
    obtained; the default admits. Never raises.
    """
    started = time.monotonic()
    # Resolve fail-closed before any other work, so the last-resort handler
    # below honours the option and the environment (review FR-S02).
    closed = _resolve_fail_closed(fail_closed)
    try:
        return _admit(
            message,
            tenant=tenant,
            user=user,
            session=session,
            trace_id=trace_id,
            request_id=request_id,
            endpoint=endpoint,
            org_url=org_url,
            api_key=api_key,
            headers=headers,
            timeout=timeout,
            fail_closed=closed,
            started=started,
        )
    except Exception as exc:  # noqa: BLE001 - the last line of defence: never raise into the host
        v = _degraded(BAD_RESPONSE, fail_closed=closed, error=f"{type(exc).__name__}: {exc}", started=started)
        note_degraded(v, "")
        return v


def _resolve_fail_closed(arg: Optional[bool]) -> bool:
    """The per-call option, else ``SUPERBASED_ADMISSION_FAIL_CLOSED``."""
    try:
        if arg is not None:
            return bool(arg)
        raw = (os.environ.get("SUPERBASED_ADMISSION_FAIL_CLOSED") or "").strip().lower()
        return raw not in ("", "0", "false", "no", "off")
    except Exception:  # noqa: BLE001
        return False


def _machine_admission_url() -> str:
    """This machine's admission check: the one discovery advertised (loopback
    only), else the machine URL's route."""
    from . import _plan

    plan = _plan()
    if plan is None:
        return DEFAULT_ADMISSION_ENDPOINT
    from ._destination import ADMISSION_PATH

    return plan.machine_admit_url or (plan.node_url.rstrip("/") + ADMISSION_PATH)


def _admit(message: Any, *, started: float, **kw: Any) -> Verdict:
    env = os.environ
    fail_closed = bool(kw["fail_closed"])  # resolved by admit()
    url, origin, init_key = _resolve_url(kw["endpoint"], kw["org_url"], env)

    # Identity: the argument, else the request scope (propagate_attributes),
    # else init()'s process-wide value (contract section 2).
    scope = _scope_values()
    base = _init_identity()
    payload = json.dumps(
        {
            "text": "" if message is None else str(message),
            "tenant": kw["tenant"] or scope.get("tenant") or base.get("tenant", ""),
            "user": kw["user"] or scope.get("user") or base.get("user", ""),
            "session": kw["session"] or scope.get("session_id") or base.get("session_id", ""),
            # service.name: service-scoped budget caps bind on it, on the
            # machine and on the org.
            "service": _service_name(env),
            "trace_id": kw["trace_id"] or _current_trace_id(),
            "request_id": kw["request_id"] or "",
        }
    ).encode("utf-8")

    v = _post(url, origin, init_key, payload, kw, env, fail_closed, started)
    if origin in (ORG, PLAN_ORG) and not v.degraded and v.mode == "off":
        # The org has no admission policy, so it made no decision (L-05).
        # Under destination both, this machine's policy decides; otherwise
        # the verdict says nothing decided.
        from . import _plan
        from ._destination import BOTH

        plan = _plan()
        if origin == PLAN_ORG and plan is not None and plan.destination == BOTH:
            # The key never goes to the machine, not even an explicit one.
            hdrs = {k: v for k, v in (kw["headers"] or {}).items() if str(k).lower() != "authorization"}
            v = _post(_machine_admission_url(), MACHINE, "", payload, dict(kw, api_key=None, headers=hdrs), env, fail_closed, started)
        else:
            v = _degraded(ADMISSION_OFF, fail_closed=fail_closed, http_status=v.http_status, error="the organization answered mode off", started=started)
            note_degraded(v, url)
    _stamp_span(v)
    return v


def _refusal_of(exc: Any, deadline: float) -> Optional[_planrefusal.PlanRefusalError]:
    """The org's plan refusal in an HTTP error answer, or None (a 403 or a
    429 only; the body is read within the call's deadline)."""
    if exc.code not in (403, 429):
        return None
    try:
        raw = _http.read_bounded(exc, deadline, _http.ADMIT_BODY_CAP)
    except Exception:  # noqa: BLE001 - reporting never breaks admit()
        return None
    return _planrefusal.parse_plan_refusal(exc.code, raw, dict(exc.headers or {}))


def _post(url: str, origin: str, init_key: str, payload: bytes, kw: Mapping[str, Any], env: Mapping[str, str], fail_closed: bool, started: float) -> Verdict:
    """One admission request to ``url``; a failure is a counted degraded
    verdict. The caller stamps the span with the final verdict."""
    import http.client
    import urllib.error
    import urllib.request

    timeout = kw["timeout"]
    if timeout is None:
        timeout = _advertised_timeout(url) or DEFAULT_ADMIT_TIMEOUT
    # One deadline for connect, headers AND body (review FR-S09).
    deadline = time.monotonic() + max(0.001, float(timeout))

    hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    # The credential goes to the org (a URL built from an org address) or to
    # an explicit remote endpoint, never to this machine's own routes. An
    # explicit api_key= is the caller's call.
    key = kw["api_key"] or ""
    if not key and (origin in (ORG, PLAN_ORG) or (origin == EXPLICIT and not _http.is_loopback_url(url))):
        key = init_key or env.get("SUPERBASED_API_KEY") or ""
    if key:
        hdrs["Authorization"] = "Bearer " + key
    if kw["headers"]:
        hdrs.update({str(k): str(v) for k, v in kw["headers"].items()})
    req = urllib.request.Request(url, data=payload, headers=hdrs, method="POST")

    def fail(cause: str, status: int = 0, error: str = "", refusal: Optional[_planrefusal.PlanRefusalError] = None) -> Verdict:
        v = _degraded(cause, fail_closed=fail_closed, http_status=status, error=error, started=started, plan_refusal=refusal)
        note_degraded(v, url)
        return v

    try:
        # The shared opener: never follows a redirect (the key must not ride
        # to a host it was not sent to), and a loopback check never goes
        # through an HTTP(S)_PROXY from the environment.
        with _http._opener(_http.is_loopback_url(url)).open(req, timeout=max(0.001, float(timeout))) as resp:
            status = getattr(resp, "status", 200)
            _remember_timeout(url, _first_present(resp.headers.get, TIMEOUT_HEADERS))
            raw = _http.read_bounded(resp, deadline, _http.ADMIT_BODY_CAP)
    except urllib.error.HTTPError as exc:
        refusal = _refusal_of(exc, deadline)
        error = f"HTTP {exc.code}" + (f" {refusal.code}: {refusal.message}" if refusal is not None else "")
        if exc.code in (403, 404):
            return fail(UNAVAILABLE, exc.code, error, refusal)
        return fail(HTTP_ERROR, exc.code, error, refusal)
    except (socket.timeout, TimeoutError) as exc:
        return fail(TIMEOUT, error=str(exc) or "timed out")
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return fail(TIMEOUT, error=str(reason) or "timed out")
        return fail(TRANSPORT, error=str(reason))
    except (http.client.HTTPException, OSError, ValueError) as exc:
        return fail(TRANSPORT, error=f"{type(exc).__name__}: {exc}")

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return fail(BAD_RESPONSE, status, f"{type(exc).__name__}: {exc}")
    if not isinstance(data, dict):
        return fail(BAD_RESPONSE, status, f"response body is {type(data).__name__}, not an object")
    if not isinstance(data.get("allowed"), bool):
        return fail(BAD_RESPONSE, status, "response field 'allowed' is missing or not a boolean")
    _remember_timeout(url, _first_present(data.get, TIMEOUT_FIELDS))
    v = Verdict(data)
    v.http_status = status
    return v
