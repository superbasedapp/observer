"""AI gateway helpers (hosted AI gateway arc L-172, lane L8; the shared cases
are sdk/contract/ai-gateway-cases.json).

The AI gateway is the proxy an app's model calls go through on their way to
the provider: it prices each call exactly, holds the app's budgets and applies
the organization's model, egress and admission rules. It runs in three places
with one client shape:

- the organization's address, ``https://<org host>/ai/<upstream>`` (hosted, or
  a self-hosted server with its path lane);
- any address you name (a self-hosted gateway on its own listener);
- this machine's app lane, ``http://127.0.0.1:8820/up/<lane>``.

``gateway_base_url()`` resolves which one applies; ``openai_client()`` and
``anthropic_client()`` build a client pointed at it; ``parse_gateway_refusal()``
reads a refusal.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from . import _http, _planrefusal

# The client families (seam S4's upstreams[].client). Each client adds its own
# API path after the base URL.
OPENAI = "openai"  # OpenAI and every OpenAI-compatible client: the base ends in /v1
ANTHROPIC = "anthropic"  # the gateway address as it is (the client adds /v1/messages)
AZURE_OPENAI = "azure_openai"  # its azure_endpoint; no default upstream

ENV_URL = "SUPERBASED_AI_GATEWAY_URL"
ENV_KEY = "SUPERBASED_AI_GATEWAY_KEY"
UPSTREAM_HEADER = "X-SBO-Upstream"

# Where a base URL came from.
SOURCE_ARGUMENT = "argument"
SOURCE_ENV = "env"
SOURCE_ORG = "org"
SOURCE_MACHINE = "machine"

# Why no base URL could be resolved (GatewayNotConfigured.problem).
UNKNOWN_PROVIDER = "unknown_provider"
BAD_UPSTREAM = "bad_upstream"
UPSTREAM_REQUIRED = "upstream_required"
BAD_URL = "bad_url"
NOT_CONFIGURED = "not_configured"
NO_KEY = "no_key"

_AI_PATH_LANE = "/ai"

# client family -> (the path its base URL ends in, the upstream used when none
# is named). One row per family.
_PROVIDERS: Dict[str, Tuple[str, str]] = {
    OPENAI: ("/v1", "openai"),
    ANTHROPIC: ("", "anthropic"),
    AZURE_OPENAI: ("", ""),
}

# A pooled upstream id (plan section 3.4); v1 and v1beta read as provider paths.
_UPSTREAM_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
_RESERVED = frozenset({"v1", "v1beta"})


class GatewayNotConfigured(ValueError):
    """No usable AI gateway address (or key). ``problem`` is one of
    ``unknown_provider``, ``bad_upstream``, ``upstream_required``,
    ``bad_url``, ``not_configured`` or ``no_key``."""

    def __init__(self, problem: str, message: str) -> None:
        super().__init__(message)
        self.problem = problem
        self.message = message


@dataclass(frozen=True)
class GatewayEndpoint:
    """Where a model client sends its calls.

    ``base_url`` is the client's base URL option; ``source`` where it came
    from (``argument``, ``env``, ``org`` or ``machine``); ``upstream`` the
    upstream id ("" when the address names none); ``upstream_header`` the
    ``X-SBO-Upstream`` value the client must send ("" when none: the org
    address and the machine lane carry the upstream in the path)."""

    base_url: str
    source: str
    upstream: str = ""
    upstream_header: str = ""


def url_problem(raw: str) -> str:
    """"" when ``raw`` is a usable gateway address: http(s), a host, no user
    info, query or fragment, plain http only to a loopback host (the AI
    gateway key travels with every call)."""
    try:
        u = urllib.parse.urlsplit(raw)
        host = u.hostname or ""
        user = u.username
        _ = u.port  # an invalid port raises here
    except ValueError:
        return f"{raw!r} is not a URL"
    if u.scheme not in ("http", "https") or not host:
        return f"{raw!r} is not an http(s) address with a host"
    if user is not None or "@" in u.netloc:
        return f"{raw!r} carries a user name or password"
    if u.query or u.fragment or raw.rstrip().endswith("?") or "#" in raw:
        return f"{raw!r} carries a query or fragment"
    if u.scheme == "http" and not _http.is_loopback_url(raw):
        return f"{raw!r} is plain http to a remote host"
    return ""


def _with_suffix(base: str, suffix: str) -> str:
    base = base.rstrip("/")
    if not suffix or base.endswith(suffix):
        return base
    return base + suffix


def _machine_lane(local: Any, upstream: str) -> str:
    """The base URL of the lane named ``upstream`` in the discovery answer's
    ``local.app_lanes`` ("" when none is usable)."""
    lanes = local.get("app_lanes") if isinstance(local, Mapping) else None
    if not isinstance(lanes, list):
        return ""
    for lane in lanes:
        if not isinstance(lane, Mapping):
            continue
        lid, base = lane.get("id"), lane.get("base_url")
        if not isinstance(lid, str) or not isinstance(base, str) or lid != upstream or not base:
            continue
        if url_problem(base) or not _http.is_loopback_url(base):
            continue
        return base.rstrip("/")
    return ""


def resolve_endpoint(
    provider: str,
    *,
    upstream: Optional[str] = None,
    url: Optional[str] = None,
    env: Optional[str] = None,
    destination: str = "",
    org_url: str = "",
    local: Optional[Callable[[], Any]] = None,
) -> Tuple[Optional[GatewayEndpoint], str, str]:
    """The pure resolver (contract base_url cases): (endpoint, "", "") or
    (None, problem, message). ``local`` loads the machine's discovery answer's
    ``local`` object, and is called only when it is needed."""
    fam = (provider or "").strip().lower()
    row = _PROVIDERS.get(fam)
    if row is None:
        return None, UNKNOWN_PROVIDER, f"the AI gateway helpers know the clients openai, anthropic and azure_openai, not {provider!r}"
    suffix, default_upstream = row
    named = (upstream or "").strip()
    if named and (not _UPSTREAM_RE.fullmatch(named) or named in _RESERVED):
        return None, BAD_UPSTREAM, f"upstream {named!r} is not an upstream id (lower-case letters, digits and -, at most 32, not v1 or v1beta)"
    up = named or default_upstream
    for value, source, origin in ((url, SOURCE_ARGUMENT, "the AI gateway URL"), (env, SOURCE_ENV, ENV_URL)):
        v = (value or "").strip()
        if not v:
            continue
        problem = url_problem(v)
        if problem:
            return None, BAD_URL, f"{origin} is not usable: {problem}"
        return GatewayEndpoint(_with_suffix(v, suffix), source, named, named), "", ""
    not_configured = (
        f"no AI gateway address for {fam}: pass the URL, set {ENV_URL}, use destination online with the "
        "organization's address (SUPERBASED_ORG_URL or `observer sdk sign-in`), or add an app lane on this "
        "machine (`observer apps lane add`)"
    )
    if destination == "online":
        org = (org_url or "").strip().rstrip("/")
        if not org or url_problem(org):
            return None, NOT_CONFIGURED, not_configured
        if not up:
            return None, UPSTREAM_REQUIRED, f"the {fam} client has no default upstream: name one"
        return GatewayEndpoint(f"{org}{_AI_PATH_LANE}/{up}{suffix}", SOURCE_ORG, up), "", ""
    if destination in ("local", "both"):
        if not up:
            return None, UPSTREAM_REQUIRED, f"the {fam} client has no default upstream: name one"
        base = _machine_lane(local() if local is not None else None, up)
        if base:
            return GatewayEndpoint(base + suffix, SOURCE_MACHINE, up), "", ""
    return None, NOT_CONFIGURED, not_configured


def _discovery_allowed() -> bool:
    from . import settings
    from ._config import Settings

    s = settings()
    if s is None:
        s = Settings.resolve(os.environ)
    return bool(s.discover)


def gateway_endpoint(provider: str, upstream: Optional[str] = None, *, url: Optional[str] = None) -> GatewayEndpoint:
    """Where a model client of the given family (``"openai"``,
    ``"anthropic"``, ``"azure_openai"``) sends its calls, first set wins:

    1. ``url``;
    2. ``SUPERBASED_AI_GATEWAY_URL``;
    3. the organization's address, ``<org url>/ai/<upstream>``, when the
       destination is ``online`` (the org url is the trace gateway address the
       SDK already uses: ``org_url=``, ``SUPERBASED_ORG_URL`` or the sign-in
       key file);
    4. this machine's app lane for the upstream, from its loopback discovery
       answer, when the destination is ``local`` or ``both``.

    The destination is ``init()``'s, or the one the environment resolves
    before ``init()``. Raises ``GatewayNotConfigured`` when nothing applies; it
    never falls back to the provider itself, which would skip every rule the
    gateway applies. (Go: ``ResolveGateway``; TS: ``gatewayEndpoint``.)"""
    from . import _control, _destination

    plan = _control.current_plan()

    def local() -> Any:
        if not _discovery_allowed():
            return None
        body, _err = _destination.discover(plan.node_url)
        return (body or {}).get("local")

    ep, problem, message = resolve_endpoint(
        provider,
        upstream=upstream,
        url=url,
        env=os.environ.get(ENV_URL),
        destination=plan.destination,
        org_url=plan.gateway_url,
        local=local,
    )
    if ep is None:
        raise GatewayNotConfigured(problem, message)
    return ep


def gateway_base_url(provider: str, upstream: Optional[str] = None, *, url: Optional[str] = None) -> str:
    """The base URL to give a model client of the given family:
    ``gateway_endpoint(...).base_url``. Raises ``GatewayNotConfigured`` when
    nothing applies."""
    return gateway_endpoint(provider, upstream, url=url).base_url


def gateway_key() -> str:
    """The AI gateway key from ``SUPERBASED_AI_GATEWAY_KEY`` ("" when unset)."""
    return (os.environ.get(ENV_KEY) or "").strip()


def _client_key(ep: GatewayEndpoint, api_key: Optional[str]) -> Optional[str]:
    """The key the client sends: ``api_key``; on the machine's app lane the
    provider's own key (None: the client reads its usual variable, and the
    lane forwards it); else ``SUPERBASED_AI_GATEWAY_KEY``, and on a loopback
    address with none set the provider's own key. A remote gateway with no
    gateway key raises, so the provider's key is never sent there."""
    if api_key:
        return api_key
    if ep.source == SOURCE_MACHINE:
        return None
    key = gateway_key()
    if key:
        return key
    if _http.is_loopback_url(ep.base_url):
        return None
    raise GatewayNotConfigured(NO_KEY, f"no AI gateway key for {ep.base_url}: set {ENV_KEY} or pass api_key=")


def _hook_client(http_client: Any, async_client: bool) -> None:
    """Add the SDK's request hook to an httpx client the caller passed."""
    from ._gatewayid import _httpx_async_request_hook, _httpx_request_hook

    hook = _httpx_async_request_hook if async_client else _httpx_request_hook
    hooks = dict(getattr(http_client, "event_hooks", {}) or {})
    req = list(hooks.get("request", []))
    if hook not in req:
        req.append(hook)
    hooks["request"] = req
    http_client.event_hooks = hooks


def _client_parts(
    module: Any, ep: GatewayEndpoint, api_key: Optional[str], async_client: bool, kwargs: Dict[str, Any]
) -> Dict[str, Any]:
    from ._gatewayid import async_gateway_event_hooks, gateway_event_hooks

    key = _client_key(ep, api_key)
    http_client = kwargs.pop("http_client", None)
    if http_client is None:
        factory = module.DefaultAsyncHttpxClient if async_client else module.DefaultHttpxClient
        hooks = async_gateway_event_hooks() if async_client else gateway_event_hooks()
        # No redirect is followed: every call carries the key.
        http_client = factory(event_hooks=hooks, follow_redirects=False)
    else:
        _hook_client(http_client, async_client)
    headers = dict(kwargs.pop("default_headers", None) or {})
    if ep.upstream_header and not any(str(k).lower() == UPSTREAM_HEADER.lower() for k in headers):
        headers[UPSTREAM_HEADER] = ep.upstream_header
    parts: Dict[str, Any] = {"base_url": ep.base_url, "http_client": http_client}
    if key is not None:
        parts["api_key"] = key
    if headers:
        parts["default_headers"] = headers
    return parts


def openai_client(
    upstream: Optional[str] = None,
    *,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    async_client: bool = False,
    **kwargs: Any,
) -> Any:
    """An ``openai.OpenAI`` (``openai.AsyncOpenAI`` with
    ``async_client=True``) pointed at the AI gateway (``gateway_endpoint``):
    its key is ``api_key``, else ``SUPERBASED_AI_GATEWAY_KEY`` (on this
    machine's app lane, the provider's own ``OPENAI_API_KEY``), and its HTTP
    client sends the app identity headers, a request id and the current
    span's ``traceparent`` (``gateway_event_hooks()``) and follows no
    redirect. Other keyword arguments go to the client. Raises
    ``GatewayNotConfigured`` when there is no address or key, and
    ``ImportError`` without the ``openai`` package."""
    import openai

    ep = gateway_endpoint(OPENAI, upstream, url=url)
    parts = _client_parts(openai, ep, api_key, async_client, kwargs)
    cls = openai.AsyncOpenAI if async_client else openai.OpenAI
    return cls(**parts, **kwargs)


def anthropic_client(
    upstream: Optional[str] = None,
    *,
    url: Optional[str] = None,
    api_key: Optional[str] = None,
    async_client: bool = False,
    **kwargs: Any,
) -> Any:
    """An ``anthropic.Anthropic`` (``anthropic.AsyncAnthropic`` with
    ``async_client=True``) pointed at the AI gateway, as ``openai_client``
    (on this machine's app lane the key is the provider's own
    ``ANTHROPIC_API_KEY``). The gateway reads the key from ``x-api-key`` or
    ``Authorization: Bearer``, whichever the client version sends. Raises ``GatewayNotConfigured`` or ``ImportError`` like
    ``openai_client``."""
    import anthropic

    ep = gateway_endpoint(ANTHROPIC, upstream, url=url)
    parts = _client_parts(anthropic, ep, api_key, async_client, kwargs)
    cls = anthropic.AsyncAnthropic if async_client else anthropic.Anthropic
    return cls(**parts, **kwargs)


# --- refusals -------------------------------------------------------------------------

BUDGET_EXCEEDED = "budget_exceeded"
MODEL_NOT_ALLOWED = "model_not_allowed"
ADMISSION_DENIED = "admission_denied"
PLAN_REQUIRED = "plan_required"
QUOTA_EXCEEDED = "quota_exceeded"
OTHER = "other"

AIGW_QUOTA_EXCEEDED = _planrefusal.AIGW_QUOTA_EXCEEDED

# code -> (the status it rides on, the kind). One row per code; any other code,
# or a code on another status, is "other".
_KINDS: Dict[str, Tuple[int, str]] = {
    "budget_exceeded": (402, BUDGET_EXCEEDED),
    "model_not_allowed": (403, MODEL_NOT_ALLOWED),
    "admission_denied": (403, ADMISSION_DENIED),
    _planrefusal.PLAN_REQUIRED: (403, PLAN_REQUIRED),
    AIGW_QUOTA_EXCEEDED: (429, QUOTA_EXCEEDED),
}


@dataclass(frozen=True)
class GatewayBudget:
    """The cap a 402 refusal names, in the cap's own unit (``usd`` or
    ``tokens``). A ``remaining`` below zero is how far calls already let
    through went past the cap; None means the body did not say."""

    level: Optional[str] = None
    scope_id: Optional[str] = None
    unit: Optional[str] = None
    remaining: Optional[float] = None
    cap: Optional[float] = None
    estimated: bool = False


class GatewayRefusalError(RuntimeError):
    """The AI gateway refused a model call.

    ``kind`` is ``budget_exceeded`` (402), ``model_not_allowed``,
    ``admission_denied``, ``plan_required`` (403), ``quota_exceeded`` (429,
    the organization's monthly allowance) or ``other``; ``code`` the gateway's
    reason; ``request_id`` its ``X-SBO-Request-Id``; ``retry_after`` the
    Retry-After header in seconds. ``budget`` is set for a budget refusal,
    ``plan_refusal`` (a ``PlanRefusalError``) for a plan refusal that names
    where to change the plan."""

    def __init__(
        self,
        message: str,
        *,
        kind: str,
        code: str,
        status: int,
        request_id: str = "",
        retry_after: Optional[float] = None,
        budget: Optional[GatewayBudget] = None,
        plan_refusal: Optional[_planrefusal.PlanRefusalError] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.code = code
        self.status = status
        self.request_id = request_id
        self.retry_after = retry_after
        self.budget = budget
        self.plan_refusal = plan_refusal

    def __repr__(self) -> str:
        return f"GatewayRefusalError(kind={self.kind!r}, code={self.code!r}, status={self.status}, message={self.message!r})"


def _header(headers: Optional[Mapping[str, Any]], name: str) -> str:
    if not headers:
        return ""
    want = name.lower()
    for k, v in headers.items():
        if str(k).lower() == want:
            if isinstance(v, (list, tuple)):
                v = v[0] if v else ""
            return str(v).strip()
    return ""


def _str(v: Any) -> str:
    return v.strip() if isinstance(v, str) else ""


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return float(v)


def _code(obj: Mapping[str, Any]) -> str:
    reason = _str(obj.get("reason"))
    if reason:
        return reason
    err = _str(obj.get("error"))
    return err if err in _KINDS else ""


def _message(obj: Mapping[str, Any], code: str) -> str:
    err = obj.get("error")
    if isinstance(err, Mapping) and _str(err.get("message")):
        return _str(err.get("message"))
    if _str(obj.get("message")):
        return _str(obj.get("message"))
    if _str(err) and _str(err) != code:
        return _str(err)
    return ""


def _budget(obj: Mapping[str, Any]) -> GatewayBudget:
    unit = obj.get("unit") if isinstance(obj.get("unit"), str) else None
    fields = {"usd": ("remaining_usd", "cap_usd"), "tokens": ("remaining_tokens", "cap_tokens")}.get(unit or "")
    remaining = _num(obj.get(fields[0])) if fields else None
    cap = _num(obj.get(fields[1])) if fields else None
    return GatewayBudget(
        level=obj.get("level") if isinstance(obj.get("level"), str) else None,
        scope_id=obj.get("scope_id") if isinstance(obj.get("scope_id"), str) else None,
        unit=unit,
        remaining=remaining,
        cap=cap,
        estimated=obj.get("estimated") is True,
    )


def _body(body: Any) -> Any:
    if isinstance(body, Mapping):
        return body
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8")
    if isinstance(body, str):
        return json.loads(body) if body.strip() else None
    return None


def parse_gateway_refusal(status: int, body: Any, headers: Optional[Mapping[str, Any]] = None) -> Optional[GatewayRefusalError]:
    """The AI gateway refusal in one HTTP answer, or None.

    ``body`` is the decoded JSON object, or the raw body (bytes or text);
    ``headers`` any mapping (names matched without regard to case). A gateway
    refusal is a non-2xx answer whose JSON object body carries the gateway's
    top-level ``reason`` (or a plan refusal's code as a top-level string
    ``error``); a provider's own error the gateway relays as is, malformed
    input included, is None. Never raises."""
    try:
        return _parse(status, body, headers)
    except Exception:  # noqa: BLE001 - a parser of untrusted input never raises
        return None


def _parse(status: int, body: Any, headers: Optional[Mapping[str, Any]]) -> Optional[GatewayRefusalError]:
    if not isinstance(status, int) or status < 400:
        return None
    obj = _body(body)
    if not isinstance(obj, Mapping):
        return None
    code = _code(obj)
    if not code:
        return None
    kind = OTHER
    row = _KINDS.get(code)
    if row is not None and row[0] == status:
        kind = row[1]
    message = _message(obj, code) or f"the AI gateway refused the call ({code})"
    request_id = _header(headers, "X-SBO-Request-Id") or _header(headers, "request-id") or _header(headers, "x-request-id")
    plan_refusal = None
    if code in (_planrefusal.PLAN_REQUIRED, AIGW_QUOTA_EXCEEDED):
        # The plan detail is the planrefusal body's top-level fields; its
        # parser reads the code from a string error.
        norm = dict(obj)
        norm["error"] = code
        if not _str(norm.get("message")):
            norm["message"] = message
        plan_refusal = _planrefusal.parse_plan_refusal(status, norm, headers)
    return GatewayRefusalError(
        message,
        kind=kind,
        code=code,
        status=status,
        request_id=request_id,
        retry_after=_planrefusal._retry_after(headers),
        budget=_budget(obj) if code == "budget_exceeded" else None,
        plan_refusal=plan_refusal,
    )


def gateway_refusal(source: Any) -> Optional[GatewayRefusalError]:
    """``parse_gateway_refusal`` over a model SDK's error or an HTTP response:
    an ``openai.APIStatusError`` / ``anthropic.APIStatusError`` (its
    ``response``), an ``httpx.Response`` or a ``requests.Response``. None when
    it is not a gateway refusal. Never raises."""
    try:
        resp = getattr(source, "response", None)
        if resp is None or not hasattr(resp, "status_code"):
            resp = source
        status = getattr(resp, "status_code", None)
        if not isinstance(status, int):
            return None
        body: Any = None
        content = getattr(resp, "content", None)
        if isinstance(content, (bytes, bytearray, str)):
            body = content
        elif getattr(source, "body", None) is not None:
            body = source.body
        return parse_gateway_refusal(status, body, getattr(resp, "headers", None))
    except Exception:  # noqa: BLE001
        return None
