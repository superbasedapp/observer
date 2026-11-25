"""Stamp the AI gateway's request id on the span that made the call (W4-2,
contracts/cost-source.md section 4 rule 1).

The org AI gateway answers every inference request with
``X-SBO-Request-Id: <id>``; the org joins its exact cost to the app span whose
``request_id`` equals that id. Instrumentors do not read response headers, so
the SDK wraps the HTTP clients the model SDKs use (httpx, the httpx2 fork
openai and anthropic ship, and requests) and, when a response carries the
header, sets ``request_id`` on the span active during the call: the
instrumentor's LLM span, or your ``llm_span``. A response without the header
(any call that did not go through the gateway) is left alone, a span that
already carries ``request_id`` is never overwritten, and nothing is sent: the
wrapper only reads a response header.

On by default; ``init(gateway_request_id=False)`` or
``SUPERBASED_GATEWAY_REQUEST_ID=0`` turns it off (and restores the clients).
"""

from __future__ import annotations

import importlib
import threading
from typing import Any, Callable, Dict, List, Tuple

from . import _keys as K

HEADER = "x-sbo-request-id"
MAX_LEN = 256

# (module, class, method, async)
_TARGETS: Tuple[Tuple[str, str, str, bool], ...] = (
    ("httpx", "Client", "send", False),
    ("httpx", "AsyncClient", "send", True),
    ("httpx2", "Client", "send", False),
    ("httpx2", "AsyncClient", "send", True),
    ("requests", "Session", "send", False),
)

_lock = threading.Lock()
_patched: Dict[Tuple[str, str, str], Any] = {}  # -> the original function
_MARK = "__superbased_gateway_request_id__"


def stamp_gateway_request_id(response: Any, span: Any = None) -> bool:
    """Set ``request_id`` on ``span`` (default: the current span) from the AI
    gateway's ``X-SBO-Request-Id`` on ``response``: any object with a
    ``headers`` mapping (httpx, requests, an OpenAI SDK raw response) or a
    headers mapping itself. For HTTP clients the SDK does not wrap. Returns
    True when it stamped; a missing header, a span that already has
    ``request_id`` or a non-recording span stamps nothing. Never raises.
    (TS: ``stampGatewayRequestId``.)"""
    headers = getattr(response, "headers", response)
    return stamp(headers, span)


def stamp(headers: Any, span: Any = None) -> bool:
    """Set ``request_id`` on the current span from a response's headers when
    the gateway's header is there. Returns True when it stamped. Never
    raises."""
    try:
        rid = _header(headers)
        if not rid:
            return False
        if span is None:
            from opentelemetry import trace

            span = trace.get_current_span()
        if not span.is_recording():
            return False
        attrs = getattr(span, "attributes", None) or {}
        if K.REQUEST_ID in attrs:
            return False
        span.set_attribute(K.REQUEST_ID, str(rid).strip()[:MAX_LEN])
        return True
    except Exception:  # noqa: BLE001 - never breaks the host's HTTP call
        return False


def _header(headers: Any) -> str:
    """The gateway header from any headers object, case-insensitively (httpx
    and requests headers are; a plain dict is not)."""
    if headers is None:
        return ""
    rid = headers.get(HEADER)
    if not rid and hasattr(headers, "items"):
        rid = next((v for k, v in headers.items() if str(k).lower() == HEADER), "")
    return str(rid or "")


def _sync_wrapper(orig: Callable[..., Any]) -> Callable[..., Any]:
    def send(self: Any, *args: Any, **kwargs: Any) -> Any:
        resp = orig(self, *args, **kwargs)
        stamp(getattr(resp, "headers", None))
        return resp

    setattr(send, _MARK, orig)
    send.__wrapped__ = orig  # type: ignore[attr-defined]
    return send


def _async_wrapper(orig: Callable[..., Any]) -> Callable[..., Any]:
    async def send(self: Any, *args: Any, **kwargs: Any) -> Any:
        resp = await orig(self, *args, **kwargs)
        stamp(getattr(resp, "headers", None))
        return resp

    setattr(send, _MARK, orig)
    send.__wrapped__ = orig  # type: ignore[attr-defined]
    return send


def install() -> List[str]:
    """Wrap every importable client once (idempotent). Returns the wrapped
    ``module.Class.method`` names."""
    with _lock:
        for mod_name, cls_name, meth, is_async in _TARGETS:
            key = (mod_name, cls_name, meth)
            if key in _patched:
                continue
            try:
                mod = importlib.import_module(mod_name)
                cls = getattr(mod, cls_name)
                orig = getattr(cls, meth)
            except Exception:  # noqa: BLE001 - not installed
                continue
            if getattr(orig, _MARK, None) is not None:
                continue
            setattr(cls, meth, (_async_wrapper if is_async else _sync_wrapper)(orig))
            _patched[key] = orig
        return sorted(".".join(k) for k in _patched)


def uninstall() -> None:
    """Restore every wrapped client."""
    with _lock:
        for (mod_name, cls_name, meth), orig in list(_patched.items()):
            try:
                cls = getattr(importlib.import_module(mod_name), cls_name)
                if getattr(getattr(cls, meth), _MARK, None) is orig:
                    setattr(cls, meth, orig)
            except Exception:  # noqa: BLE001
                pass
            _patched.pop((mod_name, cls_name, meth), None)


def installed() -> List[str]:
    with _lock:
        return sorted(".".join(k) for k in _patched)


# --- sending the app's identity to the AI gateway (review E-64) ---------------------
#
# The org AI gateway's app budget caps reserve against a hosted app's end user
# and service, which it reads from two request headers. These helpers send
# them, at parity with the TypeScript SDK's gatewayFetch(): the per-request
# user (propagate_attributes / identify, else init()'s user) and the
# service.name the app's spans carry (the one admit() sends), plus an
# X-SBO-Request-Id when the request carries none. A header the request
# already carries is kept. Use them only on a client pointed at the gateway:
# the end user is PII, and the gateway never forwards these headers upstream.

USER_HEADER = "X-Superbased-User"
SERVICE_HEADER = "X-Superbased-Service"
REQUEST_ID_HEADER = "X-SBO-Request-Id"
TRACEPARENT_HEADER = "traceparent"
# The gateway ignores a longer value (internal/aigateway/gwhttp maxAppIDLen).
MAX_APP_ID_LEN = 512


def _app_value(v: Any) -> str:
    """A header-safe app id: trimmed, printable ASCII (what every Python HTTP
    client can send), at most MAX_APP_ID_LEN bytes; "" to leave it out."""
    s = str(v or "").strip()
    if not s or len(s) > MAX_APP_ID_LEN or not all(" " <= c <= "~" for c in s):
        return ""
    return s


def gateway_headers() -> Dict[str, str]:
    """The headers the org AI gateway reads a call's app identity from, for
    the request being made now: ``X-Superbased-User`` (the per-request user,
    else ``init()``'s), ``X-Superbased-Service`` (the spans' ``service.name``),
    a fresh ``X-SBO-Request-Id`` and the current span's ``traceparent``. A value that is empty, too long or not
    printable ASCII is left out. For an HTTP client the hooks below do not
    cover (pass them as per-request headers). Never raises. (TS: what
    ``gatewayFetch()`` sends.)"""
    out: Dict[str, str] = {}
    try:
        import os
        import uuid

        from ._admit import _init_identity, _scope_values, _service_name

        user = _app_value(_scope_values().get("user") or _init_identity().get("user"))
        if user:
            out[USER_HEADER] = user
        service = _app_value(_service_name(os.environ))
        if service:
            out[SERVICE_HEADER] = service
        out[REQUEST_ID_HEADER] = "sdk-" + uuid.uuid4().hex
        # The span active during the call (an instrumentor's LLM span), so the
        # organization joins the call to it even without the request id.
        from ._context import get_traceparent

        tp = get_traceparent()
        if tp:
            out[TRACEPARENT_HEADER] = tp
    except Exception:  # noqa: BLE001 - never breaks the host's HTTP call
        pass
    return out


def _add_missing(headers: Any) -> None:
    """Set each gateway header ``headers`` does not already carry
    (case-insensitively). Never raises."""
    try:
        have = {str(k).lower() for k in headers.keys()}
        for k, v in gateway_headers().items():
            if k.lower() not in have:
                headers[k] = v
    except Exception:  # noqa: BLE001
        pass


def _httpx_request_hook(request: Any) -> None:
    _add_missing(request.headers)


async def _httpx_async_request_hook(request: Any) -> None:
    _add_missing(request.headers)


def gateway_event_hooks() -> Dict[str, List[Callable[..., Any]]]:
    """httpx ``event_hooks`` for a client that calls the org AI gateway::

        http = httpx.Client(event_hooks=superbased_sdk.gateway_event_hooks())
        client = OpenAI(base_url=GATEWAY + "/v1", api_key=..., http_client=http)

    Each request gets the app identity headers (``gateway_headers()``),
    keeping any the request already carries. The gateway's answered request
    id is stamped on the active span by the SDK's response wrapper (on by
    default). For ``httpx.AsyncClient`` use ``async_gateway_event_hooks()``."""
    return {"request": [_httpx_request_hook]}


def async_gateway_event_hooks() -> Dict[str, List[Callable[..., Any]]]:
    """``gateway_event_hooks()`` for ``httpx.AsyncClient`` (its hooks must be
    coroutines)."""
    return {"request": [_httpx_async_request_hook]}


class GatewayAuth:
    """A ``requests`` auth that adds the app identity headers to each request
    (``requests`` has no request hook), wrapping any auth the session already
    has::

        session = requests.Session()
        session.auth = superbased_sdk.GatewayAuth(session.auth)

    The wrapped auth runs first; then each gateway header the request does
    not already carry is added (``gateway_headers()``)."""

    def __init__(self, inner: Any = None) -> None:
        self.inner = inner

    def __call__(self, request: Any) -> Any:
        if self.inner is not None:
            request = self.inner(request)
        _add_missing(request.headers)
        return request
