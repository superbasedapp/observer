"""Per-request attributes (``propagate_attributes`` / ``identify``) and W3C
trace-context helpers (``inject`` / ``extract`` / ``continue_trace``).

The attribute scope lives in the OpenTelemetry ``Context`` (itself backed by
``contextvars``), so it follows ``asyncio`` tasks, ``contextvars.copy_context``
and an explicit ``context=`` passed to ``start_span``. The SDK's span
processor reads it in ``on_start`` and stamps the values onto each new span
(never over a value the span already carries).
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional, Tuple

from opentelemetry import baggage as otel_baggage
from opentelemetry import context as otel_context
from opentelemetry import trace
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositePropagator
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from . import _keys as K

_SCOPE_KEY = otel_context.create_key("superbased-sdk-attributes")
_PROPAGATOR = CompositePropagator([TraceContextTextMapPropagator(), W3CBaggagePropagator()])

# Option name -> span attribute (scalar options).
SCALAR_KEYS: Dict[str, str] = {
    "user": K.USER,
    "session_id": K.SESSION,
    "tenant": K.TENANT,
    "release": K.RELEASE,
    "environment": K.ENVIRONMENT,
}
_BAGGAGE_KEYS = tuple(SCALAR_KEYS.values()) + (K.TAGS,)


def _clamp(value: str, limit: int) -> str:
    value = value.strip()
    return value[:limit] if limit > 0 else value


def normalize_tags(*lists: Optional[Iterable[Any]]) -> List[str]:
    """otelident.NormalizeTags: trimmed, clamped, de-duplicated, sorted, capped."""
    seen = set()
    out: List[str] = []
    for lst in lists:
        if not lst:
            continue
        if isinstance(lst, str):
            lst = lst.split(",")
        for t in lst:
            s = _clamp(str(t), K.MAX_TAG_LEN)
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    out.sort()
    return out[: K.MAX_TAGS]


def _meta_value(v: Any) -> str:
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, separators=(",", ":"), sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(v)


def normalize_metadata(*maps: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """otelident.NormalizeMetadata with LATER maps winning (inner scope over
    outer), keys and values clamped, capped at MAX_METADATA_KEYS keeping the
    lexically smallest keys."""
    out: Dict[str, str] = {}
    for m in maps:
        if not m:
            continue
        for k, v in m.items():
            key = _clamp(str(k), K.MAX_METADATA_KEY_LEN)
            if not key:
                continue
            if v is None:
                out.pop(key, None)
                continue
            out[key] = _clamp(_meta_value(v), K.MAX_METADATA_VALUE_LEN)
    if len(out) > K.MAX_METADATA_KEYS:
        for k in sorted(out)[K.MAX_METADATA_KEYS :]:
            del out[k]
    return out


class Scope:
    """An immutable set of per-request values (one level of nesting)."""

    __slots__ = ("scalars", "tags", "metadata", "baggage")

    def __init__(
        self,
        scalars: Optional[Mapping[str, str]] = None,
        tags: Tuple[str, ...] = (),
        metadata: Optional[Mapping[str, str]] = None,
        baggage: bool = False,
    ) -> None:
        self.scalars: Dict[str, str] = dict(scalars or {})
        self.tags: Tuple[str, ...] = tuple(tags)
        self.metadata: Dict[str, str] = dict(metadata or {})
        self.baggage = baggage

    def merged(self, **opts: Any) -> "Scope":
        """This scope with ``opts`` (the propagate_attributes options) on top."""
        scalars = dict(self.scalars)
        for name, key in SCALAR_KEYS.items():
            v = opts.get(name)
            if v is None:
                continue
            s = _clamp(str(v), K.MAX_VALUE_LEN)
            if s:
                scalars[key] = s
            else:
                scalars.pop(key, None)  # "" clears it for the inner scope
        tags = tuple(normalize_tags(self.tags, opts.get("tags")))
        meta = opts.get("metadata")
        if meta is not None and not isinstance(meta, Mapping):
            raise TypeError("metadata must be a mapping")
        metadata = normalize_metadata(self.metadata, meta)
        return Scope(scalars, tags, metadata, self.baggage or bool(opts.get("as_baggage")))

    def attributes(self) -> Dict[str, Any]:
        """The span attributes this scope writes."""
        out: Dict[str, Any] = dict(self.scalars)
        if self.tags:
            out[K.TAGS] = list(self.tags)
        for k, v in self.metadata.items():
            out[K.METADATA_PREFIX + k] = v
        return out

    def public(self) -> Dict[str, Any]:
        """The option-named view (get_current_attributes)."""
        out: Dict[str, Any] = {}
        for name, key in SCALAR_KEYS.items():
            if key in self.scalars:
                out[name] = self.scalars[key]
        if self.tags:
            out["tags"] = list(self.tags)
        if self.metadata:
            out["metadata"] = dict(self.metadata)
        return out


_EMPTY = Scope()


def current_scope(ctx: Any = None) -> Scope:
    s = otel_context.get_value(_SCOPE_KEY, ctx)
    return s if isinstance(s, Scope) else _EMPTY


def scope_attributes(ctx: Any = None) -> Dict[str, Any]:
    """The attributes in effect for a span started in ``ctx`` (None: current)."""
    return current_scope(ctx).attributes()


def _with_baggage(ctx: Any, scope: Scope) -> Any:
    for key, value in scope.scalars.items():
        ctx = otel_baggage.set_baggage(key, value, ctx)
    if scope.tags:
        ctx = otel_baggage.set_baggage(K.TAGS, ",".join(scope.tags), ctx)
    for k, v in scope.metadata.items():
        ctx = otel_baggage.set_baggage(K.METADATA_PREFIX + k, v, ctx)
    return ctx


def _apply_to_current_span(scope: Scope, opts: Mapping[str, Any]) -> None:
    """Write the values just set onto the current span too (so a trace root
    entered before propagate_attributes is tagged)."""
    sp = trace.get_current_span()
    if not sp.is_recording():
        return
    try:
        attrs = scope.attributes()
        for name, key in SCALAR_KEYS.items():
            if opts.get(name) and key in attrs:
                sp.set_attribute(key, attrs[key])
        if opts.get("tags") and K.TAGS in attrs:
            existing = getattr(sp, "attributes", None) or {}
            sp.set_attribute(K.TAGS, normalize_tags(existing.get(K.TAGS), attrs[K.TAGS]))
        if opts.get("metadata"):
            for k in opts["metadata"]:
                key = K.METADATA_PREFIX + _clamp(str(k), K.MAX_METADATA_KEY_LEN)
                if key in attrs:
                    sp.set_attribute(key, attrs[key])
    except Exception:  # noqa: BLE001 - tagging must never break the caller
        pass


class AttributeScope:
    """The handle ``identify()`` returns: ``reset()`` undoes it. Usable as a
    context manager too (``with identify(...):`` resets on exit)."""

    def __init__(self, token: Any) -> None:
        self._token = token

    def reset(self) -> None:
        tok, self._token = self._token, None
        if tok is not None:
            try:
                otel_context.detach(tok)
            except Exception:  # noqa: BLE001
                pass

    def __enter__(self) -> "AttributeScope":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.reset()


def _enter(opts: Dict[str, Any]) -> Any:
    scope = current_scope().merged(**opts)
    ctx = otel_context.set_value(_SCOPE_KEY, scope)
    if scope.baggage:
        ctx = _with_baggage(ctx, scope)
    token = otel_context.attach(ctx)
    _apply_to_current_span(scope, opts)
    return token


def identify(
    *,
    user: Optional[str] = None,
    session_id: Optional[str] = None,
    tenant: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    release: Optional[str] = None,
    environment: Optional[str] = None,
) -> AttributeScope:
    """Set the end user, session, tenant, tags, metadata, release and
    environment for the rest of the current context (this asyncio task, this
    thread) and on the current span. Returns a handle whose ``reset()`` undoes
    it. In a thread-pool server, prefer ``propagate_attributes`` (a block),
    since a pooled thread outlives the request."""
    opts = dict(user=user, session_id=session_id, tenant=tenant, tags=tags, metadata=metadata, release=release, environment=environment)
    return AttributeScope(_enter(opts))


@contextmanager
def propagate_attributes(
    *,
    user: Optional[str] = None,
    session_id: Optional[str] = None,
    tenant: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    release: Optional[str] = None,
    environment: Optional[str] = None,
    as_baggage: bool = False,
) -> Iterator[None]:
    """Apply per-request values to the current span and to every span started
    inside the block (sync or async code; nested blocks merge, inner wins,
    tags union). ``as_baggage=True`` also puts them into W3C baggage so
    ``inject()`` carries them to downstream services. Baggage travels in
    request headers: only use it for values you may send to those services.
    """
    opts = dict(
        user=user,
        session_id=session_id,
        tenant=tenant,
        tags=tags,
        metadata=metadata,
        release=release,
        environment=environment,
        as_baggage=as_baggage,
    )
    token = _enter(opts)
    try:
        yield
    finally:
        try:
            otel_context.detach(token)
        except Exception:  # noqa: BLE001
            pass


def get_current_attributes() -> Dict[str, Any]:
    """The per-request values in effect here, by option name."""
    return current_scope().public()


# --- trace context ----------------------------------------------------------------


def _valid_context() -> Any:
    sc = trace.get_current_span().get_span_context()
    return sc if sc is not None and sc.is_valid else None


def get_current_trace_id() -> str:
    """The current trace id (32 lowercase hex), or "" outside a span."""
    sc = _valid_context()
    return trace.format_trace_id(sc.trace_id) if sc else ""


def get_current_span_id() -> str:
    """The current span id (16 lowercase hex), or "" outside a span."""
    sc = _valid_context()
    return trace.format_span_id(sc.span_id) if sc else ""


class _Getter:
    """Case-insensitive header lookup over any mapping."""

    def get(self, carrier: Mapping[str, Any], key: str) -> Optional[List[str]]:
        want = key.lower()
        for k, v in carrier.items():
            if str(k).lower() == want:
                if isinstance(v, (list, tuple)):
                    return [str(x) for x in v]
                return [str(v)]
        return None

    def keys(self, carrier: Mapping[str, Any]) -> List[str]:
        return [str(k) for k in carrier]


_GETTER = _Getter()


def inject(carrier: Optional[MutableMapping[str, str]] = None) -> MutableMapping[str, str]:
    """Write ``traceparent`` (and ``tracestate`` / ``baggage`` when present)
    for the current context into ``carrier`` (a new dict when None) and return
    it. Always W3C, whatever propagator the host configured."""
    out: MutableMapping[str, str] = {} if carrier is None else carrier
    try:
        _PROPAGATOR.inject(out)
    except Exception:  # noqa: BLE001
        pass
    return out


def get_traceparent() -> str:
    """The W3C ``traceparent`` of the current span, or ""."""
    return inject({}).get("traceparent", "")


def extract(carrier: Mapping[str, Any]) -> Any:
    """The OpenTelemetry Context carried by W3C headers in ``carrier``
    (case-insensitive). Pass it as ``context=`` or use ``continue_trace``."""
    try:
        return _PROPAGATOR.extract(carrier or {}, getter=_GETTER)  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001
        return otel_context.get_current()


def _scope_from_baggage(ctx: Any) -> Optional[Scope]:
    entries = otel_baggage.get_all(ctx)
    if not entries:
        return None
    opts: Dict[str, Any] = {}
    reverse = {v: k for k, v in SCALAR_KEYS.items()}
    meta: Dict[str, str] = {}
    for key, value in entries.items():
        if key in reverse:
            opts[reverse[key]] = str(value)
        elif key == K.TAGS:
            opts["tags"] = str(value).split(",")
        elif key.startswith(K.METADATA_PREFIX):
            meta[key[len(K.METADATA_PREFIX) :]] = str(value)
    if meta:
        opts["metadata"] = meta
    if not opts:
        return None
    return current_scope(ctx).merged(as_baggage=True, **opts)


@contextmanager
def continue_trace(carrier: Mapping[str, Any]) -> Iterator[Any]:
    """Make the context carried by ``carrier`` current for the block (spans
    inside join the caller's trace) and restore per-request values the caller
    sent as baggage. Yields the context."""
    ctx = extract(carrier)
    scope = _scope_from_baggage(ctx)
    if scope is not None:
        ctx = otel_context.set_value(_SCOPE_KEY, scope, ctx)
    token = otel_context.attach(ctx)
    try:
        yield ctx
    finally:
        try:
            otel_context.detach(token)
        except Exception:  # noqa: BLE001
            pass
