"""What happens to a finished span before the SDK exports it: the attached-mode
sample filter, the ``should_export`` hook, and the content rules
(``capture_content``, the ``mask`` hook, ``max_content_chars``).

The original span is never changed: when a content rule changes something the
SDK exports a shallow copy with new attributes and events, so a host's other
span processors still see the original.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from opentelemetry.sdk.trace.sampling import Sampler as _Sampler

from . import _keys as K

MaskFn = Callable[[Any, str], Any]
ShouldExportFn = Callable[[Any], bool]

TRUNCATED_MARK = "…[truncated]"

_TRACE_ID_LIMIT = (1 << 64) - 1


@dataclass(frozen=True)
class Pipeline:
    """The export-side rules, swapped as one value by ``init()``."""

    capture_content: bool = True
    max_content_chars: int = 0
    mask: Optional[MaskFn] = None
    should_export: Optional[ShouldExportFn] = None
    # Applied only when the host's sampler, not the SDK's, made the decision
    # (attached mode). None: export every recorded span.
    export_ratio: Optional[float] = None
    # Tracer scopes of model client libraries whose own spans are dropped
    # (_vendor.py: they would count every call a second time).
    drop_scope_prefixes: Tuple[str, ...] = ()


class Counters:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.sampled_out_spans = 0
        self.filtered_spans = 0
        self.mask_errors = 0
        self.should_export_errors = 0
        self.vendor_spans_dropped = 0
        self.usage_net_input_corrected = 0
        self.last_hook_error = ""

    def add(self, name: str, err: str = "") -> None:
        with self.lock:
            setattr(self, name, getattr(self, name) + 1)
            if err:
                self.last_hook_error = err[:500]

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "sampled_out_spans": self.sampled_out_spans,
                "filtered_spans": self.filtered_spans,
                "mask_errors": self.mask_errors,
                "should_export_errors": self.should_export_errors,
                "vendor_spans_dropped": self.vendor_spans_dropped,
                "usage_net_input_corrected": self.usage_net_input_corrected,
                "last_hook_error": self.last_hook_error,
            }


COUNTERS = Counters()


def ratio_bound(rate: float) -> int:
    """TraceIdRatioBased's bound: a trace is kept when the low 64 bits of its
    id are below it (the OTel algorithm, so services agree)."""
    return round(max(0.0, min(1.0, rate)) * (_TRACE_ID_LIMIT + 1))


def keep_by_ratio(trace_id: int, rate: float) -> bool:
    return (trace_id & _TRACE_ID_LIMIT) < ratio_bound(rate)


def _truncate(value: Any, limit: int) -> Any:
    if limit > 0 and isinstance(value, str) and len(value) > limit:
        return value[:limit] + TRUNCATED_MARK
    return value


def _content_value(key: str, value: Any, p: Pipeline) -> Tuple[bool, Any]:
    """(keep, new value) for one content attribute."""
    if not p.capture_content:
        return False, None
    if p.mask is not None:
        try:
            value = p.mask(value, key)
        except Exception as exc:  # noqa: BLE001 - fail safe: drop the content, keep the span
            COUNTERS.add("mask_errors", f"mask({key}): {type(exc).__name__}: {exc}")
            return False, None
        if value is None:
            return False, None
        if not isinstance(value, (str, bool, int, float, list, tuple)):
            value = str(value)
    return True, _truncate(value, p.max_content_chars)


def _rewrite(attrs: Any, p: Pipeline) -> Optional[Dict[str, Any]]:
    """New attributes when a content rule changes ``attrs``; None when none."""
    if not attrs:
        return None
    out: Dict[str, Any] = {}
    changed = False
    for key, value in attrs.items():
        if not K.is_content_key(key):
            out[key] = value
            continue
        keep, new = _content_value(key, value, p)
        if not keep:
            changed = True
            continue
        if new is not value and new != value:
            changed = True
        out[key] = new
    return out if changed else None


def _needs_content_rules(p: Pipeline) -> bool:
    return (not p.capture_content) or p.mask is not None or p.max_content_chars > 0


def apply_content_rules(span: Any, p: Pipeline) -> Any:
    """The span to export: ``span`` itself, or a copy with rewritten content."""
    if not _needs_content_rules(p):
        return span
    try:
        new_attrs = _rewrite(getattr(span, "attributes", None), p)
        events = list(getattr(span, "events", ()) or ())
        new_events = None
        for i, ev in enumerate(events):
            ev_attrs = _rewrite(getattr(ev, "attributes", None), p)
            if ev_attrs is not None:
                if new_events is None:
                    new_events = list(events)
                new_events[i] = _event_copy(ev, ev_attrs)
        if new_attrs is None and new_events is None:
            return span
        view = copy.copy(span)
        if new_attrs is not None:
            view._attributes = _bounded(new_attrs, getattr(span, "_attributes", None))
        if new_events is not None:
            view._events = _events_like(getattr(span, "_events", None), new_events)
        return view
    except Exception as exc:  # noqa: BLE001
        # A span the rules cannot copy is exported without its content rather
        # than with unmasked content.
        COUNTERS.add("mask_errors", f"content rules: {type(exc).__name__}: {exc}")
        return _strip_all(span)


def _strip_all(span: Any) -> Any:
    try:
        view = copy.copy(span)
        attrs = {k: v for k, v in (span.attributes or {}).items() if not K.is_content_key(k)}
        view._attributes = _bounded(attrs, getattr(span, "_attributes", None))
        view._events = _events_like(getattr(span, "_events", None), [])
        return view
    except Exception:  # noqa: BLE001
        return None


def _bounded(attrs: Dict[str, Any], like: Any) -> Any:
    from opentelemetry.attributes import BoundedAttributes

    b = BoundedAttributes(maxlen=None, attributes=attrs, immutable=True)
    dropped = getattr(like, "dropped", 0)
    if dropped:
        try:
            b.dropped = dropped
        except Exception:  # noqa: BLE001
            pass
    return b


def _events_like(like: Any, events: Any) -> Any:
    if like is not None and hasattr(like, "maxlen"):
        from collections import deque

        return deque(events, maxlen=like.maxlen)
    return tuple(events)


def _event_copy(ev: Any, attrs: Dict[str, Any]) -> Any:
    from opentelemetry.sdk.trace import Event

    return Event(ev.name, attributes=_bounded(attrs, getattr(ev, "_attributes", None)), timestamp=ev.timestamp)


def decide(span: Any, p: Pipeline) -> Optional[Any]:
    """The span to hand to the exporter, or None to drop it (counted)."""
    if p.drop_scope_prefixes:
        from . import _vendor

        scope = _vendor.scope_name(span)
        if scope and scope.startswith(p.drop_scope_prefixes):
            COUNTERS.add("vendor_spans_dropped")
            return None
    if p.export_ratio is not None and p.export_ratio < 1.0:
        try:
            if not keep_by_ratio(span.context.trace_id, p.export_ratio):
                COUNTERS.add("sampled_out_spans")
                return None
        except Exception:  # noqa: BLE001
            pass
    if p.should_export is not None:
        try:
            ok = p.should_export(span)
        except Exception as exc:  # noqa: BLE001 - fail open: keep the span, count the error
            COUNTERS.add("should_export_errors", f"should_export: {type(exc).__name__}: {exc}")
            ok = True
        if not ok:
            COUNTERS.add("filtered_spans")
            return None
    return apply_content_rules(span, p)


class SwitchableSampler(_Sampler):
    """The sampler of a provider the SDK owns: parent-based (or not) trace-id
    ratio, with the rate swappable by a later ``init()``."""

    def __init__(self, rate: float = 1.0, parent_based: bool = True) -> None:
        self.set(rate, parent_based)

    def set(self, rate: float, parent_based: bool = True) -> None:
        from opentelemetry.sdk.trace import sampling

        if rate >= 1.0:
            root: Any = sampling.ALWAYS_ON
        elif rate <= 0.0:
            root = sampling.ALWAYS_OFF
        else:
            root = sampling.TraceIdRatioBased(rate)
        self._rate = rate
        self._inner = sampling.ParentBased(root) if parent_based else root

    @property
    def rate(self) -> float:
        return self._rate

    def should_sample(self, *args: Any, **kwargs: Any) -> Any:
        return self._inner.should_sample(*args, **kwargs)

    def get_description(self) -> str:
        return f"SuperbasedSampler{{{self._inner.get_description()}}}"
