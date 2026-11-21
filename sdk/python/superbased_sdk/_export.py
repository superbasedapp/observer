"""Export plumbing: a failure-counting exporter wrapper, a switchable span
processor, quiet logging and the diagnostics snapshot.

The SDK adds exactly ONE span processor (``SwitchableProcessor``) to whichever
TracerProvider holds the app's spans: its own provider, or one the host
already registered. Re-running ``init()`` swaps the processor's delegate
(a BatchSpanProcessor over a ``CountingExporter``) instead of adding another
processor, so spans are never exported twice or lost to an orphaned provider.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Mapping, Optional, Sequence

from opentelemetry.sdk.trace.export import SpanExporter

LOG = logging.getLogger("superbased_sdk")

# How often (seconds) the SDK may write its one-line export-failure summary.
FAILURE_LOG_INTERVAL = 60.0

_tls = threading.local()


class _Stats:
    """Process-wide export counters; one lock, read by diagnostics()."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.handed_spans = 0
        self.exported_spans = 0
        self.abandoned_spans = 0
        self.failed_exports = 0
        self.dropped_spans = 0
        self.last_error = ""
        self.last_error_at = 0.0
        self.last_logged_at = 0.0
        self.unlogged_failures = 0


STATS = _Stats()


def _note_error(message: str) -> None:
    with STATS.lock:
        STATS.last_error = message[:500]
        STATS.last_error_at = time.time()


class _ExportLogFilter(logging.Filter):
    """Drops log records emitted on the thread that is inside our exporter's
    ``export()``/``shutdown()``, keeping the message as ``last_error``. Records
    from the host's own exporters (other threads, or outside our call) pass."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(_tls, "inside", False) and getattr(_tls, "quiet", True):
            if record.levelno >= logging.WARNING:
                try:
                    _note_error(record.getMessage())
                except Exception:  # noqa: BLE001 - a bad format string must not escape
                    pass
            return False
        return True


_FILTER = _ExportLogFilter()
_QUIET_PREFIXES = ("opentelemetry.exporter", "urllib3", "requests")


def install_quiet_filter() -> None:
    """Attach the filter to every exporter-related logger that exists now.
    Idempotent; called after the exporter (and so its loggers) is created."""
    names = [n for n in list(logging.root.manager.loggerDict) if n.startswith(_QUIET_PREFIXES)]
    names.append("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    for name in names:
        lg = logging.getLogger(name)
        if _FILTER not in lg.filters:
            lg.addFilter(_FILTER)


class CountingExporter(SpanExporter):
    """Wraps a SpanExporter: never raises, counts failures and dropped spans,
    and (when quiet) keeps the wrapped exporter's warnings out of host logs."""

    def __init__(self, inner: Any, *, quiet: bool = True) -> None:
        self._inner = inner
        self._quiet = quiet

    def export(self, spans: Sequence[Any]) -> Any:
        from opentelemetry.sdk.trace.export import SpanExportResult

        _tls.inside, _tls.quiet = True, self._quiet
        try:
            result = self._inner.export(spans)
        except Exception as exc:  # noqa: BLE001 - an exporter must never raise into the processor
            _note_error(f"{type(exc).__name__}: {exc}")
            result = SpanExportResult.FAILURE
        finally:
            _tls.inside = False
        n = len(spans)
        if result == SpanExportResult.SUCCESS:
            with STATS.lock:
                # Spans a timed-out flush already wrote off may still arrive.
                late = min(STATS.abandoned_spans, n)
                STATS.abandoned_spans -= late
                STATS.dropped_spans -= late
                STATS.exported_spans += n
        else:
            with STATS.lock:
                late = min(STATS.abandoned_spans, n)
                STATS.abandoned_spans -= late
                if late == 0:
                    STATS.failed_exports += 1
                    STATS.unlogged_failures += 1
                STATS.dropped_spans += n - late
                if not STATS.last_error:
                    STATS.last_error = "export failed"
                    STATS.last_error_at = time.time()
            maybe_log_failures()
        return result

    def shutdown(self) -> None:
        _tls.inside, _tls.quiet = True, self._quiet
        try:
            self._inner.shutdown()
        except Exception:  # noqa: BLE001
            pass
        finally:
            _tls.inside = False

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        fn = getattr(self._inner, "force_flush", None)
        if fn is None:
            return True
        try:
            return bool(fn(timeout_millis))
        except Exception:  # noqa: BLE001
            return False


def maybe_log_failures(now: Optional[float] = None) -> bool:
    """Write at most one summary line per FAILURE_LOG_INTERVAL. Returns True
    when a line was written."""
    now = time.time() if now is None else now
    with STATS.lock:
        if STATS.unlogged_failures == 0 or now - STATS.last_logged_at < FAILURE_LOG_INTERVAL:
            return False
        n, err, total = STATS.unlogged_failures, STATS.last_error, STATS.dropped_spans
        STATS.unlogged_failures = 0
        STATS.last_logged_at = now
    LOG.warning(
        "superbased_sdk: %d trace export(s) failed since the last report (%d spans dropped in total); last error: %s",
        n,
        total,
        err or "unknown",
    )
    return True


# Attribute enrichers an instrument() target registers (name -> fn(attrs) ->
# extra attributes or None). The SDK exports a copy of a finished span with the
# extra attributes added (never overwriting one the span carries); the original
# span is not changed. Used by the pydantic-ai target, whose OpenInference
# mapping is a span processor rather than an instrumentor.
ENRICHERS: Dict[str, Any] = {}


def enrich(span: Any) -> Any:
    """``span``, or a copy with every registered enricher's attributes added."""
    if not ENRICHERS:
        return span
    try:
        attrs = dict(span.attributes or {})
        added: Dict[str, Any] = {}
        for fn in list(ENRICHERS.values()):
            extra = fn(attrs)
            if extra:
                for k, v in extra.items():
                    if k not in attrs and k not in added:
                        added[k] = v
        if not added:
            return span
        import copy

        from . import _pipeline

        view = copy.copy(span)
        attrs.update(added)
        view._attributes = _pipeline._bounded(attrs, getattr(span, "_attributes", None))
        return view
    except Exception:  # noqa: BLE001 - an enricher never breaks export
        return span


def legs_of(delegate: Any) -> int:
    """How many counted destinations a delegate hands each span to: the
    ``legs`` attribute, else 1. A console-only delegate has 0."""
    n = getattr(delegate, "legs", 1)
    return n if isinstance(n, int) and n >= 0 else 1


class SwitchableProcessor:
    """The one span processor the SDK adds. Forwards to a replaceable delegate,
    stamps identity and per-request attributes the span does not carry, and
    applies the export pipeline (sample filter, should_export, content rules)
    before the delegate sees a finished span."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._delegate: Any = None
        self._stamp: Dict[str, Any] = {}
        self.pipeline: Any = None  # a _pipeline.Pipeline; None: export as is
        self.shutdown_timeout = 2.0

    def swap(self, delegate: Any, stamp: Mapping[str, Any]) -> Any:
        """Install a new delegate; returns the previous one (caller shuts it down)."""
        with self._lock:
            old, self._delegate = self._delegate, delegate
            self._stamp = dict(stamp)
        return old

    def detach(self) -> Any:
        return self.swap(None, {})

    @property
    def delegate(self) -> Any:
        return self._delegate

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        d, stamp = self._delegate, self._stamp
        if d is None:
            return
        try:
            from . import _context, _keys

            scope = _context.scope_attributes(parent_context)
            existing = span.attributes or {}
            for k, v in scope.items():
                if k not in existing:
                    span.set_attribute(k, v)
            existing = span.attributes or {}
            for k, v in stamp.items():
                if k not in existing:
                    span.set_attribute(k, v)
                elif k == _keys.TAGS and k in scope:
                    span.set_attribute(k, _context.normalize_tags(existing.get(k), v))
        except Exception:  # noqa: BLE001
            pass
        try:
            d.on_start(span, parent_context=parent_context)
        except Exception:  # noqa: BLE001
            pass

    def _on_ending(self, span: Any) -> None:  # newer SDKs call this; nothing to do
        return None

    def on_end(self, span: Any) -> None:
        d = self._delegate
        if d is None:
            return
        if ENRICHERS:
            span = enrich(span)
        p = self.pipeline
        if p is not None:
            from . import _pipeline

            span = _pipeline.decide(span, p)
            if span is None:
                return
        # Counted once per destination the span goes to (review E-31): each
        # destination's exporter counts it as exported or dropped on its own,
        # so a span handed to both counts twice. A delegate without ``legs``
        # is one destination.
        with STATS.lock:
            STATS.handed_spans += legs_of(d)
        try:
            d.on_end(span)
        except Exception:  # noqa: BLE001
            pass

    def shutdown(self) -> None:
        # Called when the HOLDING provider shuts down. Close our delegate, bounded.
        old = self.detach()
        if old is not None:
            shutdown_bounded(old, self.shutdown_timeout)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        d = self._delegate
        if d is None:
            return True
        try:
            return bool(d.force_flush(timeout_millis))
        except Exception:  # noqa: BLE001
            return False


def _run_bounded(fn: Any, timeout: float) -> bool:
    """Run ``fn`` on a daemon thread; wait at most ``timeout`` seconds. Returns
    True when it finished in time. A stuck exporter cannot block the host."""
    done = threading.Event()

    def target() -> None:
        try:
            fn()
        except Exception:  # noqa: BLE001
            pass
        finally:
            done.set()

    t = threading.Thread(target=target, name="superbased-sdk-flush", daemon=True)
    t.start()
    return done.wait(max(0.0, timeout))


def _pending_locked() -> int:
    return max(0, STATS.handed_spans - STATS.exported_spans - STATS.dropped_spans - STATS.abandoned_spans)


def note_timeout(op: str, timeout: float) -> None:
    """A flush/shutdown ran out of time: count it as a failed export and the
    spans still unresolved as dropped (from the SDK's point of view)."""
    with STATS.lock:
        pending = _pending_locked()
        STATS.failed_exports += 1
        STATS.abandoned_spans += pending
        STATS.dropped_spans += pending
        STATS.unlogged_failures += 1
        STATS.last_error = f"{op} timed out after {timeout:g}s with {pending} span(s) not exported" + (
            f"; exporter: {STATS.last_error}" if STATS.last_error else ""
        )
        STATS.last_error = STATS.last_error[:500]
        STATS.last_error_at = time.time()


def flush_bounded(processor: Any, timeout: float) -> bool:
    """True only when the flush finished in time and no span failed to export,
    was dropped or is still pending, in every quiet mode (review FR-S07)."""
    with STATS.lock:
        dropped_before = STATS.dropped_spans
    ok = [False]

    def run() -> None:
        ok[0] = bool(processor.force_flush(int(timeout * 1000)))

    finished = _run_bounded(run, timeout)
    if not finished:
        note_timeout("flush", timeout)
    with STATS.lock:
        clean = _pending_locked() == 0 and STATS.dropped_spans <= dropped_before
    return finished and ok[0] and clean


def shutdown_bounded(processor: Any, timeout: float) -> bool:
    finished = _run_bounded(processor.shutdown, timeout)
    if not finished:
        note_timeout("shutdown", timeout)
    return finished


def snapshot() -> Dict[str, Any]:
    with STATS.lock:
        return {
            "pending_spans": _pending_locked(),
            "exported_spans": STATS.exported_spans,
            "failed_exports": STATS.failed_exports,
            "dropped_spans": STATS.dropped_spans,
            "last_error": STATS.last_error,
            "last_error_at": STATS.last_error_at,
        }
