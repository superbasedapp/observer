"""SuperBased SDK for Python: send LLM-app and agent traces to SuperBased.

A thin layer over standard OpenTelemetry tracing. It points an OTLP/HTTP
exporter at an Observer node (``http://127.0.0.1:4318/v1/traces`` by default)
or an org OTLP gateway, and tags spans with SuperBased attributes. Anything it
does, a stock OTel exporter pointed at Observer can do too.

Quick start::

    import superbased_sdk as sb

    sb.init(session_id="run-42", user="alice")

    with sb.span("plan", kind=sb.AGENT):
        with sb.llm_span("chat", model="gpt-4o", provider="openai") as s:
            ...  # call your model
            sb.set_usage(s, input_tokens=1200, output_tokens=80,
                         response_id=resp.id)

    sb.shutdown()  # flush before a short-lived process exits

``init()`` is idempotent. When the app already registered an OpenTelemetry
SDK TracerProvider, the SDK adds its span processor to that provider instead
of replacing it, so the app's own and the SDK's spans land in one trace.

IMPORTANT: never set ``sbo.emitted_by=observer``. That is Observer's own
echo-guard marker; a resource carrying it is DROPPED at ingestion.
"""

from __future__ import annotations

import dataclasses
import functools
import inspect
import json
import threading
import time
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional, TypeVar, Union, overload

from . import _config, _destination, _export, _pipeline, _vendor
from . import _keys
from ._instrument import instrument, uninstrument
from ._cost import async_get_trace_cost, get_trace_cost
from . import _gatewayid
from ._gatewayid import GatewayAuth, async_gateway_event_hooks, gateway_event_hooks, gateway_headers, stamp_gateway_request_id
from ._scores import ScoreResult, async_feedback, async_score, feedback, score
from ._experiments import (
    Dataset,
    Evaluation,
    ExperimentError,
    ExperimentGateFailed,
    ExperimentResult,
    ItemResult,
    async_run_experiment,
    get_dataset,
    run_experiment,
)
from ._prompts import (
    Prompt,
    PromptCompileError,
    PromptError,
    PromptFetchError,
    PromptNotFound,
    async_get_prompt,
    get_prompt,
)
from ._context import (
    AttributeScope,
    continue_trace,
    extract,
    get_current_attributes,
    get_current_span_id,
    get_current_trace_id,
    get_traceparent,
    identify,
    inject,
    propagate_attributes,
)
from ._config import Destination, Settings
from ._admit import (
    BAD_RESPONSE,
    DEFAULT_ADMISSION_ENDPOINT,
    DEFAULT_ADMIT_TIMEOUT,
    HTTP_ERROR,
    SDK_ADMIT_PATH,
    TIMEOUT,
    TRANSPORT,
    UNAVAILABLE,
    Verdict,
    admit,
)

__version__ = "0.1.0"

__all__ = [
    "init",
    "span",
    "llm_span",
    "observe",
    "set_usage",
    "set_content",
    "set_input",
    "set_output",
    "set_tool_result",
    "set_documents",
    "set_request_params",
    "tool_span",
    "retriever_span",
    "agent_span",
    "embedding_span",
    "instrument",
    "uninstrument",
    "score",
    "feedback",
    "async_score",
    "async_feedback",
    "ScoreResult",
    "run_experiment",
    "async_run_experiment",
    "get_dataset",
    "Dataset",
    "Evaluation",
    "ExperimentResult",
    "ItemResult",
    "ExperimentError",
    "ExperimentGateFailed",
    "get_prompt",
    "async_get_prompt",
    "get_trace_cost",
    "async_get_trace_cost",
    "stamp_gateway_request_id",
    "gateway_headers",
    "gateway_event_hooks",
    "async_gateway_event_hooks",
    "GatewayAuth",
    "Prompt",
    "PromptError",
    "PromptNotFound",
    "PromptFetchError",
    "PromptCompileError",
    "propagate_attributes",
    "identify",
    "AttributeScope",
    "get_current_attributes",
    "get_current_trace_id",
    "get_current_span_id",
    "get_traceparent",
    "inject",
    "extract",
    "continue_trace",
    "admit",
    "Verdict",
    "flush",
    "shutdown",
    "diagnostics",
    "settings",
    "Settings",
    "Destination",
    "LLM",
    "TOOL",
    "RETRIEVER",
    "EMBEDDING",
    "CHAIN",
    "AGENT",
    "GUARDRAIL",
    "EVALUATOR",
    "DEFAULT_ENDPOINT",
    "DEFAULT_ADMISSION_ENDPOINT",
    "DEFAULT_ADMIT_TIMEOUT",
    "SDK_ADMIT_PATH",
    "UNAVAILABLE",
    "TIMEOUT",
    "TRANSPORT",
    "HTTP_ERROR",
    "BAD_RESPONSE",
]

# Canonical OpenInference span kinds (uppercase; Observer's mapper normalizes
# either case). Pass one of these as ``kind=`` to span()/observe().
LLM = "LLM"
TOOL = "TOOL"
RETRIEVER = "RETRIEVER"
EMBEDDING = "EMBEDDING"
CHAIN = "CHAIN"
AGENT = "AGENT"
GUARDRAIL = "GUARDRAIL"
EVALUATOR = "EVALUATOR"

DEFAULT_ENDPOINT = _config.DEFAULT_ENDPOINT
TRACER_NAME = "superbased_sdk"
SDK_MARKER = "superbased-python"

# Content capture (prompt/response bodies attached to spans) is ON by default.
# Off via init(capture_content=False) or SUPERBASED_CAPTURE_CONTENT=0 (the old
# OBSERVER_CAPTURE_CONTENT is still read). A per-body char cap keeps a giant
# prompt from bloating the export; the client owns this cap.
DEFAULT_MAX_CONTENT_CHARS = _config.DEFAULT_MAX_CONTENT_CHARS
CAPTURE_ENV = ("SUPERBASED_CAPTURE_CONTENT", "OBSERVER_CAPTURE_CONTENT")

# Per-request export timeout (s) and the bound on flush()/shutdown() (s).
DEFAULT_EXPORT_TIMEOUT = _config.DEFAULT_EXPORT_TIMEOUT
DEFAULT_SHUTDOWN_TIMEOUT = _config.DEFAULT_SHUTDOWN_TIMEOUT

_lock = threading.RLock()
_TRACER: Any = None
_PROVIDER: Any = None  # the provider that holds the SDK's spans (ours or the host's)
_OWNS_PROVIDER = False
_PROCESSOR: Optional[_export.SwitchableProcessor] = None
_CONFIG_KEY: Any = None
_MODE = ""  # "", "owned" or "attached"
# {library: "off" | "kept"}: model client libraries that trace themselves
# (_vendor.py), as the last init() left them.
_VENDOR_TRACING: Dict[str, str] = {}
_CAPTURE_CONTENT = True
_MAX_CONTENT_CHARS = DEFAULT_MAX_CONTENT_CHARS
_SHUTDOWN_TIMEOUT = DEFAULT_SHUTDOWN_TIMEOUT
_SETTINGS: Optional[Settings] = None
_PLAN: Optional["_destination.Plan"] = None
_SAMPLER = _pipeline.SwitchableSampler()

F = TypeVar("F", bound=Callable[..., Any])


def _env_flag(name: str, default: bool) -> bool:
    """Parse a boolean-ish env var; unset gives default."""
    return _config.env_flag(_config.environ(), (name,), default)


def _truncate(value: str) -> str:
    """Clip a content body to the configured per-body char cap (marking it)."""
    if _MAX_CONTENT_CHARS > 0 and len(value) > _MAX_CONTENT_CHARS:
        return value[:_MAX_CONTENT_CHARS] + "…[truncated]"
    return value


def _is_sdk_provider(tp: Any) -> bool:
    return callable(getattr(tp, "add_span_processor", None)) and hasattr(tp, "resource")


def init(
    *,
    endpoint: Optional[str] = None,
    tenant: Optional[str] = None,
    user: Optional[str] = None,
    session_id: Optional[str] = None,
    service_name: Optional[str] = None,
    headers: Optional[Mapping[str, str]] = None,
    api_key: Optional[str] = None,
    console: Optional[bool] = None,
    capture_content: Optional[bool] = None,
    max_content_chars: Optional[int] = None,
    export_timeout: Optional[float] = None,
    shutdown_timeout: Optional[float] = None,
    quiet: Optional[bool] = None,
    release: Optional[str] = None,
    environment: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    sample_rate: Optional[float] = None,
    should_export: Optional[Callable[[Any], bool]] = None,
    mask: Optional[Callable[[Any, str], Any]] = None,
    destination: Optional[str] = None,
    org_url: Optional[str] = None,
    node_url: Optional[str] = None,
    discover: Optional[bool] = None,
    api_timeout: Optional[float] = None,
    prompt_cache_ttl: Optional[float] = None,
    gateway_request_id: Optional[bool] = None,
    exporter: Any = None,
    tracer_provider: Any = None,
) -> Settings:
    """Configure tracing to export to SuperBased over OTLP/HTTP. Idempotent.

    Every option maps to an env var (``SUPERBASED_*``, then the standard
    ``OTEL_*`` one where it exists); an explicit argument wins. See
    ``Settings`` and the README's settings table. Highlights:

    - endpoint: the machine (``local``) exporter's address:
      ``$SUPERBASED_OTLP_ENDPOINT``, ``$OTEL_EXPORTER_OTLP_TRACES_ENDPOINT``,
      ``$OTEL_EXPORTER_OTLP_ENDPOINT`` + ``/v1/traces``, else the local node
      ``http://127.0.0.1:4318/v1/traces``. The ``online`` exporter always
      goes to ``org_url`` + ``/v1/traces``.
    - service_name: ``$SUPERBASED_SERVICE_NAME``, ``$OTEL_SERVICE_NAME``,
      ``service.name`` in ``$OTEL_RESOURCE_ATTRIBUTES``, else ``custom-app``.
    - headers merge over ``$OTEL_EXPORTER_OTLP_HEADERS``. api_key
      (``$SUPERBASED_API_KEY``) is sent as ``Authorization: Bearer`` only to
      the org gateway (it replaces any ``Authorization`` header there, in any
      case) or to a remote collector you named yourself; never to this
      machine or to an ``OTEL_EXPORTER_OTLP_*`` endpoint.
    - tenant/user/session_id identify the trace (resource attributes, or
      per-span attributes when attached to the host's provider).
    - export_timeout: seconds per request (default 5). shutdown_timeout bounds
      flush() and shutdown() (default 2 s). flush() returns False when any
      span failed to export, was dropped or is still pending.
    - quiet (default on): exporter warnings stay out of the host's logs;
      failures are counted (``diagnostics()``) and summarised in at most one
      ``superbased_sdk`` log line a minute.
    - release / environment / tags / metadata: process-wide trace identity
      (``$SUPERBASED_RELEASE``, ``$SUPERBASED_ENVIRONMENT``,
      ``$SUPERBASED_TAGS``, ``$SUPERBASED_METADATA``); per request use
      ``propagate_attributes`` / ``identify``.
    - sample_rate: head sampling, 0..1 (``$SUPERBASED_SAMPLE_RATE``, else the
      standard ``$OTEL_TRACES_SAMPLER`` / ``$OTEL_TRACES_SAMPLER_ARG``).
    - should_export(span) -> bool: drop finished spans before export. A hook
      that raises keeps the span.
    - mask(value, key) -> value: rewrite each content attribute before export
      (return None to drop it). A hook that raises drops that content, never
      the span.
    - destination: ``local`` (this machine), ``online`` (the org gateway) or
      ``both`` (``$SUPERBASED_DESTINATION``, else the machine's default over
      loopback, else ``local``). ``both`` runs two independent exporters.
      org_url (``$SUPERBASED_ORG_URL``) is the gateway; the credential is
      api_key, ``$SUPERBASED_API_KEY`` or the machine's SDK credential file.
      node_url (``$SUPERBASED_NODE_URL``) is this machine's dashboard API;
      discover=False (``$SUPERBASED_DISCOVER=0``) never asks it.
    - api_timeout (``$SUPERBASED_API_TIMEOUT_MS``) bounds score, prompt and
      experiment calls; prompt_cache_ttl (``$SUPERBASED_PROMPT_CACHE_TTL_MS``)
      is how long a fetched prompt is fresh.
    - gateway_request_id (default on, ``$SUPERBASED_GATEWAY_REQUEST_ID``):
      when a model call's response carries the org AI gateway's
      ``X-SBO-Request-Id``, set it as ``request_id`` on the span active during
      the call, so the org joins the gateway's exact cost to that span
      (httpx, httpx2 and requests; reads a response header, sends nothing).
    - exporter: a SpanExporter to use instead of OTLP/HTTP (tests, custom
      transport); a dict ``{"local": e1, "online": e2}`` gives each
      destination its own. tracer_provider: an SDK TracerProvider to attach to instead
      of the global one.

    If the app already registered an OpenTelemetry SDK TracerProvider, the SDK
    adds its span processor to it rather than replacing it. A second call with
    the same settings is a no-op; with different settings it replaces the
    SDK's exporter in place (never a second processor). Returns the resolved
    settings.
    """
    global _TRACER, _PROVIDER, _OWNS_PROVIDER, _PROCESSOR, _CONFIG_KEY, _MODE, _SETTINGS, _PLAN
    global _CAPTURE_CONTENT, _MAX_CONTENT_CHARS, _SHUTDOWN_TIMEOUT

    env = _config.environ()
    extra = []
    if exporter is not None:
        extra.append(("exporter", id(exporter)))
    if tracer_provider is not None:
        extra.append(("tracer_provider", id(tracer_provider)))
    settings = Settings.resolve(
        env,
        endpoint=endpoint,
        tenant=tenant,
        user=user,
        session_id=session_id,
        service_name=service_name,
        headers=headers,
        api_key=api_key,
        console=console,
        capture_content=capture_content,
        max_content_chars=max_content_chars,
        export_timeout=export_timeout,
        shutdown_timeout=shutdown_timeout,
        quiet=quiet,
        release=release,
        environment=environment,
        tags=tags,
        metadata=metadata,
        sample_rate=sample_rate,
        destination=destination,
        org_url=org_url,
        node_url=node_url,
        discover=discover,
        api_timeout=api_timeout,
        prompt_cache_ttl=prompt_cache_ttl,
        gateway_request_id=gateway_request_id,
        extra=tuple(extra),
    )
    plan = _destination.resolve(
        settings,
        env,
        explicit_destination=destination,
        explicit_endpoint=endpoint,
        explicit_headers=headers,
        explicit_api_key=api_key,
    )
    if sample_rate is None:
        # A bad env sampling value is ignored, never fatal; it is said once
        # (review E-38; TypeScript does the same).
        bad = _config.sampling_env_problem(env)
        if bad:
            plan = dataclasses.replace(plan, warnings=plan.warnings + (bad,))
    _destination.log_once(plan)
    with _lock:
        # A model client library that traces itself (the Anthropic SDKs) would
        # record every call a second time on the provider registered below.
        _VENDOR_TRACING.clear()
        _VENDOR_TRACING.update(_vendor.apply())
        _SETTINGS, _PLAN = settings, plan
        _CAPTURE_CONTENT = settings.capture_content
        _MAX_CONTENT_CHARS = settings.max_content_chars
        _SHUTDOWN_TIMEOUT = settings.shutdown_timeout

        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        identity = settings.identity(SDK_MARKER)
        # Content and sampling options are applied without a new exporter.
        config_key = (
            dataclasses.replace(
                settings,
                capture_content=True,
                max_content_chars=0,
                sample_rate=1.0,
                sample_parent_based=True,
                api_timeout=0.0,
                prompt_cache_ttl=0.0,
                gateway_request_id=True,
            ),
            plan.exporters,
        )
        _SAMPLER.set(settings.sample_rate, settings.sample_parent_based)
        if settings.gateway_request_id:
            _gatewayid.install()
        else:
            _gatewayid.uninstall()
        hooks = (should_export, mask)
        if _PROCESSOR is not None and _PROCESSOR.delegate is not None and config_key == _CONFIG_KEY:
            _PROCESSOR.pipeline = _make_pipeline(settings, hooks, _OWNS_PROVIDER)
            return settings  # idempotent: already exporting with exactly these settings

        # Pick the provider that will hold the spans.
        if _PROVIDER is None or (tracer_provider is not None and tracer_provider is not _PROVIDER):
            current = tracer_provider if tracer_provider is not None else trace.get_tracer_provider()
            if _is_sdk_provider(current):
                provider, owns = current, False
            else:
                attrs: Dict[str, Any] = dict(settings.resource_attributes)
                attrs.update(identity)
                attrs["service.name"] = settings.service_name
                provider, owns = TracerProvider(resource=Resource.create(attrs), sampler=_SAMPLER), True
                if tracer_provider is None and isinstance(current, trace.ProxyTracerProvider):
                    # Nothing registered yet: register ours so auto-instrumentation
                    # (OpenInference etc.) lands in the same pipeline. A host that
                    # registered a non-SDK provider keeps it; ours stays private.
                    trace.set_tracer_provider(provider)
            processor = _export.SwitchableProcessor()
            provider.add_span_processor(processor)  # type: ignore[union-attr]
            _PROVIDER, _OWNS_PROVIDER, _PROCESSOR = provider, owns, processor
            _MODE = "owned" if owns else "attached"
        assert _PROCESSOR is not None

        delegate = _build_delegate(settings, plan, exporter)

        # Identity the holding provider's resource does not already carry is
        # stamped onto each span (attach mode, or a re-init with new identity).
        res_attrs = getattr(getattr(_PROVIDER, "resource", None), "attributes", {}) or {}
        stamp = {k: v for k, v in identity.items() if not _same_attr(res_attrs.get(k), v)}
        _PROCESSOR.shutdown_timeout = _SHUTDOWN_TIMEOUT
        _PROCESSOR.pipeline = _make_pipeline(settings, hooks, _OWNS_PROVIDER)
        old = _PROCESSOR.swap(delegate, stamp)
        if old is not None:
            _export.shutdown_bounded(old, _SHUTDOWN_TIMEOUT)
        _CONFIG_KEY = config_key
        _TRACER = _PROVIDER.get_tracer(TRACER_NAME, __version__)
        return settings


def _same_attr(a: Any, b: Any) -> bool:
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return tuple(a) == tuple(b)
    return bool(a == b)


def _make_pipeline(settings: Settings, hooks: Any, owns: bool) -> _pipeline.Pipeline:
    should_export, mask = hooks
    return _pipeline.Pipeline(
        capture_content=settings.capture_content,
        max_content_chars=settings.max_content_chars,
        mask=mask,
        should_export=should_export,
        # The SDK's own provider samples at the head; attached to the host's
        # provider, the host's sampler decides what is recorded and the SDK
        # applies its rate to what it exports.
        export_ratio=None if owns else settings.sample_rate,
        drop_scope_prefixes=_vendor.drop_prefixes(_VENDOR_TRACING),
    )


def _build_delegate(settings: Settings, plan: "_destination.Plan", exporter: Any = None) -> Any:
    """One BatchSpanProcessor (over a CountingExporter) per destination, so a
    slow or down destination never delays the other, plus the console
    processor when asked; fanned out as one delegate. A plan with no target
    (``online`` without a gateway or credential) counts every span as dropped."""
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    procs: List[Any] = []
    for dest in plan.exporters:
        inner = exporter.get(dest.name) if isinstance(exporter, Mapping) else exporter
        if inner is None:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

            inner = OTLPSpanExporter(endpoint=dest.endpoint, headers=dict(dest.headers) or None, timeout=dest.timeout)
        procs.append(BatchSpanProcessor(_export.CountingExporter(inner, quiet=settings.quiet)))
    if settings.quiet:
        _export.install_quiet_filter()
    if settings.console:
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

        procs.append(SimpleSpanProcessor(ConsoleSpanExporter()))
    if not procs:
        return _Discard()
    # Every destination's CountingExporter counts a span on its own; the
    # console processor counts nothing (review E-31).
    if len(procs) == 1 and len(plan.exporters) == 1:
        return procs[0]
    return _Fanout(*procs, legs=len(plan.exporters))


class _Discard:
    """The delegate of a plan with nowhere to export: every span is counted
    as dropped (never silently lost; diagnostics() says why)."""

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        return None

    def on_end(self, span: Any) -> None:
        with _export.STATS.lock:
            _export.STATS.dropped_spans += 1

    def shutdown(self) -> None:
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


class _Fanout:
    """Several processors as one delegate: one per destination of ``both``,
    plus the console debug option.

    shutdown() and force_flush() run every processor at the same time, each
    on its own thread, so a destination that is down (its exporter retrying
    for the whole export timeout) never spends the other's share of the
    caller's deadline. Run one after the other, a down machine listed first
    cost the online copy too."""

    def __init__(self, *procs: Any, legs: Optional[int] = None) -> None:
        self._procs = procs
        # The number of counted destinations (diagnostics' pending figure).
        self.legs = len(procs) if legs is None else legs

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        for p in self._procs:
            p.on_start(span, parent_context=parent_context)

    def on_end(self, span: Any) -> None:
        for p in self._procs:
            p.on_end(span)

    def _each(self, fn: Callable[[Any], Any], timeout: Optional[float]) -> List[bool]:
        """fn(p) for every processor concurrently; waits at most ``timeout``
        seconds in all (None: until each returns). A processor that did not
        return in time, or raised, counts as False."""
        results = [False] * len(self._procs)

        def run(i: int, p: Any) -> None:
            try:
                out = fn(p)
                results[i] = True if out is None else bool(out)
            except Exception:  # noqa: BLE001
                results[i] = False

        threads = [
            threading.Thread(target=run, args=(i, p), name="superbased-sdk-fanout", daemon=True)
            for i, p in enumerate(self._procs)
        ]
        for t in threads:
            t.start()
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        for t in threads:
            t.join(None if deadline is None else max(0.0, deadline - time.monotonic()))
        return [r and not t.is_alive() for r, t in zip(results, threads)]

    def shutdown(self) -> None:
        # Bounded by the caller (_export.shutdown_bounded); each processor's
        # own shutdown is bounded by its exporter's timeout.
        self._each(lambda p: p.shutdown(), None)

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return all(self._each(lambda p: p.force_flush(timeout_millis), timeout_millis / 1000.0))


def _tracer() -> Any:
    if _TRACER is not None:
        return _TRACER
    # Fall back to the API's (possibly no-op) tracer so spans never crash a
    # caller who forgot init().
    from opentelemetry import trace

    return trace.get_tracer(TRACER_NAME)


def flush(timeout: Optional[float] = None) -> bool:
    """Export every finished span now. Bounded by ``timeout`` (default: the
    init shutdown_timeout). Returns True when everything was exported in time;
    never raises. Call at the end of a serverless handler."""
    proc = _PROCESSOR
    if proc is None or proc.delegate is None:
        return True
    try:
        return _export.flush_bounded(proc, _SHUTDOWN_TIMEOUT if timeout is None else timeout)
    except Exception:  # noqa: BLE001
        return False


def shutdown(timeout: Optional[float] = None) -> bool:
    """Flush and stop the SDK's exporter. Bounded by ``timeout`` (default: the
    init shutdown_timeout) even when the endpoint is down; never raises. The
    host's own provider, when the SDK attached to one, is left running. A later
    ``init()`` starts exporting again."""
    global _CONFIG_KEY
    _gatewayid.uninstall()
    with _lock:
        proc = _PROCESSOR
        if proc is None:
            return True
        old = proc.detach()
        _CONFIG_KEY = None
    if old is None:
        return True
    try:
        return _export.shutdown_bounded(old, _SHUTDOWN_TIMEOUT if timeout is None else timeout)
    except Exception:  # noqa: BLE001
        return False
    finally:
        _export.maybe_log_failures()


def settings() -> Optional[Settings]:
    """The settings the last ``init()`` resolved (None before init)."""
    return _SETTINGS


def diagnostics() -> Dict[str, Any]:
    """A snapshot of the SDK's export health: ``mode`` ("owned": the SDK's own
    provider; "attached": the host's provider; "": not initialised),
    ``initialized``, ``exported_spans``, ``failed_exports``, ``dropped_spans``,
    ``last_error`` and ``last_error_at`` (epoch seconds), and
    ``admission_degraded`` / ``admission_last_error`` /
    ``admission_last_error_at``: how many admit() calls got no decision and
    were admitted (or denied under fail_closed), and why the last one.
    ``vendor_tracing`` says, per model client library that traces itself
    (``anthropic``), whether its own spans are ``off`` (init() turned them
    off: ``instrument([...])`` records the calls) or ``kept`` (the app set
    its switch, e.g. ``ANTHROPIC_OPEN_TELEMETRY=true``);
    ``vendor_spans_dropped`` counts spans from such a library dropped at
    export (a client built before init())."""
    out = _export.snapshot()
    out.update(_pipeline.COUNTERS.snapshot())
    from . import _admit

    # admit() fails open, but the count and the last cause are here (E-39).
    out.update(_admit.snapshot())
    proc = _PROCESSOR
    out["mode"] = _MODE
    out["initialized"] = bool(proc is not None and proc.delegate is not None)
    out["vendor_tracing"] = dict(_VENDOR_TRACING)
    if _PLAN is not None:
        out.update(_PLAN.summary())
    else:
        out["destinations"] = []
    return out


def _plan() -> Optional["_destination.Plan"]:
    """The destination plan of the last init() (None before init)."""
    return _PLAN


def _status_is_unset(sp: Any) -> bool:
    from opentelemetry.trace import StatusCode

    st = getattr(sp, "status", None)
    code = getattr(st, "status_code", StatusCode.UNSET)
    return code == StatusCode.UNSET


def _mark_ok(sp: Any) -> None:
    """Set OK unless the user already set a status (never overwrite ERROR)."""
    from opentelemetry.trace import Status, StatusCode

    try:
        if _status_is_unset(sp):
            sp.set_status(Status(StatusCode.OK))
    except Exception:  # noqa: BLE001
        pass


def _mark_error(sp: Any, exc: BaseException) -> None:
    """Record the exception exactly once and set ERROR."""
    from opentelemetry.trace import Status, StatusCode

    try:
        sp.record_exception(exc)
        sp.set_status(Status(StatusCode.ERROR, f"{type(exc).__name__}: {exc}"))
    except Exception:  # noqa: BLE001
        pass


@contextmanager
def span(name: str, kind: str = CHAIN, attributes: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
    """Open a span of the given OpenInference kind as a context manager.

    Records an exception once and sets ERROR when the body raises; sets OK on
    success unless the body already set a status.
    """
    attrs: Dict[str, Any] = {"openinference.span.kind": kind}
    if attributes:
        attrs.update(attributes)
    with _tracer().start_as_current_span(
        name, attributes=attrs, record_exception=False, set_status_on_exception=False
    ) as sp:
        try:
            yield sp
        except Exception as exc:
            _mark_error(sp, exc)
            raise
        else:
            _mark_ok(sp)


def _json(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)


def _set(sp: Any, key: str, value: Any) -> None:
    """set_attribute that never raises (a non-recording span ignores it)."""
    try:
        sp.set_attribute(key, value)
    except Exception:  # noqa: BLE001
        pass


def _content(value: Any) -> Any:
    """A content body as an attribute value (clipped), or None when capture is off."""
    if not _CAPTURE_CONTENT or value is None:
        return None
    return _truncate(_json(value))


def _kind_of(sp: Any) -> str:
    try:
        return str((getattr(sp, "attributes", None) or {}).get(_keys.SPAN_KIND, "")).upper()
    except Exception:  # noqa: BLE001
        return ""


def _is_message_list(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and all(isinstance(m, Mapping) for m in value)


@contextmanager
def llm_span(
    name: str,
    *,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    operation: str = "chat",
    prompt: Any = None,
    system: Any = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> Iterator[Any]:
    """Open an LLM span pre-tagged in both the OTel GenAI and the OpenInference
    vocabularies: ``gen_ai.operation.name`` (default ``chat``),
    ``gen_ai.request.model``, ``gen_ai.provider.name`` and the legacy
    ``gen_ai.system``, plus ``llm.model_name`` / ``llm.provider``.

    prompt (when content capture is on): a string goes to ``input.value``; a
    list of message dicts (``{"role": ..., "content": ...}``) goes to
    ``gen_ai.input.messages``; a ``Prompt`` from ``get_prompt()`` stamps
    ``sbo.prompt.name`` / ``.version`` / ``.label`` on the span. system goes to ``gen_ai.system_instructions``.
    Pass the response with set_usage(..., response=...) or set_content()."""
    attrs: Dict[str, Any] = {_keys.OPERATION: operation}
    if model:
        attrs[_keys.REQUEST_MODEL] = model
        attrs[_keys.OI_MODEL] = model
    if provider:
        attrs[_keys.PROVIDER] = provider
        attrs[_keys.LEGACY_SYSTEM] = provider
        attrs[_keys.OI_PROVIDER] = provider
    if isinstance(prompt, Prompt):
        # A registry prompt: stamp its name and version (the template itself is
        # not the request content; pass the compiled text with set_content).
        attrs.update(prompt.attributes())
        prompt = None
    body = _content(prompt)
    if body is not None:
        attrs[_keys.INPUT_MESSAGES if _is_message_list(prompt) else _keys.INPUT_VALUE] = body
    instr = _content(system)
    if instr is not None:
        attrs[_keys.SYSTEM_INSTRUCTIONS] = instr
    if attributes:
        attrs.update(attributes)
    with span(name, kind=LLM, attributes=attrs) as sp:
        yield sp


@contextmanager
def tool_span(
    name: str,
    *,
    tool_name: Optional[str] = None,
    call_id: Optional[str] = None,
    arguments: Any = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> Iterator[Any]:
    """Open a TOOL span (``gen_ai.operation.name=execute_tool``):
    ``gen_ai.tool.name`` / ``tool.name`` (default: the span name),
    ``gen_ai.tool.call.id`` and, when content capture is on,
    ``gen_ai.tool.call.arguments`` (a non-string is JSON-encoded). Record the
    result with set_tool_result()."""
    tname = tool_name or name
    attrs: Dict[str, Any] = {_keys.OPERATION: "execute_tool", _keys.TOOL_NAME: tname, _keys.OI_TOOL_NAME: tname}
    if call_id:
        attrs[_keys.TOOL_CALL_ID] = call_id
    body = _content(arguments)
    if body is not None:
        attrs[_keys.TOOL_ARGUMENTS] = body
    if attributes:
        attrs.update(attributes)
    with span(name, kind=TOOL, attributes=attrs) as sp:
        yield sp


@contextmanager
def retriever_span(name: str, *, query: Any = None, attributes: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
    """Open a RETRIEVER span (``gen_ai.operation.name=retrieval``) with the
    query as ``gen_ai.retrieval.query.text`` (content). Record the hits with
    set_documents()."""
    attrs: Dict[str, Any] = {_keys.OPERATION: "retrieval"}
    body = _content(query)
    if body is not None:
        attrs[_keys.RETRIEVAL_QUERY] = body
    if attributes:
        attrs.update(attributes)
    with span(name, kind=RETRIEVER, attributes=attrs) as sp:
        yield sp


@contextmanager
def agent_span(
    name: str,
    *,
    agent_name: Optional[str] = None,
    agent_id: Optional[str] = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> Iterator[Any]:
    """Open an AGENT span (``gen_ai.operation.name=invoke_agent``) with
    ``gen_ai.agent.name`` / ``agent.name`` (default: the span name) and
    ``gen_ai.agent.id``."""
    aname = agent_name or name
    attrs: Dict[str, Any] = {_keys.OPERATION: "invoke_agent", _keys.AGENT_NAME: aname, _keys.OI_AGENT_NAME: aname}
    if agent_id:
        attrs[_keys.AGENT_ID] = agent_id
    if attributes:
        attrs.update(attributes)
    with span(name, kind=AGENT, attributes=attrs) as sp:
        yield sp


@contextmanager
def embedding_span(
    name: str,
    *,
    model: Optional[str] = None,
    provider: Optional[str] = None,
    attributes: Optional[Mapping[str, Any]] = None,
) -> Iterator[Any]:
    """Open an EMBEDDING span (``gen_ai.operation.name=embeddings``) with the
    request model and provider. Record usage with set_usage(input_tokens=...)."""
    attrs: Dict[str, Any] = {_keys.OPERATION: "embeddings"}
    if model:
        attrs[_keys.REQUEST_MODEL] = model
    if provider:
        attrs[_keys.PROVIDER] = provider
        attrs[_keys.LEGACY_SYSTEM] = provider
    if attributes:
        attrs.update(attributes)
    with span(name, kind=EMBEDDING, attributes=attrs) as sp:
        yield sp


def _count(name: str, value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, got a bool")
    n = int(value)
    if n < 0:
        raise ValueError(f"{name} must not be negative, got {value!r}")
    return n


_NET_INPUT_WARNED = threading.Event()


def _gross_input(input_tokens: Optional[int], cache_read: Optional[int], cache_write: Optional[int]) -> Optional[int]:
    """The gross input count: ``input_tokens`` as given, unless it is below its
    own cache parts. Then it cannot be gross (it is a NET count, as Anthropic's
    ``usage.input_tokens`` is), so the cache parts are added, the correction is
    counted (``diagnostics()["usage_net_input_corrected"]``) and a warning is
    logged once per process."""
    cache = (cache_read or 0) + (cache_write or 0)
    if input_tokens is None or input_tokens >= cache:
        return input_tokens
    _pipeline.COUNTERS.add("usage_net_input_corrected")
    if not _NET_INPUT_WARNED.is_set():
        _NET_INPUT_WARNED.set()
        import logging

        logging.getLogger("superbased_sdk").warning(
            "set_usage: input_tokens %d is below cache_read_tokens + cache_write_tokens (%d); "
            "recorded as a net count (input + cache = %d). Pass the gross input: for Anthropic, "
            "usage.input_tokens + cache_creation_input_tokens + cache_read_input_tokens.",
            input_tokens,
            cache,
            input_tokens + cache,
        )
    return input_tokens + cache


def set_usage(
    sp: Any,
    *,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
    cache_read_tokens: Optional[int] = None,
    cache_write_tokens: Optional[int] = None,
    reasoning_tokens: Optional[int] = None,
    response_id: Optional[str] = None,
    request_id: Optional[str] = None,
    response_model: Optional[str] = None,
    finish_reasons: Optional[Iterable[str]] = None,
    cost_usd: Optional[float] = None,
    prompt: Any = None,
    response: Any = None,
) -> None:
    """Record token usage, ids and the outcome on an LLM (or embedding) span
    using the keys Observer reconciles against proxy turns.

    Token buckets follow the GenAI semconv: ``input_tokens`` is the GROSS
    input and includes cache reads and writes, so ``cache_read_tokens`` and
    ``cache_write_tokens`` are subsets of it, never addends.
    ``output_tokens`` includes ``reasoning_tokens``. ``total_tokens`` is
    optional (ingest derives input + output). A negative count raises
    ValueError. An ``input_tokens`` below ``cache_read_tokens +
    cache_write_tokens`` cannot be gross: it is read as a net count (Anthropic's
    ``usage.input_tokens`` is net), recorded as input + cache, counted in
    ``diagnostics()["usage_net_input_corrected"]`` and warned about once; a
    ``total_tokens`` equal to that net input + output is raised by the same
    amount.

    response_id (the provider message id, e.g. Anthropic ``msg_…`` or OpenAI
    ``chatcmpl-…``) doubles as the dedup key when no request_id is set.
    prompt/response, when passed and content capture is on, attach the bodies
    (a convenience wrapper over set_content)."""
    counts = (
        (_keys.INPUT_TOKENS, "input_tokens", input_tokens),
        (_keys.OUTPUT_TOKENS, "output_tokens", output_tokens),
        (_keys.TOTAL_TOKENS, "total_tokens", total_tokens),
        (_keys.CACHE_READ_TOKENS, "cache_read_tokens", cache_read_tokens),
        (_keys.CACHE_WRITE_TOKENS, "cache_write_tokens", cache_write_tokens),
        (_keys.REASONING_TOKENS, "reasoning_tokens", reasoning_tokens),
    )
    resolved = [(key, _count(label, v)) for key, label, v in counts]  # validate before writing any
    by_key = dict(resolved)
    net_in = by_key[_keys.INPUT_TOKENS]
    gross_in = _gross_input(net_in, by_key[_keys.CACHE_READ_TOKENS], by_key[_keys.CACHE_WRITE_TOKENS])
    if gross_in != net_in and net_in is not None:
        added = gross_in - net_in
        total = by_key[_keys.TOTAL_TOKENS]
        fixed = {_keys.INPUT_TOKENS: gross_in}
        if total is not None and total == net_in + (by_key[_keys.OUTPUT_TOKENS] or 0):
            fixed[_keys.TOTAL_TOKENS] = total + added
        resolved = [(key, fixed.get(key, n)) for key, n in resolved]
    for key, n in resolved:
        if n is not None:
            _set(sp, key, n)
    if response_id:
        _set(sp, _keys.RESPONSE_ID, response_id)
    if request_id:
        _set(sp, _keys.REQUEST_ID, request_id)
    if response_model:
        _set(sp, _keys.RESPONSE_MODEL, response_model)
    if finish_reasons is not None:
        reasons = [finish_reasons] if isinstance(finish_reasons, str) else [str(r) for r in finish_reasons]
        _set(sp, _keys.FINISH_REASONS, reasons)
    if cost_usd is not None:
        _set(sp, _keys.COST, float(cost_usd))
    if prompt is not None or response is not None:
        set_content(sp, prompt=prompt, response=response)


def set_content(
    sp: Any,
    *,
    prompt: Any = None,
    response: Any = None,
    tool_args: Any = None,
    tool_result: Any = None,
) -> None:
    """Attach prompt/response (LLM span) or tool args/result (TOOL span)
    bodies so Observer can persist the conversation content.

    No-op when content capture is off. Each body is clipped to
    max_content_chars. On an LLM span a string goes to ``input.value`` /
    ``output.value`` and a list of message dicts to ``gen_ai.input.messages``
    / ``gen_ai.output.messages``; on a TOOL span the bodies go to
    ``gen_ai.tool.call.arguments`` / ``gen_ai.tool.call.result``."""
    if not _CAPTURE_CONTENT:
        return
    req = prompt if prompt is not None else tool_args
    res = response if response is not None else tool_result
    if _kind_of(sp) == TOOL:
        in_key, out_key = _keys.TOOL_ARGUMENTS, _keys.TOOL_RESULT
    else:
        in_key = _keys.INPUT_MESSAGES if _is_message_list(req) else _keys.INPUT_VALUE
        out_key = _keys.OUTPUT_MESSAGES if _is_message_list(res) else _keys.OUTPUT_VALUE
    if req is not None:
        _set(sp, in_key, _truncate(_json(req)))
    if res is not None:
        _set(sp, out_key, _truncate(_json(res)))


def set_input(sp: Any, value: Any) -> None:
    """Record a span's input (``input.value``; a non-string is JSON-encoded).
    Content: honours capture_content and max_content_chars."""
    body = _content(value)
    if body is not None:
        _set(sp, _keys.INPUT_VALUE, body)


def set_output(sp: Any, value: Any) -> None:
    """Record a span's output (``output.value``; on a RETRIEVER span,
    ``gen_ai.retrieval.documents``). Content rules apply."""
    if _kind_of(sp) == RETRIEVER:
        set_documents(sp, value)
        return
    body = _content(value)
    if body is not None:
        _set(sp, _keys.OUTPUT_VALUE, body)


def set_tool_result(sp: Any, result: Any) -> None:
    """Record a tool call's result (``gen_ai.tool.call.result``). Content rules apply."""
    body = _content(result)
    if body is not None:
        _set(sp, _keys.TOOL_RESULT, body)


def set_documents(sp: Any, documents: Any) -> None:
    """Record retrieved documents (``gen_ai.retrieval.documents``, a JSON
    array; strings become ``{"content": ...}``). Content rules apply."""
    if documents is None:
        return
    if isinstance(documents, (list, tuple)):
        documents = [d if isinstance(d, Mapping) else {"content": d} for d in documents]
    body = _content(documents)
    if body is not None:
        _set(sp, _keys.RETRIEVAL_DOCUMENTS, body)


def set_request_params(
    sp: Any,
    *,
    max_tokens: Optional[int] = None,
    temperature: Optional[float] = None,
    top_p: Optional[float] = None,
    top_k: Optional[float] = None,
    stop_sequences: Optional[Iterable[str]] = None,
    frequency_penalty: Optional[float] = None,
    presence_penalty: Optional[float] = None,
    seed: Optional[int] = None,
    stream: Optional[bool] = None,
    reasoning_level: Optional[str] = None,
) -> None:
    """Record the model request parameters (``gen_ai.request.<name>``)."""
    given = dict(
        max_tokens=max_tokens,
        temperature=temperature,
        top_p=top_p,
        top_k=top_k,
        stop_sequences=stop_sequences,
        frequency_penalty=frequency_penalty,
        presence_penalty=presence_penalty,
        seed=seed,
        stream=stream,
        reasoning_level=reasoning_level,
    )
    for name, value in given.items():
        if value is None:
            continue
        if name == "stop_sequences":
            value = [value] if isinstance(value, str) else [str(v) for v in value]  # type: ignore[union-attr]
        _set(sp, _keys.REQUEST_PARAMS[name], value)


# --- observe ------------------------------------------------------------------


def _start(name: str, kind: str) -> Any:
    return _tracer().start_span(name, attributes={"openinference.span.kind": kind})


def _active(sp: Any) -> Any:
    from opentelemetry import trace

    return trace.use_span(sp, end_on_exit=False, record_exception=False, set_status_on_exception=False)


def _wrap_sync(fn: Callable[..., Any], name: str, kind: str) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with span(name, kind=kind):
            return fn(*args, **kwargs)

    return wrapper


def _wrap_async(fn: Callable[..., Any], name: str, kind: str) -> Callable[..., Any]:
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        with span(name, kind=kind):
            return await fn(*args, **kwargs)

    return wrapper


def _wrap_gen(fn: Callable[..., Any], name: str, kind: str) -> Callable[..., Any]:
    """The span covers the whole iteration, from the first ``next()`` to
    exhaustion, an exception or ``close()``. The span is current only while
    the generator body runs, never while the consumer holds control."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        sp = _start(name, kind)
        try:
            with _active(sp):
                gen = fn(*args, **kwargs)
            method: Any = gen.send
            arg: Any = None
            while True:
                with _active(sp):
                    try:
                        item = method(arg)
                    except StopIteration as stop:
                        _mark_ok(sp)
                        return stop.value
                try:
                    arg = yield item
                    method = gen.send
                except GeneratorExit:
                    with _active(sp):
                        gen.close()
                    raise
                except BaseException as exc:  # noqa: BLE001 - forwarded into the generator
                    method, arg = gen.throw, exc
        except GeneratorExit:
            raise
        except Exception as exc:
            _mark_error(sp, exc)
            raise
        finally:
            sp.end()

    return wrapper


def _wrap_async_gen(fn: Callable[..., Any], name: str, kind: str) -> Callable[..., Any]:
    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        sp = _start(name, kind)
        try:
            with _active(sp):
                agen = fn(*args, **kwargs)
            method: Any = agen.asend
            arg: Any = None
            while True:
                with _active(sp):
                    try:
                        item = await method(arg)
                    except StopAsyncIteration:
                        _mark_ok(sp)
                        return
                try:
                    arg = yield item
                    method = agen.asend
                except GeneratorExit:
                    with _active(sp):
                        await agen.aclose()
                    raise
                except BaseException as exc:  # noqa: BLE001 - forwarded into the generator
                    method, arg = agen.athrow, exc
        except GeneratorExit:
            raise
        except Exception as exc:
            _mark_error(sp, exc)
            raise
        finally:
            sp.end()

    return wrapper


@overload
def observe(name: F) -> F: ...


@overload
def observe(name: Optional[str] = None, kind: str = CHAIN) -> Callable[[F], F]: ...


def observe(name: Union[str, Callable[..., Any], None] = None, kind: str = CHAIN) -> Any:
    """Decorator that wraps each call in a span (name defaults to the
    function's qualified name). Handles plain functions, ``async def``
    functions, generators and async generators: the span covers the awaited
    call or the whole iteration, and an exception is recorded once.

    Use as ``@observe``, ``@observe()`` or ``@observe("name", kind=TOOL)``.
    """
    if callable(name):
        return observe()(name)

    def deco(fn: F) -> F:
        span_name = str(name or getattr(fn, "__qualname__", getattr(fn, "__name__", "observe")))
        if inspect.isasyncgenfunction(fn):
            return _wrap_async_gen(fn, span_name, kind)  # type: ignore[return-value]
        if inspect.isgeneratorfunction(fn):
            return _wrap_gen(fn, span_name, kind)  # type: ignore[return-value]
        if inspect.iscoroutinefunction(fn):
            return _wrap_async(fn, span_name, kind)  # type: ignore[return-value]
        return _wrap_sync(fn, span_name, kind)  # type: ignore[return-value]

    return deco


def _reset_for_tests() -> None:
    """Forget all SDK state (tests only). Does not touch the global provider."""
    global _TRACER, _PROVIDER, _OWNS_PROVIDER, _PROCESSOR, _CONFIG_KEY, _MODE, _SETTINGS, _PLAN
    with _lock:
        if _PROCESSOR is not None:
            old = _PROCESSOR.detach()
            if old is not None:
                _export.shutdown_bounded(old, 1.0)
        _TRACER = _PROVIDER = _PROCESSOR = _CONFIG_KEY = _SETTINGS = _PLAN = None
        _destination.reset_for_tests()
        from . import _control

        _control.reset_for_tests()
        from . import _prompts

        _prompts.CACHE.clear()
        _gatewayid.uninstall()
        _export.ENRICHERS.clear()
        _OWNS_PROVIDER = False
        _MODE = ""
        _export.STATS.reset()
        from . import _admit

        _admit.STATS.reset()
        _pipeline.COUNTERS.reset()
        _vendor._reset_for_tests()
        _VENDOR_TRACING.clear()
        _NET_INPUT_WARNED.clear()
        _SAMPLER.set(1.0, True)
