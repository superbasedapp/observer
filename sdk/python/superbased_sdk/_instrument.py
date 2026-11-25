"""``instrument([...])``: framework auto-instrumentation over the upstream
OpenInference instrumentors (plan D10: depend on them, own only the mapping
and the conformance fixtures).

Each target is a row of ``TARGETS``; the instrumentor is installed by the
matching extra (``pip install "superbased-sdk[openai]"``). A missing extra or
library is reported, never raised. The spans the instrumentors emit go through
the SDK's provider, so identity, sampling, masking and the destination apply
to them like to the SDK's own spans.

``init()`` instruments by itself (``auto_instrument``, plan 3.1): only when
the SDK owns the tracer provider, never ``openai-agents`` unless named, and
without importing a framework the app has not imported: an installed one is
instrumented on its first import, through a small ``sys.meta_path`` finder.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import logging
import sys
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Set, Tuple

LOG = logging.getLogger("superbased_sdk")

INSTRUMENTED = "instrumented"
ALREADY = "already"
NOT_INSTALLED = "not-installed"
# Auto-instrumentation only (diagnostics()["instrumented"], sdk-api-surface.md 14):
PENDING = "pending"  # installed, not imported yet: instrumented on its first import
AUTO_EXCLUDED = "skipped: auto_excluded"  # installed, but instrumented only when named
SKIPPED_HOST_PROVIDER = "skipped: host_provider"  # the app registered its own provider
SKIPPED_NOT_INSTALLED = "skipped: not_installed"  # the framework or its instrumentation is missing


@dataclass(frozen=True)
class Target:
    """One instrumentable framework."""

    name: str
    module: str  # the OpenInference instrumentor module
    cls: str  # its BaseInstrumentor subclass
    library: str  # the framework's import name (must be importable)
    extra: str  # pip extra that installs the instrumentor
    package: str  # the instrumentor's distribution name
    note: str = ""
    # Whether init()'s auto mode instruments it (False: only when named).
    auto: bool = True
    # The distributions that mean "this app uses the framework" (setup's
    # detection reads these; one owner, plan 3.5).
    distributions: Tuple[str, ...] = ()
    # Further modules that must be importable for the instrumentor to load
    # (beside ``module`` and ``library``).
    requires: Tuple[str, ...] = ()


TARGETS: Tuple[Target, ...] = (
    Target(
        "openai",
        "openinference.instrumentation.openai",
        "OpenAIInstrumentor",
        "openai",
        "openai",
        "openinference-instrumentation-openai",
        distributions=("openai",),
    ),
    Target(
        "anthropic",
        "openinference.instrumentation.anthropic",
        "AnthropicInstrumentor",
        "anthropic",
        "anthropic",
        "openinference-instrumentation-anthropic",
        distributions=("anthropic",),
    ),
    Target(
        "langchain",
        "openinference.instrumentation.langchain",
        "LangChainInstrumentor",
        "langchain_core",
        "langchain",
        "openinference-instrumentation-langchain",
        note="covers LangGraph (its runs are LangChain runs)",
        distributions=("langchain-core", "langchain", "langgraph"),
    ),
    Target(
        "mcp",
        "openinference.instrumentation.mcp",
        "MCPInstrumentor",
        "mcp",
        "mcp",
        "openinference-instrumentation-mcp",
        note="carries trace context across MCP client and server, so server-side spans join the caller's trace",
        distributions=("mcp",),
    ),
    # Wave 5 (W5-1).
    Target(
        "gemini",
        "openinference.instrumentation.google_genai",
        "GoogleGenAIInstrumentor",
        "google.genai",
        "gemini",
        "openinference-instrumentation-google-genai",
        note="the google-genai SDK, for the Gemini API and Vertex AI (Client(vertexai=True)); the legacy vertexai SDK is not covered",
        distributions=("google-genai",),
    ),
    Target(
        "bedrock",
        "openinference.instrumentation.bedrock",
        "BedrockInstrumentor",
        "boto3",
        "bedrock",
        "openinference-instrumentation-bedrock",
        note="boto3 bedrock-runtime clients created after instrument() (converse, invoke_model and their streams)",
        distributions=("boto3",),
    ),
    Target(
        "llama-index",
        "openinference.instrumentation.llama_index",
        "LlamaIndexInstrumentor",
        "llama_index.core",
        "llama-index",
        "openinference-instrumentation-llama-index",
        distributions=("llama-index-core", "llama-index"),
    ),
    Target(
        "crewai",
        "openinference.instrumentation.crewai",
        "CrewAIInstrumentor",
        "crewai",
        "crewai",
        "openinference-instrumentation-crewai",
        note="crew, task and agent spans; the model calls come from the openai (or litellm) instrumentation",
        distributions=("crewai",),
    ),
    Target(
        "pydantic-ai",
        "superbased_sdk._pydantic_ai",
        "PydanticAIInstrumentor",
        "pydantic_ai",
        "pydantic-ai",
        "openinference-instrumentation-pydantic-ai",
        note="turns on Pydantic AI's own OpenTelemetry spans and adds the OpenInference attributes at export",
        distributions=("pydantic-ai", "pydantic-ai-slim"),
        requires=("openinference.instrumentation.pydantic_ai",),
    ),
    Target(
        "openai-agents",
        "openinference.instrumentation.openai_agents",
        "OpenAIAgentsInstrumentor",
        "agents",
        "openai-agents",
        "openinference-instrumentation-openai-agents",
        note="replaces the Agents SDK's own trace processors while instrumented, so its traces are not also uploaded to OpenAI",
        auto=False,
        distributions=("openai-agents",),
    ),
)

# Other spellings accepted by instrument() / uninstrument(). Underscores are
# read as hyphens first (llama_index -> llama-index).
ALIASES: Dict[str, str] = {
    "langgraph": "langchain",
    "google-genai": "gemini",
    "vertex": "gemini",
    "vertexai": "gemini",
    "boto3": "bedrock",
    "llamaindex": "llama-index",
    "agents": "openai-agents",
}

_BY_NAME = {t.name: t for t in TARGETS}
# Re-entrant: a framework's first import can fire a hook (and so
# instrument()) on a thread that is already inside instrument(). Never held
# while a module is imported (see _instrument_one).
_lock = threading.RLock()
_active: Dict[str, Any] = {}  # target name -> instrumentor instance
_inflight: Set[str] = set()  # targets being instrumented right now


def _names(targets: Optional[Iterable[str]]) -> List[str]:
    if targets is None:
        return [t.name for t in TARGETS]
    if isinstance(targets, str):
        targets = [targets]
    out: List[str] = []
    for raw in targets:
        name = _canonical(raw)
        if name not in _BY_NAME:
            raise ValueError(f"unknown instrument target {raw!r}; known: {_known()}")
        if name not in out:
            out.append(name)
    return out


def _canonical(raw: Any) -> str:
    name = str(raw).strip().lower().replace("_", "-")
    return ALIASES.get(name, name)


def _known() -> str:
    return ", ".join(sorted(set(_BY_NAME) | set(ALIASES)))


def _load(t: Target) -> Any:
    """The instrumentor class, or None when the extra or the library is missing."""
    try:
        importlib.import_module(t.library)
        mod = importlib.import_module(t.module)
    except ImportError:
        return None
    return getattr(mod, t.cls, None)


def _instrument_one(name: str, provider: Any) -> str:
    """Instrument one target; the status. The lock is held only around the
    bookkeeping, never while the framework or its instrumentor is imported,
    so a hook fired by another thread's import cannot deadlock on it."""
    with _lock:
        if name in _active or name in _inflight:
            return ALREADY
        _inflight.add(name)
    inst: Any = None
    try:
        t = _BY_NAME[name]
        cls = _load(t)
        if cls is None:
            return NOT_INSTALLED
        try:
            inst = cls()  # BaseInstrumentor subclasses are per-class singletons
            if getattr(inst, "_is_instrumented_by_opentelemetry", False):
                inst = None
                return ALREADY  # the host (or opentelemetry-instrument) got there first
            check = getattr(inst, "_check_dependency_conflicts", None)
            conflict = check() if callable(check) else None
            if conflict:
                inst = None
                return f"error: {conflict}"[:300]
            kwargs: Dict[str, Any] = {"skip_dep_check": True}
            if provider is not None:
                kwargs["tracer_provider"] = provider
            inst.instrument(**kwargs)
        except Exception as exc:  # noqa: BLE001 - instrumenting must never break the app
            inst = None
            return f"error: {type(exc).__name__}: {exc}"[:300]
        return INSTRUMENTED
    finally:
        with _lock:
            _inflight.discard(name)
            if inst is not None:
                _active[name] = inst


def instrument(targets: Optional[Iterable[str]] = None, *, tracer_provider: Any = None) -> Dict[str, str]:
    """Turn on auto-instrumentation for ``targets`` (``openai``, ``anthropic``,
    ``langchain`` (also ``langgraph``), ``mcp``, ``gemini`` (also
    ``google-genai``, ``vertex``), ``bedrock``, ``llama-index``, ``crewai``,
    ``pydantic-ai``, ``openai-agents``); None instruments every installed
    one. Returns ``{target: status}`` where status is
    ``instrumented``, ``already``, ``not-installed`` (install
    ``superbased-sdk[<target>]`` and the framework) or ``error: <message>``.
    An unknown target name raises ValueError. Call after ``init()`` so the
    spans use the SDK's provider; idempotent. ``init()`` already does this
    for every installed framework when the SDK owns the provider
    (``init(instrument=...)``)."""
    names = _names(targets)
    provider = tracer_provider if tracer_provider is not None else _provider()
    out: Dict[str, str] = {}
    for name in names:
        out[name] = _instrument_one(name, provider)
        if name in _active:
            _cancel_hook(name)
    return out


def uninstrument(targets: Optional[Iterable[str]] = None) -> None:
    """Undo ``instrument()`` for ``targets`` (None: every instrumented one),
    and drop the pending first-import hooks ``init()`` set for them. Never
    raises for a target that was not instrumented."""
    with _lock:
        names = sorted(set(_active) | set(_hooks.values())) if targets is None else _names(targets)
    for name in names:
        _cancel_hook(name)
        with _lock:
            inst = _active.pop(name, None)
            _auto_managed.discard(name)
            _auto_status.pop(name, None)
        if inst is None:
            continue
        try:
            inst.uninstrument()
        except Exception:  # noqa: BLE001
            pass


def instrumented() -> List[str]:
    """The targets currently instrumented."""
    return sorted(_active)


def available() -> Dict[str, bool]:
    """Which targets could be instrumented here (extra and library installed)."""
    return {t.name: _load(t) is not None for t in TARGETS}


def _provider() -> Any:
    from . import _PROVIDER  # the provider that holds the SDK's spans (None before init)

    return _PROVIDER


# --- finding a module without importing it ----------------------------------------


def findable(name: str) -> bool:
    """True when ``name`` could be imported, decided without running any
    module: each package level is located with the import system's finders
    (``sys.meta_path``), never executed. A name already imported is
    findable."""
    if name in sys.modules:
        return True
    parts = name.split(".")
    path: Optional[List[str]] = None
    for i in range(len(parts)):
        sub = ".".join(parts[: i + 1])
        last = i == len(parts) - 1
        mod = sys.modules.get(sub)
        if mod is not None:
            if last:
                return True
            locs = getattr(mod, "__path__", None)
            if locs is None:
                return False
            path = list(locs)
            continue
        spec = _find_spec(sub, path)
        if spec is None:
            return False
        if last:
            return True
        locs = spec.submodule_search_locations
        if locs is None:
            return False
        path = list(locs)
    return True


def _find_spec(name: str, path: Optional[List[str]]) -> Any:
    for finder in list(sys.meta_path):
        if isinstance(finder, _PostImportFinder):
            continue
        fs = getattr(finder, "find_spec", None)
        if fs is None:
            continue
        try:
            spec = fs(name, path)
        except (ImportError, ValueError, AttributeError, TypeError, OSError):
            continue
        if spec is not None:
            return spec
    return None


def installed(t: Target) -> bool:
    """The framework and its instrumentor are both installed (nothing is
    imported to tell)."""
    return all(findable(m) for m in (t.library, t.module) + t.requires)


# --- post-import hooks ---------------------------------------------------------------

_hooks: Dict[str, str] = {}  # framework module -> target name
_hook_provider: List[Any] = [None]  # the provider the hooks instrument with


class _HookLoader:
    """Wraps a framework's loader: runs it, then the hook. The module keeps
    its real loader (``__loader__`` and ``__spec__.loader``)."""

    def __init__(self, inner: Any, name: str) -> None:
        self._inner = inner
        self._name = name

    def create_module(self, spec: Any) -> Any:
        create = getattr(self._inner, "create_module", None)
        return create(spec) if create is not None else None

    def exec_module(self, module: Any) -> None:
        try:
            module.__loader__ = self._inner
            if getattr(module, "__spec__", None) is not None:
                module.__spec__.loader = self._inner
        except Exception:  # noqa: BLE001
            pass
        self._inner.exec_module(module)
        _fire(self._name)

    def __getattr__(self, attr: str) -> Any:
        return getattr(self._inner, attr)


class _PostImportFinder:
    """A ``sys.meta_path`` finder that only answers for a hooked framework
    module: it asks the other finders for the real spec and wraps its loader
    so the framework is instrumented right after its first import."""

    def __init__(self) -> None:
        self._busy = threading.local()

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname not in _hooks:
            return None
        busy: Set[str] = getattr(self._busy, "names", None) or set()
        if fullname in busy:
            return None
        busy.add(fullname)
        self._busy.names = busy
        try:
            spec = None
            for finder in list(sys.meta_path):
                if finder is self:
                    continue
                fs = getattr(finder, "find_spec", None)
                if fs is None:
                    continue
                spec = fs(fullname, path, target)
                if spec is not None:
                    break
        finally:
            busy.discard(fullname)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return None
        spec.loader = _HookLoader(spec.loader, fullname)
        return spec

    def invalidate_caches(self) -> None:
        return None


_FINDER = _PostImportFinder()


def _add_hook(t: Target, provider: Any) -> None:
    with _lock:
        _hooks[t.library] = t.name
        _hook_provider[0] = provider
        if _FINDER not in sys.meta_path:
            sys.meta_path.insert(0, _FINDER)


def _cancel_hook(name: str) -> None:
    with _lock:
        for mod in [m for m, n in _hooks.items() if n == name]:
            del _hooks[mod]
        if not _hooks and _FINDER in sys.meta_path:
            try:
                sys.meta_path.remove(_FINDER)
            except ValueError:
                pass


def _fire(module_name: str) -> None:
    """A hooked framework finished its first import: instrument it. Never
    raises into the app's import."""
    try:
        with _lock:
            name = _hooks.get(module_name)
            provider = _provider() or _hook_provider[0]
        if name is None:
            return
        _cancel_hook(name)
        status = _instrument_one(name, provider)
        with _lock:
            _auto_status[name] = status
            if status == INSTRUMENTED:
                _auto_managed.add(name)
    except Exception:  # noqa: BLE001
        pass


def pending() -> List[str]:
    """The targets waiting for their framework's first import."""
    with _lock:
        return sorted(set(_hooks.values()))


# --- init(instrument=...) ---------------------------------------------------------------

AUTO = "auto"
OFF = "off"
LIST = "list"
ENV = "SUPERBASED_INSTRUMENT"
_OFF_WORDS = frozenset({"off", "false", "0", "none"})

HOST_PROVIDER_NOTE = (
    "auto-instrumentation skipped because the app registered its own OpenTelemetry provider; "
    "call instrument([...]) to add model-library spans"
)


@dataclass(frozen=True)
class Setting:
    """The resolved ``instrument`` option: ``mode`` is ``auto``, ``off`` or
    ``list`` (then ``names``); ``source`` is ``argument``, ``env`` or
    ``default``."""

    mode: str = AUTO
    names: Tuple[str, ...] = ()
    source: str = "default"
    warnings: Tuple[str, ...] = ()


def parse_setting(value: Any, env: Mapping[str, str]) -> Setting:
    """``init(instrument=)`` over ``SUPERBASED_INSTRUMENT``, else ``auto``.
    Values: ``auto``, ``off`` (also ``false``, ``0``, ``none``, or False;
    trimmed, any case), or target names (a list, a tuple or a comma string;
    an empty list is ``off``). An unknown name in the argument raises
    ValueError, as ``instrument()`` does; in the env it is skipped with a
    warning naming it, and the rest still applies (never fatal)."""
    if value is not None:
        return _parse(value, "argument", strict=True)
    raw = env.get(ENV)
    if raw is not None and raw.strip():
        return _parse(raw, "env", strict=False)
    return Setting(AUTO, source="default")


def _parse(value: Any, source: str, *, strict: bool) -> Setting:
    if isinstance(value, bool):
        return Setting(AUTO if value else OFF, source=source)
    if isinstance(value, str):
        word = value.strip().lower()
        if word in ("", AUTO):
            return Setting(AUTO, source=source)
        if word in _OFF_WORDS:
            return Setting(OFF, source=source)
        items: Iterable[Any] = [p for p in value.split(",") if p.strip()]
    else:
        try:
            items = list(value)
        except TypeError:
            raise ValueError(f"instrument must be 'auto', 'off' or a list of target names, got {value!r}") from None
    names: List[str] = []
    warnings: List[str] = []
    for raw in items:
        name = _canonical(raw)
        if name not in _BY_NAME:
            if strict:
                raise ValueError(f"unknown instrument target {raw!r}; known: {_known()}")
            warnings.append(f"{ENV} names an unknown instrument target {str(raw).strip()!r}; skipped (known: {_known()})")
            continue
        if name not in names:
            names.append(name)
    if not names and not warnings:
        return Setting(OFF, source=source)  # an empty list is off
    return Setting(LIST, tuple(names), source, tuple(warnings))


# The rule table (plan 3.1), walked top-down: (setting mode, provider modes
# or None for any, action).
NONE = "none"
NAMED = "named"
SKIP = "skipped_host_provider"
INSTALLED = "installed"
RULES: Tuple[Tuple[str, Optional[Tuple[str, ...]], str], ...] = (
    (OFF, None, NONE),
    (LIST, None, NAMED),
    (AUTO, ("attached", "standalone"), SKIP),
    (AUTO, ("owned",), INSTALLED),
)


def decide(mode: str, provider_mode: str) -> str:
    """The action for a setting mode under the SDK's provider mode."""
    for want_mode, modes, action in RULES:
        if want_mode == mode and (modes is None or provider_mode in modes):
            return action
    return NONE


@dataclass
class _Report:
    setting: Setting = field(default_factory=Setting)
    action: str = NONE


_auto_status: Dict[str, str] = {}  # target -> status, for diagnostics()
_auto_managed: Set[str] = set()  # targets init()'s auto step instrumented
_last = _Report()
_noted: Set[str] = set()


def auto_instrument(
    setting: Setting,
    provider_mode: str,
    provider: Any,
    *,
    is_installed: Optional[Callable[[Target], bool]] = None,
) -> Dict[str, str]:
    """Apply ``setting`` under ``provider_mode`` (init()'s one call into this
    module). A framework already imported is instrumented now; one installed
    but not imported is hooked and instrumented on its first import
    (``pending``). Targets this step instrumented before and the new setting
    leaves out are uninstrumented. Returns ``{target: status}``."""
    global _last
    if is_installed is None:
        is_installed = installed
    action = decide(setting.mode, provider_mode)
    for w in setting.warnings:
        _note(w, logging.WARNING)
    if action == SKIP:
        _note(HOST_PROVIDER_NOTE, logging.INFO)
    wanted: List[str] = []
    skipped: Dict[str, str] = {}
    if action == NAMED:
        wanted = list(setting.names)
    elif action == INSTALLED:
        for t in TARGETS:
            if not is_installed(t):
                skipped[t.name] = SKIPPED_NOT_INSTALLED
            elif t.auto:
                wanted.append(t.name)
            else:
                skipped[t.name] = AUTO_EXCLUDED
    elif action == SKIP:
        skipped = {t.name: SKIPPED_HOST_PROVIDER for t in TARGETS}
    with _lock:
        stale = [n for n in set(_auto_managed) | set(_hooks.values()) if n not in wanted]
    for name in stale:
        _cancel_hook(name)
        with _lock:
            inst = _active.pop(name, None) if name in _auto_managed else None
            _auto_managed.discard(name)
        if inst is not None:
            try:
                inst.uninstrument()
            except Exception:  # noqa: BLE001
                pass
    out: Dict[str, str] = {}
    for name in wanted:
        t = _BY_NAME[name]
        with _lock:
            mine = name in _auto_managed
            hooked = name in _hooks.values()
        if name in _active:
            out[name] = INSTRUMENTED if mine else ALREADY
        elif hooked:
            out[name] = PENDING
        elif t.library in sys.modules:
            status = _instrument_one(name, provider)
            if status == INSTRUMENTED:
                with _lock:
                    _auto_managed.add(name)
            out[name] = status
        elif action == NAMED and not is_installed(t):
            out[name] = NOT_INSTALLED
        else:
            _add_hook(t, provider)
            out[name] = PENDING
    for name, status in skipped.items():
        out.setdefault(name, status)
    with _lock:
        _auto_status.clear()
        _auto_status.update(out)
        _last = _Report(setting, action)
    return dict(out)


def _note(msg: str, level: int) -> None:
    with _lock:
        if msg in _noted:
            return
        _noted.add(msg)
    LOG.log(level, "superbased_sdk: %s", msg)


def setting_value() -> Any:
    """diagnostics()["instrument"]: ``auto``, ``off`` or the list of names."""
    with _lock:
        st = _last.setting
        return list(st.names) if st.mode == LIST else st.mode


def report() -> Dict[str, str]:
    """diagnostics()["instrumented"]: per target ``instrumented``,
    ``pending`` (waiting for the framework's first import), ``already``,
    ``not-installed`` (a named target), ``error: ...``, or ``skipped:
    <reason>`` (``auto_excluded``, ``host_provider``, ``not_installed``)."""
    with _lock:
        return dict(_auto_status)


def action() -> str:
    """The rule the last init() applied (``none``, ``named``,
    ``skipped_host_provider`` or ``installed``)."""
    with _lock:
        return _last.action


def _reset_for_tests() -> None:
    """Undo the auto step's instrumentations and hooks (tests only); an
    explicit instrument() stays, as it does across init() calls."""
    global _last
    with _lock:
        managed = sorted(_auto_managed)
    if managed:
        uninstrument(managed)
    with _lock:
        _hooks.clear()
        if _FINDER in sys.meta_path:
            sys.meta_path.remove(_FINDER)
        _auto_status.clear()
        _auto_managed.clear()
        _noted.clear()
        _last = _Report()
