"""``instrument([...])``: framework auto-instrumentation over the upstream
OpenInference instrumentors (plan D10: depend on them, own only the mapping
and the conformance fixtures).

Each target is a row of ``TARGETS``; the instrumentor is installed by the
matching extra (``pip install "superbased-sdk[openai]"``). A missing extra or
library is reported, never raised. The spans the instrumentors emit go through
the SDK's provider, so identity, sampling, masking and the destination apply
to them like to the SDK's own spans.
"""

from __future__ import annotations

import importlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

INSTRUMENTED = "instrumented"
ALREADY = "already"
NOT_INSTALLED = "not-installed"


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


TARGETS: Tuple[Target, ...] = (
    Target("openai", "openinference.instrumentation.openai", "OpenAIInstrumentor", "openai", "openai", "openinference-instrumentation-openai"),
    Target("anthropic", "openinference.instrumentation.anthropic", "AnthropicInstrumentor", "anthropic", "anthropic", "openinference-instrumentation-anthropic"),
    Target(
        "langchain",
        "openinference.instrumentation.langchain",
        "LangChainInstrumentor",
        "langchain_core",
        "langchain",
        "openinference-instrumentation-langchain",
        note="covers LangGraph (its runs are LangChain runs)",
    ),
    Target(
        "mcp",
        "openinference.instrumentation.mcp",
        "MCPInstrumentor",
        "mcp",
        "mcp",
        "openinference-instrumentation-mcp",
        note="carries trace context across MCP client and server, so server-side spans join the caller's trace",
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
    ),
    Target(
        "bedrock",
        "openinference.instrumentation.bedrock",
        "BedrockInstrumentor",
        "boto3",
        "bedrock",
        "openinference-instrumentation-bedrock",
        note="boto3 bedrock-runtime clients created after instrument() (converse, invoke_model and their streams)",
    ),
    Target(
        "llama-index",
        "openinference.instrumentation.llama_index",
        "LlamaIndexInstrumentor",
        "llama_index.core",
        "llama-index",
        "openinference-instrumentation-llama-index",
    ),
    Target(
        "crewai",
        "openinference.instrumentation.crewai",
        "CrewAIInstrumentor",
        "crewai",
        "crewai",
        "openinference-instrumentation-crewai",
        note="crew, task and agent spans; the model calls come from the openai (or litellm) instrumentation",
    ),
    Target(
        "pydantic-ai",
        "superbased_sdk._pydantic_ai",
        "PydanticAIInstrumentor",
        "pydantic_ai",
        "pydantic-ai",
        "openinference-instrumentation-pydantic-ai",
        note="turns on Pydantic AI's own OpenTelemetry spans and adds the OpenInference attributes at export",
    ),
    Target(
        "openai-agents",
        "openinference.instrumentation.openai_agents",
        "OpenAIAgentsInstrumentor",
        "agents",
        "openai-agents",
        "openinference-instrumentation-openai-agents",
        note="replaces the Agents SDK's own trace processors while instrumented, so its traces are not also uploaded to OpenAI",
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
_lock = threading.Lock()
_active: Dict[str, Any] = {}  # target name -> instrumentor instance


def _names(targets: Optional[Iterable[str]]) -> List[str]:
    if targets is None:
        return [t.name for t in TARGETS]
    if isinstance(targets, str):
        targets = [targets]
    out: List[str] = []
    for raw in targets:
        name = str(raw).strip().lower().replace("_", "-")
        name = ALIASES.get(name, name)
        if name not in _BY_NAME:
            known = ", ".join(sorted(set(_BY_NAME) | set(ALIASES)))
            raise ValueError(f"unknown instrument target {raw!r}; known: {known}")
        if name not in out:
            out.append(name)
    return out


def _load(t: Target) -> Any:
    """The instrumentor class, or None when the extra or the library is missing."""
    try:
        importlib.import_module(t.library)
        mod = importlib.import_module(t.module)
    except ImportError:
        return None
    return getattr(mod, t.cls, None)


def instrument(targets: Optional[Iterable[str]] = None, *, tracer_provider: Any = None) -> Dict[str, str]:
    """Turn on auto-instrumentation for ``targets`` (``openai``, ``anthropic``,
    ``langchain`` (also ``langgraph``), ``mcp``, ``gemini`` (also
    ``google-genai``, ``vertex``), ``bedrock``, ``llama-index``, ``crewai``,
    ``pydantic-ai``, ``openai-agents``); None instruments every installed
    one. Returns ``{target: status}`` where status is
    ``instrumented``, ``already``, ``not-installed`` (install
    ``superbased-sdk[<target>]`` and the framework) or ``error: <message>``.
    An unknown target name raises ValueError. Call after ``init()`` so the
    spans use the SDK's provider; idempotent."""
    names = _names(targets)
    provider = tracer_provider if tracer_provider is not None else _provider()
    out: Dict[str, str] = {}
    with _lock:
        for name in names:
            if name in _active:
                out[name] = ALREADY
                continue
            t = _BY_NAME[name]
            cls = _load(t)
            if cls is None:
                out[name] = NOT_INSTALLED
                continue
            try:
                inst = cls()  # BaseInstrumentor subclasses are per-class singletons
                if getattr(inst, "_is_instrumented_by_opentelemetry", False):
                    out[name] = ALREADY  # the host (or opentelemetry-instrument) got there first
                    continue
                check = getattr(inst, "_check_dependency_conflicts", None)
                conflict = check() if callable(check) else None
                if conflict:
                    out[name] = f"error: {conflict}"[:300]
                    continue
                kwargs: Dict[str, Any] = {"skip_dep_check": True}
                if provider is not None:
                    kwargs["tracer_provider"] = provider
                inst.instrument(**kwargs)
            except Exception as exc:  # noqa: BLE001 - instrumenting must never break the app
                out[name] = f"error: {type(exc).__name__}: {exc}"[:300]
                continue
            _active[name] = inst
            out[name] = INSTRUMENTED
    return out


def uninstrument(targets: Optional[Iterable[str]] = None) -> None:
    """Undo ``instrument()`` for ``targets`` (None: every instrumented one).
    Never raises for a target that was not instrumented."""
    names = list(_active) if targets is None else _names(targets)
    with _lock:
        for name in names:
            inst = _active.pop(name, None)
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
