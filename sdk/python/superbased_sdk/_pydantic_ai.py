"""The ``pydantic-ai`` instrument() target.

Pydantic AI writes its own OpenTelemetry spans (GenAI semantic conventions)
once ``Agent.instrument_all()`` is on; OpenInference ships no instrumentor for
it, only ``OpenInferenceSpanProcessor``, which adds the OpenInference
attributes to each finished span. That processor rewrites the span in place
and must run before the exporter sees it, which an OpenTelemetry provider
cannot guarantee for a processor added after the SDK's. So this target turns
on Pydantic AI's spans with the SDK's provider and registers the same
attribute mapping (``get_attributes``) as an enricher of the SDK's span
processor: the SDK exports a copy with the added attributes and leaves the
original span unchanged.

The class mimics the small part of ``BaseInstrumentor`` that ``instrument()``
uses, so the target stays one row of ``_instrument.TARGETS``.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

# Imported at module load so a missing extra reads as "not-installed".
from openinference.instrumentation.pydantic_ai.semantic_conventions import get_attributes as _oi_attributes
from pydantic_ai import Agent as _Agent

from . import _export

ENRICHER = "pydantic-ai"


def openinference_attributes(attrs: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
    """The OpenInference attributes for a Pydantic AI span, or None when the
    span is not one (no ``gen_ai.operation.name`` and no agent name) or the
    span already carries them."""
    if not attrs or "openinference.span.kind" in attrs:
        return None
    if "gen_ai.operation.name" not in attrs and "gen_ai.agent.name" not in attrs and "agent_name" not in attrs:
        return None
    try:
        added = {k: v for k, v in _oi_attributes(attrs) if k not in attrs and v is not None}
    except Exception:  # noqa: BLE001 - a mapping bug never breaks export
        return None
    return added or None


class PydanticAIInstrumentor:
    """``Agent.instrument_all()`` with the SDK's provider, plus the
    OpenInference attribute enricher."""

    _active = False
    _previous: Any = False

    @property
    def _is_instrumented_by_opentelemetry(self) -> bool:
        # A host that turned Pydantic AI's instrumentation on itself (or
        # logfire.instrument_pydantic_ai) got there first.
        return not PydanticAIInstrumentor._active and bool(_Agent._instrument_default)

    def _check_dependency_conflicts(self) -> None:
        return None

    def instrument(self, tracer_provider: Any = None, **_: Any) -> None:
        from pydantic_ai.models.instrumented import InstrumentationSettings

        settings = InstrumentationSettings(tracer_provider=tracer_provider) if tracer_provider is not None else InstrumentationSettings()
        PydanticAIInstrumentor._previous = _Agent._instrument_default
        _Agent.instrument_all(settings)
        _export.ENRICHERS[ENRICHER] = openinference_attributes
        PydanticAIInstrumentor._active = True

    def uninstrument(self, **_: Any) -> None:
        _export.ENRICHERS.pop(ENRICHER, None)
        if PydanticAIInstrumentor._active:
            _Agent.instrument_all(PydanticAIInstrumentor._previous or False)
        PydanticAIInstrumentor._active = False
        PydanticAIInstrumentor._previous = False
