"""Model client libraries that trace themselves.

Some provider SDKs start an OpenTelemetry span for every API call on the global
tracer provider (the Anthropic SDKs, ``ANTHROPIC_OPEN_TELEMETRY``). ``init()``
registers that provider, so under a framework instrumentation (LangChain,
LlamaIndex, Pydantic AI, CrewAI) or a manual LLM span every call would be
recorded twice and counted twice. ``instrument(["anthropic"])`` records the
raw calls on its own.

So ``init()`` turns such a library's own tracing off when the app has not set
its switch, and the export pipeline drops spans from its tracer scope (a client
built before ``init()`` read the switch already). An app that sets the switch
to anything other than its "off" value keeps the library's spans.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

OFF = "off"
KEPT = "kept"


@dataclass(frozen=True)
class SelfTracing:
    """One client library that traces itself."""

    name: str
    env: str  # the switch the library reads when a client is built
    off: str  # the switch value that turns its spans off
    scope_prefix: str  # its tracer's instrumentation scope


LIBRARIES: Tuple[SelfTracing, ...] = (
    SelfTracing("anthropic", "ANTHROPIC_OPEN_TELEMETRY", "false", "com.anthropic.sdk"),
)

_lock = threading.Lock()
# name -> the app's own value of the switch, captured at the first init()
# (None: unset). Later init() calls see the value the SDK wrote, so the
# app's is kept here.
_app_value: Dict[str, Optional[str]] = {}


def apply() -> Dict[str, str]:
    """Turn each library's own tracing off unless the app set its switch.
    Returns ``{name: "off" | "kept"}``."""
    out: Dict[str, str] = {}
    with _lock:
        for lib in LIBRARIES:
            if lib.name not in _app_value:
                _app_value[lib.name] = os.environ.get(lib.env)
            app = _app_value[lib.name]
            if app is None:
                os.environ[lib.env] = lib.off
                out[lib.name] = OFF
            elif app.strip().lower() == lib.off:
                out[lib.name] = OFF
            else:
                out[lib.name] = KEPT
    return out


def drop_prefixes(state: Dict[str, str]) -> Tuple[str, ...]:
    """The tracer scopes whose spans the export pipeline drops."""
    return tuple(lib.scope_prefix for lib in LIBRARIES if state.get(lib.name) == OFF)


def scope_name(span: object) -> str:
    """A finished span's instrumentation scope name ("" when none)."""
    scope = getattr(span, "instrumentation_scope", None) or getattr(span, "instrumentation_info", None)
    return str(getattr(scope, "name", "") or "")


def _reset_for_tests() -> None:
    with _lock:
        for lib in LIBRARIES:
            if lib.name in _app_value:
                app = _app_value.pop(lib.name)
                if app is None:
                    os.environ.pop(lib.env, None)
                else:
                    os.environ[lib.env] = app
