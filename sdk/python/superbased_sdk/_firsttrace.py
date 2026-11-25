"""The app's first-trace line (plan 3.8, ruling R12; sdk-api-surface.md
section 16): once per process, after the first root span is exported, one
line on stderr with a link to its trace on the dashboard; or, when that
export was refused by the organization's plan, the refusal's message and
link instead.

Only on a terminal (stderr is a TTY), only when ``CI`` is unset, empty,
``0`` or ``false``, and never with ``SUPERBASED_FIRST_TRACE_LINK`` set to
``0``, ``false`` or ``off``, so production logs stay quiet. The line is
written to stderr directly: apps usually leave logging at WARNING.

The base of a link: ``<node_url>/apps/traces?trace=<id>`` for this machine
(when it answered discovery), ``<dashboard_url>/trajectories?trace=<id>``
online (the SDK-held file's ``dashboard_url``, or discovery's
``online.dashboard_url`` with the machine's key; none with a key the app
named). Under ``both`` the decision waits for every destination's outcome
of that trace: the online link when the online export succeeded and its
base is known, else the local link. A trace every destination failed to
export waits for the next one.

``decide()`` is the pure rule; ``on_export()`` the one seam the exporter
calls.
"""

from __future__ import annotations

import sys
import threading
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

ENV = "SUPERBASED_FIRST_TRACE_LINK"
LOCAL_PATH = "/apps/traces?trace="
ONLINE_PATH = "/trajectories?trace="
PREFIX = "superbased: first trace from this process: "
REFUSED_PREFIX = "superbased: traces from this process were refused: "

OK = "ok"
FAILED = "failed"
REFUSED = "refused"

_OFF = ("0", "false", "off")
_CI_UNSET = ("", "0", "false")
MAX_PENDING = 64


def enabled(env: Mapping[str, str], stderr_tty: bool) -> bool:
    """The gate: a terminal, no ``CI``, and not opted out."""
    if not stderr_tty:
        return False
    if (env.get("CI") or "").strip().lower() not in _CI_UNSET:
        return False
    raw = env.get(ENV)
    if raw is not None and raw.strip().lower() in _OFF:
        return False
    return True


def link(destination: str, trace_id: str, bases: Mapping[str, str]) -> str:
    """The trace's link on the destination's dashboard ("" when that
    destination has no known base)."""
    base = (bases.get(destination) or "").rstrip("/")
    if not base or not trace_id:
        return ""
    return base + (LOCAL_PATH if destination == "local" else ONLINE_PATH) + trace_id


def refusal_line(refusal: Mapping[str, Any]) -> str:
    msg = " ".join(str(refusal.get("message") or "").split())
    up = str(refusal.get("upgrade_url") or "").strip()
    return REFUSED_PREFIX + msg + (" " + up if up else "")


def decide(
    trace_id: str,
    outcomes: Mapping[str, str],
    bases: Mapping[str, str],
    refusal: Optional[Mapping[str, Any]] = None,
) -> Tuple[bool, str]:
    """(settled, line) for one trace once every destination reported:
    ``outcomes`` maps ``local`` / ``online`` to ``ok``, ``failed`` or
    ``refused``. Not settled when every destination failed (the next trace
    is tried); settled with "" when it was exported but no base is known."""
    if REFUSED in outcomes.values() and refusal:
        return True, refusal_line(refusal)
    if outcomes.get("online") == OK and bases.get("online"):
        return True, PREFIX + link("online", trace_id, bases)
    if outcomes.get("local") == OK and bases.get("local"):
        return True, PREFIX + link("local", trace_id, bases)
    if OK in outcomes.values():
        return True, ""
    return False, ""


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.done = False
        self.on = False
        self.bases: Dict[str, str] = {}
        self.legs: Tuple[str, ...] = ()
        self.pending: Dict[str, Dict[str, str]] = {}
        self.refusals: Dict[str, Dict[str, Any]] = {}
        self.line = ""
        self.link = ""


STATE = _State()


def configure(env: Mapping[str, str], bases: Mapping[str, str], legs: Sequence[str], stderr_tty: Optional[bool] = None) -> None:
    """init(): where links point and which destinations export. A process
    that already printed its line never prints another."""
    tty = _stderr_tty() if stderr_tty is None else stderr_tty
    with STATE.lock:
        STATE.bases = {k: v for k, v in bases.items() if v}
        STATE.legs = tuple(legs)
        STATE.pending.clear()
        STATE.refusals.clear()
        STATE.on = enabled(env, tty) and bool(STATE.legs)


def _stderr_tty() -> bool:
    try:
        return bool(sys.stderr is not None and sys.stderr.isatty())
    except Exception:  # noqa: BLE001
        return False


def root_trace_id(spans: Sequence[Any]) -> str:
    """The trace id (32 hex) of the first local root span in a batch, or ""."""
    for sp in spans:
        parent = getattr(sp, "parent", None)
        if parent is None or getattr(parent, "is_remote", False):
            ctx = getattr(sp, "context", None)
            tid = getattr(ctx, "trace_id", 0)
            if tid:
                return format(tid, "032x")
    return ""


def on_export(destination: str, spans: Sequence[Any], ok: bool, refusal: Optional[Mapping[str, Any]] = None) -> None:
    """The exporter's seam: called after each export of a batch to one
    destination. Never raises."""
    try:
        if not STATE.on or STATE.done:
            return
        tid = root_trace_id(spans)
        if not tid:
            return
        line = ""
        with STATE.lock:
            if STATE.done or destination not in STATE.legs:
                return
            outcomes = STATE.pending.setdefault(tid, {})
            outcomes[destination] = OK if ok else (REFUSED if refusal else FAILED)
            if refusal:
                STATE.refusals[tid] = dict(refusal)
            if not set(STATE.legs) <= set(outcomes):
                while len(STATE.pending) > MAX_PENDING:
                    STATE.pending.pop(next(iter(STATE.pending)))
                return
            settled, line = decide(tid, outcomes, STATE.bases, STATE.refusals.get(tid))
            STATE.pending.pop(tid, None)
            STATE.refusals.pop(tid, None)
            if not settled:
                return
            STATE.done = True
            STATE.line = line
            if line.startswith(PREFIX):
                STATE.link = line[len(PREFIX):]
        if line:
            _emit(line)
    except Exception:  # noqa: BLE001
        pass


def printed_link() -> str:
    """diagnostics()["first_trace_link"]: the link once printed, else ""."""
    return STATE.link


def _emit(line: str) -> None:
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
