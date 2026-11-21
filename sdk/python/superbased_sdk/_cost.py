"""``get_trace_cost()``: a trace's cost and where each number came from (W4-2,
contracts/cost-source.md section 6).

The org answers ``GET /v1/sdk/traces/{trace_id}/cost`` (scope ``sdk:read``)
with a TraceCost object; the machine carries the same object under ``cost`` in
``GET /api/obs/trace/{id}``. Destination ``online`` reads the org, ``local``
the machine, ``both`` the org first, then the machine. A degraded ``online``
reads nothing (destination.md section 7).

The object keeps the wire field names (``cost_usd``, ``cost_provenance``,
``spans[].cost_source``, ``cost_delta_usd``, ...). ``cost_source`` is one of
``gateway_exact``, ``proxy_exact``, ``computed``, ``reported`` or ``""``
(unpriced): an exact number beats a computed one, and a cost the app reported
never wins over either. The SDK adds one key, ``destination`` (``online`` or
``local``: which side answered).

The cost of a span is known only after the span was exported and ingested, and
the gateway's exact cost joins whenever both sides have arrived: call
``flush()`` first, and expect a later read to move a span from ``computed`` to
``gateway_exact``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any, Dict, List, Optional

from . import _control

LOG = logging.getLogger("superbased_sdk")

# The cost_source values (contracts/cost-source.md section 1).
GATEWAY_EXACT = "gateway_exact"
PROXY_EXACT = "proxy_exact"
COMPUTED = "computed"
REPORTED = "reported"
UNPRICED = ""
COST_SOURCES = (GATEWAY_EXACT, PROXY_EXACT, COMPUTED, REPORTED, UNPRICED)
EXACT_SOURCES = (GATEWAY_EXACT, PROXY_EXACT)

# The display label of each value (section 1), for an app that shows them.
LABELS: Dict[str, str] = {
    GATEWAY_EXACT: "Gateway exact",
    PROXY_EXACT: "Proxy exact",
    COMPUTED: "Computed",
    REPORTED: "Reported",
    UNPRICED: "Unpriced",
}

_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_last_log = [0.0]


def is_exact(cost_source: Optional[str]) -> bool:
    """True for the exact family (``gateway_exact`` or ``proxy_exact``)."""
    return cost_source in EXACT_SOURCES


def _trace_id(trace_id: Optional[str]) -> str:
    if trace_id is None:
        from . import get_current_trace_id

        return get_current_trace_id()
    tid = str(trace_id).strip().lower()
    if not _TRACE_ID.match(tid) or tid == "0" * 32:
        raise ValueError(f"trace_id {trace_id!r} must be 32 hex digits, not all zero")
    return tid


def _log(msg: str) -> None:
    now = time.time()
    if now - _last_log[0] < 60:
        return
    _last_log[0] = now
    LOG.warning("superbased_sdk: trace cost not read: %s", msg)


def _cost_object(side_name: str, body: Any) -> Optional[Dict[str, Any]]:
    """The TraceCost object of a 200 answer, or None when it has none (an
    older machine whose trace detail has no ``cost``)."""
    if not isinstance(body, dict):
        return None
    obj = body.get("cost") if side_name == "local" else body
    if not isinstance(obj, dict) or "spans" not in obj:
        return None
    out = dict(obj)
    out["destination"] = side_name
    return out


def get_trace_cost(trace_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The TraceCost object of ``trace_id`` (default: the current trace), or
    None when no destination has it yet, there is no trace, or the read
    failed (logged at most once a minute). A malformed ``trace_id`` raises
    ValueError; nothing else raises."""
    tid = _trace_id(trace_id)
    if not tid:
        return None
    targets = _control.sides()
    if not targets:
        _log(_control.unavailable_reason())
        return None
    errors: List[str] = []
    for side in targets:
        try:
            resp = side.call("GET", "trace_cost", id=tid)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{side.name}: {type(exc).__name__}: {exc}")
            continue
        if resp.status == 200:
            obj = _cost_object(side.name, resp.body)
            if obj is not None:
                return obj
            errors.append(f"{side.name}: the answer carries no trace cost (an older server)")
            continue
        if resp.status == 404:
            continue  # not there (yet), or not this credential's org: try the next side
        errors.append(f"{side.name}: {resp.describe()}")
    if errors:
        _log("; ".join(errors))
    return None


async def async_get_trace_cost(trace_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """``get_trace_cost()`` without blocking the event loop. The default trace
    is the one current HERE."""
    tid = _trace_id(trace_id)
    if not tid:
        return None
    return await asyncio.get_running_loop().run_in_executor(None, lambda: get_trace_cost(tid))
