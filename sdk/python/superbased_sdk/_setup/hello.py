"""Phase 5 (plan 3.8): the hello span, the arrival check and the links.

The hello goes through the SDK setup ships with: ``init(destination=...,
service_name=..., instrument="off")``, one span named ``superbased setup:
hello from <service>`` carrying only ``sbo.setup.hello = true`` (no content,
SDKQS-9), then ``flush()``. Arrival is checked with reads that exist: this
computer's ``GET /api/obs/trace/{id}``, the organization's ``GET
/v1/sdk/traces/{id}/cost`` (scope ``sdk:read``), once a second for up to 60
seconds. A refusal is read with the SDK's one plan-refusal parser and said
as the server sent it (the table ``REFUSAL_ROWS``).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from .. import _http, _keys

ARRIVAL_WAIT = 60.0
ARRIVAL_EVERY = 1.0
LOCAL_TRACE_PATH = "/api/obs/trace/"
ONLINE_COST_PATH = "/v1/sdk/traces/{}/cost"
LOCAL_LINK = "/apps/traces?trace="
ONLINE_LINK = "/trajectories?trace="

QUOTA_CODES = ("planea_events_quota_exceeded", "planea_bytes_quota_exceeded")

# (error code family, upgrade_url present?, the line after the server's
# message). Never a plan name or a number of setup's own (setup-cases.json
# first_run_refusals).
REFUSAL_ROWS: Tuple[Tuple[str, Optional[bool], str], ...] = (
    ("plan_required", True, "Change the plan: {upgrade_url}"),
    ("quota", True, "Ingest resumes {resets_at}. More: {upgrade_url}"),
    ("quota", False, "This is not a plan limit: your organization set this cap itself (Settings > Server > Runtime settings)."),
    ("", None, ""),
)


def refusal_lines(code: str, message: str, upgrade_url: str = "", resets_at: str = "") -> List[str]:
    """The lines setup prints for a refusal: the server's message as sent,
    then one line from ``REFUSAL_ROWS`` (never a plan name or a number of
    setup's own)."""
    family = "plan_required" if code == "plan_required" else ("quota" if code in QUOTA_CODES else "")
    has_link = bool(upgrade_url)
    out = [" ".join(message.split())] if message.strip() else []
    for fam, link, tail in REFUSAL_ROWS:
        if fam == family and (link is None or link == has_link):
            if tail:
                line = tail.format(upgrade_url=upgrade_url, resets_at=resets_at or "at the start of next month")
                out.append(line)
            break
    return out


def link(destination: str, base: str, trace_id: str) -> str:
    if not base:
        return ""
    return base.rstrip("/") + (LOCAL_LINK if destination == "local" else ONLINE_LINK) + trace_id


@dataclass
class Sent:
    """What the hello did. ``plan`` is the SDK's destination plan (it holds
    the key for the online arrival check; never printed)."""

    trace_id: str = ""
    service: str = ""
    exported: bool = False
    refusal: List[str] = field(default_factory=list)
    refusal_code: str = ""
    unauthorized: bool = False
    plan: Any = field(default=None, repr=False)
    warnings: List[str] = field(default_factory=list)


def send(destination: str, service: str, env: Optional[Mapping[str, str]] = None) -> Sent:
    """Send the hello span through the SDK."""
    import superbased_sdk as sb
    from superbased_sdk import _export

    saved = os.environ.get("SUPERBASED_FIRST_TRACE_LINK")
    os.environ["SUPERBASED_FIRST_TRACE_LINK"] = "0"  # setup prints its own link
    started = time.time()
    try:
        sb.init(destination=destination, service_name=service, instrument="off", quiet=True)
        with sb.span(f"superbased setup: hello from {service}", kind=sb.CHAIN, attributes={_keys.SETUP_HELLO: True}) as sp:
            tid = format(sp.get_span_context().trace_id, "032x")
        exported = sb.flush(10.0)
    finally:
        if saved is None:
            os.environ.pop("SUPERBASED_FIRST_TRACE_LINK", None)
        else:
            os.environ["SUPERBASED_FIRST_TRACE_LINK"] = saved
    plan = sb._plan()
    out = Sent(trace_id=tid, service=service, exported=exported, plan=plan)
    if plan is not None:
        out.warnings = [plan.degraded] if plan.degraded else []
    ans = _export.last_answer()
    if not exported and ans and ans.get("at", 0) >= started:
        code = str(ans.get("error") or "")
        if ans.get("status") == 401:
            out.unauthorized = True
        elif code == "plan_required" or code in QUOTA_CODES:
            out.refusal_code = code
            out.refusal = refusal_lines(code, str(ans.get("message") or ""), str(ans.get("upgrade_url") or ""), str(ans.get("resets_at") or ""))
    return out


def stop_sdk() -> None:
    import superbased_sdk as sb

    sb.shutdown(5.0)


Http = Callable[..., _http.Response]


def check_local(http: Http, node_url: str, trace_id: str) -> str:
    """``yes``, ``no`` (not stored yet)."""
    resp = http("GET", _http.join(node_url, LOCAL_TRACE_PATH + trace_id), timeout=5.0)
    return "yes" if resp.status == 200 else "no"


def check_online(http: Http, gateway: str, headers: Mapping[str, str], trace_id: str) -> str:
    """``yes``, ``no`` (not stored yet: 404, or a 200 with no span) or
    ``unauthorized`` (the key was not accepted)."""
    resp = http("GET", _http.join(gateway, ONLINE_COST_PATH.format(trace_id)), headers=dict(headers), timeout=5.0)
    if resp.status == 200:
        spans = resp.body.get("spans") if isinstance(resp.body, dict) else None
        return "yes" if isinstance(spans, list) and spans else "no"
    if resp.status == 401:
        return "unauthorized"
    return "no"


def wait_for_arrival(
    http: Http,
    plan: Any,
    trace_id: str,
    *,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    wait: float = ARRIVAL_WAIT,
    every: float = ARRIVAL_EVERY,
) -> Dict[str, str]:
    """``{destination: yes | no | unauthorized}`` for each destination the
    plan exported to, polled until all arrived or ``wait`` passed."""
    sides: Dict[str, str] = {}
    for d in getattr(plan, "exporters", ()):
        sides[d.name] = "no"
    deadline = monotonic() + wait
    while True:
        for name, state in list(sides.items()):
            if state != "no":
                continue
            if name == "local":
                sides[name] = check_local(http, plan.node_url, trace_id)
            elif name == "online":
                sides[name] = check_online(http, plan.gateway_url, plan.online_headers(), trace_id)
        if all(v != "no" for v in sides.values()) or monotonic() >= deadline:
            return sides
        sleep(every)
