"""The SDK control API by destination: which base URL, path and headers a
score, prompt, dataset or experiment call uses on this machine (local) and on
the org gateway (online). One table, so the resources never disagree about
where a destination is.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from . import _destination, _http

API_VERSION_HEADER = "X-SBO-SDK-API-Version"
API_VERSION = "1"

# resource -> (machine path, gateway path). {name}, {id}, {version} are filled
# by the caller (URL-escaped).
PATHS: Dict[str, Dict[str, str]] = {
    "scores": {"local": "/api/obs/scores", "online": "/v1/sdk/scores"},
    "prompt": {"local": "/api/obs/sdk/prompts/{name}", "online": "/v1/sdk/prompts/{name}"},
    "prompts": {"local": "/api/obs/sdk/prompts", "online": "/v1/sdk/prompts"},
    "datasets": {"local": "/api/obs/eval/datasets", "online": "/v1/sdk/datasets"},
    "dataset": {"local": "/api/obs/eval/datasets/{id}", "online": "/v1/sdk/datasets/{id}"},
    "dataset_items": {"local": "/api/obs/eval/datasets/{id}/items", "online": "/v1/sdk/datasets/{id}/snapshots/{version}/items"},
    "dataset_snapshot": {"local": "/api/obs/eval/datasets/{id}/items", "online": "/v1/sdk/datasets/{id}/snapshots"},
    "experiments": {"local": "/api/obs/eval/experiments", "online": "/v1/sdk/experiments"},
    "experiment": {"local": "/api/obs/eval/experiments/{id}", "online": "/v1/sdk/experiments/{id}"},
    "experiment_results": {"local": "/api/obs/eval/experiments/{id}/results", "online": "/v1/sdk/experiments/{id}/results"},
    "experiment_finish": {"local": "/api/obs/eval/experiments/{id}/finish", "online": "/v1/sdk/experiments/{id}/finish"},
    # W4-2 (contracts/cost-source.md section 6): the machine's trace detail
    # carries the TraceCost object under "cost"; the org answers it directly.
    "trace_cost": {"local": "/api/obs/trace/{id}", "online": "/v1/sdk/traces/{id}/cost"},
}


@dataclass(frozen=True)
class Side:
    """One destination's control API."""

    name: str  # "local" or "online"
    base: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)  # the online one carries the credential
    timeout: float = 5.0

    def url(self, resource: str, query: Optional[Mapping[str, Any]] = None, **parts: Any) -> str:
        from urllib.parse import quote

        path = PATHS[resource][self.name]
        for k, v in parts.items():
            path = path.replace("{" + k + "}", quote(str(v), safe=""))
        return _http.join(self.base, path, query)

    def call(self, method: str, resource: str, *, body: Any = None, query: Optional[Mapping[str, Any]] = None, headers: Optional[Mapping[str, str]] = None, **parts: Any) -> _http.Response:
        hdrs = dict(self.headers)
        if headers:
            hdrs.update(headers)
        return _http.request(method, self.url(resource, query, **parts), body=body, headers=hdrs, timeout=self.timeout)


_lock = threading.Lock()
_fallback_plan: Optional[_destination.Plan] = None


def current_plan() -> _destination.Plan:
    """The plan of the last init(), or one resolved from the environment
    (cached) when the app calls a control function before init()."""
    global _fallback_plan
    from . import _plan

    plan = _plan()
    if plan is not None:
        return plan
    with _lock:
        if _fallback_plan is None:
            from ._config import Settings

            env = os.environ
            _fallback_plan = _destination.resolve(Settings.resolve(env), env)
        return _fallback_plan


def api_timeout() -> float:
    from . import settings

    s = settings()
    return s.api_timeout if s is not None else 5.0


def sides(plan: Optional[_destination.Plan] = None) -> List[Side]:
    """The control API of each active destination, online first: ``local``
    -> the machine; ``online`` -> the gateway; ``both`` -> both (the machine
    only while the gateway or credential is missing).

    A degraded ``online`` (no gateway or no credential) has NO target: score,
    experiment, dataset, prompt and trace-cost calls never go to the machine
    the user chose to keep out of it (contract destination.md section 7;
    review R-B18). The caller reports ``unavailable_reason()``. Only
    ``admit()`` may fall back to the machine (section 8), and it does not use
    this function."""
    p = plan or current_plan()
    t = api_timeout()
    out: List[Side] = []
    if p.online_enabled:
        hdrs = dict(p.online_headers())
        hdrs[API_VERSION_HEADER] = API_VERSION
        out.append(Side("online", p.gateway_url, hdrs, t))
    if p.destination in (_destination.LOCAL, _destination.BOTH):
        out.append(Side("local", p.node_url, {}, t))
    return out


def unavailable_reason(plan: Optional[_destination.Plan] = None) -> str:
    """Why ``sides()`` is empty: the plan's degraded reason (``online``
    without a gateway or credential), else a generic line."""
    p = plan or current_plan()
    return p.degraded or f"destination {p.destination} has no usable target"


def reset_for_tests() -> None:
    global _fallback_plan
    with _lock:
        _fallback_plan = None
