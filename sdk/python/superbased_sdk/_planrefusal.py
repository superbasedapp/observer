"""The AI Apps gateway's plan refusal (sdk/contract/plan-refusal-cases.json).

The org's AI Apps gateway (OTLP ``/v1/traces`` and the SDK control API
``/v1/sdk/*``) refuses ingest when the organization's plan does not include
AI Apps (HTTP 403 ``plan_required``) or this month's allowance is used up
(HTTP 429 ``planea_events_quota_exceeded`` / ``planea_bytes_quota_exceeded``).
Every such refusal carries ``upgrade_url``: where the organization's billing
owner changes the plan. ``parse_plan_refusal()`` is the one pure parser; the
SDK calls it wherever it sees a response body, and keeps the last refusal for
``diagnostics()["plan_refusal"]``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, ClassVar, Dict, List, Mapping, Optional, Sequence, Tuple, Type

LOG = logging.getLogger("superbased_sdk")

PLAN_REQUIRED = "plan_required"
EVENTS_QUOTA_EXCEEDED = "planea_events_quota_exceeded"
BYTES_QUOTA_EXCEEDED = "planea_bytes_quota_exceeded"
# The AI gateway's monthly request allowance (the same refusal shape).
AIGW_QUOTA_EXCEEDED = "aigw_requests_quota_exceeded"

KIND_PLAN_REQUIRED = "plan_required"
KIND_ALLOWANCE_EXCEEDED = "allowance_exceeded"

# How often (seconds) the SDK may write its one-line plan-refusal warning.
LOG_INTERVAL = 60.0


@dataclass(frozen=True)
class Allowance:
    """A plan's allowance: AI Apps events and GB a month, and the AI
    gateway's requests a month and concurrent calls. ``None`` on an axis: no
    cap (or the refusal did not name it)."""

    events_monthly: Optional[int] = None
    gb_monthly: Optional[int] = None
    requests_monthly: Optional[int] = None
    concurrency: Optional[int] = None


@dataclass(frozen=True)
class PlanInfo:
    """A catalog plan: the plan in force, or one on offer (with its allowance)."""

    name: str
    version: int = 0
    label: str = ""
    allowance: Optional[Allowance] = None


@dataclass(frozen=True)
class Quota:
    """The monthly quota a 429 refusal is about. ``resets_at`` is RFC 3339."""

    quota: str = ""
    unit: str = ""
    used: int = 0
    limit: int = 0
    resets_at: str = ""


class PlanRefusalError(RuntimeError):
    """The organization's plan refused AI Apps ingest.

    ``code`` is the gateway's error code, ``status`` the HTTP status (403 or
    429), ``message`` the gateway's explanation and ``upgrade_url`` where the
    organization's billing owner changes the plan. ``capability`` names what
    was refused; ``plan`` is the plan in force, ``allowance`` the org's
    monthly allowance and ``plans`` the plans that include more (each may be
    absent). A 429 also carries ``quota`` (the quota used up and when it
    resets) and ``retry_after`` (seconds, from the Retry-After header).

    Raised by the calls that raise (a prompt or dataset fetch, an
    experiment): there it is also that call's own error (``PromptFetchError``,
    ``ExperimentError``), so an existing ``except`` keeps working. The calls
    that never raise carry it instead (``ScoreResult.plan_refusal``,
    ``Verdict.plan_refusal``, ``ExperimentResult.plan_refusal``), and
    ``diagnostics()["plan_refusal"]`` keeps the last one, export included.
    """

    kind: ClassVar[str] = ""

    def __init__(
        self,
        message: str,
        *,
        code: str,
        status: int,
        upgrade_url: str,
        capability: str = "",
        plan: Optional[PlanInfo] = None,
        allowance: Optional[Allowance] = None,
        plans: Sequence[PlanInfo] = (),
        quota: Optional[Quota] = None,
        retry_after: Optional[float] = None,
        detail: Optional[str] = None,
    ) -> None:
        super().__init__(detail or message)
        self.message = message
        self.code = code
        self.status = status
        self.upgrade_url = upgrade_url
        self.capability = capability
        self.plan = plan
        self.allowance = allowance
        self.plans: List[PlanInfo] = list(plans)
        self.quota = quota
        self.retry_after = retry_after

    def _fields(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "status": self.status,
            "upgrade_url": self.upgrade_url,
            "capability": self.capability,
            "plan": self.plan,
            "allowance": self.allowance,
            "plans": tuple(self.plans),
            "quota": self.quota,
            "retry_after": self.retry_after,
        }

    def to_dict(self) -> Dict[str, Any]:
        """The fields as plain values (the wire's snake_case names, plus
        ``kind`` and ``retry_after``); what ``diagnostics()`` shows."""
        return {
            "kind": self.kind,
            "code": self.code,
            "status": self.status,
            "message": self.message,
            "upgrade_url": self.upgrade_url,
            "capability": self.capability,
            "plan": asdict(self.plan) if self.plan is not None else None,
            "allowance": asdict(self.allowance) if self.allowance is not None else None,
            "plans": [asdict(p) for p in self.plans],
            "quota": asdict(self.quota) if self.quota is not None else None,
            "retry_after": self.retry_after,
        }

    def rebased(self, families: Mapping[str, Type["PlanRefusalError"]], detail: str) -> "PlanRefusalError":
        """This refusal as ``families[kind]`` (a class that is also a call's
        own error) with ``str()`` = ``detail``; the fields are kept."""
        cls = families.get(self.kind, type(self))
        return cls(self.message, detail=detail, **self._fields())

    def __reduce__(self) -> Tuple[Any, ...]:
        return (_restore, (type(self), self.message, str(self), self._fields()))

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, status={self.status}, upgrade_url={self.upgrade_url!r})"


def _restore(cls: Type[PlanRefusalError], message: str, detail: str, fields: Dict[str, Any]) -> PlanRefusalError:
    return cls(message, detail=detail, **fields)


class PlanRequiredError(PlanRefusalError):
    """HTTP 403 ``plan_required``: the organization's plan does not include
    AI Apps ingest, or includes no allowance. Fix it at ``upgrade_url``."""

    kind: ClassVar[str] = KIND_PLAN_REQUIRED


class AllowanceExceededError(PlanRefusalError):
    """HTTP 429 over the plan's monthly AI Apps allowance (events or bytes);
    ``quota`` says which and when it resets. Fix it at ``upgrade_url``."""

    kind: ClassVar[str] = KIND_ALLOWANCE_EXCEEDED


# code -> (the status it rides on, the class). One row per code.
_CODES: Dict[str, Tuple[int, Type[PlanRefusalError]]] = {
    PLAN_REQUIRED: (403, PlanRequiredError),
    EVENTS_QUOTA_EXCEEDED: (429, AllowanceExceededError),
    BYTES_QUOTA_EXCEEDED: (429, AllowanceExceededError),
    AIGW_QUOTA_EXCEEDED: (429, AllowanceExceededError),
}


def _str(v: Any) -> str:
    return v if isinstance(v, str) else ""


def _int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return None


def _allowance(v: Any) -> Optional[Allowance]:
    if not isinstance(v, Mapping):
        return None
    return Allowance(
        _int(v.get("events_monthly")),
        _int(v.get("gb_monthly")),
        _int(v.get("requests_monthly")),
        _int(v.get("concurrency")),
    )


def _plan(v: Any, with_allowance: bool) -> Optional[PlanInfo]:
    if not isinstance(v, Mapping) or not _str(v.get("name")):
        return None
    return PlanInfo(
        name=v["name"],
        version=_int(v.get("version")) or 0,
        label=_str(v.get("label")),
        allowance=_allowance(v.get("allowance")) if with_allowance else None,
    )


def _quota(v: Any) -> Optional[Quota]:
    if not isinstance(v, Mapping):
        return None
    return Quota(_str(v.get("quota")), _str(v.get("unit")), _int(v.get("used")) or 0, _int(v.get("limit")) or 0, _str(v.get("resets_at")))


def _retry_after(headers: Optional[Mapping[str, Any]]) -> Optional[float]:
    if not headers:
        return None
    raw = next((v for k, v in headers.items() if str(k).lower() == "retry-after"), None)
    text = str(raw).strip() if raw is not None else ""
    return float(int(text)) if text.isdigit() else None


def _body(body: Any) -> Any:
    if isinstance(body, Mapping):
        return body
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8")
    if isinstance(body, str):
        return json.loads(body) if body.strip() else None
    return None


def default_message(code: str, upgrade_url: str) -> str:
    """The line a refusal shows when the gateway sent no message."""
    if code == AIGW_QUOTA_EXCEEDED:
        return f"AI gateway calls were refused by the organization's plan ({code}); its billing owner can change the plan at {upgrade_url}"
    return f"AI Apps ingest was refused by the organization's plan ({code}); its billing owner can change the plan at {upgrade_url}"


def parse_plan_refusal(status: int, body: Any, headers: Optional[Mapping[str, Any]] = None) -> Optional[PlanRefusalError]:
    """The plan refusal in one HTTP answer, or None.

    ``body`` is the decoded JSON object, or the raw body (bytes or text);
    ``headers`` any mapping (the name ``Retry-After`` is matched without
    regard to case). A plan refusal is a 403 ``plan_required`` or a 429
    ``planea_events_quota_exceeded`` / ``planea_bytes_quota_exceeded`` /
    ``aigw_requests_quota_exceeded`` (the AI gateway's allowance) whose body carries a non-empty ``upgrade_url``; anything else, malformed
    input included, is None. Never raises."""
    try:
        return _parse(status, body, headers)
    except Exception:  # noqa: BLE001 - a parser of untrusted input never raises
        return None


def _parse(status: int, body: Any, headers: Optional[Mapping[str, Any]]) -> Optional[PlanRefusalError]:
    if status not in (403, 429):
        return None
    obj = _body(body)
    if not isinstance(obj, Mapping):
        return None
    code = _str(obj.get("error"))
    row = _CODES.get(code)
    upgrade_url = _str(obj.get("upgrade_url")).strip()
    if row is None or row[0] != status or not upgrade_url:
        return None
    cls = row[1]
    plans_raw = obj.get("plans")
    plans = [p for p in (_plan(x, True) for x in (plans_raw if isinstance(plans_raw, list) else ())) if p is not None]
    return cls(
        _str(obj.get("message")).strip() or default_message(code, upgrade_url),
        code=code,
        status=status,
        upgrade_url=upgrade_url,
        capability=_str(obj.get("capability")),
        plan=_plan(obj.get("plan"), False),
        allowance=_allowance(obj.get("allowance")),
        plans=plans,
        quota=_quota(obj.get("quota")),
        retry_after=_retry_after(headers),
    )


class _Last:
    """The last plan refusal the SDK saw (export or a control call)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self.refusal: Optional[PlanRefusalError] = None
        self.at = 0.0
        self.logged_at = 0.0


LAST = _Last()


def _one_line(s: str) -> str:
    return " ".join(s.split())


def note(refusal: PlanRefusalError, *, log_as: str = "") -> bool:
    """Keep ``refusal`` as the last one. With ``log_as`` (what was refused,
    e.g. "trace export"), write ONE warning line, at most once per
    LOG_INTERVAL: the message and the upgrade URL. True when it logged."""
    now = time.time()
    with LAST.lock:
        LAST.refusal, LAST.at = refusal, now
        due = bool(log_as) and now - LAST.logged_at >= LOG_INTERVAL
        if due:
            LAST.logged_at = now
    if due:
        LOG.warning("superbased_sdk: %s refused by the organization's plan: %s (upgrade: %s)", log_as, _one_line(refusal.message), refusal.upgrade_url)
    return due


def snapshot() -> Dict[str, Any]:
    with LAST.lock:
        r, at = LAST.refusal, LAST.at
    return {"plan_refusal": r.to_dict() if r is not None else None, "plan_refusal_at": at}
