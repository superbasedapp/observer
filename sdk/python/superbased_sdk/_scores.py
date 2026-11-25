"""``score()`` and ``feedback()`` (W3-1; contract
docs/plans/plane-a-sdk-buildout/contracts/scores.md).

A score is one judgement about a trace or span. The SDK validates it with the
same rules as ``internal/scorecore`` (so a bad score is reported here, before
any network call), mints an idempotency ``id`` when the caller gives none, and
writes it to each destination of the plan (``both``: the machine and the
gateway, with the same id, so the stored score id is the same on both sides).
Never raises into the host: problems come back in ``ScoreResult``.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from . import _control
from ._context import get_current_trace_id
from ._planrefusal import PlanRefusalError

LOG = logging.getLogger("superbased_sdk")

Value = Union[bool, int, float, str]

SOURCE_SDK = "sdk"
SOURCE_FEEDBACK = "feedback"
KINDS = ("numeric", "boolean", "categorical")
DEFAULT_FEEDBACK_NAME = "user_feedback"

_NAME = re.compile(r"^[a-z0-9_.-]{1,64}$")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TRACE = re.compile(r"^[0-9a-f]{32}$")
_SPAN = re.compile(r"^[0-9a-f]{16}$")
MAX_VALUE_BYTES = 120
MAX_COMMENT_BYTES = 2000
MAX_SCORER_NAME = 64
MAX_SCORER_VERSION = 32


@dataclass
class ScoreResult:
    """The outcome of one score write. ``ok`` is True when every destination
    accepted it. ``id`` is the stored score id (``sc_…``) the first accepting
    destination returned; ``client_id`` the idempotency id that was sent.
    ``destinations`` maps each destination name to ``{"ok", "status", "id",
    "error"}``; ``errors`` lists every problem (validation or transport).
    ``plan_refusal`` is set when the org's plan refused the score (a
    ``PlanRefusalError``: its message and ``upgrade_url`` say why and where
    to fix it)."""

    ok: bool = False
    id: str = ""
    client_id: str = ""
    destinations: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    plan_refusal: Optional[PlanRefusalError] = None

    def __bool__(self) -> bool:
        return self.ok


class ScoreError(ValueError):
    """A score the rules refuse (only raised by ``build_score``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _kind_of(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "numeric"
    if isinstance(value, str):
        return "categorical"
    raise ScoreError("invalid_value", f"value must be a number, a bool or a string, got {type(value).__name__}")


def build_score(
    name: str,
    value: Value,
    *,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    comment: Optional[str] = None,
    kind: Optional[str] = None,
    source: str = SOURCE_SDK,
    scorer: Optional[str] = None,
    scorer_version: Optional[str] = None,
    run_id: Optional[str] = None,
    score_id: Optional[str] = None,
    timestamp: Optional[str] = None,
    use_current_trace: bool = True,
) -> Dict[str, Any]:
    """The wire score object (scores.md section 1), validated. Raises
    ScoreError naming the contract's error code."""
    n = (name or "").strip().lower()
    if not _NAME.match(n):
        raise ScoreError("invalid_name", f"name {name!r} must be 1-64 chars of a-z 0-9 _ . -")
    inferred = _kind_of(value)
    if kind is not None and kind != inferred:
        if kind not in KINDS:
            raise ScoreError("kind_mismatch", f"kind {kind!r} is not numeric, boolean or categorical")
        raise ScoreError("kind_mismatch", f"kind {kind} does not match a {type(value).__name__} value")
    if inferred == "numeric" and not math.isfinite(float(value)):
        raise ScoreError("invalid_value", f"value {value!r} is not a finite number")
    if inferred == "categorical":
        v = str(value).strip()
        if not v or len(v.encode("utf-8")) > MAX_VALUE_BYTES or "\n" in v or "\r" in v:
            raise ScoreError("invalid_value", f"a categorical value must be 1-{MAX_VALUE_BYTES} bytes on one line")
        value = v
    tid = (trace_id or (get_current_trace_id() if use_current_trace else "")).strip().lower()
    if not tid:
        raise ScoreError("invalid_trace_id", "no trace_id given and no current span")
    if not _TRACE.match(tid) or tid == "0" * 32:
        raise ScoreError("invalid_trace_id", f"trace_id {trace_id!r} must be 32 hex characters, not all zero")
    sid = (span_id or "").strip().lower()
    if sid and (not _SPAN.match(sid) or sid == "0" * 16):
        raise ScoreError("invalid_span_id", f"span_id {span_id!r} must be 16 hex characters")
    if comment is not None and len(str(comment).encode("utf-8")) > MAX_COMMENT_BYTES:
        raise ScoreError("comment_too_long", f"comment is over {MAX_COMMENT_BYTES} bytes")
    cid = score_id or ("sdk_" + uuid.uuid4().hex)
    if not _ID.match(cid):
        raise ScoreError("invalid_id", f"score_id {score_id!r} must be 1-128 chars of A-Z a-z 0-9 _ . : -")
    if source not in (SOURCE_SDK, SOURCE_FEEDBACK):
        raise ScoreError("invalid_source", f"source {source!r} must be sdk or feedback")
    out: Dict[str, Any] = {"id": cid, "trace_id": tid, "name": n, "value": value, "kind": inferred, "source": source}
    if sid:
        out["span_id"] = sid
    if comment:
        out["comment"] = str(comment)
    if scorer:
        if len(scorer) > MAX_SCORER_NAME or (scorer_version and len(scorer_version) > MAX_SCORER_VERSION):
            raise ScoreError("bad_request", "scorer name is 1-64 chars and version 1-32")
        out["scorer"] = {"name": scorer, "version": scorer_version or "1"}
    if run_id:
        out["run_id"] = str(run_id)
    if timestamp:
        out["timestamp"] = timestamp
    return out


def result_ok(res: "ScoreResult") -> bool:
    """True only when every destination the score went to accepted it; no
    destination at all is not ok (sdk/contract/sdk-behaviour-cases.json
    ``score_ok``, the same rule in both SDKs)."""
    return bool(res.destinations) and all(d.get("ok") for d in res.destinations.values())


def post_scores(objs: List[Dict[str, Any]]) -> List[ScoreResult]:
    """Write already-built score objects to every destination (one request
    per destination). Never raises."""
    results = [ScoreResult(client_id=o["id"]) for o in objs]
    body: Any = objs[0] if len(objs) == 1 else {"scores": objs}
    targets = _control.sides()
    if not targets:
        # A degraded "online" sends nothing anywhere (destination.md section 7).
        reason = _control.unavailable_reason()
        for res in results:
            res.destinations["online"] = {"ok": False, "status": 0, "id": "", "error": reason}
            res.errors.append(f"online: {reason}")
    for side in targets:
        resp = side.call("POST", "scores", body=body)
        if _retryable(resp):
            # Once, with the same ids: the id makes a repeat a no-op (contract
            # scores.md), so a blip never loses a score and never doubles one.
            resp = side.call("POST", "scores", body=body)
        refusal = resp.plan_refusal()
        accepted: Dict[int, str] = {}
        rejected: Dict[int, str] = {}
        if isinstance(resp.body, dict):
            for a in resp.body.get("accepted") or ():
                if isinstance(a, dict) and isinstance(a.get("index"), int):
                    accepted[a["index"]] = str(a.get("id") or "")
            for r in resp.body.get("rejected") or ():
                if isinstance(r, dict) and isinstance(r.get("index"), int):
                    rejected[r["index"]] = f"{r.get('error', 'rejected')}: {r.get('message', '')}".strip(": ")
        for i, res in enumerate(results):
            if i in accepted and resp.status in (200, 201):
                res.destinations[side.name] = {"ok": True, "status": resp.status, "id": accepted[i], "error": ""}
                res.id = res.id or accepted[i]
            else:
                err = rejected.get(i) or resp.describe()
                res.destinations[side.name] = {"ok": False, "status": resp.status, "id": "", "error": err}
                res.errors.append(f"{side.name}: {err}")
                res.plan_refusal = res.plan_refusal or refusal
    for res in results:
        res.ok = result_ok(res)
        if not res.ok:
            _log_failure(res)
    return results


def _retryable(resp: Any) -> bool:
    """No answer, 429 or a 5xx: worth one more try (as the TypeScript SDK).
    A 429 over the plan's allowance is not: it holds until the plan changes
    or the month turns."""
    status = getattr(resp, "status", 0)
    if status == 429 and resp.plan_refusal() is not None:
        return False
    return status == 0 or status == 429 or status >= 500


_last_log = [0.0]


def _log_failure(res: ScoreResult) -> None:
    now = time.time()
    if now - _last_log[0] < 60:
        return
    _last_log[0] = now
    LOG.warning("superbased_sdk: a score was not stored: %s", "; ".join(res.errors) or "unknown")


def _write(**kw: Any) -> ScoreResult:
    try:
        obj = build_score(**kw)
    except ScoreError as exc:
        res = ScoreResult(errors=[str(exc)])
        _log_failure(res)
        return res
    try:
        return post_scores([obj])[0]
    except Exception as exc:  # noqa: BLE001 - never raise into the host
        return ScoreResult(client_id=obj["id"], errors=[f"{type(exc).__name__}: {exc}"])


def score(
    name: str,
    value: Value,
    *,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    comment: Optional[str] = None,
    kind: Optional[str] = None,
    scorer: Optional[str] = None,
    scorer_version: Optional[str] = None,
    run_id: Optional[str] = None,
    score_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ScoreResult:
    """Record a score (``source=sdk``) on a trace or span: ``value`` is a
    number (numeric), a bool (boolean) or a short string (categorical).

    trace_id defaults to the current trace; span_id is optional (a
    trace-level score). scorer / scorer_version name the evaluator, so two
    versions never overwrite each other. score_id is the idempotency id (a
    random one by default): sending the same id again overwrites instead of
    adding. comment is content (masked by the server's capture policy).
    Written to the destination(s) chosen at ``init()``. Never raises: check
    ``ScoreResult.ok`` / ``.errors``."""
    return _write(
        name=name,
        value=value,
        trace_id=trace_id,
        span_id=span_id,
        comment=comment,
        kind=kind,
        source=SOURCE_SDK,
        scorer=scorer,
        scorer_version=scorer_version,
        run_id=run_id,
        score_id=score_id,
        timestamp=timestamp,
    )


def feedback(
    value: Value,
    *,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    comment: Optional[str] = None,
    name: str = DEFAULT_FEEDBACK_NAME,
    score_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> ScoreResult:
    """Record an end user's feedback (``source=feedback``): thumbs as a bool,
    stars as a number, or a short label. Every call is its own row (a new
    id each time), so feedback from many users on one trace is kept. Pass
    the trace id you sent to the browser (``get_current_trace_id()`` while
    the request was traced). Never raises."""
    return _write(
        name=name,
        value=value,
        trace_id=trace_id,
        span_id=span_id,
        comment=comment,
        source=SOURCE_FEEDBACK,
        score_id=score_id,
        timestamp=timestamp,
    )


async def async_score(name: str, value: Value, **kw: Any) -> ScoreResult:
    """``score()`` without blocking the event loop (runs in a worker thread).
    trace_id defaults to the trace current HERE, before the hand-off."""
    kw.setdefault("trace_id", get_current_trace_id() or None)
    return await asyncio.get_running_loop().run_in_executor(None, lambda: score(name, value, **kw))


async def async_feedback(value: Value, **kw: Any) -> ScoreResult:
    """``feedback()`` without blocking the event loop."""
    kw.setdefault("trace_id", get_current_trace_id() or None)
    return await asyncio.get_running_loop().run_in_executor(None, lambda: feedback(value, **kw))
