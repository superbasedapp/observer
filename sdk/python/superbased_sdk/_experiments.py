"""``run_experiment(dataset, task, evaluators)`` (W3-2; contract
docs/plans/plane-a-sdk-buildout/contracts/experiments.md).

The run lives on the destination(s) of the plan: the machine
(``/api/obs/eval/*``) and/or the org gateway (``/v1/sdk/*``, scope
``sdk:eval``). The SDK creates the run (which freezes a dataset snapshot),
reads the snapshot's items, runs ``task`` on each item in its own trace,
runs the evaluators in-process, posts each item's result as soon as it is
done, finishes the run and reads back the totals. Under ``both`` the task runs
once and each result goes to both sides (items matched by their client id,
else by input).

Unlike the tracing calls, an experiment is an explicit batch job: a dataset
that cannot be found or a run that cannot be created raises
``ExperimentError``; ``fail_under`` raises ``ExperimentGateFailed`` (a
``SystemExit``, so a CI script exits non-zero). One refusal is not an error:
a destination that answers 403 ``insufficient_scope`` (the org, to a member
key without ``sdk:eval``) is skipped with an entry in ``errors``, and the run
goes on with the other destination. With ``fail_under`` set the gate is
strict by default (review E-12, ruling D29): a run that scored nothing, a
skipped destination or a result that was not posted fails it, because a CI
gate that passes on an outage is worse than none; ``strict=False`` gates on
the pass rate alone.
"""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import inspect
import json
import logging
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

from opentelemetry import context as otel_context

from . import _control
from . import _keys as K
from ._scores import ScoreError, _retryable, build_score

LOG = logging.getLogger("superbased_sdk")

RESULTS_PER_POST = 200
ITEMS_PAGE = 500
_FAIL_WORDS = {"fail", "false", "no", "bad"}


class ExperimentError(RuntimeError):
    """The experiment could not be set up (dataset, run creation)."""


class ExperimentGateFailed(SystemExit):
    """The pass rate is below ``fail_under``. A ``SystemExit`` with code 1, so
    an uncaught one ends a CI script non-zero; ``.result`` has the details."""

    def __init__(self, result: "ExperimentResult", fail_under: float, reasons: Sequence[str] = ()) -> None:
        super().__init__(1)
        self.result = result
        self.fail_under = fail_under
        # Why the strict gate failed before the rate was compared (E-12);
        # empty when the pass rate itself is below fail_under.
        self.reasons = list(reasons)

    def __str__(self) -> str:
        if self.reasons:
            return (
                f"experiment {self.result.name!r}: the fail_under gate cannot pass: " + "; ".join(self.reasons)
                + " (strict; pass strict=False to gate on the pass rate alone)"
            )
        return f"experiment {self.result.name!r}: pass rate {self.result.pass_rate:.3f} is below {self.fail_under:.3f}"


@dataclass
class Evaluation:
    """One evaluator result. ``value`` is a number, a bool or a short label."""

    name: str
    value: Any
    comment: Optional[str] = None
    scorer_version: str = "1"

    @property
    def passed(self) -> bool:
        return passes(self.value)


def passes(value: Any) -> bool:
    """The contract's pass rule: boolean true, numeric >= 0.5, or a label not
    in fail/false/no/bad."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value) >= 0.5
    return str(value).strip().lower() not in _FAIL_WORDS


@dataclass
class Dataset:
    """A dataset on one destination."""

    id: str
    name: str
    side: str = ""
    item_count: int = 0
    latest_snapshot: int = 0
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass
class ItemResult:
    item_id: str
    input: Any
    expected: Any = None
    metadata: Any = None
    output: Any = None
    trace_id: str = ""
    scores: List[Evaluation] = field(default_factory=list)
    error: str = ""
    evaluator_errors: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.error and all(s.passed for s in self.scores)


@dataclass
class ExperimentResult:
    name: str
    run_id: str = ""  # the first destination's run
    runs: Dict[str, str] = field(default_factory=dict)  # destination -> run id
    items: List[ItemResult] = field(default_factory=list)
    skipped_no_content: int = 0
    server: Dict[str, Any] = field(default_factory=dict)  # destination -> GET experiment body
    errors: List[str] = field(default_factory=list)  # posting problems (results kept locally), and "no scores"
    # Destinations skipped for want of a scope (403 insufficient_scope).
    skipped_sides: List[str] = field(default_factory=list)
    # Results a destination did not accept (a failed post counts each result
    # it carried; a rejected result counts once).
    failed_posts: int = 0

    @property
    def scored(self) -> int:
        """How many items were scored: the first side's ``total``, else the
        local count of items with a score or a task error. An item with
        neither (no evaluator ran) is neither passed nor failed."""
        for body in self.server.values():
            if isinstance(body, dict) and _is_count(body.get("total")) and (body["total"] > 0 or not _local_scored(self.items)):
                return int(body["total"])
        return len(_local_scored(self.items))

    @property
    def pass_rate(self) -> float:
        """The first side's pass rate, else the local rate over scored items.
        NaN when nothing was scored (``scored`` 0): no rate, not 0."""
        for body in self.server.values():
            if not isinstance(body, dict) or not isinstance(body.get("pass_rate"), (int, float)) or isinstance(body.get("pass_rate"), bool):
                continue
            if _is_count(body.get("total")) and body["total"] == 0:
                continue  # an older server's 0 for "nothing scored"
            return float(body["pass_rate"])
        scored = _local_scored(self.items)
        return (sum(1 for i in scored if i.passed) / len(scored)) if scored else float("nan")

    @property
    def summary(self) -> Dict[str, Dict[str, float]]:
        """Per evaluator: count, passed, mean of numeric/boolean values."""
        out: Dict[str, Dict[str, float]] = {}
        for it in self.items:
            for s in it.scores:
                row = out.setdefault(s.name, {"count": 0, "passed": 0, "sum": 0.0, "numeric": 0})
                row["count"] += 1
                row["passed"] += 1 if s.passed else 0
                if isinstance(s.value, (bool, int, float)):
                    row["sum"] += float(s.value)
                    row["numeric"] += 1
        for row in out.values():
            row["mean"] = row["sum"] / row["numeric"] if row["numeric"] else 0.0
            del row["sum"], row["numeric"]
        return out


def _is_count(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _local_scored(items: Sequence["ItemResult"]) -> List["ItemResult"]:
    """Items that count toward a pass rate: a score, or a task error."""
    return [i for i in items if i.error or i.scores]


def gate_problems(result: "ExperimentResult") -> List[str]:
    """Why a strict ``fail_under`` gate fails before the rate is compared
    (review E-12, ruling D29): nothing was scored, a destination was skipped,
    or results were not posted (a side's pass rate then covers only part of
    the run). Contract experiments.md 4.2."""
    out: List[str] = []
    if result.scored == 0:
        out.append("no item was scored (no evaluator returned a score)")
    for side in result.skipped_sides:
        out.append(f"the {side} destination was skipped")
    if result.failed_posts:
        out.append(f"{result.failed_posts} result(s) were not accepted, so the recorded pass rate covers only part of the run")
    return out


def gate_fails(result: "ExperimentResult", fail_under: Optional[float], strict: bool = True) -> bool:
    """Whether ``fail_under`` fails this run. Strict (the default): any of
    ``gate_problems`` fails it. Not strict: only the rate does, and a run
    that scored nothing is not failed (it reports "no scores" instead)."""
    if fail_under is None:
        return False
    if strict and gate_problems(result):
        return True
    if result.scored == 0:
        return False
    return not (result.pass_rate >= float(fail_under))


# --- evaluators -------------------------------------------------------------------

EvaluatorFn = Callable[..., Any]
_NAME_BAD = re.compile(r"[^a-z0-9_.-]+")


def _evaluator_name(ev: Any) -> str:
    raw = getattr(ev, "name", None) or getattr(ev, "__name__", None) or type(ev).__name__
    n = _NAME_BAD.sub("_", str(raw).strip().lower()).strip("_") or "evaluator"
    return n[:64]


def _call_flexible(fn: Callable[..., Any], kwargs: Mapping[str, Any]) -> Any:
    """Call ``fn`` with the keyword arguments it accepts (all, when it takes **kw)."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return fn(**kwargs)
    params = sig.parameters.values()
    if any(p.kind == p.VAR_KEYWORD for p in params):
        return fn(**kwargs)
    names = {p.name for p in params if p.kind in (p.KEYWORD_ONLY, p.POSITIONAL_OR_KEYWORD)}
    return fn(**{k: v for k, v in kwargs.items() if k in names})


def _await(value: Any) -> Any:
    """The result of ``value``, awaiting it when it is awaitable. With an
    event loop already running on this thread (a notebook, or the sync
    ``run_experiment`` called from async code), ``asyncio.run`` would raise,
    so the awaitable runs on its own loop in a helper thread, in this
    thread's context (the item's span stays the parent). Review E-77."""
    if not inspect.isawaitable(value):
        return value

    async def run() -> Any:
        return await value

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(run())
    ctx = contextvars.copy_context()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="superbased-experiment-await") as pool:
        return pool.submit(ctx.run, asyncio.run, run()).result()


def _normalize(ev: Any, out: Any) -> List[Evaluation]:
    name, version = _evaluator_name(ev), str(getattr(ev, "version", "1"))
    if out is None:
        return []
    if isinstance(out, Evaluation):
        return [out]
    if isinstance(out, (list, tuple)):
        res: List[Evaluation] = []
        for o in out:
            res.extend(_normalize(ev, o))
        return res
    if isinstance(out, Mapping):
        return [Evaluation(str(out.get("name") or name), out.get("value"), out.get("comment"), str(out.get("version") or version))]
    return [Evaluation(name, out, None, version)]


# --- destinations -----------------------------------------------------------------


@dataclass
class _Run:
    side: _control.Side
    dataset_id: str
    run_id: str = ""
    snapshot_version: int = 0
    items: List[Dict[str, Any]] = field(default_factory=list)
    item_map: Dict[int, str] = field(default_factory=dict)  # our item index -> this side's item id
    # The machine's ids of a literal upload's items: the run is pinned to
    # exactly them (R-B22, review E-75).
    item_ids: List[str] = field(default_factory=list)


class _SideSkipped(ExperimentError):
    """A destination refused the call for want of a scope (403
    ``insufficient_scope``): a member SDK key from ``observer sdk sign-in``
    deliberately lacks ``sdk:eval``, which every org dataset and experiment
    route needs. The run treats that destination as skipped: the reason goes
    to ``ExperimentResult.errors`` and the other destination carries on."""


def _scope_refused(resp: Any) -> bool:
    return getattr(resp, "status", 0) == 403 and resp.error_code() == "insufficient_scope"


def _ok(resp: Any, what: str, side: str) -> Any:
    if not resp.ok:
        if _scope_refused(resp):
            raise _SideSkipped(
                f"{side}: skipped, {what} refused: {resp.describe()} "
                "(an SDK key from sign-in has no sdk:eval scope; run experiments on the org with a CI credential that has it)"
            )
        raise ExperimentError(f"{side}: {what} failed: {resp.describe()}")
    return resp.body if isinstance(resp.body, dict) else {}


def _find_dataset(side: _control.Side, ref: str) -> Optional[Dataset]:
    query = {"name": ref} if side.name == "online" and not ref.startswith("ds_") else None
    body = _ok(side.call("GET", "datasets", query=query), "dataset list", side.name)
    for d in body.get("datasets") or ():
        if not isinstance(d, dict):
            continue
        if str(d.get("id")) == ref or d.get("name") == ref:
            return Dataset(
                str(d.get("id")), str(d.get("name") or ""), side.name, int(d.get("item_count") or 0), int(d.get("latest_snapshot") or 0), d
            )
    return None


def get_dataset(name_or_id: str) -> Dataset:
    """A dataset by name or id on the first destination that has it (the
    gateway first under ``both``). Raises ExperimentError when none does."""
    errors = []
    targets = _control.sides()
    if not targets:
        errors.append(_control.unavailable_reason())
    for side in targets:
        try:
            d = _find_dataset(side, name_or_id)
        except ExperimentError as exc:
            errors.append(str(exc))
            continue
        if d is not None:
            return d
    raise ExperimentError(f"dataset {name_or_id!r} not found" + (": " + "; ".join(errors) if errors else ""))


def _canonical(v: Any) -> str:
    """Compact JSON with object keys sorted at every level and numbers in
    the ECMAScript form: the same text the TypeScript SDK's canonical form
    gives, so both derive the same item id."""
    from ._prompts import _js_json

    def sort(x: Any) -> Any:
        if isinstance(x, Mapping):
            return {str(k): sort(x[k]) for k in sorted(x, key=str)}
        if isinstance(x, (list, tuple)):
            return [sort(y) for y in x]
        return x

    return _js_json(sort(v))


def literal_item_id(input: Any, expected: Any = None, metadata: Any = None) -> str:
    """The default id of a literal item: derived from its content (review
    E-75), so a re-run with changed inputs makes new items on the machine
    instead of matching the previous run's ``item-00001``. Both SDKs give the
    same id (sdk-behaviour-cases.json ``literal_item_ids``)."""
    text = _canonical([input, expected, metadata])
    return "item-" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _literal(items: Iterable[Any]) -> List[Dict[str, Any]]:
    out = []
    seen: Dict[str, int] = {}
    for it in items:
        if not isinstance(it, Mapping):
            it = {"input": it}
        expected = it.get("expected", it.get("expected_output"))
        item_id = str(it.get("id") or "")
        if not item_id:
            item_id = literal_item_id(it.get("input"), expected, it.get("metadata"))
            # The same content twice is two items: the second is <id>-2.
            seen[item_id] = seen.get(item_id, 0) + 1
            if seen[item_id] > 1:
                item_id = f"{item_id}-{seen[item_id]}"
        row = {"id": item_id, "input": it.get("input"), "expected": expected}
        if it.get("metadata") is not None:
            row["metadata"] = it.get("metadata")
        out.append(row)
    return out


def _upload_literal(side: _control.Side, dataset_name: str, items: List[Dict[str, Any]]) -> Tuple[str, int, List[str]]:
    """Put literal items where a run can see them: (dataset id, snapshot
    version, the machine's ids of exactly these items; empty on the org)."""
    if side.name == "local":
        body = _ok(side.call("POST", "datasets", body={"name": dataset_name}), "dataset create", side.name)
        ds = body.get("dataset") if isinstance(body.get("dataset"), dict) else body
        ds_id = str(ds.get("id") or "")
        if not ds_id:
            raise ExperimentError("local: dataset create answered no id")
        body = _ok(side.call("POST", "dataset_snapshot", body={"items": items}, id=ds_id), "dataset items", side.name)
        ids = [str(x) for x in body.get("item_ids") or () if isinstance(x, (str, int)) and not isinstance(x, bool)]
        return ds_id, int(body.get("version") or body.get("snapshot_version") or 0), ids
    d = _find_dataset(side, dataset_name)
    if d is None:
        raise ExperimentError(f"online: dataset {dataset_name!r} does not exist on the org (create it on the dashboard first)")
    body = _ok(side.call("POST", "dataset_snapshot", body={"items": items}, id=d.id), "dataset snapshot", side.name)
    return d.id, int(body.get("version") or 0), []


def _read_items(side: _control.Side, run: _Run) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    cursor = ""
    for _ in range(10_000):  # bounded paging
        query: Dict[str, Any] = {"limit": ITEMS_PAGE, "cursor": cursor}
        if side.name == "local":
            query["version"] = run.snapshot_version or None
            # The run's own items: its pinned set (a literal upload), else
            # every item up to its version (R-B22, review E-75).
            if run.run_id:
                query["run"] = run.run_id
        body = _ok(side.call("GET", "dataset_items", query=query, id=run.dataset_id, version=run.snapshot_version), "dataset items", side.name)
        out.extend(i for i in body.get("items") or () if isinstance(i, dict))
        cursor = str(body.get("next_cursor") or "")
        if not cursor:
            break
    return out


def _key(item: Mapping[str, Any]) -> str:
    return json.dumps(item.get("input"), sort_keys=True, default=str)


def _map_items(primary: List[Dict[str, Any]], other: List[Dict[str, Any]]) -> Dict[int, str]:
    """Our item index -> the other side's item id, by client id then input."""
    by_client = {str(i.get("client_id")): str(i.get("item_id")) for i in other if i.get("client_id")}
    by_input: Dict[str, List[str]] = {}
    for i in other:
        by_input.setdefault(_key(i), []).append(str(i.get("item_id")))
    out: Dict[int, str] = {}
    for n, it in enumerate(primary):
        cid = str(it.get("client_id") or "")
        if cid and cid in by_client:
            out[n] = by_client[cid]
        elif by_input.get(_key(it)):
            out[n] = by_input[_key(it)].pop(0)
    return out


# --- the run ----------------------------------------------------------------------


def run_experiment(
    dataset: Union[str, Dataset, Iterable[Any]],
    task: Callable[..., Any],
    evaluators: Sequence[Any] = (),
    *,
    name: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    max_concurrency: int = 4,
    snapshot_version: Optional[int] = None,
    dataset_name: Optional[str] = None,
    fail_under: Optional[float] = None,
    strict: bool = True,
) -> ExperimentResult:
    """Run ``task`` over every item of ``dataset`` and score each output.

    dataset: a dataset name or id, a ``Dataset`` from ``get_dataset()``, or
    an iterable of items (``{"input", "expected", "metadata", "id"}``, or bare
    inputs). Literal items are uploaded to ``dataset_name`` (created on the
    machine; on the org it must exist, and a new snapshot is frozen with the
    items); without ``dataset_name`` they run in-process only and nothing is
    posted.

    task(input) (or task(input=..., expected=..., metadata=...)), sync or
    async, runs inside its own trace; evaluators are callables taking any of
    ``input``, ``output``, ``expected``, ``metadata`` and returning a number,
    a bool, a label, an ``Evaluation``, a ``{"name", "value", "comment"}``
    dict or a list of those. An evaluator's ``name`` / ``version`` attributes
    (else its function name and "1") name the scorer.

    snapshot_version pins the dataset snapshot (default: freeze a new one).
    Results are posted per item as they finish. fail_under (0..1) raises
    ExperimentGateFailed when the pass rate is below it; with strict (the
    default) also when nothing was scored, a destination was skipped or a
    result was not accepted. strict=False gates on the rate alone."""
    run_name = str(name or getattr(task, "__name__", None) or "experiment")
    result = ExperimentResult(name=run_name)
    runs: List[_Run] = []
    items: List[Dict[str, Any]] = []
    scorers = [{"name": _evaluator_name(e), "version": str(getattr(e, "version", "1"))} for e in evaluators]

    targets = _control.sides()
    if isinstance(dataset, (str, Dataset)):
        ref = dataset.id if isinstance(dataset, Dataset) else dataset
        if not targets:
            raise ExperimentError(f"dataset {ref!r}: {_control.unavailable_reason()}")
        skipped = 0
        for side in targets:
            try:
                if isinstance(dataset, Dataset) and dataset.side and dataset.side != side.name:
                    d: Optional[Dataset] = _find_dataset(side, dataset.name) if dataset.name else None
                else:
                    d = _find_dataset(side, ref)
            except _SideSkipped as exc:
                result.errors.append(str(exc))
                result.skipped_sides.append(side.name)
                skipped += 1
                continue
            if d is not None:
                runs.append(_Run(side, d.id, snapshot_version=int(snapshot_version or 0)))
        if not runs and not skipped:
            raise ExperimentError(f"dataset {ref!r} not found on any destination")
    else:
        literal = _literal(dataset)
        if dataset_name and not targets:
            result.errors.append(f"dataset {dataset_name!r} not uploaded, the run is in-process only: {_control.unavailable_reason()}")
        if dataset_name:
            for side in targets:
                try:
                    ds_id, version, item_ids = _upload_literal(side, dataset_name, literal)
                except _SideSkipped as exc:
                    result.errors.append(str(exc))
                    result.skipped_sides.append(side.name)
                    continue
                runs.append(_Run(side, ds_id, snapshot_version=version, item_ids=item_ids))
        items = [{"item_id": it["id"], "client_id": it["id"], "input": it["input"], "expected": it["expected"], "metadata": it.get("metadata"), "has_content": True} for it in literal]

    started: List[_Run] = []
    # One idempotency id per run_experiment call (review E-79): every side's
    # create carries it, and a create retried after no answer, a 429 or a 5xx
    # carries it again, so the side answers the run the first attempt opened
    # instead of opening a second one (contract experiments.md 4.1).
    create_id = uuid.uuid4().hex
    for r in runs:
        try:
            create: Dict[str, Any] = {"id": create_id, "name": run_name, "dataset_id": r.dataset_id, "snapshot_version": r.snapshot_version, "metadata": dict(metadata or {}), "scorers": scorers}
            if r.item_ids:
                create["item_ids"] = r.item_ids
            resp = r.side.call("POST", "experiments", body=create)
            if _retryable(resp):
                resp = r.side.call("POST", "experiments", body=create)
            body = _ok(resp, "experiment create", r.side.name)
            r.run_id = str(body.get("id") or "")
            r.snapshot_version = int(body.get("snapshot_version") or r.snapshot_version)
            if not r.run_id:
                raise ExperimentError(f"{r.side.name}: experiment create answered no id")
            r.items = _read_items(r.side, r)
        except _SideSkipped as exc:
            result.errors.append(str(exc))
            result.skipped_sides.append(r.side.name)
            continue
        result.runs[r.side.name] = r.run_id
        started.append(r)
    runs = started
    if runs:
        items = runs[0].items
        runs[0].item_map = {n: str(it.get("item_id")) for n, it in enumerate(items)}
        for r in runs[1:]:
            r.item_map = _map_items(items, r.items)
            unmapped = len(items) - len(r.item_map)
            if unmapped:
                result.errors.append(f"{r.side.name}: {unmapped} item(s) have no match there; their results go to {runs[0].side.name} only")
        result.run_id = runs[0].run_id

    runnable = [(n, it) for n, it in enumerate(items) if it.get("has_content", True) is not False]
    result.skipped_no_content = len(items) - len(runnable)
    lock = threading.Lock()
    done: List[Optional[ItemResult]] = [None] * len(items)
    pending: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {r.side.name: [] for r in runs}

    def flush_pending() -> None:
        for r in runs:
            with lock:
                batch = pending[r.side.name]
                if not batch:
                    continue
                pending[r.side.name] = []
            for start in range(0, len(batch), RESULTS_PER_POST):
                chunk = batch[start : start + RESULTS_PER_POST]
                resp = r.side.call("POST", "experiment_results", body={"results": [row for _, row in chunk]}, id=r.run_id)
                if not resp.ok:
                    with lock:
                        result.failed_posts += len(chunk)
                        result.errors.append(f"{r.side.name}: posting {len(chunk)} result(s) failed: {resp.describe()}")
                elif isinstance(resp.body, dict):
                    for rej in resp.body.get("rejected") or ():
                        if isinstance(rej, dict):
                            with lock:
                                result.failed_posts += 1
                                result.errors.append(f"{r.side.name}: result rejected: {rej.get('error')}: {rej.get('message', '')}")

    def one(n: int, it: Dict[str, Any]) -> None:
        res = _run_item(task, evaluators, it, run_name, runs[0].run_id if runs else "")
        done[n] = res
        for r in runs:
            if n in r.item_map:
                row = _result_row(r.item_map[n], res)
                with lock:
                    pending[r.side.name].append((n, row))
        flush_pending()

    workers = max(1, int(max_concurrency))
    if workers == 1 or len(runnable) <= 1:
        for n, it in runnable:
            one(n, it)
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="superbased-experiment") as pool:
            for f in [pool.submit(one, n, it) for n, it in runnable]:
                f.result()
    flush_pending()
    result.items = [r for r in done if r is not None]

    from . import flush

    flush()  # the items' traces, before the run is read back
    for r in runs:
        resp = r.side.call("POST", "experiment_finish", body={}, id=r.run_id)
        if not resp.ok:
            result.errors.append(f"{r.side.name}: finish failed: {resp.describe()}")
        got = r.side.call("GET", "experiment", id=r.run_id)
        if got.ok and isinstance(got.body, dict):
            result.server[r.side.name] = got.body
    for e in result.errors:
        LOG.warning("superbased_sdk: experiment %s: %s", run_name, e)
    if fail_under is not None and strict:
        problems = gate_problems(result)
        if problems:
            for msg in problems:
                result.errors.append("gate: " + msg)
            raise ExperimentGateFailed(result, float(fail_under), problems)
    if fail_under is not None and result.scored == 0:
        msg = "no scores: no item was scored (no evaluator ran), so fail_under was not applied (strict=False)"
        result.errors.append(msg)
        LOG.warning("superbased_sdk: experiment %s: %s", run_name, msg)
    if gate_fails(result, fail_under, strict):
        raise ExperimentGateFailed(result, float(fail_under))  # type: ignore[arg-type]
    return result


def _run_item(task: Callable[..., Any], evaluators: Sequence[Any], it: Mapping[str, Any], run_name: str, run_id: str) -> ItemResult:
    from . import CHAIN, _tracer, set_input, set_output

    res = ItemResult(item_id=str(it.get("item_id") or ""), input=it.get("input"), expected=it.get("expected"), metadata=it.get("metadata"))
    attrs: Dict[str, Any] = {K.SPAN_KIND: CHAIN}
    if run_id:
        attrs[K.EXPERIMENT_RUN_ID] = run_id
    if res.item_id:
        attrs[K.EXPERIMENT_ITEM_ID] = res.item_id
    # A fresh root context: every item is its own trace, even when the
    # experiment itself runs inside a span.
    token = otel_context.attach(otel_context.Context())
    try:
        with _tracer().start_as_current_span(
            f"experiment {run_name}", attributes=attrs, record_exception=False, set_status_on_exception=False
        ) as sp:
            sc = sp.get_span_context()
            res.trace_id = format(sc.trace_id, "032x") if sc.is_valid else ""
            set_input(sp, res.input)
            try:
                res.output = _await(_call_task(task, it))
                set_output(sp, res.output)
            except Exception as exc:  # noqa: BLE001 - an item failure is a result, not a crash
                res.error = f"{type(exc).__name__}: {exc}"[:500]
                try:
                    from opentelemetry.trace import Status, StatusCode

                    sp.record_exception(exc)
                    sp.set_status(Status(StatusCode.ERROR, res.error))
                except Exception:  # noqa: BLE001
                    pass
    finally:
        otel_context.detach(token)
    if res.error:
        return res
    kwargs = {"input": res.input, "output": res.output, "expected": res.expected, "expected_output": res.expected, "metadata": res.metadata}
    for ev in evaluators:
        try:
            res.scores.extend(_normalize(ev, _await(_call_flexible(ev, kwargs))))
        except Exception as exc:  # noqa: BLE001
            res.evaluator_errors.append(f"{_evaluator_name(ev)}: {type(exc).__name__}: {exc}"[:300])
    return res


def _call_task(task: Callable[..., Any], it: Mapping[str, Any]) -> Any:
    try:
        sig = inspect.signature(task)
        params = list(sig.parameters.values())
    except (TypeError, ValueError):
        return task(it.get("input"))
    kw = {"input": it.get("input"), "expected": it.get("expected"), "metadata": it.get("metadata")}
    names = {p.name for p in params}
    if any(p.kind == p.VAR_KEYWORD for p in params) or ("input" in names and len(names & set(kw)) > 1):
        return _call_flexible(task, kw)
    return task(it.get("input"))


def _result_row(item_id: str, res: ItemResult) -> Dict[str, Any]:
    from . import _CAPTURE_CONTENT

    row: Dict[str, Any] = {"item_id": item_id}
    if res.trace_id:
        row["trace_id"] = res.trace_id
    if res.error:
        row["error"] = res.error
    elif _CAPTURE_CONTENT and res.output is not None:
        row["output"] = res.output if isinstance(res.output, str) else json.dumps(res.output, ensure_ascii=False, default=str)
    scores = []
    for s in res.scores:
        try:
            obj = build_score(
                s.name, s.value, trace_id=res.trace_id or "1" * 32, comment=s.comment, scorer=s.name, scorer_version=s.scorer_version
            )
        except ScoreError as exc:
            res.evaluator_errors.append(f"{s.name}: {exc}")
            continue
        scores.append({k: v for k, v in obj.items() if k not in ("id", "trace_id", "span_id", "source")})
    row["scores"] = scores
    return row


async def async_run_experiment(*args: Any, **kw: Any) -> ExperimentResult:
    """``run_experiment()`` from async code (runs in a worker thread)."""
    return await asyncio.get_running_loop().run_in_executor(None, lambda: run_experiment(*args, **kw))
