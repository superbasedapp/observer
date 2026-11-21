"""W3-2: run_experiment() to contracts/experiments.md, against a fake eval
API on the machine and on the gateway."""

import asyncio
import json
import re

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _experiments as X


class FakeEval:
    """The eval routes of one side (machine or gateway) over a Stub."""

    def __init__(self, stub, side, datasets=None):
        self.stub, self.side = stub, side
        self.datasets = datasets or {}  # id -> {"name", "items": [...]}
        self.runs = {}
        self.results = {}
        self.finished = set()
        p = "/api/obs/eval" if side == "local" else "/v1/sdk"
        self.p = p
        stub.route("GET", f"{p}/datasets", self.list_datasets)
        stub.route("POST", f"{p}/experiments", self.create)
        if side == "local":
            stub.route("POST", f"{p}/datasets", self.create_dataset)
        self.n = 0

    def list_datasets(self, req):
        out = [{"id": i, "name": d["name"], "item_count": len(d["items"]), "latest_snapshot": 1} for i, d in self.datasets.items()]
        if "name=" in req["path"]:
            want = req["path"].split("name=", 1)[1]
            out = [d for d in out if d["name"] == want]
        return 200, {"api_version": "v1", "datasets": out}, {}

    def create_dataset(self, req):
        name = req["body"]["name"]
        for i, d in self.datasets.items():
            if d["name"] == name:
                return 200, {"id": i, "name": name}, {}
        i = str(len(self.datasets) + 10)
        self.add(i, name, [])
        return 201, {"id": i, "name": name}, {}

    def add(self, ds_id, name, items):
        self.datasets[ds_id] = {"name": name, "items": items}
        snap = f"{self.p}/datasets/{ds_id}/items" if self.side == "local" else f"{self.p}/datasets/{ds_id}/snapshots"
        self.stub.route("POST", snap, lambda req, ds_id=ds_id: self.add_literal(ds_id, req))
        if self.side == "local":
            self.stub.route("GET", f"{self.p}/datasets/{ds_id}/items", lambda req, ds_id=ds_id: self.items(ds_id, req))

    def add_literal(self, ds_id, req):
        d = self.datasets[ds_id]
        for it in req["body"]["items"]:
            d["items"].append({"item_id": f"it_{len(d['items'])}", "client_id": it["id"], "input": it["input"], "expected": it["expected"], "metadata": it.get("metadata"), "has_content": True})
        return 200, {"version": 2, "item_count": len(d["items"]), "with_content": len(d["items"])}, {}

    def items(self, ds_id, req):
        return 200, {"api_version": "v1", "version": 1, "items": self.datasets[ds_id]["items"], "next_cursor": ""}, {}

    def create(self, req):
        b = req["body"]
        self.n += 1
        rid = f"run_{self.side}_{self.n}"
        self.runs[rid] = b
        self.results[rid] = []
        v = b["snapshot_version"] or 1
        if self.side == "online":
            self.stub.route("GET", f"{self.p}/datasets/{b['dataset_id']}/snapshots/{v}/items", lambda req, ds=b["dataset_id"]: self.items(ds, req))
        self.stub.route("POST", f"{self.p}/experiments/{rid}/results", lambda req, rid=rid: self.post(rid, req))
        self.stub.route("POST", f"{self.p}/experiments/{rid}/finish", lambda req, rid=rid: self.finish(rid))
        self.stub.route("GET", f"{self.p}/experiments/{rid}", lambda req, rid=rid: self.get(rid))
        return 201, {"id": rid, "dataset_id": b["dataset_id"], "snapshot_version": v, "item_count": 0, "status": "running"}, {}

    def post(self, rid, req):
        if rid in self.finished:
            return 409, {"error": "run_finished", "message": "m"}, {}
        self.results[rid].extend(req["body"]["results"])
        return 200, {"accepted": len(req["body"]["results"]), "rejected": []}, {}

    def finish(self, rid):
        self.finished.add(rid)
        return 200, {}, {}

    def get(self, rid):
        # As the servers tally (contract 4.2): an unscored result (no scores,
        # no error) is neither passed nor failed. This fake answers an older
        # server's pass_rate 0 for "nothing scored", the harder case.
        rs = [r for r in self.results[rid] if r.get("error") or r.get("scores")]
        passed = sum(1 for r in rs if not r.get("error") and all(X.passes(s["value"]) for s in r["scores"]))
        return 200, {"api_version": "v1", "id": rid, "status": "done" if rid in self.finished else "running", "total": len(rs), "passed": passed, "pass_rate": passed / len(rs) if rs else 0.0}, {}


ITEMS = [
    {"item_id": "it_0", "client_id": "q1", "input": {"q": "2+2"}, "expected": "4", "has_content": True},
    {"item_id": "it_1", "client_id": "q2", "input": {"q": "3+3"}, "expected": "6", "has_content": True},
    {"item_id": "it_2", "client_id": "q3", "input": {"q": "?"}, "expected": None, "has_content": False},
]


def solve(input):
    return str(eval(input["q"]))  # noqa: S307 - test arithmetic


def exact_match(*, output, expected):
    return output == expected


exact_match.version = "2"


@pytest.fixture
def local_eval(stub):
    f = FakeEval(stub, "local")
    f.add("7", "golden", [dict(i) for i in ITEMS])
    mem = InMemorySpanExporter()
    sb.init(exporter=mem, node_url=stub.url)
    f.mem = mem
    return f


def test_runs_posts_finishes_and_reads_back(local_eval):
    res = sb.run_experiment("golden", solve, [exact_match], name="calc-v1", metadata={"git": "abc"})
    f = local_eval
    assert res.run_id == "run_local_1" and res.runs == {"local": "run_local_1"}
    assert res.skipped_no_content == 1 and len(res.items) == 2
    create = dict(f.runs["run_local_1"])
    # The create carries one idempotency id per call (E-79).
    assert isinstance(create.pop("id", None), str)
    assert create == {"name": "calc-v1", "dataset_id": "7", "snapshot_version": 0, "metadata": {"git": "abc"}, "scorers": [{"name": "exact_match", "version": "2"}]}
    posted = sorted(f.results["run_local_1"], key=lambda r: r["item_id"])
    assert [r["item_id"] for r in posted] == ["it_0", "it_1"]
    assert posted[0]["output"] == "4" and posted[0]["scores"] == [{"name": "exact_match", "value": True, "kind": "boolean", "scorer": {"name": "exact_match", "version": "2"}}]
    assert re.fullmatch(r"[0-9a-f]{32}", posted[0]["trace_id"])
    assert "run_local_1" in f.finished and res.pass_rate == 1.0
    assert res.summary["exact_match"] == {"count": 2, "passed": 2, "mean": 1.0}
    # each item is its own trace, tagged with the run and item
    assert sb.flush(5)
    spans = [s for s in f.mem.get_finished_spans() if s.name == "experiment calc-v1"]
    assert len({s.context.trace_id for s in spans}) == 2
    assert all(s.attributes["sbo.experiment.run_id"] == "run_local_1" and s.parent is None for s in spans)
    assert {s.attributes["sbo.experiment.item_id"] for s in spans} == {"it_0", "it_1"}


def test_task_failures_and_evaluator_shapes(local_eval):
    def task(input):
        if input["q"] == "3+3":
            raise RuntimeError("model down")
        return "4"

    class Judge:
        name = "LLM Judge"
        version = "5"

        def __call__(self, output, **kw):
            return [{"name": "tone", "value": "good", "comment": "polite"}, X.Evaluation("len", 0.2)]

    def broken(output):
        raise ValueError("bad evaluator")

    res = sb.run_experiment("golden", task, [Judge(), broken], max_concurrency=1)
    ok = next(i for i in res.items if i.item_id == "it_0")
    failed = next(i for i in res.items if i.item_id == "it_1")
    assert failed.error.startswith("RuntimeError") and failed.scores == [] and not failed.passed
    assert [s.name for s in ok.scores] == ["tone", "len"] and not ok.passed  # 0.2 < 0.5
    assert ok.evaluator_errors and "broken" in ok.evaluator_errors[0]
    rows = {r["item_id"]: r for r in local_eval.results[res.run_id]}
    assert rows["it_1"]["error"].startswith("RuntimeError") and "output" not in rows["it_1"]
    assert rows["it_0"]["scores"][0]["comment"] == "polite"


def test_async_task_and_evaluator(local_eval):
    async def task(input):
        await asyncio.sleep(0)
        return solve(input)

    async def ev(output, expected):
        return 1.0 if output == expected else 0.0

    res = sb.run_experiment("golden", task, [ev], max_concurrency=4)
    assert res.pass_rate == 1.0 and len(local_eval.results[res.run_id]) == 2


def test_fail_under_raises_systemexit(local_eval):
    with pytest.raises(sb.ExperimentGateFailed) as e:
        sb.run_experiment("golden", lambda input: "wrong", [exact_match], fail_under=0.9)
    assert e.value.code == 1 and e.value.result.pass_rate == 0.0 and isinstance(e.value, SystemExit)


def test_fail_under_is_not_applied_to_a_run_that_scored_nothing(local_eval):
    """R-C31: with strict=False, no evaluators means no scores, so the gate
    cannot fail the run."""
    res = sb.run_experiment("golden", solve, [], fail_under=0.9, strict=False)
    assert res.scored == 0 and res.pass_rate != res.pass_rate  # NaN: no rate
    assert any(e.startswith("no scores") for e in res.errors)
    assert all(r.get("scores") == [] for r in local_eval.results[res.run_id])


def test_literal_items_with_dataset_name(local_eval):
    data = [{"input": {"q": "1+1"}, "expected": "2"}, {"id": "mine", "input": {"q": "5"}, "expected": "5"}]
    res = sb.run_experiment(data, solve, [exact_match], dataset_name="adhoc")
    ds = [d for d in local_eval.datasets.values() if d["name"] == "adhoc"][0]
    # A default id is derived from the content (review E-75).
    assert [i["client_id"] for i in ds["items"]] == [X.literal_item_id({"q": "1+1"}, "2"), "mine"]
    assert res.pass_rate == 1.0 and len(local_eval.results[res.run_id]) == 2


def test_literal_items_in_process_only(stub):
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url)
    res = sb.run_experiment([1, 2, 3], lambda input: input * 2, [lambda output: output > 2])
    assert res.run_id == "" and stub.requests == []
    assert [i.output for i in sorted(res.items, key=lambda i: i.input)] == [2, 4, 6]
    assert abs(res.pass_rate - 2 / 3) < 1e-9


def test_dataset_not_found_raises(local_eval):
    with pytest.raises(sb.ExperimentError):
        sb.run_experiment("nope", solve)
    with pytest.raises(sb.ExperimentError):
        sb.get_dataset("nope")
    d = sb.get_dataset("golden")
    assert (d.id, d.name, d.side, d.item_count) == ("7", "golden", "local", 3)


def test_both_runs_once_posts_to_each_side(stub, stub2):
    loc = FakeEval(stub, "local")
    loc.add("7", "golden", [dict(i, item_id="L" + i["item_id"]) for i in ITEMS])
    org = FakeEval(stub2, "online")
    org.add("ds_1", "golden", [dict(i) for i in ITEMS])
    calls = []

    def task(input):
        calls.append(input)
        return solve(input)

    sb.init(destination="both", node_url=stub.url, org_url=stub2.url, api_key="ik.k", exporter={"local": InMemorySpanExporter(), "online": InMemorySpanExporter()})
    res = sb.run_experiment("golden", task, [exact_match])
    assert len(calls) == 2  # the task ran once per item
    assert set(res.runs) == {"online", "local"} and res.run_id.startswith("run_online")
    assert sorted(r["item_id"] for r in org.results[res.runs["online"]]) == ["it_0", "it_1"]
    assert sorted(r["item_id"] for r in loc.results[res.runs["local"]]) == ["Lit_0", "Lit_1"]
    gw = [r for r in stub2.requests if r["path"].startswith("/v1/sdk/experiments")]
    assert all(r["headers"]["Authorization"] == "Bearer ik.k" for r in gw)
    assert not any("Authorization" in r["headers"] for r in stub.requests)


SCOPE_REFUSED = {"error": "insufficient_scope", "message": "this credential lacks the sdk:eval scope"}


@pytest.mark.parametrize("dataset", ["golden", "literal"])
def test_org_scope_refusal_skips_the_org_and_runs_on_the_machine(stub, stub2, dataset):
    """R-B10: a member key (sign-in) has no sdk:eval, so every org dataset and
    experiment route answers 403 insufficient_scope. Under both, the org side
    is skipped with an entry in errors; the machine side runs in full."""
    loc = FakeEval(stub, "local")
    if dataset == "golden":
        loc.add("7", "golden", [dict(i, item_id="L" + i["item_id"]) for i in ITEMS])
    stub2.reply(SCOPE_REFUSED, status=403)
    sb.init(destination="both", node_url=stub.url, org_url=stub2.url, api_key="ik.member", exporter={"local": InMemorySpanExporter(), "online": InMemorySpanExporter()})
    if dataset == "golden":
        res = sb.run_experiment("golden", solve, [exact_match])
    else:  # literal items uploaded to a new machine dataset
        literal = [{"id": i["client_id"], "input": i["input"], "expected": i["expected"]} for i in ITEMS[:2]]
        res = sb.run_experiment(literal, solve, [exact_match], dataset_name="fresh")
    assert set(res.runs) == {"local"} and res.run_id.startswith("run_local")
    assert len(res.items) == 2 and loc.results[res.run_id] and loc.finished == {res.run_id}
    skips = [e for e in res.errors if e.startswith("online: skipped")]
    assert len(skips) == 1 and "insufficient_scope" in skips[0] and "sdk:eval" in skips[0], res.errors
    assert any(r["path"].startswith("/v1/sdk/datasets") for r in stub2.requests)
    assert not any(r["path"].startswith("/v1/sdk/experiments") for r in stub2.requests)


def test_org_scope_refusal_under_online_returns_an_empty_run(stub, stub2):
    """With only the org to run on, a scope refusal still never raises: the
    result says why nothing ran."""
    stub2.reply(SCOPE_REFUSED, status=403)
    sb.init(destination="online", org_url=stub2.url, api_key="ik.member", exporter=InMemorySpanExporter())
    res = sb.run_experiment("golden", solve, [exact_match])
    assert res.runs == {} and res.items == [] and res.run_id == ""
    assert len(res.errors) == 1 and res.errors[0].startswith("online: skipped") and "insufficient_scope" in res.errors[0]


def test_org_scope_refusal_on_experiment_create_keeps_the_machine(stub, stub2):
    """The org lists datasets (a key with sdk:read could) but refuses the
    run itself: still skipped, the machine still runs."""
    loc = FakeEval(stub, "local")
    loc.add("7", "golden", [dict(i, item_id="L" + i["item_id"]) for i in ITEMS])
    org = FakeEval(stub2, "online")
    org.add("ds_1", "golden", [dict(i) for i in ITEMS])
    stub2.route("POST", "/v1/sdk/experiments", SCOPE_REFUSED, status=403)
    sb.init(destination="both", node_url=stub.url, org_url=stub2.url, api_key="ik.member", exporter={"local": InMemorySpanExporter(), "online": InMemorySpanExporter()})
    res = sb.run_experiment("golden", solve, [exact_match])
    assert set(res.runs) == {"local"} and len(res.items) == 2
    assert [e for e in res.errors if e.startswith("online: skipped, experiment create refused")], res.errors


def test_posting_failure_is_reported_not_raised(local_eval, monkeypatch):
    orig = local_eval.post
    local_eval.post = lambda rid, req: (500, {"error": "boom", "message": "m"}, {})
    res = sb.run_experiment("golden", solve, [exact_match])
    assert any("posting" in e for e in res.errors)
    local_eval.post = orig


class TestStrictGate:
    """Review E-12 (ruling D29): with fail_under set, the gate is strict by
    default: nothing scored, a skipped destination or a result that was not
    accepted fails it (a SystemExit with code 1), even though every scored
    item passed. strict=False keeps the rate-only gate."""

    def test_nothing_scored(self, local_eval):
        with pytest.raises(sb.ExperimentGateFailed) as exc:
            sb.run_experiment("golden", solve, [], fail_under=0.9)
        assert exc.value.code == 1 and "no item was scored" in str(exc.value)

    def test_every_evaluator_raises(self, local_eval):
        def broken(output):
            raise RuntimeError("judge API down")

        with pytest.raises(sb.ExperimentGateFailed) as exc:
            sb.run_experiment("golden", solve, [broken], fail_under=0.9)
        assert "no item was scored" in str(exc.value)
        res = sb.run_experiment("golden", solve, [broken], fail_under=0.9, strict=False)
        assert res.scored == 0

    def test_a_skipped_side(self, stub, stub2):
        loc = FakeEval(stub, "local")
        loc.add("7", "golden", [dict(i, item_id="L" + i["item_id"]) for i in ITEMS])
        stub2.reply(SCOPE_REFUSED, status=403)
        sb.init(destination="both", node_url=stub.url, org_url=stub2.url, api_key="ik.member", exporter={"local": InMemorySpanExporter(), "online": InMemorySpanExporter()})
        with pytest.raises(sb.ExperimentGateFailed) as exc:
            sb.run_experiment("golden", solve, [exact_match], fail_under=0.9)
        assert exc.value.result.pass_rate == 1.0 and "the online destination was skipped" in str(exc.value)
        res = sb.run_experiment("golden", solve, [exact_match], fail_under=0.9, strict=False)
        assert res.skipped_sides == ["online"] and res.pass_rate == 1.0

    def test_online_only_skipped(self, stub2):
        stub2.reply(SCOPE_REFUSED, status=403)
        sb.init(destination="online", org_url=stub2.url, api_key="ik.member", exporter=InMemorySpanExporter())
        with pytest.raises(sb.ExperimentGateFailed):
            sb.run_experiment("golden", solve, [exact_match], fail_under=0.9)

    def test_failed_posts(self, local_eval):
        local_eval.post = lambda rid, req: (500, {"error": "boom", "message": "m"}, {})
        with pytest.raises(sb.ExperimentGateFailed) as exc:
            sb.run_experiment("golden", solve, [exact_match], fail_under=0.9)
        assert "not accepted" in str(exc.value) and exc.value.result.failed_posts == 2

    def test_a_clean_run_passes(self, local_eval):
        res = sb.run_experiment("golden", solve, [exact_match], fail_under=0.9)
        assert res.pass_rate == 1.0 and not res.skipped_sides and res.failed_posts == 0


def test_capture_off_omits_output(local_eval):
    sb.init(exporter=local_eval.mem, node_url=local_eval.stub.url, capture_content=False)
    res = sb.run_experiment("golden", solve, [exact_match])
    assert all("output" not in r for r in local_eval.results[res.run_id])
