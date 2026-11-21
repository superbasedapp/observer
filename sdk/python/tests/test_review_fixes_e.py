"""End-to-end review fixes owned by lane E4 (review
docs/plans/plane-a-sdk-buildout/reviews/e2e-fable-review-2026-11-20.md):
E-31 (pending spans under ``both``), E-39 (admit fails open, but says so),
E-75 (experiment item ids), E-76 (admit with an explicit org_url) and E-77
(the sync experiment runner inside a running event loop)."""

import threading

from opentelemetry.sdk.trace.export import SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb


class _Held:
    """An exporter that holds its first export until released."""

    def __init__(self):
        self.release = threading.Event()
        self.entered = threading.Event()

    def export(self, spans):
        self.entered.set()
        self.release.wait(5)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        self.release.set()

    def force_flush(self, timeout_millis=30000):
        return True


# --- E-31 ------------------------------------------------------------------------------


def test_e31_pending_counts_each_destination(monkeypatch):
    """A span handed to both destinations is pending until BOTH exported it:
    one exported copy must not read as nothing pending."""
    monkeypatch.setenv("SUPERBASED_ORG_URL", "https://gw.example")
    monkeypatch.setenv("SUPERBASED_API_KEY", "ik.k")
    local, online = InMemorySpanExporter(), _Held()
    sb.init(destination="both", exporter={"local": local, "online": online})
    with sb.span("tail"):
        pass
    # The local copy goes out; the online copy is still held.
    sb._PROCESSOR.delegate._procs[0].force_flush()
    assert [s.name for s in local.get_finished_spans()] == ["tail"]
    assert sb.diagnostics()["pending_spans"] == 1
    online.release.set()
    assert sb.flush(5)
    assert sb.diagnostics()["pending_spans"] == 0
    assert sb.diagnostics()["exported_spans"] == 2


def test_e31_single_destination_counts_once(mem):
    sb.init(exporter=mem, destination="local")
    with sb.span("one"):
        pass
    assert sb.flush(5)
    d = sb.diagnostics()
    assert d["pending_spans"] == 0 and d["exported_spans"] == 1


# --- E-38 ------------------------------------------------------------------------------


def test_e38_bad_env_sampling_is_ignored_and_said(monkeypatch, mem, caplog):
    monkeypatch.setenv("OTEL_TRACES_SAMPLER", "traceidratio")
    monkeypatch.setenv("OTEL_TRACES_SAMPLER_ARG", "5")
    with caplog.at_level("WARNING", logger="superbased_sdk"):
        s = sb.init(exporter=mem, destination="local")
    assert s.sample_rate == 1.0 and s.sample_parent_based is False
    w = sb.diagnostics()["warnings"]
    assert any("OTEL_TRACES_SAMPLER_ARG='5' is not a number in 0..1; ignored" in x for x in w), w
    assert any("OTEL_TRACES_SAMPLER_ARG" in r.getMessage() for r in caplog.records)


def test_e38_explicit_bad_rate_still_raises(mem):
    import pytest

    with pytest.raises(ValueError):
        sb.init(exporter=mem, sample_rate=1.5)


# --- E-39 ------------------------------------------------------------------------------


def test_e39_admit_fails_open_but_says_so(stub, caplog):
    stub.reply({"error": "not found"}, status=404)
    with caplog.at_level("WARNING", logger="superbased_sdk"):
        v1 = sb.admit("hi", endpoint=stub.url + "/check")
        v2 = sb.admit("again", endpoint=stub.url + "/check")
    assert v1.allowed and v2.allowed, "fail open is the contract"
    assert v1.degraded == "admission-unavailable"
    lines = [r.getMessage() for r in caplog.records if "admit()" in r.getMessage()]
    assert len(lines) == 1, "one warning per cause per minute"
    assert "HTTP 404" in lines[0] and "admitted (fail open)" in lines[0] and "Fix:" in lines[0]
    d = sb.diagnostics()
    assert d["admission_degraded"] == 2
    assert "HTTP 404" in d["admission_last_error"]


def test_e39_each_cause_warns_and_key_never_logged(stub, dead_url, caplog):
    stub.reply({}, status=401)
    with caplog.at_level("WARNING", logger="superbased_sdk"):
        sb.admit("hi", endpoint=stub.url + "/check", api_key="ik_secret.s")
        sb.admit("hi", endpoint=dead_url + "/check", timeout=0.5)
    text = "\n".join(r.getMessage() for r in caplog.records)
    assert "HTTP 401" in text and "SDK key was refused" in text
    assert "client-transport" in text
    assert "ik_secret" not in text


def test_e39_a_clean_decision_is_not_counted(stub):
    stub.reply({"allowed": True, "decision": "allow"})
    assert sb.admit("hi", endpoint=stub.url + "/check").degraded == ""
    assert sb.diagnostics()["admission_degraded"] == 0


# --- E-76 ------------------------------------------------------------------------------


def test_e76_explicit_org_url_sends_the_init_key(stub, mem):
    stub.reply({"allowed": True, "decision": "allow"})
    sb.init(exporter=mem, destination="local", api_key="ik_init.s")
    sb.admit("hi", org_url=stub.url)
    req = stub.requests[-1]
    assert req["path"] == "/v1/sdk/admit"
    assert req["headers"].get("Authorization") == "Bearer ik_init.s"


# --- E-75 ------------------------------------------------------------------------------


class _Machine:
    """The machine's eval routes as the Go server answers them: a literal
    upload is deduplicated by client id (a duplicate answers its EXISTING
    item), the upload answers ``item_ids``, a run created with ``item_ids``
    is pinned to them, and ``GET .../items?run=`` reads a run's own items."""

    def __init__(self, stub):
        self.items = []  # {"item_id", "client_id", "input", "expected"}
        self.runs = {}
        self.results = {}
        p = "/api/obs/eval"
        stub.route("GET", p + "/datasets", lambda r: (200, {"datasets": [{"id": "9", "name": "adhoc", "item_count": len(self.items)}]}, {}))
        stub.route("POST", p + "/datasets", lambda r: (200, {"id": "9", "name": "adhoc"}, {}))
        stub.route("POST", p + "/datasets/9/items", self.upload)
        stub.route("GET", p + "/datasets/9/items", self.read)
        stub.route("POST", p + "/experiments", self.create)
        self.stub = stub

    def upload(self, req):
        ids = []
        for it in req["body"]["items"]:
            hit = next((x for x in self.items if x["client_id"] == it["id"]), None)
            if hit is None:
                hit = {"item_id": str(len(self.items) + 1), "client_id": it["id"], "input": it["input"], "expected": it["expected"], "has_content": True}
                self.items.append(hit)
            ids.append(hit["item_id"])
        return 200, {"version": len(self.items), "item_ids": ids}, {}

    def read(self, req):
        q = dict(kv.split("=", 1) for kv in req["path"].split("?", 1)[1].split("&") if "=" in kv) if "?" in req["path"] else {}
        pinned = self.runs.get(q.get("run", ""), {}).get("item_ids")
        out = [x for x in self.items if pinned is None or x["item_id"] in pinned]
        return 200, {"items": out, "next_cursor": ""}, {}

    def create(self, req):
        rid = str(100 + len(self.runs))
        self.runs[rid] = req["body"]
        self.results[rid] = []
        p = "/api/obs/eval/experiments/" + rid
        self.stub.route("POST", p + "/results", lambda r, rid=rid: (self.results[rid].extend(r["body"]["results"]) or (200, {"accepted": 1, "rejected": []}, {})))
        self.stub.route("POST", p + "/finish", lambda r: (200, {}, {}))
        self.stub.route("GET", p, lambda r: (200, {"id": rid, "total": 0}, {}))
        return 201, {"id": rid, "snapshot_version": len(self.items)}, {}


def test_e75_a_literal_rerun_with_changed_inputs_runs_the_new_inputs(stub):
    machine = _Machine(stub)
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
    seen = []

    def task(input):
        seen.append(input)
        return input

    sb.run_experiment([{"input": "old-a"}, {"input": "old-b"}], task, dataset_name="adhoc")
    seen.clear()
    res = sb.run_experiment([{"input": "new-a"}, {"input": "new-b"}], task, dataset_name="adhoc")
    assert sorted(seen) == ["new-a", "new-b"], "the task ran the new inputs, not the stored old ones"
    create = machine.runs[res.run_id]
    assert len(create["item_ids"]) == 2, "the run is pinned to this upload's items"
    posted = {r["item_id"] for r in machine.results[res.run_id]}
    assert posted == set(create["item_ids"]), "results go to the new items"
    # The same content again is the same items (no duplicates on the machine).
    before = len(machine.items)
    sb.run_experiment([{"input": "new-a"}, {"input": "new-b"}], task, dataset_name="adhoc")
    assert len(machine.items) == before


def test_e75_default_ids_are_content_derived_and_repeats_differ():
    from superbased_sdk import _experiments as X

    rows = X._literal([{"input": 1}, {"input": 1}, {"input": 2, "id": "mine"}])
    assert rows[0]["id"] == X.literal_item_id(1) and rows[1]["id"] == rows[0]["id"] + "-2"
    assert rows[2]["id"] == "mine"
    assert X.literal_item_id({"b": 1.0, "a": [True, None]}) == X.literal_item_id({"a": [True, None], "b": 1})


# --- E-77 ------------------------------------------------------------------------------


def test_e77_sync_run_experiment_inside_a_running_loop(mem):
    import asyncio

    sb.init(exporter=mem, destination="local")

    async def task(input):
        with sb.span("inner"):
            await asyncio.sleep(0)
        return input * 2

    async def evaluator(output):
        return output > 0

    async def main():
        # One item and max_concurrency=1 used to run asyncio.run() on the
        # loop's own thread: every item errored.
        return sb.run_experiment([3], task, [evaluator], max_concurrency=1)

    res = asyncio.run(main())
    assert [i.error for i in res.items] == [""], res.items
    assert [i.evaluator_errors for i in res.items] == [[]]
    assert [i.output for i in res.items] == [6]
    assert res.pass_rate == 1.0
    sb.flush(5)
    spans = {s.name: s for s in mem.get_finished_spans()}
    inner, item = spans["inner"], [s for s in spans.values() if s.name.startswith("experiment ")][0]
    assert inner.parent is not None and inner.parent.span_id == item.context.span_id, "the task's span stays under the item"
