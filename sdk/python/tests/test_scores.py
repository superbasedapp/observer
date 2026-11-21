"""W3-1: score() / feedback() to contracts/scores.md."""

import asyncio
import json
import math

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _scores

TID = "4bf92f3577b34da6a3ce929d0e0e4736"


def accept_all(req):
    body = req["body"]
    items = body["scores"] if "scores" in body else [body]
    return 200, {"api_version": "v1", "accepted": [{"index": i, "id": f"sc_{i:024x}", "client_id": s["id"]} for i, s in enumerate(items)], "rejected": []}, {}


@pytest.fixture
def local(stub, monkeypatch):
    stub.route("POST", "/api/obs/scores", accept_all)
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url)
    return stub


@pytest.mark.parametrize(
    "value,kind",
    [(0.8, "numeric"), (3, "numeric"), (True, "boolean"), (False, "boolean"), ("good", "categorical")],
)
def test_kind_is_inferred(value, kind):
    assert _scores.build_score("q", value, trace_id=TID)["kind"] == kind


@pytest.mark.parametrize(
    "kw,code",
    [
        (dict(name="Bad Name!", value=1), "invalid_name"),
        (dict(name="x" * 65, value=1), "invalid_name"),
        (dict(name="q", value=math.nan), "invalid_value"),
        (dict(name="q", value=float("inf")), "invalid_value"),
        (dict(name="q", value="two\nlines"), "invalid_value"),
        (dict(name="q", value="x" * 121), "invalid_value"),
        (dict(name="q", value=[1]), "invalid_value"),
        (dict(name="q", value=1, kind="boolean"), "kind_mismatch"),
        (dict(name="q", value=1, kind="stars"), "kind_mismatch"),
        (dict(name="q", value=1, trace_id="0" * 32), "invalid_trace_id"),
        (dict(name="q", value=1, trace_id="xyz"), "invalid_trace_id"),
        (dict(name="q", value=1, span_id="123"), "invalid_span_id"),
        (dict(name="q", value=1, comment="c" * 2001), "comment_too_long"),
        (dict(name="q", value=1, score_id="has space"), "invalid_id"),
        (dict(name="q", value=1, source="llm"), "invalid_source"),
    ],
)
def test_refused_like_scorecore(kw, code):
    kw.setdefault("trace_id", TID)
    with pytest.raises(_scores.ScoreError) as e:
        _scores.build_score(**kw)
    assert e.value.code == code


def test_wire_object():
    o = _scores.build_score("Helpfulness", 0.8, trace_id=TID.upper(), span_id="00F067AA0BA902B7", comment="c", scorer="judge", scorer_version="3", run_id="run_1", score_id="abc")
    assert o == {
        "id": "abc", "trace_id": TID, "span_id": "00f067aa0ba902b7", "name": "helpfulness", "value": 0.8, "kind": "numeric",
        "source": "sdk", "comment": "c", "scorer": {"name": "judge", "version": "3"}, "run_id": "run_1",
    }


def test_score_defaults_to_current_trace_and_posts_locally(local):
    with sb.span("req") as sp:
        res = sb.score("accuracy", 1.0, span_id=sb.get_current_span_id())
        tid = sb.get_current_trace_id()
    assert res.ok and res.id == "sc_" + "0" * 24 and res.client_id.startswith("sdk_")
    r = local.requests[-1]
    assert r["path"] == "/api/obs/scores" and r["body"]["trace_id"] == tid and r["body"]["source"] == "sdk"
    assert r["body"]["span_id"] == format(sp.get_span_context().span_id, "016x")
    assert "Authorization" not in r["headers"]


def test_feedback_is_its_own_row(local):
    a = sb.feedback(True, trace_id=TID, comment="great")
    b = sb.feedback(True, trace_id=TID)
    assert a.ok and b.ok and a.client_id != b.client_id
    body = local.requests[-2]["body"]
    assert body["source"] == "feedback" and body["name"] == "user_feedback" and body["kind"] == "boolean"


def test_no_trace_is_reported_not_raised(local):
    res = sb.score("q", 1)
    assert not res.ok and "invalid_trace_id" in res.errors[0]
    assert local.requests == []


def test_rejection_and_transport_failure_are_reported(stub, dead_url):
    stub.route("POST", "/api/obs/scores", status=400, body={"api_version": "v1", "accepted": [], "rejected": [{"index": 0, "error": "invalid_value", "message": "nope"}]})
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url)
    res = sb.score("q", 1, trace_id=TID)
    assert not res.ok and res.destinations["local"]["status"] == 400 and "invalid_value" in res.errors[0]
    sb.init(exporter=InMemorySpanExporter(), node_url=dead_url, api_timeout=0.5)
    res = sb.score("q", 1, trace_id=TID)
    assert not res.ok and res.destinations["local"]["status"] == 0


def test_both_writes_the_same_id_to_each_side(stub, stub2):
    stub.route("POST", "/api/obs/scores", accept_all)
    stub2.route("POST", "/v1/sdk/scores", accept_all)
    sb.init(destination="both", node_url=stub.url, org_url=stub2.url, api_key="ik.k", exporter={"local": InMemorySpanExporter(), "online": InMemorySpanExporter()})
    res = sb.score("q", "good", trace_id=TID, score_id="fixed-1")
    assert res.ok and set(res.destinations) == {"online", "local"}
    org = stub2.requests[-1]
    assert org["headers"]["Authorization"] == "Bearer ik.k" and org["headers"]["X-Sbo-Sdk-Api-Version"] == "1"
    assert org["body"]["id"] == stub.requests[-1]["body"]["id"] == "fixed-1"
    assert "Authorization" not in stub.requests[-1]["headers"]


def test_online_only(stub2):
    stub2.route("POST", "/v1/sdk/scores", accept_all)
    sb.init(destination="online", org_url=stub2.url, api_key="ik.k", exporter=InMemorySpanExporter())
    assert sb.score("q", 2, trace_id=TID).destinations.keys() == {"online"}


def test_async_score_keeps_the_trace(local):
    async def handler():
        with sb.span("req"):
            tid = sb.get_current_trace_id()
            res = await sb.async_score("latency_ok", True)
        return tid, res

    tid, res = asyncio.run(handler())
    assert res.ok and local.requests[-1]["body"]["trace_id"] == tid
    res = asyncio.run(sb.async_feedback(4, trace_id=TID))
    assert res.ok and local.requests[-1]["body"]["value"] == 4


def test_batch_post_maps_each_index(stub):
    def half(req):
        return 200, {"accepted": [{"index": 0, "id": "sc_a"}], "rejected": [{"index": 1, "error": "invalid_value", "message": "m"}]}, {}

    stub.route("POST", "/api/obs/scores", half)
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url)
    a, b = _scores.post_scores([_scores.build_score("a", 1, trace_id=TID), _scores.build_score("b", 2, trace_id=TID)])
    assert a.ok and a.id == "sc_a" and not b.ok
    assert "scores" in stub.requests[-1]["body"]


def test_a_5xx_is_retried_once_with_the_same_id(stub):
    """R-C34: as the TypeScript SDK, one retry on no answer / 429 / 5xx; the id
    makes the repeat a no-op on the server."""
    answers = [(503, {"error": "unavailable"}, {}), (200, {"accepted": [{"index": 0, "id": "sc_1"}], "rejected": []}, {})]
    stub.route("POST", "/api/obs/scores", lambda req: answers.pop(0) if answers else (500, {}, {}))
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
    res = sb.score("accuracy", 1.0, trace_id=TID)
    posts = [r for r in stub.requests if r["path"] == "/api/obs/scores"]
    assert res.ok and res.id == "sc_1" and len(posts) == 2
    assert posts[0]["body"]["id"] == posts[1]["body"]["id"]
    stub.route("POST", "/api/obs/scores", lambda req: (400, {"error": "invalid"}, {}))
    n = len(stub.requests)
    assert not sb.score("accuracy", 1.0, trace_id=TID).ok and len(stub.requests) == n + 1, "a 4xx is not retried"
