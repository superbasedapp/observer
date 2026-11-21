"""W4-2: get_trace_cost() and the gateway request-id stamp, to
contracts/cost-source.md (the TraceCost fixture is
sdk/contract/trace-cost-response.json)."""

import asyncio
import json
import os

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _cost, _gatewayid

TID = "4bf92f3577b34da6a3ce929d0e0e4736"
FIXTURE = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "trace-cost-response.json")


@pytest.fixture
def fx():
    if not os.path.exists(FIXTURE):
        pytest.skip("sdk/contract is not present (an sdist)")
    with open(FIXTURE, encoding="utf-8") as f:
        return json.load(f)


def test_cost_source_values_match_the_contract(fx):
    assert list(_cost.COST_SOURCES) == fx["cost_source_values"]
    assert _cost.LABELS == fx["cost_source_labels"]
    assert _cost.is_exact("gateway_exact") and _cost.is_exact("proxy_exact")
    assert not _cost.is_exact("computed") and not _cost.is_exact("reported") and not _cost.is_exact("")


def test_local_reads_the_machine_trace_detail(stub, fx):
    stub.route("GET", f"/api/obs/trace/{TID}", body=fx["machine"]["body"])
    sb.init(exporter=InMemorySpanExporter(), destination="local", node_url=stub.url, discover=False)
    cost = sb.get_trace_cost(TID.upper())
    assert cost["destination"] == "local"
    assert cost["cost_provenance"]["label"] == "proxy_exact"
    assert cost["spans"][0]["cost_source"] == "proxy_exact"
    assert stub.paths("GET") == [f"/api/obs/trace/{TID}"]
    assert "Authorization" not in stub.requests[-1]["headers"]


def test_online_reads_the_org_route_with_the_credential(stub, fx):
    stub.route("GET", f"/v1/sdk/traces/{TID}/cost", body=fx["org"]["body"])
    sb.init(exporter=InMemorySpanExporter(), destination="online", org_url=stub.url, api_key="ik_1.secret", discover=False)
    cost = sb.get_trace_cost(TID)
    assert cost["destination"] == "online" and cost["api_version"] == "v1"
    exact = cost["spans"][0]
    assert exact["cost_source"] == "gateway_exact" and exact["cost_delta_usd"] == pytest.approx(0.0023)
    assert cost["spans"][2]["cost_source"] == "" and cost["spans"][2]["cost_usd"] is None  # unpriced: never $0
    h = {k.lower(): v for k, v in stub.requests[-1]["headers"].items()}
    assert h["authorization"] == "Bearer ik_1.secret" and h["x-sbo-sdk-api-version"] == "1"


def test_both_reads_the_org_then_the_machine(stub, stub2, fx):
    stub.route("GET", f"/v1/sdk/traces/{TID}/cost", body=fx["not_found"]["body"], status=404)
    stub2.route("GET", f"/api/obs/trace/{TID}", body=fx["machine"]["body"])
    sb.init(exporter=InMemorySpanExporter(), destination="both", org_url=stub.url, api_key="k", node_url=stub2.url, discover=False)
    cost = sb.get_trace_cost(TID)
    assert cost["destination"] == "local"
    assert stub.paths() == [f"/v1/sdk/traces/{TID}/cost"] and stub2.paths() == [f"/api/obs/trace/{TID}"]


def test_not_found_and_older_servers_are_none(stub, fx):
    sb.init(exporter=InMemorySpanExporter(), destination="local", node_url=stub.url, discover=False)
    stub.route("GET", f"/api/obs/trace/{TID}", body=fx["not_found"]["body"], status=404)
    assert sb.get_trace_cost(TID) is None
    stub.route("GET", f"/api/obs/trace/{TID}", body={"trace": {"trace_id": TID}})  # a machine from before W4-2
    assert sb.get_trace_cost(TID) is None
    stub.route("GET", f"/api/obs/trace/{TID}", body={"error": "boom"}, status=500)
    assert sb.get_trace_cost(TID) is None


def test_default_trace_and_bad_ids(stub, fx):
    stub.route("GET", "/api/obs/trace/" + "0" * 31 + "1", body=fx["machine"]["body"])
    sb.init(exporter=InMemorySpanExporter(), destination="local", node_url=stub.url, discover=False)
    assert sb.get_trace_cost() is None  # no current trace: nothing asked
    assert stub.requests == []
    with pytest.raises(ValueError):
        sb.get_trace_cost("xyz")
    with pytest.raises(ValueError):
        sb.get_trace_cost("0" * 32)
    with sb.span("req"):
        tid = sb.get_current_trace_id()
        stub.route("GET", f"/api/obs/trace/{tid}", body=fx["machine"]["body"])
        assert sb.get_trace_cost()["destination"] == "local"
        assert asyncio.run(sb.async_get_trace_cost(tid))["destination"] == "local"


def test_degraded_online_reads_nothing(stub):
    sb.init(exporter=InMemorySpanExporter(), destination="online", node_url=stub.url, discover=False)
    assert sb.get_trace_cost(TID) is None
    assert stub.requests == []


# --- the gateway request-id stamp ------------------------------------------------------


def _httpx_or_skip():
    return pytest.importorskip("httpx")


def _gateway_client(httpx, header="gw-req-1"):
    def handler(request):
        headers = {"X-SBO-Request-Id": header} if header else {}
        return httpx.Response(200, json={"ok": True}, headers=headers)

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_stamp_sets_request_id_on_the_active_span(mem):
    httpx = _httpx_or_skip()
    sb.init(exporter=mem)
    assert "httpx.Client.send" in _gatewayid.installed()
    with sb.llm_span("chat", model="gpt-4o-mini"):
        _gateway_client(httpx).get("http://gateway.invalid/v1/chat/completions")
    with sb.llm_span("not-the-gateway"):
        _gateway_client(httpx, header="").get("http://api.invalid/v1/chat/completions")
    with sb.llm_span("already") as sp:
        sb.set_usage(sp, request_id="mine")
        _gateway_client(httpx).get("http://gateway.invalid/v1/chat/completions")
    assert sb.flush(5)
    spans = {s.name: s for s in mem.get_finished_spans()}
    assert spans["chat"].attributes["request_id"] == "gw-req-1"
    assert "request_id" not in spans["not-the-gateway"].attributes
    assert spans["already"].attributes["request_id"] == "mine"  # never overwritten


def test_stamp_async_client(mem):
    httpx = _httpx_or_skip()
    sb.init(exporter=mem)

    async def main():
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, headers={"x-sbo-request-id": "gw-async"})))
        with sb.llm_span("chat"):
            await client.get("http://gateway.invalid/v1/messages")

    asyncio.run(main())
    assert sb.flush(5)
    assert mem.get_finished_spans()[0].attributes["request_id"] == "gw-async"


def test_stamp_reaches_an_instrumentor_llm_span(mem):
    from superbased_sdk import _instrument

    if not _instrument.available()["openai"]:
        pytest.skip("openai instrumentor not installed")
    openai = pytest.importorskip("openai")
    import openai._base_client as base

    hx = getattr(base, "httpx2", None) or base.httpx

    def handler(request):
        return hx.Response(
            200,
            headers={"X-SBO-Request-Id": "gw-openai"},
            json={
                "id": "chatcmpl-gw",
                "object": "chat.completion",
                "created": 1763510400,
                "model": "gpt-4o-mini",
                "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
            },
        )

    sb.init(exporter=mem)
    assert sb.instrument(["openai"])["openai"] == _instrument.INSTRUMENTED
    try:
        client = openai.OpenAI(api_key="sk-fixture", base_url="http://gateway.invalid/v1", http_client=hx.Client(transport=hx.MockTransport(handler)))
        client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
    finally:
        sb.uninstrument(["openai"])
    assert sb.flush(5)
    chat = next(s for s in mem.get_finished_spans() if s.name == "ChatCompletion")
    assert chat.attributes["request_id"] == "gw-openai"


def test_stamp_off_restores_the_clients(mem, monkeypatch):
    httpx = _httpx_or_skip()
    original = _gatewayid._patched.get(("httpx", "Client", "send")) or httpx.Client.send
    monkeypatch.setenv("SUPERBASED_GATEWAY_REQUEST_ID", "0")
    sb.init(exporter=mem)
    assert _gatewayid.installed() == [] and httpx.Client.send is original
    with sb.llm_span("chat"):
        _gateway_client(httpx).get("http://gateway.invalid/v1/chat/completions")
    assert sb.flush(5)
    assert "request_id" not in mem.get_finished_spans()[0].attributes


def test_stamp_never_breaks_the_call():
    class Bad:
        def get(self, k):
            raise RuntimeError("weird headers")

    assert _gatewayid.stamp(Bad()) is False
    assert _gatewayid.stamp(None) is False


def test_stamp_reaches_openai_agents_generation_spans(mem, monkeypatch):
    from superbased_sdk import _instrument

    if not _instrument.available()["openai-agents"]:
        pytest.skip("openai-agents not installed")
    import openai._base_client as base

    import test_instrument as T

    hx = getattr(base, "httpx2", None) or base.httpx
    real = hx.Response

    class WithHeader(real):  # the gateway's answer: every response carries its id
        def __init__(self, *a, **kw):
            headers = dict(kw.pop("headers", None) or {})
            headers["X-SBO-Request-Id"] = "gw-agents"
            super().__init__(*a, headers=headers, **kw)

    monkeypatch.setattr(hx, "Response", WithHeader)
    sb.init(exporter=mem)
    assert sb.instrument(["openai-agents"])["openai-agents"] == _instrument.INSTRUMENTED
    try:
        T.scenario_openai_agents()
    finally:
        sb.uninstrument(["openai-agents"])
    assert sb.flush(5)
    gens = [s for s in mem.get_finished_spans() if s.name == "generation"]
    assert len(gens) == 2 and all(s.attributes.get("request_id") == "gw-agents" for s in gens)
    assert all("request_id" not in s.attributes for s in mem.get_finished_spans() if s.name != "generation")


def test_stamp_gateway_request_id_helper(mem):
    httpx = _httpx_or_skip()
    sb.init(exporter=mem, gateway_request_id=False)  # the helper works without the wrapper
    resp = _gateway_client(httpx, header="gw-manual").get("http://gateway.invalid/v1/x")
    with sb.llm_span("chat") as sp:
        assert sb.stamp_gateway_request_id(resp) is True
        assert sb.stamp_gateway_request_id(resp) is False  # already stamped
    with sb.llm_span("explicit") as sp2:
        pass
    assert sb.stamp_gateway_request_id({"X-SBO-Request-Id": "late"}, span=sp2) is False  # ended: not recording
    assert sb.stamp_gateway_request_id(object()) is False
    with sb.llm_span("plain-dict"):
        assert sb.stamp_gateway_request_id({"X-SBO-Request-Id": "gw-dict"}) is True
    assert sb.flush(5)
    assert {s.name: s.attributes.get("request_id") for s in mem.get_finished_spans()} == {"chat": "gw-manual", "explicit": None, "plain-dict": "gw-dict"}
