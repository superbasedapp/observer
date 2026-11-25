"""The AI gateway helpers (hosted AI gateway arc, lane L8):
sdk/contract/ai-gateway-cases.json through the pure resolver and
parse_gateway_refusal(), and the client factories against a stub gateway."""

import json
import os

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _aigateway

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "ai-gateway-cases.json")


def _cases(section):
    if not os.path.exists(CASES):
        return []
    with open(CASES, encoding="utf-8") as f:
        return json.load(f)[section]


@pytest.mark.parametrize("case", _cases("base_url"), ids=lambda c: c["name"])
def test_base_url_case(case):
    asked = []

    def local():
        asked.append(True)
        return case["local"]

    ep, problem, message = _aigateway.resolve_endpoint(
        case["provider"],
        upstream=case["upstream"],
        url=case["url"],
        env=case["env"],
        destination=case["destination"],
        org_url=case["org_url"],
        local=local,
    )
    want = case["want"]
    if "problem" in want:
        assert ep is None and problem == want["problem"] and message, (ep, problem)
        return
    assert problem == "" and ep is not None, (problem, message)
    assert ep.base_url == want["url"] and ep.source == want["source"]
    assert ep.upstream_header == want.get("upstream_header", "")
    if case["destination"] == "online":
        assert not asked, "asked the machine under destination online"


def _check_refusal(got, want, name):
    if want is None:
        assert got is None, name
        return
    assert isinstance(got, sb.GatewayRefusalError), name
    assert (got.kind, got.code, got.status) == (want["kind"], want["code"], want["status"]), name
    assert got.message and str(got) == got.message, name
    if "message" in want:
        assert got.message == want["message"], name
    assert got.request_id == want.get("request_id", ""), name
    if "retry_after_seconds" in want:
        assert got.retry_after == want["retry_after_seconds"], name
    else:
        assert got.retry_after is None, name
    if "budget" in want:
        b = want["budget"]
        assert got.budget == sb.GatewayBudget(b["level"], b["scope_id"], b["unit"], b["remaining"], b["cap"], b["estimated"]), (name, got.budget)
    else:
        assert got.budget is None, name
    if "plan_refusal" in want:
        p, w = got.plan_refusal, want["plan_refusal"]
        assert isinstance(p, sb.PlanRefusalError), name
        assert (p.kind, p.code, p.upgrade_url, p.capability) == (w["kind"], w["code"], w["upgrade_url"], w["capability"]), name
    else:
        assert got.plan_refusal is None, name


@pytest.mark.parametrize("case", _cases("refusal"), ids=lambda c: c["name"])
def test_refusal_case(case):
    body = case["body"]
    _check_refusal(sb.parse_gateway_refusal(case["status"], body, case["headers"]), case["want"], case["name"])
    raw = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    _check_refusal(sb.parse_gateway_refusal(case["status"], raw, case["headers"]), case["want"], case["name"] + " (bytes)")


@pytest.mark.parametrize("case", _cases("api_key"), ids=lambda c: c["name"])
def test_api_key_case(case, monkeypatch):
    """The shared key rule (hosted AI gateway review L7), through the client
    factories' own rule: a provider's own key never reaches a remote gateway."""
    if case["gateway_key"] is None:
        monkeypatch.delenv(_aigateway.ENV_KEY, raising=False)
    else:
        monkeypatch.setenv(_aigateway.ENV_KEY, case["gateway_key"])
    ep = _aigateway.GatewayEndpoint(base_url=case["base_url"], source=case["source"])
    want = case["want"]
    if "problem" in want:
        with pytest.raises(_aigateway.GatewayNotConfigured) as err:
            _aigateway._client_key(ep, None)
        assert err.value.problem == want["problem"]
        return
    assert _aigateway._client_key(ep, None) == want["key"]


def test_contract_file_is_present_in_the_tree():
    if not os.path.isdir(os.path.join(os.path.dirname(__file__), "..", "..", "contract")):
        pytest.skip("sdk/contract is not present (an sdist)")
    assert len(_cases("base_url")) >= 20 and len(_cases("refusal")) >= 15


@pytest.mark.parametrize("junk", [None, 0, object(), b"\xff\xfe", "null", [], {"reason": 7}])
def test_parse_never_raises(junk):
    assert sb.parse_gateway_refusal(402, junk, None) is None
    assert sb.parse_gateway_refusal("402", {"reason": "budget_exceeded"}, None) is None


def test_online_resolves_the_organizations_address(monkeypatch):
    monkeypatch.setenv("SUPERBASED_DESTINATION", "online")
    monkeypatch.setenv("SUPERBASED_ORG_URL", "https://acme.superbased.app")
    monkeypatch.setenv("SUPERBASED_API_KEY", "ik_1.secret")
    assert sb.gateway_base_url("openai") == "https://acme.superbased.app/ai/openai/v1"
    ep = sb.gateway_endpoint("anthropic", "claude")
    assert (ep.base_url, ep.source, ep.upstream_header) == ("https://acme.superbased.app/ai/claude", "org", "")
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_URL", "https://ai.example.com")
    sb._reset_for_tests()
    ep = sb.gateway_endpoint("openai", "openai-eu")
    assert (ep.base_url, ep.source, ep.upstream_header) == ("https://ai.example.com/v1", "env", "openai-eu")
    assert sb.gateway_base_url("openai", url="https://arg.example.com") == "https://arg.example.com/v1"


def test_the_machine_lane_from_discovery(monkeypatch, stub):
    stub.route(
        "GET",
        "/api/sdk/destination",
        body={"api_version": 1, "destination": "local", "local": {"app_lanes": [{"id": "openai", "base_url": "http://127.0.0.1:8820/up/openai"}]}},
    )
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    monkeypatch.setenv("SUPERBASED_NODE_URL", stub.url)
    assert sb.gateway_base_url("openai") == "http://127.0.0.1:8820/up/openai/v1"
    with pytest.raises(sb.GatewayNotConfigured) as e:
        sb.gateway_base_url("anthropic")
    assert e.value.problem == "not_configured" and "observer apps lane add" in str(e.value)
    # Discovery is asked once per process.
    sb.gateway_base_url("openai")
    assert stub.paths("GET").count("/api/sdk/destination") == 1


def test_discovery_off_never_asks(monkeypatch, stub):
    monkeypatch.setenv("SUPERBASED_DESTINATION", "local")
    monkeypatch.setenv("SUPERBASED_NODE_URL", stub.url)
    with pytest.raises(sb.GatewayNotConfigured):
        sb.gateway_base_url("openai")
    assert stub.requests == []


def test_a_bad_address_raises(monkeypatch):
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_URL", "http://ai.example.com")
    with pytest.raises(sb.GatewayNotConfigured) as e:
        sb.gateway_base_url("openai")
    assert e.value.problem == "bad_url" and isinstance(e.value, ValueError)


def test_headers_carry_the_current_traceparent(monkeypatch):
    sb.init(destination="local", service_name="svc", exporter=InMemorySpanExporter())
    assert "traceparent" not in sb.gateway_headers()
    with sb.span("call") as sp:
        h = sb.gateway_headers()
        ctx = sp.get_span_context()
        assert h["traceparent"].startswith(f"00-{ctx.trace_id:032x}-{ctx.span_id:016x}-")


openai = pytest.importorskip("openai")


def _gateway(stub, status=200, body=None, headers=None):
    stub.reply(body if body is not None else {"id": "c1", "object": "chat.completion", "created": 1, "model": "m", "choices": []}, status, headers)


def test_openai_client_through_the_gateway(monkeypatch, stub):
    _gateway(stub, headers={"Content-Type": "application/json", "X-SBO-Request-Id": "gw-1"})
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider-must-not-leak")
    sb.init(destination="local", service_name="support-bot", user="u1", exporter=InMemorySpanExporter())
    client = sb.openai_client("openai-eu", url=stub.url)
    assert str(client.base_url).rstrip("/") == stub.url + "/v1"
    client.chat.completions.create(model="m", messages=[{"role": "user", "content": "hi"}])
    req = stub.requests[-1]
    h = {k.lower(): v for k, v in req["headers"].items()}
    assert req["path"] == "/v1/chat/completions"
    assert h["authorization"] == "Bearer sbo-vk-test"
    assert h["x-sbo-upstream"] == "openai-eu"
    assert h["x-superbased-service"] == "support-bot" and h["x-superbased-user"] == "u1"
    assert h["x-sbo-request-id"].startswith("sdk-")


def test_a_remote_gateway_without_a_gateway_key_never_gets_the_provider_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider-must-not-leak")
    with pytest.raises(sb.GatewayNotConfigured) as e:
        sb.openai_client(url="https://ai.example.com")
    assert e.value.problem == "no_key"


def test_the_machine_lane_keeps_the_provider_key(monkeypatch, stub):
    _gateway(stub, headers={"Content-Type": "application/json"})
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-not-for-the-lane")
    monkeypatch.setattr(
        _aigateway,
        "gateway_endpoint",
        lambda provider, upstream=None, url=None: sb.GatewayEndpoint(stub.url + "/up/openai/v1", "machine", "openai"),
    )
    client = sb.openai_client()
    client.chat.completions.create(model="m", messages=[])
    h = {k.lower(): v for k, v in stub.requests[-1]["headers"].items()}
    assert stub.requests[-1]["path"] == "/up/openai/v1/chat/completions"
    assert h["authorization"] == "Bearer sk-provider" and "x-sbo-upstream" not in h


def test_openai_refusal_reads_from_the_error(monkeypatch, stub):
    body = {
        "error": {"message": "model gpt-5 is not allowed", "type": "permission_error", "param": None, "code": "model_not_allowed"},
        "reason": "model_not_allowed",
    }
    _gateway(stub, 403, body, {"Content-Type": "application/json", "X-SBO-Request-Id": "gw-9", "x-request-id": "gw-9"})
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-test")
    client = sb.openai_client(url=stub.url, max_retries=0)
    with pytest.raises(openai.APIStatusError) as e:
        client.chat.completions.create(model="gpt-5", messages=[])
    r = sb.gateway_refusal(e.value)
    assert r is not None and r.kind == "model_not_allowed" and r.request_id == "gw-9"
    assert sb.gateway_refusal(ValueError("x")) is None


def test_a_redirect_is_not_followed(monkeypatch, stub):
    stub.reply(b"", 307, {"Location": "https://elsewhere.example.com/v1/chat/completions"})
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-test")
    client = sb.openai_client(url=stub.url, max_retries=0)
    with pytest.raises(openai.APIStatusError):
        client.chat.completions.create(model="m", messages=[])
    assert len(stub.requests) == 1


def test_a_callers_http_client_gets_the_hook(monkeypatch, stub):
    _gateway(stub, headers={"Content-Type": "application/json"})
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-test")
    mine = openai.DefaultHttpxClient()
    client = sb.openai_client(url=stub.url, http_client=mine)
    client.chat.completions.create(model="m", messages=[])
    assert {k.lower() for k in stub.requests[-1]["headers"]} >= {"x-sbo-request-id"}


def test_async_openai_client(monkeypatch, stub):
    import asyncio

    _gateway(stub, headers={"Content-Type": "application/json"})
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-test")
    client = sb.openai_client(url=stub.url, async_client=True)
    assert isinstance(client, openai.AsyncOpenAI)

    async def go():
        await client.chat.completions.create(model="m", messages=[])

    asyncio.run(go())
    assert stub.requests[-1]["headers"].get("X-SBO-Request-Id", "").startswith("sdk-")


def test_anthropic_client_through_the_gateway(monkeypatch, stub):
    anthropic = pytest.importorskip("anthropic")
    stub.reply(
        {"id": "m1", "type": "message", "role": "assistant", "model": "m", "content": [], "stop_reason": "end_turn", "usage": {"input_tokens": 1, "output_tokens": 1}},
        200,
        {"Content-Type": "application/json"},
    )
    monkeypatch.setenv("SUPERBASED_AI_GATEWAY_KEY", "sbo-vk-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-must-not-leak")
    client = sb.anthropic_client(url=stub.url)
    assert isinstance(client, anthropic.Anthropic)
    client.messages.create(model="m", max_tokens=8, messages=[{"role": "user", "content": "hi"}])
    req = stub.requests[-1]
    h = {k.lower(): v for k, v in req["headers"].items()}
    # The gateway reads the key from either header; client versions differ.
    assert req["path"] == "/v1/messages"
    assert h.get("x-api-key") == "sbo-vk-test" or h.get("authorization") == "Bearer sbo-vk-test"
    assert "sk-ant-must-not-leak" not in json.dumps(h)
