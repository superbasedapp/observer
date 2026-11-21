"""Review E-64 (ruling D29): the Python SDK sends the AI gateway's app
identity headers, at parity with the TypeScript SDK's gatewayFetch()."""

import asyncio

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("SUPERBASED_DISCOVER", "0")
    sb.init(destination="local", service_name="support-bot", user="init-user", exporter=InMemorySpanExporter())


def test_headers_name_the_request_user_and_the_service(app):
    h = sb.gateway_headers()
    assert h["X-Superbased-User"] == "init-user"
    assert h["X-Superbased-Service"] == "support-bot"
    assert h["X-SBO-Request-Id"].startswith("sdk-")
    with sb.propagate_attributes(user="alice"):
        assert sb.gateway_headers()["X-Superbased-User"] == "alice"


def test_values_the_clients_cannot_send_are_left_out(app):
    for bad in ("", "zoë", "a\nb"):
        with sb.propagate_attributes(user=bad):
            got = sb.gateway_headers().get("X-Superbased-User")
            assert got in (None, "init-user"), (bad, got)
    from superbased_sdk._gatewayid import _app_value

    assert _app_value("x" * 513) == "" and _app_value("x" * 512) == "x" * 512


class FakeRequest:
    def __init__(self, headers):
        self.headers = headers


def test_the_hooks_keep_a_header_the_request_already_has(app):
    req = FakeRequest({"x-superbased-user": "explicit", "X-SBO-Request-Id": "mine"})
    sb.gateway_event_hooks()["request"][0](req)
    assert req.headers["x-superbased-user"] == "explicit" and req.headers["X-SBO-Request-Id"] == "mine"
    assert "X-Superbased-User" not in req.headers and req.headers["X-Superbased-Service"] == "support-bot"
    req2 = FakeRequest({})
    asyncio.run(sb.async_gateway_event_hooks()["request"][0](req2))
    assert req2.headers["X-Superbased-User"] == "init-user"


def test_requests_auth_wraps_the_sessions_auth(app):
    seen = []

    def inner(r):
        seen.append(True)
        r.headers["Authorization"] = "Bearer k"
        return r

    req = sb.GatewayAuth(inner)(FakeRequest({}))
    assert seen and req.headers["Authorization"] == "Bearer k" and req.headers["X-Superbased-Service"] == "support-bot"


def test_httpx_client_sends_the_headers(app, stub):
    httpx = pytest.importorskip("httpx")
    stub.reply({})
    with sb.propagate_attributes(user="alice"):
        with httpx.Client(event_hooks=sb.gateway_event_hooks()) as c:
            c.post(stub.url + "/v1/chat/completions", json={})
    h = {k.lower(): v for k, v in stub.requests[-1]["headers"].items()}
    assert h["x-superbased-user"] == "alice" and h["x-superbased-service"] == "support-bot"


def test_requests_session_sends_the_headers(app, stub):
    requests = pytest.importorskip("requests")
    stub.reply({})
    s = requests.Session()
    s.auth = sb.GatewayAuth(s.auth)
    with sb.propagate_attributes(user="bob"):
        s.post(stub.url + "/v1/chat/completions", json={})
    h = {k.lower(): v for k, v in stub.requests[-1]["headers"].items()}
    assert h["x-superbased-user"] == "bob" and h["x-superbased-service"] == "support-bot"
