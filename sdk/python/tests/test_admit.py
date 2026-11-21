"""admit(): every failure body, status mapping, fail_closed, timeouts, org
endpoint + credential, advertised timeout, span stamping."""

import json
import os
import time

import pytest

import superbased_sdk as sb
from superbased_sdk import _admit

GOOD = {
    "allowed": False,
    "decision": "deny",
    "severity": "high",
    "criterion": "c1",
    "reason": "no",
    "mode": "enforce",
    "judge_used": True,
    "latency_ms": 42,
    "enforce_decision": "deny",
}


@pytest.fixture(autouse=True)
def forget_advertised():
    _admit._advertised.clear()
    yield
    _admit._advertised.clear()


def test_default_endpoint_is_node():
    assert sb.DEFAULT_ADMISSION_ENDPOINT == "http://127.0.0.1:8081/api/obs/admission/check"
    assert sb.DEFAULT_ADMIT_TIMEOUT == 12.0


def test_clean_verdict(stub):
    stub.reply(GOOD)
    v = sb.admit("hi", user="u", session="s", tenant="t", request_id="r", endpoint=stub.url + "/check")
    assert v.allowed is False and v.decision == "deny" and v.judge_used is True
    assert v.latency_ms == 42 and v.degraded == "" and v.http_status == 200
    body = stub.requests[0]["body"]
    assert body == {"text": "hi", "tenant": "t", "user": "u", "session": "s", "service": "custom-app", "trace_id": "", "request_id": "r"}


@pytest.mark.parametrize(
    "body",
    [b"[]", b'"x"', b"null", b"42", b"not json", b"\xff\xfe", b"", b'{"decision":"allow"}', b'{"allowed":"false"}',
     b'{"allowed":1}', b'{"allowed":null}'],
)
@pytest.mark.parametrize("closed", [False, True])
def test_bad_bodies_never_raise(stub, body, closed):
    stub.reply(body)
    v = sb.admit("hi", endpoint=stub.url, fail_closed=closed)
    assert v.degraded == sb.BAD_RESPONSE
    assert v.allowed is (not closed)
    assert v.decision == ("deny" if closed else "allow")


def test_string_false_does_not_admit():
    # Directly: the Verdict never treats a non-bool as True.
    assert sb.Verdict({"allowed": "false"}).allowed is False


def test_null_fields_are_tolerated(stub):
    stub.reply({"allowed": True, "decision": None, "latency_ms": None, "judge_used": None, "reason": None,
                "severity": 3, "verdict_id": 991})
    v = sb.admit("hi", endpoint=stub.url)
    assert v.allowed is True and v.decision == "allow" and v.latency_ms == 0
    assert v.judge_used is False and v.reason == "" and v.severity == ""
    assert v.verdict_id == "991" and v.degraded == ""


@pytest.mark.parametrize("status", [403, 404])
def test_unavailable_is_distinguished(stub, status):
    stub.reply(b"admission not enabled", status=status)
    v = sb.admit("hi", endpoint=stub.url)
    assert v.degraded == sb.UNAVAILABLE and v.http_status == status and v.allowed is True
    v = sb.admit("hi", endpoint=stub.url, fail_closed=True)
    assert v.allowed is False and v.decision == "deny"


@pytest.mark.parametrize("status", [400, 401, 500, 503])
def test_http_errors(stub, status):
    stub.reply(b"oops", status=status)
    v = sb.admit("hi", endpoint=stub.url)
    assert v.degraded == sb.HTTP_ERROR and v.http_status == status


def test_transport_error(dead_url):
    v = sb.admit("hi", endpoint=dead_url)
    assert v.degraded == sb.TRANSPORT and v.allowed is True and v.error
    v = sb.admit("hi", endpoint=dead_url, fail_closed=True)
    assert v.allowed is False


def test_fail_closed_env(monkeypatch, dead_url):
    monkeypatch.setenv("SUPERBASED_ADMISSION_FAIL_CLOSED", "1")
    assert sb.admit("hi", endpoint=dead_url).allowed is False
    assert sb.admit("hi", endpoint=dead_url, fail_closed=False).allowed is True


def test_timeout(stub):
    stub.reply(GOOD)
    stub.delay = 1.0
    t = time.monotonic()
    v = sb.admit("hi", endpoint=stub.url, timeout=0.2)
    assert time.monotonic() - t < 0.9
    assert v.degraded == sb.TIMEOUT and v.allowed is True


def test_incomplete_read(stub):
    stub.reply(b'{"allowed": true')
    stub.truncate = True
    v = sb.admit("hi", endpoint=stub.url, timeout=2)
    assert v.degraded in (sb.TRANSPORT, sb.BAD_RESPONSE, sb.TIMEOUT)
    assert v.allowed is True


def test_non_string_message_never_raises(stub):
    stub.reply(GOOD)
    assert sb.admit(None, endpoint=stub.url).decision == "deny"
    assert sb.admit(object(), endpoint=stub.url).decision == "deny"


def test_org_endpoint_and_credential(stub, monkeypatch):
    stub.reply(GOOD)
    sb.admit("hi", org_url=stub.url + "/", api_key="sk-1")
    r = stub.requests[-1]
    assert r["path"] == "/v1/sdk/admit"
    assert r["headers"]["Authorization"] == "Bearer sk-1"
    monkeypatch.setenv("SUPERBASED_ORG_URL", stub.url)
    monkeypatch.setenv("SUPERBASED_API_KEY", "sk-env")
    sb.admit("hi", headers={"X-Extra": "1"})
    r = stub.requests[-1]
    assert r["path"] == "/v1/sdk/admit"
    assert r["headers"]["Authorization"] == "Bearer sk-env" and r["headers"]["X-Extra"] == "1"
    monkeypatch.setenv("SUPERBASED_ADMISSION_ENDPOINT", stub.url + "/node")
    sb.admit("hi")
    assert stub.requests[-1]["path"] == "/node"


def test_advertised_timeout_is_used(stub):
    stub.reply(dict(GOOD, recommended_timeout_ms=300))
    sb.admit("hi", endpoint=stub.url)
    assert _admit._advertised[stub.url] == 0.3
    stub.delay = 1.0
    t = time.monotonic()
    v = sb.admit("hi", endpoint=stub.url)
    assert v.degraded == sb.TIMEOUT and time.monotonic() - t < 0.9


def test_advertised_timeout_header(stub):
    stub.reply(GOOD, headers={"X-Superbased-Admit-Timeout-Ms": "15000"})
    sb.admit("hi", endpoint=stub.url)
    assert _admit._advertised[stub.url] == 15.0
    stub.reply(GOOD, headers={"X-Superbased-Admit-Timeout-Ms": "nonsense"})
    sb.admit("hi", endpoint=stub.url + "/x")
    assert stub.url + "/x" not in _admit._advertised


def test_canonical_timeout_names(stub):
    stub.reply(dict(GOOD, recommended_client_timeout_ms=4000, recommended_timeout_ms=9000))
    sb.admit("hi", endpoint=stub.url)
    assert _admit._advertised[stub.url] == 4.0, "the canonical body field wins over the legacy one"
    stub.reply(GOOD, headers={"x-sbo-recommended-timeout-ms": "7000"})
    sb.admit("hi", endpoint=stub.url + "/h")
    assert _admit._advertised[stub.url + "/h"] == 7.0, "the canonical header is read case-insensitively"


def _recorded_org_admit():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "org-admit-response.json")
    if not os.path.exists(path):
        pytest.skip("sdk/contract fixtures are only in the source repository, not the sdist")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_contract_recorded_org_admit_response(stub):
    """Contract test (review R-A03): the SDK replays a response recorded from
    the org SDK control API (sdk/contract, pinned to the Go code by
    tests/sdkcontract) and learns the server's recommended timeout from it."""
    rec = _recorded_org_admit()
    want_ms = rec["body"]["recommended_client_timeout_ms"]
    # Body alone.
    stub.reply(rec["body"], status=rec["status"])
    v = sb.admit("hi", endpoint=stub.url)
    assert v.allowed is False and v.decision == "deny" and v.verdict_id == rec["body"]["verdict_id"]
    assert _admit._advertised[stub.url] == want_ms / 1000.0
    # Headers alone (the body field removed).
    body = {k: val for k, val in rec["body"].items() if k != "recommended_client_timeout_ms"}
    hdrs = {k: val for k, val in rec["headers"].items() if k.lower() not in ("content-type", "content-length")}
    stub.reply(body, headers=hdrs)
    sb.admit("hi", endpoint=stub.url + "/hdr")
    assert _admit._advertised[stub.url + "/hdr"] == float(rec["headers"]["X-Sbo-Recommended-Timeout-Ms"]) / 1000.0


def test_service_name_is_sent_to_the_machine_and_the_org(stub, mem, monkeypatch):
    """C1: service-scoped budget caps match the service.name the app's spans
    carry, so admit() sends it in the machine body and in the org body."""
    stub.reply(GOOD)
    monkeypatch.setenv("OTEL_SERVICE_NAME", "from-env")
    sb.admit("hi", endpoint=stub.url + "/check")  # no init(): the configured name
    assert stub.requests[-1]["body"]["service"] == "from-env"

    sb.init(exporter=mem, service_name="checkout")  # the SDK's own resource
    sb.admit("hi", endpoint=stub.url + "/check")
    assert stub.requests[-1]["body"]["service"] == "checkout"
    sb.admit("hi", org_url=stub.url, api_key="sk-1")
    r = stub.requests[-1]
    assert r["path"] == "/v1/sdk/admit" and r["body"]["service"] == "checkout"


def test_service_name_follows_a_host_provider(stub, mem):
    """Attached to the app's own provider, the name is that resource's."""
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider

    trace.set_tracer_provider(TracerProvider(resource=Resource.create({"service.name": "host-svc"})))
    sb.init(exporter=mem, service_name="ignored-when-attached")
    stub.reply(GOOD)
    sb.admit("hi", endpoint=stub.url + "/check")
    assert stub.requests[-1]["body"]["service"] == "host-svc"


def test_verdict_stamped_on_current_span_and_trace_id_sent(stub, mem):
    sb.init(exporter=mem)
    stub.reply(dict(GOOD, verdict_id="v-7"))
    with sb.span("front-door") as sp:
        sb.admit("hi", endpoint=stub.url)
        tid = format(sp.get_span_context().trace_id, "032x")
    assert stub.requests[-1]["body"]["trace_id"] == tid
    sb.flush(5)
    a = mem.get_finished_spans()[0].attributes
    assert a["sbo.admission.decision"] == "deny"
    assert a["sbo.admission.allowed"] is False
    assert a["sbo.admission.verdict_id"] == "v-7"


def test_verdict_to_dict_and_repr():
    v = sb.Verdict(GOOD)
    d = v.to_dict()
    assert d["decision"] == "deny" and "http_status" in d
    assert "deny" in repr(v)
