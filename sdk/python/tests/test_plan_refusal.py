"""The AI Apps gateway's plan refusal: sdk/contract/plan-refusal-cases.json
through parse_plan_refusal(), and how each call surfaces it (a raising call
raises the typed error, a never-raise call carries it, export keeps it in
diagnostics())."""

import json
import logging
import os
import pickle

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _planrefusal

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "plan-refusal-cases.json")


def _cases():
    if not os.path.exists(CASES):
        return []
    with open(CASES, encoding="utf-8") as f:
        return json.load(f)["cases"]


def _allowance(a):
    """want.allowance as an Allowance: every axis; one absent reads as no cap."""
    return sb.Allowance(a.get("events_monthly"), a.get("gb_monthly"), a.get("requests_monthly"), a.get("concurrency"))


def _check(got, want, name):
    if want is None:
        assert got is None, name
        return
    assert isinstance(got, sb.PlanRefusalError), name
    assert got.kind == want["kind"], name
    assert isinstance(got, sb.PlanRequiredError if want["kind"] == "plan_required" else sb.AllowanceExceededError), name
    assert got.code == want["code"] and got.status == want["status"], name
    assert got.upgrade_url == want["upgrade_url"] and got.capability == want["capability"], name
    assert got.message, name  # the body's message, else the SDK's default line
    if "message" in want:
        assert got.message == want["message"] and str(got) == want["message"], name
    if "plan_name" in want:
        assert got.plan is not None and got.plan.name == want["plan_name"], name
        if "plan_version" in want:
            assert got.plan.version == want["plan_version"] and got.plan.label == want["plan_label"], name
    else:
        assert got.plan is None, name
    if "allowance" in want:
        a = want["allowance"]
        assert got.allowance == _allowance(a), name
    else:
        assert got.allowance is None, name
    assert [p.name for p in got.plans] == want["plans"], name
    if "offered_allowance" in want:
        a = want["offered_allowance"]
        assert got.plans[0].allowance == _allowance(a), name
    if "quota" in want:
        assert got.quota == sb.Quota(**want["quota"]), name
    else:
        assert got.quota is None, name
    if "retry_after_seconds" in want:
        assert got.retry_after == want["retry_after_seconds"], name
    else:
        assert got.retry_after is None, name


@pytest.mark.parametrize("case", _cases(), ids=lambda c: c["name"])
def test_contract_case(case):
    body = case["body"]
    got = sb.parse_plan_refusal(case["status"], body, case["headers"])
    _check(got, case["want"], case["name"])
    # The same answer as raw bytes (what an exporter or a transport holds).
    raw = body.encode("utf-8") if isinstance(body, str) else json.dumps(body).encode("utf-8")
    _check(sb.parse_plan_refusal(case["status"], raw, case["headers"]), case["want"], case["name"] + " (bytes)")


def test_contract_file_is_present_in_the_tree():
    if not os.path.isdir(os.path.join(os.path.dirname(__file__), "..", "..", "contract")):
        pytest.skip("sdk/contract is not present (an sdist)")
    assert len(_cases()) >= 10


@pytest.mark.parametrize("junk", [None, 0, object(), b"\xff\xfe", "null", [], {"error": None}])
def test_parser_never_raises(junk):
    assert sb.parse_plan_refusal(403, junk, None) is None
    assert sb.parse_plan_refusal(429, junk, {"Retry-After": object()}) is None


PLAN_REQUIRED = {
    "error": "plan_required",
    "message": "AI Apps ingest is not part of this organization's plan (Team).",
    "capability": "org.planea.gateway",
    "plan": {"name": "team", "version": 1, "label": "Team"},
    "plans": [{"name": "business", "version": 2, "label": "Business", "allowance": {"events_monthly": 10000000, "gb_monthly": 50}}],
    "upgrade_url": "https://cloud.superbased.app/portal/orgs/org_1",
}
EVENTS_OVER = {
    "error": "planea_events_quota_exceeded",
    "message": "This organization has used this month's AI Apps allowance of its plan (Team).",
    "quota": {"quota": "events_monthly", "unit": "events", "used": 10, "limit": 10, "resets_at": "2026-12-01T00:00:00Z"},
    "capability": "org.planea.gateway",
    "upgrade_url": "https://cloud.superbased.app/portal/orgs/org_1",
}


def test_error_pickles_and_dicts():
    e = sb.parse_plan_refusal(403, PLAN_REQUIRED)
    back = pickle.loads(pickle.dumps(e))
    assert type(back) is sb.PlanRequiredError and back.upgrade_url == e.upgrade_url and back.plans == e.plans
    d = e.to_dict()
    assert d["kind"] == "plan_required" and d["plans"][0]["allowance"]["gb_monthly"] == 50
    json.dumps(d)  # plain values only


def _online(stub):
    sb.init(destination="online", org_url=stub.url, api_key="ik.k", exporter=InMemorySpanExporter(), discover=False)


def test_get_prompt_raises_the_typed_error(stub):
    _online(stub)
    stub.route("GET", "/v1/sdk/prompts/greet", status=403, body=dict(PLAN_REQUIRED, api_version="1", request_id="r1"))
    with pytest.raises(sb.PlanRequiredError) as ei:
        sb.get_prompt("greet")
    e = ei.value
    # Also the PromptFetchError get_prompt raises: existing handlers hold.
    assert isinstance(e, sb.PromptFetchError) and isinstance(e, sb.PromptError)
    assert e.upgrade_url == PLAN_REQUIRED["upgrade_url"] and e.message == PLAN_REQUIRED["message"]
    assert "could not be fetched" in str(e) and "plan_required" in str(e)
    assert sb.diagnostics()["plan_refusal"]["code"] == "plan_required"
    # A fallback still wins (nothing raises).
    assert sb.get_prompt("greet", fallback="hi").is_fallback


def test_get_dataset_raises_the_typed_error(stub):
    _online(stub)
    stub.route("GET", "/v1/sdk/datasets", status=429, body=EVENTS_OVER, headers={"Retry-After": "120"})
    with pytest.raises(sb.AllowanceExceededError) as ei:
        sb.get_dataset("golden")
    assert isinstance(ei.value, sb.ExperimentError)
    assert ei.value.retry_after == 120 and ei.value.quota.quota == "events_monthly"


def test_score_does_not_raise_and_carries_it(stub):
    _online(stub)
    stub.route("POST", "/v1/sdk/scores", status=429, body=EVENTS_OVER, headers={"Retry-After": "120"})
    with sb.span("req"):
        res = sb.score("accuracy", 1.0)
    assert res.ok is False
    assert isinstance(res.plan_refusal, sb.AllowanceExceededError)
    assert res.plan_refusal.upgrade_url == EVENTS_OVER["upgrade_url"]
    # Not retried: an allowance holds until the plan changes or the month turns.
    assert stub.paths("POST").count("/v1/sdk/scores") == 1


def test_admit_does_not_raise_and_carries_it(stub):
    stub.reply(PLAN_REQUIRED, status=403)
    v = sb.admit("hi", org_url=stub.url, api_key="sk-1")
    assert v.allowed is True and v.degraded == "admission-unavailable" and v.http_status == 403
    assert isinstance(v.plan_refusal, sb.PlanRequiredError)
    assert v.to_dict()["plan_refusal"]["upgrade_url"] == PLAN_REQUIRED["upgrade_url"]
    assert "plan_required" in v.error
    # Another 403 is no plan refusal.
    stub.reply({"error": "insufficient_scope", "message": "no"}, status=403)
    assert sb.admit("hi", org_url=stub.url, api_key="sk-1").plan_refusal is None


def test_export_refusal_is_in_diagnostics_and_logged_once(stub, caplog):
    caplog.set_level(logging.WARNING, logger="superbased_sdk")
    stub.route("POST", "/v1/traces", status=403, body=PLAN_REQUIRED)
    assert sb.diagnostics()["plan_refusal"] is None
    sb.init(destination="online", org_url=stub.url, api_key="ik.k", discover=False)
    for _ in range(2):
        with sb.span("refused"):
            pass
        assert sb.flush() is False  # never raises
    d = sb.diagnostics()
    assert d["failed_exports"] >= 2
    pr = d["plan_refusal"]
    assert pr["kind"] == "plan_required" and pr["upgrade_url"] == PLAN_REQUIRED["upgrade_url"]
    assert pr["plan"]["name"] == "team" and d["plan_refusal_at"] > 0
    lines = [r.getMessage() for r in caplog.records if r.name == "superbased_sdk" and "refused by the organization's plan" in r.getMessage()]
    assert len(lines) == 1, lines
    assert PLAN_REQUIRED["message"] in lines[0] and PLAN_REQUIRED["upgrade_url"] in lines[0] and "\n" not in lines[0]


def test_export_without_upgrade_url_is_no_plan_refusal(stub):
    stub.route("POST", "/v1/traces", status=403, body={"error": "insufficient_scope", "message": "no"})
    sb.init(destination="online", org_url=stub.url, api_key="ik.k", discover=False)
    with sb.span("refused"):
        pass
    sb.flush()
    assert sb.diagnostics()["plan_refusal"] is None


def test_note_logs_at_most_once_a_minute(caplog, monkeypatch):
    caplog.set_level(logging.WARNING, logger="superbased_sdk")
    e = sb.parse_plan_refusal(403, PLAN_REQUIRED)
    now = [1_000_000.0]
    monkeypatch.setattr(_planrefusal.time, "time", lambda: now[0])
    assert _planrefusal.note(e, log_as="trace export") is True
    now[0] += 10
    assert _planrefusal.note(e, log_as="trace export") is False
    assert _planrefusal.note(e) is False  # a control call keeps it, never logs here
    now[0] += 61
    assert _planrefusal.note(e, log_as="trace export") is True
