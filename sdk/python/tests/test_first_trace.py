"""The app's first-trace line (plan 3.8, ruling R12): the gate, the link
shapes, once per process, and the refusal in place of the link."""

import os

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _firsttrace as FT

TID = "0af7651916cd43dd8448eb211c80319c"
BASES = {"local": "http://127.0.0.1:8081", "online": "https://u-k7x2.superbased.app"}


@pytest.mark.parametrize(
    "env, tty, want",
    [
        ({}, True, True),
        ({}, False, False),
        ({"CI": "true"}, True, False),
        ({"CI": "1"}, True, False),
        ({"CI": ""}, True, True),
        ({"CI": "0"}, True, True),
        ({"CI": "False"}, True, True),
        ({"SUPERBASED_FIRST_TRACE_LINK": "0"}, True, False),
        ({"SUPERBASED_FIRST_TRACE_LINK": "OFF"}, True, False),
        ({"SUPERBASED_FIRST_TRACE_LINK": "false"}, True, False),
        ({"SUPERBASED_FIRST_TRACE_LINK": "1"}, True, True),
    ],
)
def test_gate(env, tty, want):
    assert FT.enabled(env, tty) is want


L = "http://127.0.0.1:8081/apps/traces?trace=" + TID
O = "https://u-k7x2.superbased.app/trajectories?trace=" + TID


@pytest.mark.parametrize(
    "outcomes, bases, want",
    [
        ({"local": "ok"}, BASES, (True, FT.PREFIX + L)),
        ({"online": "ok"}, BASES, (True, FT.PREFIX + O)),
        ({"local": "ok", "online": "ok"}, BASES, (True, FT.PREFIX + O)),
        ({"local": "ok", "online": "failed"}, BASES, (True, FT.PREFIX + L)),
        ({"local": "ok", "online": "ok"}, {"local": BASES["local"]}, (True, FT.PREFIX + L)),
        ({"online": "ok"}, {"local": BASES["local"]}, (True, "")),
        ({"local": "failed", "online": "failed"}, BASES, (False, "")),
        ({"online": "ok"}, {"online": BASES["online"] + "/"}, (True, FT.PREFIX + O)),
    ],
)
def test_decide(outcomes, bases, want):
    assert FT.decide(TID, outcomes, bases) == want


def test_refusal_replaces_the_link():
    r = {"message": "This organization has used this month's AI Apps allowance.", "upgrade_url": "https://cloud.superbased.app/portal/billing"}
    settled, line = FT.decide(TID, {"online": "refused"}, BASES, r)
    assert settled and line == FT.REFUSED_PREFIX + r["message"] + " https://cloud.superbased.app/portal/billing"
    assert FT.refusal_line({"message": "cap set by the org", "upgrade_url": ""}) == FT.REFUSED_PREFIX + "cap set by the org"


@pytest.fixture
def tty(monkeypatch):
    monkeypatch.delenv("SUPERBASED_FIRST_TRACE_LINK", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setattr(FT, "_stderr_tty", lambda: True)


def machine(stub):
    stub.route("GET", "/api/sdk/destination", body={
        "api_version": 1, "destination": "local", "source": "config", "configured": "", "signed_in": False,
        "local": {"enabled": True}, "online": {}, "warnings": [],
    })


def lines(capsys):
    return [ln for ln in capsys.readouterr().err.splitlines() if ln.startswith("superbased:")]


def test_local_once_per_process(tty, stub, monkeypatch, capsys):
    machine(stub)
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
    with sb.span("first") as sp:
        with sb.span("child"):
            pass
        tid = format(sp.get_span_context().trace_id, "032x")
    assert sb.flush(5)
    with sb.span("second"):
        pass
    assert sb.flush(5)
    got = lines(capsys)
    assert got == [FT.PREFIX + stub.url + "/apps/traces?trace=" + tid]


def test_a_child_span_alone_prints_nothing(tty, stub, monkeypatch, capsys):
    from opentelemetry import trace
    from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

    machine(stub)
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
    root = sb._tracer().start_span("root")  # not ended: only its child is exported
    with trace.use_span(root):
        with sb.span("child"):
            pass
    assert sb.flush(5)
    assert lines(capsys) == []
    # A span continuing a remote parent is this process's root.
    remote = SpanContext(int(TID, 16), 0x1234, is_remote=True, trace_flags=TraceFlags(1))
    with trace.use_span(NonRecordingSpan(remote)):
        with sb.span("handler"):
            pass
    assert sb.flush(5)
    assert lines(capsys) == [FT.PREFIX + stub.url + "/apps/traces?trace=" + TID]
    root.end()


def test_no_machine_no_local_line(tty, capsys):
    sb.init(exporter=InMemorySpanExporter(), destination="local")
    with sb.span("x"):
        pass
    assert sb.flush(5)
    assert lines(capsys) == []


def held_file(tmp_path, monkeypatch, gateway, dashboard="https://u-k7x2.superbased.app"):
    p = tmp_path / "sdk-credential"
    p.write_text(f"ik_1.secret\ngateway_url={gateway}\ndestination=online\ndashboard_url={dashboard}\n")
    os.chmod(p, 0o600)
    monkeypatch.setenv("SUPERBASED_CREDENTIAL_FILE", str(p))


def test_online_link_from_the_sdk_file(tty, stub, tmp_path, monkeypatch, capsys):
    stub.route("POST", "/v1/traces", body={})
    held_file(tmp_path, monkeypatch, stub.url)
    sb.init()
    with sb.span("x") as sp:
        tid = format(sp.get_span_context().trace_id, "032x")
    assert sb.flush(5)
    assert lines(capsys) == [FT.PREFIX + "https://u-k7x2.superbased.app/trajectories?trace=" + tid]


def test_online_refusal_in_place_of_the_link(tty, stub, tmp_path, monkeypatch, capsys):
    body = {
        "error": "planea_events_quota_exceeded",
        "message": "This organization has used this month's AI Apps allowance of its plan (Personal Free): 100,000 events.",
        "quota": {"quota": "events_monthly", "unit": "events", "used": 100000, "limit": 100000, "resets_at": "2027-02-01T00:00:00Z"},
        "capability": "org.planea.gateway",
        "upgrade_url": "https://cloud.superbased.app/portal/billing",
    }
    stub.route("POST", "/v1/traces", body=body, status=429, headers={"Retry-After": "60", "Content-Type": "application/json"})
    held_file(tmp_path, monkeypatch, stub.url)
    sb.init(export_timeout=1.0)
    with sb.span("x"):
        pass
    sb.flush(5)
    got = lines(capsys)
    assert len(got) == 1 and got[0].startswith(FT.REFUSED_PREFIX)
    assert "100,000 events" in got[0] and "portal/billing" in got[0]


def test_ci_or_opt_out_prints_nothing(stub, monkeypatch, capsys):
    machine(stub)
    monkeypatch.setattr(FT, "_stderr_tty", lambda: True)
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    for env in ({"CI": "true"}, {"SUPERBASED_FIRST_TRACE_LINK": "0"}):
        sb._reset_for_tests()
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("SUPERBASED_FIRST_TRACE_LINK", raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
        with sb.span("x"):
            pass
        assert sb.flush(5)
        assert lines(capsys) == []


def test_never_through_logging(tty, stub, monkeypatch, caplog, capsys):
    """sdk-api-surface.md 16: stderr directly, even when the app shows INFO."""
    import logging

    machine(stub)
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    with caplog.at_level(logging.INFO, logger="superbased_sdk"):
        sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
        with sb.span("x"):
            pass
        assert sb.flush(5)
    assert not [r for r in caplog.records if r.getMessage().startswith("superbased:")]
    got = lines(capsys)
    assert len(got) == 1 and got[0].startswith(FT.PREFIX)
    assert sb.diagnostics()["first_trace_link"] == got[0][len(FT.PREFIX):]
