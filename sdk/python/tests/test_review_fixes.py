"""Batch B review fixes owned by lane C5: R-B17 (the sign-in verb), R-B18
(a degraded ``online`` never sends control calls to the machine) and R-B19
(one machine URL variable, ``SUPERBASED_NODE_URL``)."""

import os
import re

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _control, _destination

TID = "4bf92f3577b34da6a3ce929d0e0e4736"
# The repository root: SUPERBASED_REPO_ROOT when the tests run from a copy of
# the package (scripts/ci/sdk.sh), else three levels up from this file.
ROOT = os.environ.get("SUPERBASED_REPO_ROOT") or os.path.join(os.path.dirname(__file__), "..", "..", "..")


@pytest.fixture
def degraded_online(stub, monkeypatch):
    """destination online with no gateway and no credential, and a machine
    that would answer everything: nothing may reach it."""
    for path in ("/api/obs/scores", "/api/obs/eval/datasets", "/api/obs/eval/experiments"):
        stub.route("POST", path, {"ok": True})
        stub.route("GET", path, {"datasets": [{"id": "ds_1", "name": "golden"}]})
    stub.route("GET", "/api/obs/sdk/prompts/greeting", {"name": "greeting", "version": 1, "type": "text", "prompt": "hi"})
    sb.init(exporter=InMemorySpanExporter(), destination="online", node_url=stub.url, discover=False)
    plan = _control.current_plan()
    assert plan.destination == _destination.ONLINE and plan.degraded
    return stub


def test_rb18_degraded_online_has_no_control_target(degraded_online):
    assert _control.sides() == []
    assert "nothing is exported" in _control.unavailable_reason()


def test_rb18_score_reports_the_degraded_reason(degraded_online):
    res = sb.score("accuracy", 1.0, trace_id=TID)
    assert not res.ok and res.destinations["online"]["status"] == 0
    assert "nothing is exported" in res.errors[0]
    assert degraded_online.requests == []


def test_rb18_prompt_is_a_fetch_error_not_a_machine_read(degraded_online):
    with pytest.raises(sb.PromptFetchError) as e:
        sb.get_prompt("greeting")
    assert "nothing is exported" in str(e.value)
    assert sb.get_prompt("greeting", fallback="hello").is_fallback
    assert degraded_online.requests == []


def test_rb18_datasets_and_experiments_stay_off_the_machine(degraded_online):
    with pytest.raises(sb.ExperimentError) as e:
        sb.get_dataset("golden")
    assert "nothing is exported" in str(e.value)
    with pytest.raises(sb.ExperimentError):
        sb.run_experiment("golden", lambda x: x)
    res = sb.run_experiment([{"input": 1}], lambda x: x, dataset_name="literal")
    assert res.run_id == "" and any("in-process only" in err for err in res.errors)
    assert degraded_online.requests == []


def test_rb18_both_degraded_still_uses_the_machine(stub):
    stub.route("POST", "/api/obs/scores", lambda req: (200, {"accepted": [{"index": 0, "id": "sc_1"}], "rejected": []}, {}))
    sb.init(exporter=InMemorySpanExporter(), destination="both", node_url=stub.url, discover=False)
    assert [s.name for s in _control.sides()] == ["local"]
    assert sb.score("accuracy", 1.0, trace_id=TID).ok


# --- R-B17: the sign-in verb ---------------------------------------------------------


WRONG_VERB = re.compile(r"observer\s+obs\s+sdk\s+sign-in")


def test_rb17_messages_name_the_real_verb(monkeypatch):
    monkeypatch.setenv("SUPERBASED_DESTINATION", "online")
    monkeypatch.setenv("SUPERBASED_DISCOVER", "0")
    sb.init(exporter=InMemorySpanExporter())
    reason = _control.current_plan().degraded
    assert "observer sdk sign-in" in reason and not WRONG_VERB.search(reason)


@pytest.mark.parametrize(
    "rel",
    [
        "sdk/python/superbased_sdk",
        "sdk/python/README.md",
        "docs/sdk/python",
    ],
)
def test_rb17_no_file_names_the_wrong_verb(rel):
    path = os.path.join(ROOT, rel)
    if not os.path.exists(path):
        pytest.skip("repository files not present (an sdist)")
    files = [path] if os.path.isfile(path) else [os.path.join(d, f) for d, _, fs in os.walk(path) for f in fs if f.endswith((".py", ".md"))]
    for f in files:
        with open(f, encoding="utf-8") as fh:
            assert not WRONG_VERB.search(fh.read()), f
