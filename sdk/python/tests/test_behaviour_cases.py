"""sdk/contract/sdk-behaviour-cases.json: behaviours both SDKs share (review
R-B19). The TypeScript SDK runs the same file."""

import json
import os

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _control, _destination, _prompts, _scores
from superbased_sdk._config import Settings

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "sdk-behaviour-cases.json")


def _cases(section):
    if not os.path.exists(CASES):
        pytest.skip("sdk/contract is not present (an sdist)")
    with open(CASES, encoding="utf-8") as f:
        data = json.load(f)[section]
    return data


def _ids(section):
    if not os.path.exists(CASES):
        return []
    with open(CASES, encoding="utf-8") as f:
        return list(range(len(json.load(f)[section]["cases"])))


@pytest.mark.parametrize("i", _ids("compile_values"))
def test_compile_values(i):
    sec = _cases("compile_values")
    case = sec["cases"][i]
    assert _prompts.compile_text(sec["prompt"], {"v": case["value"]}) == case["want"]


def test_compile_non_finite_is_null():
    assert _prompts.compile_text("{{v}}", {"v": float("nan")}) == "null"
    assert _prompts.compile_text("{{v}}", {"v": float("-inf")}) == "null"


@pytest.mark.parametrize("i", _ids("score_target"))
def test_score_target(i, stub):
    case = _cases("score_target")["cases"][i]
    stub.route("POST", "/api/obs/scores", lambda req: (200, {"accepted": [{"index": 0, "id": "sc_1"}], "rejected": []}, {}))
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")

    def call():
        args = dict(case["args"])
        if args.get("span_id") == "current":
            args["span_id"] = sb.get_current_span_id()
        return sb.score("accuracy", 1.0, **args), sb.get_current_trace_id(), sb.get_current_span_id()

    if case["in_span"]:
        with sb.span("req"):
            res, tid, sid = call()
    else:
        res, tid, sid = call()
    want = case["want"]
    if "error" in want:
        assert not res.ok and any(want["error"] in e for e in res.errors)
        return
    body = stub.requests[-1]["body"]
    assert body["trace_id"] == tid
    assert body.get("span_id", "") == (sid if want["span_id"] == "current" else "")


@pytest.mark.parametrize("i", _ids("score_ok"))
def test_score_ok(i):
    case = _cases("score_ok")["cases"][i]
    res = _scores.ScoreResult(client_id="sdk_x")
    for name, ok in case["destinations"].items():
        res.destinations[name] = {"ok": ok, "status": 200 if ok else 500, "id": "", "error": ""}
    assert _scores.result_ok(res) is case["want"]


@pytest.mark.parametrize("i", _ids("destination"))
def test_destination(i, stub, monkeypatch):
    case = _cases("destination")["cases"][i]
    env = {"SUPERBASED_DISCOVER": "1", **case.get("env", {})}
    asked = []
    real = _destination.discover

    def discover(node_url, *a, **kw):  # only the stub may answer: never a real machine on this host
        asked.append(node_url)
        if case["machine"] is not None and node_url == stub.url:
            return real(node_url, *a, **kw)
        return None, "no machine (test)"

    monkeypatch.setattr(_destination, "discover", discover)
    if case["machine"] is not None:
        body = {"api_version": 1, "destination": case["machine"]["destination"], "source": "config", "configured": "", "signed_in": False,
                "local": {"enabled": True}, "online": {}, "warnings": []}
        stub.route("GET", "/api/sdk/destination", body=body)
        env["SUPERBASED_NODE_URL"] = stub.url
    elif "SUPERBASED_MACHINE_URL" not in env:
        env["SUPERBASED_NODE_URL"] = "http://127.0.0.1:1"  # nothing answers
    args = case.get("args", {})
    s = Settings.resolve(env, **{k: v for k, v in args.items() if k in Settings.__dataclass_fields__})
    p = _destination.resolve(s, env, explicit_destination=args.get("destination"), explicit_api_key=args.get("api_key"))
    want = case["want"]
    assert (p.destination, p.source) == (want["destination"], want["source"])
    if "node_url" in want:
        assert p.node_url == want["node_url"]  # SUPERBASED_MACHINE_URL is not read
        assert env["SUPERBASED_MACHINE_URL"] not in asked


@pytest.mark.parametrize("i", _ids("control_targets"))
def test_control_targets(i):
    case = _cases("control_targets")["cases"][i]
    gw, key = ("https://gw.example.com", "ik_1.s") if case["online_ready"] else ("", "")
    env = {"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": case["destination"], "SUPERBASED_ORG_URL": gw, "SUPERBASED_API_KEY": key}
    p = _destination.resolve(Settings.resolve(env), env)
    assert [s.name for s in _control.sides(p)] == case["want"]


class _Captured:
    """A stand-in for _http._opener: records each request and answers 200
    with a clean verdict, so nothing is dialled."""

    def __init__(self):
        self.calls = []

    def __call__(self, loopback):
        cap = self

        class Opener:
            def open(self, req, timeout=None):
                cap.calls.append({"url": req.full_url, "headers": {k.lower(): v for k, v in req.header_items()},
                                  "body": __import__("json").loads(req.data), "loopback": loopback})
                return _Resp()

        return Opener()


class _Resp:
    status = 200
    headers = {}

    def read(self):
        return b'{"allowed": true, "decision": "allow"}'

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.mark.parametrize("i", _ids("admit_identity"))
def test_admit_identity(i, monkeypatch):
    from superbased_sdk import _http

    case = _cases("admit_identity")["cases"][i]
    cap = _Captured()
    monkeypatch.setattr(_http, "_opener", cap)
    if case["init"]:
        sb.init(exporter=InMemorySpanExporter(), destination="local", **case["init"])
    args = dict(case["args"])
    if case["scope"]:
        with sb.propagate_attributes(**case["scope"]):
            sb.admit("hi", endpoint="http://127.0.0.1:9/check", **args)
    else:
        sb.admit("hi", endpoint="http://127.0.0.1:9/check", **args)
    body = cap.calls[-1]["body"]
    assert {k: body[k] for k in ("tenant", "user", "session")} == case["want"]


_HOSTS = {"loopback": "http://127.0.0.1:9", "remote": "https://admit.example.com"}


@pytest.mark.parametrize("i", _ids("admit_credential"))
def test_admit_credential(i, monkeypatch):
    from superbased_sdk import _http

    case = _cases("admit_credential")["cases"][i]
    cap = _Captured()
    monkeypatch.setattr(_http, "_opener", cap)
    host = _HOSTS[case["host"]]
    kw = {}
    if case["key"] == "argument":
        kw["api_key"] = "ik_arg"
    elif case["key"] == "init":
        sb.init(exporter=InMemorySpanExporter(), destination="local", api_key="ik_init")
    else:
        monkeypatch.setenv("SUPERBASED_API_KEY", "ik_env")
    via = case["via"]
    if via == "endpoint":
        kw["endpoint"] = host + "/check"
    elif via == "env_endpoint":
        monkeypatch.setenv("SUPERBASED_ADMISSION_ENDPOINT", host + "/check")
    elif via == "org_url":
        kw["org_url"] = host
    elif via == "env_org_url":
        monkeypatch.setenv("SUPERBASED_ORG_URL", host)
    sb.admit("hi", **kw)
    call = cap.calls[-1]
    assert ("authorization" in call["headers"]) is case["want_key"], call
    assert call["loopback"] is (case["host"] == "loopback")


@pytest.mark.parametrize("i", _ids("admit_redirect"))
def test_admit_redirect(i, stub, stub2):
    case = _cases("admit_redirect")["cases"][i]
    stub.reply({}, status=case["status"], headers={"Location": stub2.url + "/stolen"})
    v = sb.admit("hi", endpoint=stub.url + "/check", api_key="ik_1.s")
    want = case["want"]
    assert len(stub.requests) == want["requests"] and stub2.requests == []
    assert (v.degraded, v.http_status) == (want["degraded"], want["http_status"])


@pytest.mark.parametrize("i", _ids("local_export_credential"))
def test_local_export_credential(i):
    case = _cases("local_export_credential")["cases"][i]
    env = {"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": "local", "SUPERBASED_API_KEY": "ik_1.s"}
    explicit = None
    if case["endpoint_from"] == "argument":
        explicit = case["endpoint"]
    elif case["endpoint_from"] == "superbased_env":
        env["SUPERBASED_OTLP_ENDPOINT"] = case["endpoint"]
    elif case["endpoint_from"] == "otel_env":
        env["OTEL_EXPORTER_OTLP_ENDPOINT"] = case["endpoint"]
    p = _destination.resolve(Settings.resolve(env), env, explicit_endpoint=explicit)
    (local,) = p.exporters
    assert any(k.lower() == "authorization" for k, _ in local.headers) is case["want_key"]


@pytest.mark.parametrize("i", _ids("local_receiver_discovery"))
def test_local_receiver_discovery(i, stub):
    """Live finding L-01: a set destination still asks the machine for its
    receiver when no endpoint was named for the local destination."""
    sec = _cases("local_receiver_discovery")
    case = sec["cases"][i]
    body = {"api_version": 1, "destination": "local", "source": "config", "configured": "", "signed_in": False,
            "local": {"enabled": True, "otlp_traces_url": sec["machine_receiver"]}, "online": {}, "warnings": []}
    stub.route("GET", "/api/sdk/destination", body=body)
    env = {"SUPERBASED_DISCOVER": "1" if case["discover"] else "0", "SUPERBASED_DESTINATION": case["destination"],
           "SUPERBASED_NODE_URL": stub.url, "SUPERBASED_ORG_URL": "https://gw.example.com", "SUPERBASED_API_KEY": "ik_1.s"}
    explicit = None
    named = case.get("endpoint", "")
    if case["endpoint_from"] == "argument":
        explicit = named
    elif case["endpoint_from"] == "superbased_env":
        env["SUPERBASED_OTLP_ENDPOINT"] = named
    elif case["endpoint_from"] == "otel_env":
        env["OTEL_EXPORTER_OTLP_ENDPOINT"] = named
        named = named.rstrip("/") + "/v1/traces"
    p = _destination.resolve(Settings.resolve(env), env, explicit_endpoint=explicit)
    local = [d.endpoint for d in p.exporters if d.name == "local"]
    want = {"machine": [sec["machine_receiver"]], "named": [named], "default": ["http://127.0.0.1:4318/v1/traces"], None: []}[case["want"]["local"]]
    assert local == want
    asked = [r for r in stub.requests if r["path"] == "/api/sdk/destination"]
    assert bool(asked) is case["want"]["asked"]


def test_admit_on_loopback_bypasses_an_environment_proxy(stub, dead_url, monkeypatch):
    """R-C09: a loopback admit never goes through HTTP(S)_PROXY (the message
    text would otherwise leave the host)."""
    for k in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTP_PROXY", dead_url)
    monkeypatch.setenv("http_proxy", dead_url)
    stub.reply({"allowed": True, "decision": "allow"})
    v = sb.admit("hi", endpoint=stub.url + "/check")
    assert v.degraded == "" and len(stub.requests) == 1


@pytest.mark.parametrize("i", _ids("experiment_pass_rate"))
def test_experiment_pass_rate(i):
    import math

    from superbased_sdk import _experiments as ex

    case = _cases("experiment_pass_rate")["cases"][i]
    res = ex.ExperimentResult(name="r")
    for n, it in enumerate(case["items"]):
        res.items.append(ex.ItemResult(
            item_id=f"it_{n}", input="x", error=it.get("error", ""),
            scores=[ex.Evaluation(s["name"], s["value"]) for s in it["scores"]],
            evaluator_errors=["boom"] * it.get("evaluator_errors", 0),
        ))
    for n, body in enumerate(case["sides"]):
        res.server[("online", "local")[n]] = body
    want = case["want"]
    assert res.scored == want["scored"]
    if want["pass_rate"] is None:
        assert math.isnan(res.pass_rate)
    else:
        assert res.pass_rate == pytest.approx(want["pass_rate"])
    # This section is the rate rule alone; experiment_strict_gate covers strict.
    assert ex.gate_fails(res, case["fail_under"], strict=False) is want["gate_failed"]


# --- lane E4 sections (end-to-end review E-31, E-33, E-38, E-39, E-49, E-75) -----------

RUNNERS = {
    "compile_values", "score_target", "score_ok", "destination", "control_targets",
    "admit_identity", "admit_credential", "admit_redirect", "local_export_credential", "experiment_pass_rate",
    "literal_item_ids", "sampling_env", "pending_per_destination", "admit_degraded",
    "control_before_discovery", "experiment_snapshot_version", "llm_span_prompt",
    "experiment_create_id", "local_receiver_discovery", "vendor_self_tracing",
    "set_usage_net_input",
}


def test_every_section_has_a_runner():
    if not os.path.exists(CASES):
        pytest.skip("sdk/contract is not present (an sdist)")
    with open(CASES, encoding="utf-8") as f:
        sections = {k for k in json.load(f) if not k.startswith("_")}
    assert sections == RUNNERS


@pytest.mark.parametrize("i", _ids("literal_item_ids"))
def test_literal_item_ids(i):
    from superbased_sdk import _experiments

    case = _cases("literal_item_ids")["cases"][i]
    assert [r["id"] for r in _experiments._literal(case["items"])] == case["want"]


@pytest.mark.parametrize("i", _ids("sampling_env"))
def test_sampling_env(i):
    from superbased_sdk import _config

    case = _cases("sampling_env")["cases"][i]
    want = case["want"]
    if want.get("error"):
        with pytest.raises(ValueError):
            _config.resolve_sampling(case["explicit"], case["env"])
        return
    rate, parent = _config.resolve_sampling(case.get("explicit"), case["env"])
    assert (rate, parent) == (want["rate"], want["parent_based"])
    problem = _config.sampling_env_problem(case["env"])
    named = [v for v in ("SUPERBASED_SAMPLE_RATE", "OTEL_TRACES_SAMPLER_ARG") if v + "=" in problem]
    assert named == want["ignored"], problem


@pytest.mark.parametrize("i", _ids("pending_per_destination"))
def test_pending_per_destination(i, stub, stub2, monkeypatch):
    import threading
    import time

    case = _cases("pending_per_destination")["cases"][i]
    sides = {"local": stub, "online": stub2}
    for name, st in sides.items():
        st.reply({})
        st.delay = 1.0 if name in case["held"] else 0.0
    monkeypatch.setenv("SUPERBASED_OTLP_ENDPOINT", stub.url + "/v1/traces")
    kw = {"destination": case["destination"], "shutdown_timeout": 5.0, "export_timeout": 5.0}
    if case["destination"] == "both":
        kw.update(org_url=stub2.url, api_key="ik_1.s")
    sb.init(**kw)
    with sb.span("x"):
        pass
    t = threading.Thread(target=sb.flush, args=(5,))
    t.start()
    legs = 2 if case["destination"] == "both" else 1
    answered = legs - len(case["held"])
    deadline = time.time() + 3
    while sb.diagnostics()["exported_spans"] < answered and time.time() < deadline:
        time.sleep(0.02)
    if case["held"]:
        assert sb.diagnostics()["pending_spans"] == case["want_pending"], sb.diagnostics()
    t.join(6)
    assert sb.diagnostics()["pending_spans"] == 0
    if not case["held"]:
        assert case["want_pending"] == 0


@pytest.mark.parametrize("i", _ids("admit_degraded"))
def test_admit_degraded(i, stub, dead_url, caplog):
    case = _cases("admit_degraded")["cases"][i]
    want = case["want"]
    if case["status"] == "transport":
        url = dead_url + "/check"
    else:
        stub.reply({"allowed": True, "decision": "allow"} if case["status"] == 200 else {}, status=case["status"])
        url = stub.url + case.get("path", "/check")
    with caplog.at_level("WARNING", logger="superbased_sdk"):
        vs = [sb.admit("hi", endpoint=url, timeout=1.0, fail_closed=case.get("fail_closed", False)) for _ in range(2)]
    for v in vs:
        assert (v.allowed, v.degraded) == (want["allowed"], want["degraded"])
    lines = [r.getMessage() for r in caplog.records if "admit()" in r.getMessage()]
    assert len(lines) == want["warnings"], lines
    assert all("Fix:" in ln and want.get("fix", "") in ln for ln in lines), lines
    assert sb.diagnostics()["admission_degraded"] == want["counted"]


@pytest.mark.parametrize("i", _ids("control_before_discovery"))
def test_control_before_discovery(i, stub, stub2, monkeypatch):
    import time

    case = _cases("control_before_discovery")["cases"][i]
    machine, gateway = stub, stub2
    found = {"api_version": 1, "destination": case["discovery"], "source": "config", "configured": "", "signed_in": True,
             "local": {"enabled": True}, "online": {}, "warnings": []}

    def discovery(req):
        time.sleep(case["delay_ms"] / 1000.0)
        return 200, found, {}

    machine.route("GET", "/api/sdk/destination", discovery)
    accepted = {"accepted": [{"index": 0, "id": "sc_1"}], "rejected": []}
    machine.route("POST", "/api/obs/scores", lambda req: (200, accepted, {}))
    gateway.route("POST", "/v1/sdk/scores", lambda req: (200, accepted, {}))
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    # The gateway is named by the app (review E-04: never by discovery).
    sb.init(node_url=machine.url, api_key="ik_1.s", org_url=gateway.url)
    with sb.span("req"):
        res = sb.score("accuracy", 1.0)
    assert res.ok, res.errors
    assert list(res.destinations) == [case["want"]]


@pytest.mark.parametrize("i", _ids("experiment_snapshot_version"))
def test_experiment_snapshot_version(i, stub):
    case = _cases("experiment_snapshot_version")["cases"][i]
    created = []
    stub.route("GET", "/api/obs/eval/datasets", lambda req: (200, {"datasets": [{"id": "7", "name": "golden"}]}, {}))

    def create(req):
        created.append(req["body"])
        return 201, {"id": "1", "snapshot_version": req["body"]["snapshot_version"]}, {}

    stub.route("POST", "/api/obs/eval/experiments", create)
    stub.route("GET", "/api/obs/eval/datasets/7/items", lambda req: (200, {"items": [], "next_cursor": ""}, {}))
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
    sb.run_experiment("golden", lambda input: input, snapshot_version=case["snapshot_version"])
    assert created[0]["snapshot_version"] == case["want"]


@pytest.mark.parametrize("i", _ids("experiment_create_id"))
def test_experiment_create_id(i, stub):
    import re

    case = _cases("experiment_create_id")["cases"][i]
    created = []
    stub.route("GET", "/api/obs/eval/datasets", lambda req: (200, {"datasets": [{"id": "7", "name": "golden"}]}, {}))

    def create(req):
        created.append(req["body"])
        if len(created) == 1 and case["first_status"] != 201:
            return case["first_status"], {"error": "x", "message": "x"}, {}
        return 201, {"id": "1", "snapshot_version": 1}, {}

    stub.route("POST", "/api/obs/eval/experiments", create)
    stub.route("GET", "/api/obs/eval/datasets/7/items", lambda req: (200, {"items": [], "next_cursor": ""}, {}))
    sb.init(exporter=InMemorySpanExporter(), node_url=stub.url, destination="local")
    if case["first_status"] in (201, 429) or case["first_status"] >= 500:
        sb.run_experiment("golden", lambda input: input)
    else:
        with pytest.raises(sb.ExperimentError):
            sb.run_experiment("golden", lambda input: input)
    assert len(created) == case["want_creates"]
    ids = {c.get("id") for c in created}
    assert len(ids) == 1
    (cid,) = ids
    assert isinstance(cid, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", cid)
    if case["first_status"] == 201:
        sb.run_experiment("golden", lambda input: input)
        assert created[-1]["id"] != cid


@pytest.mark.parametrize("i", _ids("llm_span_prompt"))
def test_llm_span_prompt(i, mem):
    case = _cases("llm_span_prompt")["cases"][i]
    with open(os.path.join(os.path.dirname(CASES), case["fixture"]), encoding="utf-8") as f:
        body = json.load(f)["body"]
    prompt = _prompts._parse(body, "online", "production")
    sb.init(exporter=mem, destination="local")
    with sb.llm_span("chat", prompt=prompt):
        pass
    sb.flush(5)
    attrs = dict(mem.get_finished_spans()[-1].attributes)
    want = case["want"]
    assert (attrs.get("sbo.prompt.name"), attrs.get("sbo.prompt.version")) == (want["name"], want["version"])
    assert ("input.value" in attrs or "gen_ai.input.messages" in attrs) is want["content"]


@pytest.mark.parametrize("i", _ids("vendor_self_tracing"))
def test_vendor_self_tracing(i, mem, monkeypatch):
    case = _cases("vendor_self_tracing")["cases"][i]
    want = case["want"]
    for k in want["env_after"]:
        monkeypatch.delenv(k, raising=False)
    for k, v in case["env"].items():
        monkeypatch.setenv(k, v)
    sb.init(exporter=mem, destination="local")
    assert sb.diagnostics()["vendor_tracing"] == want["status"]
    for k, v in want["env_after"].items():
        assert os.environ.get(k) == v
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    for scope in want["exported"]:
        provider.get_tracer(scope).start_span("call " + scope).end()
    sb.flush(5)
    got = {s.instrumentation_scope.name for s in mem.get_finished_spans()}
    assert {scope: scope in got for scope in want["exported"]} == want["exported"]
    dropped = sum(1 for v in want["exported"].values() if not v)
    assert sb.diagnostics()["vendor_spans_dropped"] == dropped


@pytest.mark.parametrize("i", _ids("set_usage_net_input"))
def test_set_usage_net_input(i, mem):
    case = _cases("set_usage_net_input")["cases"][i]
    sb.init(exporter=mem, destination="local")
    before = sb.diagnostics()["usage_net_input_corrected"]
    with sb.llm_span("chat") as sp:
        sb.set_usage(sp, **case["usage"])
    sb.flush(5)
    attrs = dict(mem.get_finished_spans()[-1].attributes)
    assert attrs.get("gen_ai.usage.input_tokens") == case["want"]["input_tokens"]
    assert sb.diagnostics()["usage_net_input_corrected"] - before == case["want"]["corrected"]


# --- lane D3 sections (ruling D29: L-05, E-12) -------------------------------------------

RUNNERS |= {"admit_org_off"}


@pytest.mark.parametrize("i", _ids("admit_org_off"))
def test_admit_org_off(i, stub, stub2, dead_url, monkeypatch):
    case = _cases("admit_org_off")["cases"][i]
    want = case["want"]
    machine, gateway = stub, stub2
    gateway.route("POST", "/v1/sdk/admit", body=case["org"])
    node_url = dead_url
    if case["machine"] != "transport":
        machine.route("POST", "/api/obs/admission/check", body=case["machine"])
        node_url = machine.url
    monkeypatch.setenv("SUPERBASED_DISCOVER", "0")
    sb.init(destination=case["destination"], node_url=node_url, org_url=gateway.url, api_key="ik_1.s", exporter=InMemorySpanExporter())
    kw = {"org_url": gateway.url} if case["via"] == "org_url" else {}
    v = sb.admit("hi", timeout=1.0, fail_closed=case.get("fail_closed", False), **kw)
    assert (v.allowed, v.decision, v.degraded) == (want["allowed"], want["decision"], want["degraded"])
    asked = [r for r in machine.requests if r["path"] == "/api/obs/admission/check"]
    assert bool(asked) is want["asked_machine"]
    assert all("authorization" not in {k.lower() for k in r["headers"]} for r in asked)
    assert sb.diagnostics()["admission_degraded"] == want["counted"]


RUNNERS |= {"experiment_strict_gate"}


@pytest.mark.parametrize("i", _ids("experiment_strict_gate"))
def test_experiment_strict_gate(i):
    from superbased_sdk import _experiments as ex

    case = _cases("experiment_strict_gate")["cases"][i]
    res = ex.ExperimentResult(name="r", skipped_sides=list(case["skipped_sides"]), failed_posts=case["failed_posts"])
    for n, it in enumerate(case["items"]):
        res.items.append(ex.ItemResult(
            item_id=f"it_{n}", input="x", error=it.get("error", ""),
            scores=[ex.Evaluation(s["name"], s["value"]) for s in it["scores"]],
            evaluator_errors=["boom"] * it.get("evaluator_errors", 0),
        ))
    assert len(ex.gate_problems(res)) == case["want"]["reasons"]
    assert ex.gate_fails(res, case["fail_under"], strict=case.get("strict", True)) is case["want"]["gate_failed"]


RUNNERS |= {"get_dataset_missing"}

# The SDK quickstart's sections (sdk-api-surface.md sections 14 to 16,
# destination.md section 6a) run in test_quickstart_contract.py.
RUNNERS |= {"auto_instrument", "service_name_default", "destination_sdk_file", "first_trace_link"}


@pytest.mark.parametrize("i", _ids("get_dataset_missing"))
def test_get_dataset_missing(i, stub, monkeypatch):
    case = _cases("get_dataset_missing")["cases"][i]
    monkeypatch.setenv("SUPERBASED_DISCOVER", "0")
    if case["datasets"] == "no_destination":
        for k in ("SUPERBASED_API_KEY", "SUPERBASED_ORG_URL"):
            monkeypatch.delenv(k, raising=False)
        sb.init(destination="online", exporter=InMemorySpanExporter())
    else:
        listed = [{"id": str(n + 7), "name": name, "item_count": 0, "latest_snapshot": 1} for n, name in enumerate(case["datasets"])]
        stub.route("GET", "/api/obs/eval/datasets", body={"api_version": "v1", "datasets": listed})
        stub.reply({"items": [], "next_cursor": ""})
        sb.init(destination="local", node_url=stub.url, exporter=InMemorySpanExporter())
    if case["want"]["found"]:
        assert sb.get_dataset(case["name"]).name == case["name"]
    else:
        with pytest.raises(sb.ExperimentError):
            sb.get_dataset(case["name"])
