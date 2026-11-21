"""W2-7 (D18): the destination option, loopback discovery, the credential
file, dual export and the degraded cases (contracts/destination.md)."""

import os

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _destination as D
from superbased_sdk._config import Settings


def discovery_body(destination="both", gateway="", cred_file="", present=False, enabled=True, signed_in=True, warnings=()):
    return {
        "api_version": 1,
        "destination": destination,
        "source": "default_signed_in",
        "configured": "",
        "signed_in": signed_in,
        "local": {
            "enabled": enabled,
            "otlp_traces_url": "http://127.0.0.1:4318/v1/traces",
            "admission_url": "http://127.0.0.1:8081/api/obs/admission/check",
        },
        "online": {"gateway_url": gateway, "credential_present": present, "credential_file": cred_file, "scopes": ["admit"]},
        "warnings": list(warnings),
    }


@pytest.fixture
def machine(stub, monkeypatch):
    """The stub as this machine's dashboard API, discovery turned on."""
    monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
    monkeypatch.setenv("SUPERBASED_NODE_URL", stub.url)
    return stub


def cred_file(tmp_path, content="ik_1.s3cret\n", mode=0o600):
    p = tmp_path / "sbo-sdk-credential-v1.sdk-credential"
    p.write_text(content)
    os.chmod(p, mode)
    return str(p)


def plan(env=None, **explicit):
    env = dict(env or {})
    s = Settings.resolve(env, **{k: v for k, v in explicit.items() if k in Settings.__dataclass_fields__})
    return D.resolve(
        s, env, explicit_destination=explicit.get("destination"), explicit_endpoint=explicit.get("endpoint"), explicit_api_key=explicit.get("api_key")
    )


# --- precedence ---------------------------------------------------------------------


def test_default_is_local_without_a_machine():
    p = plan({"SUPERBASED_DISCOVER": "0"})
    assert (p.destination, p.source) == ("local", "default")
    assert [d.name for d in p.exporters] == ["local"]
    assert p.exporters[0].endpoint == "http://127.0.0.1:4318/v1/traces"


def test_argument_beats_env_beats_machine(machine):
    machine.route("GET", "/api/sdk/destination", body=discovery_body("both"))
    env = {"SUPERBASED_NODE_URL": machine.url, "SUPERBASED_DESTINATION": "local"}
    assert plan(env, destination="online", org_url="http://gw", api_key="k").source == "argument"
    D.reset_cache()
    p = plan(env)
    assert (p.destination, p.source) == ("local", "env")
    # The machine is asked for its receiver (no endpoint named, L-01), but its
    # default destination does not override the env's.
    assert machine.paths("GET") == ["/api/sdk/destination"]
    D.reset_cache()
    machine.requests.clear()
    p = plan({**env, "SUPERBASED_OTLP_ENDPOINT": "http://127.0.0.1:24318/v1/traces"})
    assert (p.destination, p.source) == ("local", "env")
    assert machine.paths("GET") == []  # an endpoint named: discovery not needed
    D.reset_cache()
    env.pop("SUPERBASED_DESTINATION")
    p = plan(env)
    assert (p.destination, p.source, p.signed_in) == ("both", "machine", True)


def test_invalid_value_falls_through_with_a_warning():
    p = plan({"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": "cloud"})
    assert p.destination == "local"
    assert any("cloud" in w for w in p.warnings)


def test_discovery_failures_fall_back_to_local(machine, dead_url):
    machine.route("GET", "/api/sdk/destination", body={"api_version": 2, "destination": "both"})
    p = plan({"SUPERBASED_NODE_URL": machine.url})
    assert (p.destination, p.source) == ("local", "default") and "api_version" in p.notes[0]
    D.reset_cache()
    p = plan({"SUPERBASED_NODE_URL": dead_url})
    assert p.destination == "local" and p.notes


def test_discovery_only_asks_a_loopback_machine():
    body, err = D.discover("http://192.0.2.10:8081")
    assert body is None and "not a loopback" in err


def test_discovery_is_cached_and_bounded(machine):
    machine.route("GET", "/api/sdk/destination", body=discovery_body("local"))
    plan({"SUPERBASED_NODE_URL": machine.url})
    plan({"SUPERBASED_NODE_URL": machine.url})
    assert machine.paths("GET") == ["/api/sdk/destination"]
    assert D.DISCOVERY_TIMEOUT == 0.5


def test_machine_warnings_and_local_off(machine):
    machine.route("GET", "/api/sdk/destination", body=discovery_body("local", enabled=False, warnings=["no gateway published"]))
    p = plan({"SUPERBASED_NODE_URL": machine.url})
    assert "machine: no gateway published" in p.warnings
    assert any("observability is off" in w for w in p.warnings)


# --- gateway and credential ----------------------------------------------------------


def test_credential_from_the_machine_file(machine, tmp_path):
    f = cred_file(tmp_path, "ik_1.s3cret\ngateway_url=https://gw.example:4318\n")
    machine.route("GET", "/api/sdk/destination", body=discovery_body("both", gateway="https://gw.example:4318", cred_file=f, present=True))
    p = plan({"SUPERBASED_NODE_URL": machine.url})
    assert p.online_ready and p.credential_source == "file"
    online = [d for d in p.exporters if d.name == "online"][0]
    assert online.endpoint == "https://gw.example:4318/v1/traces"
    assert dict(online.headers)["Authorization"] == "Bearer ik_1.s3cret"
    local = [d for d in p.exporters if d.name == "local"][0]
    assert "Authorization" not in dict(local.headers)  # never to the machine
    assert p.admit_url == "https://gw.example:4318/v1/sdk/admit"
    assert "s3cret" not in repr(p) and "s3cret" not in str(p.summary())


@pytest.mark.skipif(os.name == "nt", reason="unix file rules")
@pytest.mark.parametrize(
    "content,mode,why",
    [
        ("ik_1.s\n", 0o644, "readable by other users"),
        ("ik_1.s\nextra\n", 0o600, "not one key line"),
        ("no-dot\n", 0o600, "not one key line"),
        ("ik_1.s e\n", 0o600, "not one key line"),
    ],
)
def test_credential_file_rules(tmp_path, content, mode, why):
    key, err = D.read_credential_file(cred_file(tmp_path, content, mode))
    assert key == "" and why in err


@pytest.mark.skipif(os.name == "nt", reason="unix file rules")
def test_discovery_never_decides_where_the_key_goes(machine, tmp_path):
    """Review E-04 (ruling D29): a process answering discovery in the
    machine's place names a remote gateway and remote local URLs. The key
    goes only to the address in the owner-only key file, and the local URLs
    must be loopback."""
    f = cred_file(tmp_path, "ik_1.s3cret\ngateway_url=https://gw.example:4318\n")
    body = discovery_body("both", gateway="https://attacker.example", cred_file=f, present=True)
    body["local"] = {"enabled": True, "otlp_traces_url": "https://attacker.example/v1/traces", "admission_url": "https://attacker.example/check"}
    machine.route("GET", "/api/sdk/destination", body=body)
    p = plan({"SUPERBASED_NODE_URL": machine.url})
    endpoints = [d.endpoint for d in p.exporters]
    assert endpoints == ["http://127.0.0.1:4318/v1/traces", "https://gw.example:4318/v1/traces"]
    assert all("attacker" not in u for u in endpoints + [p.admit_url, p.gateway_url])
    assert any("non-loopback otlp_traces_url" in w for w in p.warnings)

    # A key file with no gateway line: discovery's address is still not used.
    f2 = cred_file(tmp_path, "ik_1.s3cret\n")
    machine.route("GET", "/api/sdk/destination", body=discovery_body("online", gateway="https://attacker.example", cred_file=f2, present=True))
    D.reset_for_tests()
    p = plan({"SUPERBASED_NODE_URL": machine.url})
    assert not p.online_ready and p.exporters == () and "gateway address" in p.degraded

    # An env key with no org URL uses the key file's address, not discovery's.
    f3 = cred_file(tmp_path, "ik_1.s3cret\ngateway_url=https://gw.example:4318\n")
    machine.route("GET", "/api/sdk/destination", body=discovery_body("online", gateway="https://attacker.example", cred_file=f3, present=True))
    D.reset_for_tests()
    p = plan({"SUPERBASED_NODE_URL": machine.url, "SUPERBASED_API_KEY": "ik_2.env"})
    assert p.gateway_url == "https://gw.example:4318" and p.credential_source == "env"


@pytest.mark.skipif(os.name == "nt", reason="unix file rules")
@pytest.mark.parametrize(
    "content,gateway,warn",
    [
        ("ik_1.s\ngateway_url=https://gw.example\n", "https://gw.example", ""),
        ("ik_1.s\nlater_field=x\ngateway_url=https://gw.example/\n", "https://gw.example", ""),
        ("ik_1.s\ngateway_url=http://127.0.0.1:4318\n", "http://127.0.0.1:4318", ""),
        ("ik_1.s\ngateway_url=http://gw.example\n", "", "plain http"),
        ("ik_1.s\ngateway_url=https://u:p@gw.example\n", "", "user name"),
        ("ik_1.s\ngateway_url=https://gw.example/v1/traces\n", "", "base address"),
    ],
)
def test_credential_record_gateway(tmp_path, content, gateway, warn):
    key, gw, err = D.read_credential_record(cred_file(tmp_path, content))
    assert key == "ik_1.s" and gw == gateway and warn in err


@pytest.mark.skipif(os.name == "nt", reason="unix file rules")
def test_credential_file_symlink_refused(tmp_path):
    real = cred_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    assert D.read_credential_file(str(link))[1].endswith("symlink; refused")
    assert D.read_credential_file(real) == ("ik_1.s3cret", "")
    assert D.read_credential_file(str(tmp_path / "missing"))[0] == ""


def test_argument_and_env_beat_the_file(machine, tmp_path):
    machine.route("GET", "/api/sdk/destination", body=discovery_body("both", gateway="https://gw", cred_file=cred_file(tmp_path), present=True))
    env = {"SUPERBASED_NODE_URL": machine.url, "SUPERBASED_API_KEY": "ik_env.x", "SUPERBASED_ORG_URL": "https://org"}
    p = plan(env)
    assert p.credential_source == "env" and p.gateway_url == "https://org"
    assert plan(env, api_key="ik_arg.y").credential_source == "argument"


def test_otel_env_configures_local_only_for_local():
    env = {"SUPERBASED_DISCOVER": "0", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4318", "OTEL_EXPORTER_OTLP_HEADERS": "x-team=a"}
    p = plan(env)
    assert p.exporters[0].endpoint == "http://collector:4318/v1/traces" and dict(p.exporters[0].headers)["x-team"] == "a"
    env.update({"SUPERBASED_DESTINATION": "both", "SUPERBASED_ORG_URL": "https://gw", "SUPERBASED_API_KEY": "ik.k"})
    p = plan(env)
    by = {d.name: d for d in p.exporters}
    assert by["local"].endpoint == "http://127.0.0.1:4318/v1/traces" and "x-team" not in dict(by["local"].headers)
    assert by["online"].endpoint == "https://gw/v1/traces" and "x-team" not in dict(by["online"].headers)


def test_remote_custom_endpoint_keeps_the_bearer_key():
    p = plan({"SUPERBASED_DISCOVER": "0", "SUPERBASED_OTLP_ENDPOINT": "https://collector/v1/traces", "SUPERBASED_API_KEY": "ik.k"})
    assert dict(p.exporters[0].headers)["Authorization"] == "Bearer ik.k"
    p = plan({"SUPERBASED_DISCOVER": "0", "SUPERBASED_API_KEY": "ik.k"})
    assert "Authorization" not in dict(p.exporters[0].headers)  # loopback: never


def test_gateway_and_key_without_a_machine_infer_online():
    p = plan({"SUPERBASED_DISCOVER": "0", "SUPERBASED_ORG_URL": "https://gw", "SUPERBASED_API_KEY": "ik.k"})
    assert (p.destination, p.source) == ("online", "inferred")
    assert [d.name for d in p.exporters] == ["online"]


# --- degraded cases -------------------------------------------------------------------


def test_online_without_credential_exports_nothing():
    p = plan({"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": "online", "SUPERBASED_ORG_URL": "https://gw"})
    assert p.exporters == () and "nothing is exported" in p.degraded and "sign-in" in p.degraded
    assert p.admit_url.endswith("/api/obs/admission/check")  # admit falls back to the machine


def test_both_without_gateway_exports_locally():
    p = plan({"SUPERBASED_DISCOVER": "0", "SUPERBASED_DESTINATION": "both", "SUPERBASED_API_KEY": "ik.k"})
    assert [d.name for d in p.exporters] == ["local"] and "this machine only" in p.degraded


def test_init_degraded_online_counts_drops_and_reports(monkeypatch, caplog):
    monkeypatch.setenv("SUPERBASED_DESTINATION", "online")
    sb.init()
    with sb.span("lost"):
        pass
    d = sb.diagnostics()
    assert d["destination"] == "online" and d["destinations"] == [] and d["dropped_spans"] == 1
    assert "nothing is exported" in d["degraded"]
    assert sum("nothing is exported" in r.getMessage() for r in caplog.records) == 1
    sb.init()  # logged once per process
    assert sum("nothing is exported" in r.getMessage() for r in caplog.records) == 1


# --- dual export ---------------------------------------------------------------------


def test_both_exports_to_each_destination(monkeypatch):
    local, online = InMemorySpanExporter(), InMemorySpanExporter()
    monkeypatch.setenv("SUPERBASED_ORG_URL", "https://gw.example")
    monkeypatch.setenv("SUPERBASED_API_KEY", "ik.k")
    sb.init(destination="both", exporter={"local": local, "online": online})
    with sb.span("twice"):
        pass
    assert sb.flush(5)
    assert [s.name for s in local.get_finished_spans()] == ["twice"]
    assert [s.name for s in online.get_finished_spans()] == ["twice"]
    d = sb.diagnostics()
    assert [x["name"] for x in d["destinations"]] == ["local", "online"]
    assert d["destination_source"] == "argument"


def test_one_down_destination_never_blocks_the_other(stub, dead_url, monkeypatch):
    """Real OTLP/HTTP exporters: the gateway is down, the machine still gets
    every span, and the failure is counted."""
    monkeypatch.setenv("SUPERBASED_OTLP_ENDPOINT", stub.url + "/v1/traces")
    sb.init(destination="both", org_url=dead_url, api_key="ik.k", export_timeout=0.3, shutdown_timeout=1.0)
    with sb.span("a"):
        pass
    sb.flush(1.0)
    assert "/v1/traces" in stub.paths("POST")
    posted = [r for r in stub.requests if r["path"] == "/v1/traces"]
    assert posted and "authorization" not in {k.lower() for k in posted[0]["headers"]}  # the machine never gets the key
    assert sb.diagnostics()["failed_exports"] >= 1


@pytest.mark.parametrize("finish", ["shutdown", "flush"])
def test_a_down_machine_never_costs_the_online_copy(stub, dead_url, monkeypatch, finish):
    """The machine is down and listed first; its exporter keeps retrying for
    longer than the whole shutdown budget. The online copy still arrives:
    each destination is flushed on its own, not after the other."""
    monkeypatch.setenv("SUPERBASED_OTLP_ENDPOINT", dead_url + "/v1/traces")
    sb.init(destination="both", org_url=stub.url, api_key="ik.k", export_timeout=4.0, shutdown_timeout=1.5)
    assert [x["name"] for x in sb.diagnostics()["destinations"]] == ["local", "online"]
    with sb.span("kept"):
        pass
    if finish == "shutdown":
        sb.shutdown()
    else:
        sb.flush()
    posted = [r for r in stub.requests if r["path"] == "/v1/traces"]
    assert posted, "the online copy was not sent while the machine was down"
    assert {k.lower(): v for k, v in posted[0]["headers"].items()}["authorization"] == "Bearer ik.k"


def test_online_exporter_sends_the_bearer_key(stub, monkeypatch):
    sb.init(destination="online", org_url=stub.url, api_key="ik_9.secret", export_timeout=1.0)
    with sb.span("o"):
        pass
    assert sb.flush(3)
    r = [r for r in stub.requests if r["path"] == "/v1/traces"][0]
    hdrs = {k.lower(): v for k, v in r["headers"].items()}
    assert hdrs["authorization"] == "Bearer ik_9.secret" and r["raw"]


def test_reinit_with_new_destination_rebuilds_exporters(monkeypatch):
    a, b = InMemorySpanExporter(), InMemorySpanExporter()
    sb.init(exporter={"local": a, "online": b})
    assert [x["name"] for x in sb.diagnostics()["destinations"]] == ["local"]
    sb.init(destination="online", org_url="https://gw", api_key="ik.k", exporter={"local": a, "online": b})
    with sb.span("x"):
        pass
    assert sb.flush(5)
    assert [s.name for s in b.get_finished_spans()] == ["x"]


# --- admit() routing -------------------------------------------------------------------


def test_admit_follows_the_destination(stub, monkeypatch):
    stub.reply({"allowed": True})
    sb.init(destination="online", org_url=stub.url, api_key="ik.k", exporter=InMemorySpanExporter())
    sb.admit("hi")
    r = stub.requests[-1]
    assert r["path"] == "/v1/sdk/admit" and r["headers"]["Authorization"] == "Bearer ik.k"


def test_admit_local_never_gets_the_credential(machine, monkeypatch):
    machine.reply({"allowed": True})
    machine.route("GET", "/api/sdk/destination", body=discovery_body("local"))
    monkeypatch.setenv("SUPERBASED_API_KEY", "ik.k")
    body = discovery_body("local")
    body["local"]["admission_url"] = machine.url + "/api/obs/admission/check"
    machine.route("GET", "/api/sdk/destination", body=body)
    sb.init(exporter=InMemorySpanExporter())
    with sb.propagate_attributes(user="alice", session_id="s9"):
        sb.admit("hi")
    r = [r for r in machine.requests if r["method"] == "POST"][-1]
    assert r["path"] == "/api/obs/admission/check" and "Authorization" not in r["headers"]
    assert r["body"]["user"] == "alice" and r["body"]["session"] == "s9"
