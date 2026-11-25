"""The SDK-held credential file (plan 3.4, SDKQS-4): the path ladder per OS,
the read rules (unix on real files, Windows through the rule table), the
record's fields, and the new destination rung ``sdk_file`` with the third
credential rung (R10)."""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import superbased_sdk as sb
from superbased_sdk import _credfile as CF
from superbased_sdk import _destination
from superbased_sdk._config import Settings

KEY = "00000000000000000000000000000001.FAKE-sdk-key-secret-for-contract-tests-only"
SECRET = KEY.split(".", 1)[1]
GW = "https://u-k7x2.superbased.app"


def write(path, lines, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, mode)
    return path


def held(tmp_path, monkeypatch, destination="online", extra=(), mode=0o600, gateway=GW, dashboard=GW):
    lines = [KEY]
    if gateway is not None:
        lines.append("gateway_url=" + gateway)
    if destination is not None:
        lines.append("destination=" + destination)
    if dashboard is not None:
        lines.append("dashboard_url=" + dashboard)
    lines += list(extra)
    p = write(tmp_path / "cfg" / "superbased" / "sdk-credential", lines, mode)
    monkeypatch.setenv("SUPERBASED_CREDENTIAL_FILE", str(p))
    return p


# --- the path ladder ----------------------------------------------------------------


@pytest.mark.parametrize(
    "platform, env, home, want",
    [
        ("posix", {}, "/home/me", "/home/me/.config/superbased/sdk-credential"),
        ("posix", {"XDG_CONFIG_HOME": "/xdg"}, "/home/me", "/xdg/superbased/sdk-credential"),
        ("posix", {"XDG_CONFIG_HOME": "relative/xdg"}, "/home/me", "/home/me/.config/superbased/sdk-credential"),
        ("posix", {"SUPERBASED_CREDENTIAL_FILE": "/tmp/other"}, "/home/me", "/tmp/other"),
        ("windows", {"LOCALAPPDATA": "C:\\Users\\me\\AppData\\Local"}, "C:\\Users\\me", "C:\\Users\\me\\AppData\\Local\\superbased\\sdk-credential"),
        ("windows", {"SUPERBASED_CREDENTIAL_FILE": "D:\\keys\\k"}, "", "D:\\keys\\k"),
        ("windows", {}, "C:\\Users\\me", ""),
        ("posix", {}, "", ""),
    ],
)
def test_path_ladder(platform, env, home, want):
    path, problem = CF.default_path(env, platform=platform, home=home)
    assert path == want
    assert bool(problem) is (want == "")


# --- the read rules ------------------------------------------------------------------


@pytest.mark.parametrize(
    "facts, refused",
    [
        (CF.FileFacts(), ""),
        (CF.FileFacts(symlink=True), "symlink"),
        (CF.FileFacts(regular=False), "regular"),
        (CF.FileFacts(mode=0o640), "other users"),
        (CF.FileFacts(mode=0o604), "other users"),
        (CF.FileFacts(owned_by_user=False), "another user"),
        (CF.FileFacts(size=4097), "4096"),
        (CF.FileFacts(platform="windows", mode=0o666, under_local_appdata=True), ""),
        (CF.FileFacts(platform="windows", reparse_point=True, under_local_appdata=True), "reparse point"),
        (CF.FileFacts(platform="windows", under_local_appdata=False), "LOCALAPPDATA"),
        (CF.FileFacts(platform="windows", under_local_appdata=None), "LOCALAPPDATA"),
        (CF.FileFacts(platform="windows", owned_by_user=False, under_local_appdata=True), "another user"),
        (CF.FileFacts(platform="windows", owned_by_user=None, under_local_appdata=True), "could not be confirmed"),
    ],
)
def test_refusal_rules(facts, refused):
    why = CF.refusal(facts)
    assert (why == "") if not refused else (refused in why), why


def test_reads_a_valid_file(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch, extra=["expires_at=2027-04-15T08:00:30Z", "future_field=x"])
    rec = CF.read(str(p))
    assert rec.state == CF.VALID and rec.usable
    assert (rec.key, rec.key_id, rec.gateway_url, rec.destination, rec.dashboard_url, rec.expires_at) == (
        KEY, KEY.split(".")[0], GW, "online", GW, "2027-04-15T08:00:30Z",
    )
    assert rec.warnings == ()
    assert SECRET not in repr(rec) and SECRET not in json.dumps(rec.describe())


def test_reads_the_fixture_file_when_present(tmp_path, monkeypatch):
    fx = os.path.join(os.path.dirname(__file__), "..", "..", "contract", "fixtures", "setup", "sdk-credential-file.json")
    if not os.path.exists(fx):
        pytest.skip("sdk/contract fixtures not present")
    with open(fx, encoding="utf-8") as f:
        lines = json.load(f)["lines"]
    p = write(tmp_path / "sdk-credential", lines)
    rec = CF.read(str(p))
    assert rec.usable and rec.destination == "online"


@pytest.mark.parametrize(
    "mode, want",
    [(0o600, CF.VALID), (0o400, CF.VALID), (0o640, CF.REFUSED), (0o604, CF.REFUSED), (0o660, CF.REFUSED)],
)
def test_unix_mode_rule_on_a_real_file(tmp_path, monkeypatch, mode, want):
    if os.name == "nt":
        pytest.skip("unix rule")
    p = held(tmp_path, monkeypatch, mode=mode)
    assert CF.read(str(p)).state == want


def test_symlink_is_refused(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("unix rule")
    real = held(tmp_path, monkeypatch)
    link = tmp_path / "link"
    link.symlink_to(real)
    rec = CF.read(str(link))
    assert rec.state == CF.REFUSED and "symlink" in rec.error and rec.key == ""


def test_missing_file_is_absent_without_a_warning(tmp_path):
    rec = CF.read(str(tmp_path / "none"))
    assert rec.state == CF.ABSENT and rec.error == "" and rec.warnings == ()


def test_a_directory_is_refused(tmp_path):
    d = tmp_path / "dir"
    d.mkdir()
    os.chmod(d, 0o700)
    assert "regular" in CF.read(str(d)).error


def test_foreign_owner_is_refused(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("unix rule")
    p = held(tmp_path, monkeypatch)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(p).st_uid + 1)
    assert "another user" in CF.read(str(p)).error


@pytest.mark.parametrize(
    "lines, refused",
    [
        (["nodot"], True),
        (["id.sec ret"], True),
        (["id. secret"], True),
        ([".secret"], True),
        (["id."], True),
        ([KEY, "no equals sign"], True),
        ([KEY, "=value"], True),
        ([KEY, "unknown_name=ignored", "gateway_url=" + GW], False),
        ([KEY + "\u00e9"], True),
    ],
)
def test_format_rules(tmp_path, lines, refused):
    p = tmp_path / "sdk-credential"
    p.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    os.chmod(p, 0o600)
    rec = CF.read(str(p))
    assert (rec.state == CF.REFUSED) is refused, rec.error
    if refused:
        assert rec.key == "" and SECRET not in rec.error


def test_over_4096_bytes_is_refused(tmp_path):
    p = write(tmp_path / "k", [KEY, "pad=" + "x" * 4100])
    rec = CF.read(str(p))
    assert rec.state == CF.REFUSED and "4096" in rec.error


@pytest.mark.parametrize(
    "gateway",
    ["http://u-k7x2.superbased.app", "https://u-k7x2.superbased.app/v1", "https://me:pw@u-k7x2.superbased.app", "not a url"],
)
def test_gateway_problems_make_the_key_unusable(tmp_path, monkeypatch, gateway):
    p = held(tmp_path, monkeypatch, gateway=gateway)
    rec = CF.read(str(p))
    assert rec.state == CF.VALID and not rec.usable and rec.gateway_url == ""
    assert any("gateway address" in w for w in rec.warnings)


def test_no_gateway_line_is_unusable(tmp_path, monkeypatch):
    rec = CF.read(str(held(tmp_path, monkeypatch, gateway=None)))
    assert not rec.usable and any("no gateway" in w for w in rec.warnings)


def test_invalid_destination_is_ignored_with_a_warning(tmp_path, monkeypatch):
    rec = CF.read(str(held(tmp_path, monkeypatch, destination="local")))
    assert rec.usable and rec.destination == "" and any("not online or both" in w for w in rec.warnings)


@pytest.mark.parametrize("dashboard", ["http://u-k7x2.superbased.app", "https://x.example/?a=1", "ftp://x"])
def test_dashboard_not_https_is_ignored(tmp_path, monkeypatch, dashboard):
    rec = CF.read(str(held(tmp_path, monkeypatch, dashboard=dashboard)))
    assert rec.usable and rec.dashboard_url == "" and any("dashboard" in w for w in rec.warnings)


def test_loopback_http_gateway_is_allowed(tmp_path, monkeypatch):
    rec = CF.read(str(held(tmp_path, monkeypatch, gateway="http://127.0.0.1:9999")))
    assert rec.usable and rec.gateway_url == "http://127.0.0.1:9999"


@pytest.mark.parametrize(
    "value, ok",
    [
        ("2027-04-15T08:00:30Z", True),
        ("2027-04-15T08:00:30.123456789Z", True),
        ("2027-04-15T08:00:30+02:00", True),
        ("2027-04-15T08:00:30", False),
        ("tomorrow", False),
    ],
)
def test_parse_time(value, ok):
    assert (CF.parse_time(value) is not None) is ok


def test_expiry_warning_from_14_days():
    now = datetime(2027, 4, 1, tzinfo=timezone.utc)
    rec = lambda t: CF.Record(path="/p", state=CF.VALID, expires_at=t)  # noqa: E731
    assert CF.expiry_warning(rec((now + timedelta(days=30)).isoformat()), now) == ""
    assert "expires" in CF.expiry_warning(rec((now + timedelta(days=13)).isoformat()), now)
    assert "expired" in CF.expiry_warning(rec((now - timedelta(days=1)).isoformat()), now)
    assert CF.expiry_warning(rec(""), now) == ""


# --- the destination and credential rungs (destination.md section 3) ------------------


def machine(stub, *, destination="local", signed_in=False, credential_file="", gateway_line="", enabled=True, dashboard=""):
    online = {}
    if credential_file:
        online = {"credential_present": True, "credential_file": credential_file}
        if dashboard:
            online["dashboard_url"] = dashboard
    stub.route("GET", "/api/sdk/destination", body={
        "api_version": 1, "destination": destination, "source": "config", "configured": "", "signed_in": signed_in,
        "local": {"enabled": enabled}, "online": online, "warnings": [],
    })


def resolve(env, **kw):
    s = Settings.resolve(env, **{k: v for k, v in kw.items() if k in Settings.__dataclass_fields__})
    return _destination.resolve(s, env, explicit_destination=kw.get("destination"), explicit_api_key=kw.get("api_key"))


def base_env(stub=None):
    env = {"SUPERBASED_DISCOVER": "1" if stub else "0"}
    env["SUPERBASED_NODE_URL"] = stub.url if stub else "http://127.0.0.1:1"
    return env


def test_sdk_file_and_no_machine_is_online(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch)
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env)
    assert (plan.destination, plan.source, plan.credential_source) == ("online", "sdk_file", "sdk_file")
    assert plan.gateway_url == GW and plan.dashboard_url == GW and plan.online_ready
    assert [d.name for d in plan.exporters] == ["online"]
    assert dict(plan.sdk_file)["state"] == "used"
    assert plan.online_headers() == {"Authorization": "Bearer " + KEY}
    assert SECRET not in json.dumps(plan.summary())


def test_sdk_file_beats_the_machine_default_when_not_signed_in(tmp_path, monkeypatch, stub):
    p = held(tmp_path, monkeypatch)
    machine(stub, destination="local")
    env = {**base_env(stub), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env)
    assert (plan.destination, plan.source, plan.credential_source) == ("online", "sdk_file", "sdk_file")


def test_sdk_file_both_with_the_machine_on_is_both(tmp_path, monkeypatch, stub):
    p = held(tmp_path, monkeypatch, destination="both")
    machine(stub, destination="local", enabled=True)
    env = {**base_env(stub), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env)
    assert (plan.destination, plan.source) == ("both", "sdk_file")
    assert [d.name for d in plan.exporters] == ["local", "online"]


def test_explicit_local_never_reads_the_file(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch)
    read = []
    monkeypatch.setattr(CF, "read", lambda *a, **k: read.append(a) or CF.Record())
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env, destination="local")
    assert (plan.destination, plan.source) == ("local", "argument") and read == []
    plan = resolve({**env, "SUPERBASED_DESTINATION": "local"})
    assert (plan.destination, plan.source) == ("local", "env") and read == []
    assert dict(plan.sdk_file)["state"] == "not_read"


def test_env_destination_wins_and_the_file_gives_the_key(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch, destination="online")
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p), "SUPERBASED_DESTINATION": "both"}
    plan = resolve(env)
    assert (plan.destination, plan.source, plan.credential_source) == ("both", "env", "sdk_file")
    assert plan.online_ready


def test_a_refused_file_falls_to_the_next_rung_with_a_warning(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch, mode=0o644)
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env)
    assert (plan.destination, plan.source) == ("local", "default")
    assert any("readable by other users" in w for w in plan.warnings)
    assert plan.credential_source == ""


def test_signed_in_machine_wins_the_credential_and_names_the_unused_file(tmp_path, monkeypatch, stub):
    p = held(tmp_path, monkeypatch)
    machine_file = write(tmp_path / "machine" / "cred", ["mk_1.machine-secret", "gateway_url=https://gw.machine.example"])
    machine(stub, destination="both", signed_in=True, credential_file=str(machine_file), dashboard="https://board.machine.example")
    env = {**base_env(stub), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env)
    # The destination: the file's choice beats the machine default (R10).
    assert (plan.destination, plan.source) == ("online", "sdk_file")
    # The credential: the machine's record beats the file's (R10).
    assert plan.credential_source == "file" and plan.gateway_url == "https://gw.machine.example"
    assert plan.dashboard_url == "https://board.machine.example"
    assert dict(plan.sdk_file)["state"] == "unused"
    assert any(str(p) in w and "unused" in w for w in plan.warnings)


def test_an_org_url_for_another_org_does_not_take_the_file_key(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch)
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p), "SUPERBASED_ORG_URL": "https://other.example.com"}
    plan = resolve(env)
    assert plan.credential_source == "" and not plan.online_ready
    assert any("not used" in w for w in plan.warnings)


def test_the_same_org_url_takes_the_file_key(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch)
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p), "SUPERBASED_ORG_URL": GW + "/"}
    plan = resolve(env)
    assert plan.credential_source == "sdk_file" and plan.online_ready


def test_an_env_key_wins_over_the_file(tmp_path, monkeypatch):
    p = held(tmp_path, monkeypatch)
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p), "SUPERBASED_API_KEY": "ik_env.s", "SUPERBASED_ORG_URL": "https://gw.example.com"}
    plan = resolve(env)
    assert plan.credential_source == "env" and plan.gateway_url == "https://gw.example.com"
    assert dict(plan.sdk_file)["state"] == "unused"


def test_an_expiring_key_warns(tmp_path, monkeypatch):
    soon = (datetime.now(timezone.utc) + timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    p = held(tmp_path, monkeypatch, extra=["expires_at=" + soon])
    env = {**base_env(), "SUPERBASED_CREDENTIAL_FILE": str(p)}
    plan = resolve(env)
    assert plan.credential_source == "sdk_file"
    assert any("expires" in w and "setup" in w for w in plan.warnings)


def test_init_exports_online_with_the_file(tmp_path, monkeypatch, stub):
    stub.route("POST", "/v1/traces", body={})
    p = held(tmp_path, monkeypatch, gateway=stub.url, dashboard=None)
    sb.init()
    with sb.span("x"):
        pass
    assert sb.flush(5)
    d = sb.diagnostics()
    assert (d["destination"], d["destination_source"], d["credential_source"]) == ("online", "sdk_file", "sdk_file")
    assert d["sdk_file"]["path"] == str(p) and d["sdk_file"]["state"] == "used"
    assert SECRET not in json.dumps(d, default=str)
    (req,) = [r for r in stub.requests if r["path"] == "/v1/traces"]
    assert {k.lower(): v for k, v in req["headers"].items()}.get("authorization") == "Bearer " + KEY


# --- the AI gateway helpers (SDKQS-10) ------------------------------------------------


def test_ai_gateway_reads_the_file_address_and_never_sends_the_sdk_key(tmp_path, monkeypatch):
    held(tmp_path, monkeypatch)
    sb.init(exporter=__import__("opentelemetry.sdk.trace.export.in_memory_span_exporter", fromlist=["x"]).InMemorySpanExporter())
    ep = sb.gateway_endpoint("openai")
    assert (ep.source, ep.base_url) == ("org", GW + "/ai/openai/v1")
    monkeypatch.delenv("SUPERBASED_AI_GATEWAY_KEY", raising=False)
    with pytest.raises(sb.GatewayNotConfigured) as e:
        sb._aigateway._client_key(ep, None)
    assert e.value.problem == "no_key"
    assert SECRET not in str(e.value)
