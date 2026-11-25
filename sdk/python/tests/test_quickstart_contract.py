"""The SDK quickstart contract cases (lane L0) for Python:

- sdk/contract/sdk-behaviour-cases.json: auto_instrument,
  service_name_default, destination_sdk_file, first_trace_link (the
  sections that carry ``sdks``; test_behaviour_cases.py runs the rest);
- sdk/contract/credential-file-cases.json: path_cases, reader_cases;
- sdk/contract/setup-cases.json: every section (exit_codes, detection,
  destination_plan, device_flow, first_run_refusals, next_steps, secrecy,
  no_ai_gateway, no_r165).

Every section whose ``sdks`` names python has a runner here (the guard
below); the TypeScript SDK runs the same files."""

import io
import json
import logging
import os
import re
import sys
import types
from datetime import datetime, timedelta, timezone

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import superbased_sdk as sb
from superbased_sdk import _config, _credfile, _destination, _firsttrace, _instrument
from superbased_sdk._setup import cli, detect, store
from superbased_sdk._setup import plan as P

HERE = os.path.dirname(__file__)
CONTRACT = os.environ.get("SUPERBASED_CONTRACT_DIR") or os.path.join(HERE, "..", "..", "contract")
REAL_PROJECT_FACTS = _config.project_facts  # conftest replaces it per test


def load(name):
    path = os.path.join(CONTRACT, name)
    if not os.path.exists(path):
        pytest.skip(f"sdk/contract/{name} is not present (an sdist)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cases(name, section, key="cases"):
    path = os.path.join(CONTRACT, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    sec = data
    for part in section.split("/"):
        sec = sec[part]
    if "sdks" in sec and "python" not in sec["sdks"]:
        return []
    items = sec[key] if key else sec
    return [pytest.param(c, id=c.get("name", str(i))[:80]) for i, c in enumerate(items) if "python" in c.get("sdks", ["python"])]


PY_RUNNERS_QUICKSTART = {"auto_instrument", "service_name_default", "destination_sdk_file", "first_trace_link"}


def test_every_quickstart_section_for_python_has_a_runner():
    data = load("sdk-behaviour-cases.json")
    for_python = {
        k for k, v in data.items()
        if not k.startswith("_") and isinstance(v, dict) and "python" in v.get("sdks", [])
    }
    assert for_python == PY_RUNNERS_QUICKSTART


def test_every_setup_section_has_a_runner():
    data = load("setup-cases.json")
    assert "python" in data["sdks"]
    assert {k for k in data if not k.startswith("_") and k not in ("since", "sdks")} == {
        "exit_codes", "detection", "destination_plan", "device_flow", "first_run_refusals",
        "next_steps", "secrecy", "no_ai_gateway", "no_r165",
    }


# --- auto_instrument (sdk-api-surface.md 14) ------------------------------------------------


@pytest.mark.parametrize("case", cases("sdk-behaviour-cases.json", "auto_instrument"))
def test_auto_instrument(case, mem, monkeypatch, caplog):
    installed = set(case.get("installed") or [])
    host = set(case.get("host_instrumented") or [])
    after = case.get("import") == "after_init"
    fakes = {}

    def fake_class(t):
        if t.name not in fakes:
            class Fake:
                _on = False

                @property
                def _is_instrumented_by_opentelemetry(self):
                    return Fake._on or t.name in host

                def _check_dependency_conflicts(self):
                    return None

                def instrument(self, **kw):
                    Fake._on = True

                def uninstrument(self, **kw):
                    Fake._on = False

            fakes[t.name] = Fake
        return fakes[t.name]

    monkeypatch.setattr(_instrument, "installed", lambda t: t.name in installed)
    monkeypatch.setattr(_instrument, "_load", lambda t: fake_class(t) if t.name in installed else None)
    for t in _instrument.TARGETS:
        if t.name in installed and not after:
            monkeypatch.setitem(sys.modules, t.library, types.ModuleType(t.library))
        else:
            monkeypatch.delitem(sys.modules, t.library, raising=False)
    monkeypatch.delenv("SUPERBASED_INSTRUMENT", raising=False)
    if case["env"] is not None:
        monkeypatch.setenv("SUPERBASED_INSTRUMENT", case["env"])
    if case["mode"] == "attached":
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider

        trace.set_tracer_provider(TracerProvider())
    want = case["want"]
    kw = {} if case["arg"] is None else {"instrument": case["arg"]}
    if want.get("raises"):
        with pytest.raises(ValueError):
            sb.init(exporter=mem, **kw)
        return
    with caplog.at_level(logging.INFO, logger="superbased_sdk"):
        sb.init(exporter=mem, **kw)
        assert sb.diagnostics()["mode"] == case["mode"]
        if after:
            for t in _instrument.TARGETS:
                if t.name in installed:
                    _instrument._fire(t.library)
    statuses = sb.diagnostics()["instrumented"]
    try:
        got = sorted(n for n, st in statuses.items() if st == _instrument.INSTRUMENTED)
        assert got == want["instrumented"], statuses
        for name, st in want.get("statuses", {}).items():
            if st == _instrument.SKIPPED_NOT_INSTALLED:
                assert statuses.get(name) in (None, st), statuses
            else:
                assert statuses.get(name) == st, statuses
        if "then_instrument" in want:
            assert sb.instrument(case["then_instrument"]) == want["then_instrument"]
        msgs = [(r.levelno, r.getMessage()) for r in caplog.records]
        if "note_contains" in want:
            assert any(want["note_contains"] in m for lv, m in msgs if lv == logging.INFO), msgs
        if "warning_contains" in want:
            assert any(want["warning_contains"] in m for lv, m in msgs if lv >= logging.WARNING), msgs
    finally:
        sb._reset_for_tests()


# --- service_name_default (sdk-api-surface.md 15) -------------------------------------------


@pytest.mark.parametrize("case", cases("sdk-behaviour-cases.json", "service_name_default"))
def test_service_name_default(case, tmp_path, monkeypatch):
    project = case["project"]
    root = tmp_path / "root"
    root.mkdir()
    for m in project.get("manifests", []):
        d = root / m["dir"]
        d.mkdir(parents=True, exist_ok=True)
        body = "[project]\n" + (f'name = "{m["name"]}"\n' if m["name"] is not None else 'version = "1"\n')
        (d / "pyproject.toml").write_text(body)
    home = root / (project.get("home") or "home/me")
    home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    if project.get("entry"):
        entry = root / (project["entry"] + ".py")
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_text("")
        monkeypatch.setattr(sys, "argv", [str(entry)])
        monkeypatch.chdir(root)
    else:
        cwd = root / project["cwd"]
        cwd.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(sys, "argv", ["-c"])
        monkeypatch.chdir(cwd)
    monkeypatch.setattr(_config, "project_facts", REAL_PROJECT_FACTS)
    _config._project_cache.clear()
    s = _config.Settings.resolve(dict(case["env"]), service_name=case["args"].get("service_name"))
    assert (s.service_name, s.service_name_source) == (case["want"]["service_name"], case["want"]["source"])


# --- destination_sdk_file (destination.md 3, 6, 6a) ------------------------------------------

SDK_FILE_KEY = "00000000000000000000000000000002.fake-sdk-file-secret"
MACHINE_KEY = "00000000000000000000000000000003.fake-machine-secret"


def write_file(path, lines, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    os.chmod(path, mode)
    return path


@pytest.mark.parametrize("case", cases("sdk-behaviour-cases.json", "destination_sdk_file"))
def test_destination_sdk_file(case, tmp_path, stub, dead_url):
    env = {"SUPERBASED_DISCOVER": "1", **case["env"]}
    held = tmp_path / "cfg" / "superbased" / "sdk-credential"
    sdk_file = case["sdk_file"]
    if sdk_file is not None:
        when = datetime.now(timezone.utc) + (timedelta(hours=-1) if sdk_file["state"] == "expired" else timedelta(days=365))
        lines = [SDK_FILE_KEY, "gateway_url=https://u-k7x2.superbased.app"]
        if sdk_file["destination"] is not None:
            lines.append("destination=" + sdk_file["destination"])
        lines.append("expires_at=" + when.strftime("%Y-%m-%dT%H:%M:%SZ"))
        write_file(held, lines, 0o644 if sdk_file["state"] == "refused" else 0o600)
    env["SUPERBASED_CREDENTIAL_FILE"] = str(held)
    m = case["machine"]
    if m is None:
        env["SUPERBASED_NODE_URL"] = dead_url
    else:
        online = {}
        if m["credential_present"]:
            mf = write_file(tmp_path / "machine" / "cred", [MACHINE_KEY, "gateway_url=https://gw.machine.example"])
            online = {"credential_present": True, "credential_file": str(mf)}
        stub.route("GET", "/api/sdk/destination", body={
            "api_version": 1, "destination": m["destination"], "source": "config", "configured": "",
            "signed_in": m["signed_in"], "local": {"enabled": m["local_enabled"]}, "online": online, "warnings": [],
        })
        env["SUPERBASED_NODE_URL"] = stub.url
    args = case["args"]
    s = _config.Settings.resolve(env, **{k: v for k, v in args.items() if k in _config.Settings.__dataclass_fields__})
    p = _destination.resolve(s, env, explicit_destination=args.get("destination"), explicit_api_key=args.get("api_key"))
    want = case["want"]
    got = (p.destination, p.source, p.credential_source, dict(p.sdk_file)["state"])
    assert got == (want["destination"], want["source"], want["credential_source"], want["sdk_file"]), (p.warnings, p.degraded)
    if "warning_contains" in want:
        assert any(want["warning_contains"] in w for w in p.warnings), p.warnings
    if "degraded" in want:
        assert bool(p.degraded) is want["degraded"], p.degraded
    for name in ("fake-sdk-file-secret", "fake-machine-secret"):
        assert name not in json.dumps(p.summary())


# --- first_trace_link (sdk-api-surface.md 16) -----------------------------------------------


class _Ctx:
    def __init__(self, tid):
        self.trace_id = int(tid, 16)


class _Span:
    parent = None

    def __init__(self, tid):
        self.context = _Ctx(tid)


def _refusal_case(name):
    for c in load("plan-refusal-cases.json")["cases"]:
        if c["name"] == name:
            return c
    raise AssertionError(f"no plan-refusal case {name!r}")


@pytest.mark.parametrize("case", cases("sdk-behaviour-cases.json", "first_trace_link"))
def test_first_trace_link(case, capsys):
    from superbased_sdk import _planrefusal

    dest = case["destination"]
    legs = {"local": ["local"], "online": ["online"], "both": ["local", "online"]}[dest]
    bases = {"local": case["node_url"] if "local" in legs else "", "online": case["dashboard_url"] or ""}
    _firsttrace.configure(case["env"], bases, legs, stderr_tty=case["tty"])
    for ex in case["exports"]:
        for leg in legs:
            outcome = ex.get(leg)
            if outcome is None:
                continue
            refusal = None
            ok = outcome == "ok"
            if outcome not in ("ok", "failed"):
                rc = _refusal_case(outcome)
                r = _planrefusal.parse_plan_refusal(rc["status"], rc["body"], rc["headers"])
                refusal = {"message": r.message, "upgrade_url": r.upgrade_url}
            _firsttrace.on_export(leg, [_Span(ex["trace_id"])], ok, refusal)
    got = [ln for ln in capsys.readouterr().err.splitlines() if ln.startswith("superbased: ")]
    assert got == case["want"]["lines"]


# --- credential-file-cases.json ---------------------------------------------------------------

OS_PLATFORM = {"linux": "posix", "darwin": "posix", "windows": "windows"}


def _path_cases():
    path = os.path.join(CONTRACT, "credential-file-cases.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [pytest.param(c, id=c["name"]) for c in json.load(f)["path_cases"]]


def _reader_cases():
    path = os.path.join(CONTRACT, "credential-file-cases.json")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [pytest.param(c, id=c["name"]) for c in json.load(f)["reader_cases"]]


@pytest.mark.parametrize("case", _path_cases())
def test_credential_path(case):
    path, problem = _credfile.default_path(case["env"], platform=OS_PLATFORM[case["os"]], home=case["home"])
    assert (path or None) == case["want"]["path"]
    assert bool(problem) is (case["want"]["path"] is None)


VALID_TEXT = (
    "00000000000000000000000000000002.fake-sdk-file-secret\ngateway_url=https://u-k7x2.superbased.app\n"
    "destination=online\ndashboard_url=https://u-k7x2.superbased.app\nexpires_at=2027-04-15T08:00:30Z\n"
)


def _check_record(rec, want):
    state = {"valid": "ok", "absent": "absent", "refused": "refused"}[rec.state]
    assert state == want["state"], (rec.state, rec.reason, rec.error)
    if state == "refused":
        assert rec.reason == want["reason"], rec.error
        assert rec.key == ""
    if state == "ok":
        got = {
            "key_id": rec.key_id,
            "gateway_url": rec.gateway_url or None,
            "destination": rec.destination or None,
            "dashboard_url": rec.dashboard_url or None,
            "expires_at": rec.expires_at or None,
            "ignored": sorted(rec.ignored),
        }
        assert got == {k: (sorted(v) if k == "ignored" else v) for k, v in want.items() if k != "state"}
        assert "fake-sdk-file-secret" not in repr(rec) and "fake-sdk-file-secret" not in json.dumps(rec.describe())


@pytest.mark.parametrize("case", _reader_cases())
def test_credential_reader(case, tmp_path, monkeypatch):
    want = case["want"]
    if case["os"] == "windows":
        # The Windows rules through their rule table (this runner is not on
        # Windows); the format rules are the same bytes.
        facts = _credfile.FileFacts(
            platform="windows",
            reparse_point=bool(case.get("reparse_point")),
            owned_by_user=case.get("owner_sid", "self") == "self",
            under_local_appdata=case.get("location", "localappdata") == "localappdata",
            mode=0o666,
            size=len((case.get("text") or "").encode()),
        )
        reason, _why = _credfile.refusal_reason(facts)
        if reason:
            rec = _credfile.Record(path="p", state=_credfile.REFUSED, reason=reason)
        else:
            key, fields, reason = _credfile.parse_reason(case["text"].encode())
            rec = _credfile.Record(path="p", state=_credfile.REFUSED, reason=reason) if reason else _credfile.record_from("p", key, fields)
        _check_record(rec, want)
        return
    if case["os"] == "unix" and os.name == "nt":
        pytest.skip("unix rule")
    path = tmp_path / "sdk-credential"
    if case.get("kind") == "directory":
        path.mkdir()
        os.chmod(path, 0o700)
    elif case.get("symlink"):
        real = tmp_path / "real"
        real.write_text(VALID_TEXT)
        os.chmod(real, 0o600)
        path.symlink_to(real)
    elif case.get("text") is not None:
        path.write_bytes(case["text"].encode())
        os.chmod(path, int(case.get("mode", "0600"), 8))
    if case.get("owner") == "other":
        st_uid = os.lstat(path).st_uid
        monkeypatch.setattr(os, "getuid", lambda: st_uid + 1)
    _check_record(_credfile.read(str(path)), want)


# --- setup-cases.json ------------------------------------------------------------------------------

SETUP = "setup-cases.json"


def test_exit_codes():
    want = load(SETUP)["exit_codes"]
    got = {
        "0": P.EXIT_DONE, "1": P.EXIT_UNEXPECTED, "2": P.EXIT_WAITING,
        "3": P.EXIT_REFUSED, "4": P.EXIT_ENVIRONMENT, "5": P.EXIT_NOT_SEEN,
    }
    assert set(want) == set(got)
    assert all(int(k) == v for k, v in got.items())


def _detect(case, tmp_path):
    root = tmp_path / "proj"
    root.mkdir()
    for rel, text in case["files"].items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)
    installed = case.get("installed") or []
    view = detect.gather(str(root), lambda cmd, cwd, t: (0, json.dumps(installed)), lambda n: "/usr/bin/" + n)
    return view, detect.detect(view, case["setup_version"])


@pytest.mark.parametrize("case", cases(SETUP, "detection"))
def test_detection(case, tmp_path):
    view, d = _detect(case, tmp_path)
    want = case["want"]
    if want["language"] is None:
        assert d.language not in (detect.PYTHON, detect.NODE)
        return
    assert d.language == want["language"]
    if want["language"] != "python":
        return  # the TypeScript runner checks a Node project's install
    assert d.package_manager == want["package_manager"]
    assert sorted(d.targets) == sorted(want["targets"])
    assert list(d.install) == [view.python if a == "{python}" else a for a in want["install"]]
    # No next-steps text names the AI gateway (setup-cases.json no_ai_gateway).
    out = io.StringIO()
    run = cli._Run(cli.parser().parse_args([]), {}, cli.Deps(), cli.Output(cli.Secrets(), stdout=out, stderr=out), cli.Secrets())
    run.next_steps(d)
    _no_ai_gateway(out.getvalue())


@pytest.mark.parametrize("case", cases(SETUP, "destination_plan"))
def test_destination_plan(case, tmp_path, monkeypatch):
    flags = case["flags"]
    want = case["want"]
    if "--org-url" in flags or flags.count("--local") + flags.count("--online") + flags.count("--both") > 1:
        out = io.StringIO()
        monkeypatch.chdir(tmp_path)
        code = cli.run(flags, deps=_deps(), stdout=out, stderr=out)
        assert code == want["exit"]
        if "message_contains" in want:
            assert want["message_contains"] in out.getvalue()
        _no_ai_gateway(out.getvalue())
        return
    flag = next((f[2:] for f in flags if f in ("--local", "--online", "--both")), "")
    m = case["machine"]
    facts = P.Facts(
        flag=flag,
        answered=m is not None,
        signed_in=bool(m and m["signed_in"]),
        apps_on=bool(m and m["local_enabled"]),
        on_path=case["observer_on_path"],
        held=case["sdk_file"] == "valid",
        replace="--replace" in flags,
        terminal=case["tty"],
    )
    o = P.outcome(facts, case["answer"], held_destination="online" if case["sdk_file"] == "valid" else "")
    assert (o.plan, o.credential, o.approval, o.writes_file) == (want["plan"], want["credential"], want["approval"], want["writes_file"])
    assert o.exit == want.get("exit")
    if "message_contains" in want:
        assert want["message_contains"] in o.message, o.message
    if want.get("replaces_key_id"):
        assert facts.replace and facts.held and o.credential == "device_flow"
    if "phases" in want:
        assert "--key-only" in flags
        phases = P.phases(True)
        for skipped in ("detect", "install", "next_steps"):
            assert skipped not in phases
    _no_ai_gateway(o.message)


def _deps(**kw):
    from test_setup import FakeClock

    base = dict(clock=FakeClock(), open_browser=lambda url: False, which=lambda name: None, terminal=False,
                ask=lambda prompt: "", install=lambda cmd, cwd: (0, ""), arrival_wait=3.0,
                runner=lambda cmd, cwd, timeout: (0, "[]"))
    base.update(kw)
    return cli.Deps(**base)


@pytest.fixture
def world(stub, stub2, tmp_path, monkeypatch):
    from test_setup import World

    w = World(stub, stub2, tmp_path, monkeypatch)
    w.arrive()
    return w


def _script(world, scenario):
    world.polls = list(scenario.get("polls") or ["approved_with_grant"])
    create = scenario.get("create", "created")
    if create != "created":
        world.cloud.route("POST", "/v1/connect/requests", lambda req: world._answer(world.create["responses"][create]))
    redeem = scenario.get("redeem")
    if isinstance(redeem, list):
        seq = list(redeem)

        def answer(req):
            name = seq.pop(0) if len(seq) > 1 else seq[0]
            status, body, headers = world._answer(world.redeem["responses"][name])
            if "gateway_url" in body:
                body["gateway_url"] = world.org.url
            return status, body, headers

        world.org.route("POST", "/api/agent/sdk-credential/grant", answer)
    elif redeem:
        world.redeem_answer = redeem
    # The fixture poll answers with no "polls" left keep answering the last.
    if not world.polls:
        world.polls = ["pending"]


def _run(args, d=None):
    out, err = io.StringIO(), io.StringIO()
    code = cli.run(args, deps=d or _deps(), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize("case", cases(SETUP, "device_flow"))
def test_device_flow(case, world):
    _script(world, case)
    if case.get("create") != "created":
        world.polls = ["pending"]
    code, out, err = _run(["--online", "--key-only"])
    want = case["want"]
    if want["outcome"] == "continue":
        assert code == P.EXIT_DONE, out + err
    else:
        assert code == want["exit"], out + err
    assert world.cred.exists() is want["file_written"]
    if "message_contains" in want:
        assert want["message_contains"] in out, out
    if "requests" in want:
        polls = [r for r in world.cloud.requests if r["method"] == "GET"]
        assert len(polls) == want["requests"]
    _no_ai_gateway(out + err)


@pytest.mark.parametrize("case", cases(SETUP, "first_run_refusals"))
def test_first_run_refusals(case, world, monkeypatch):
    want = case["want"]
    if case["stage"] == "redeem":
        world.redeem_answer = case["fixture"]
    else:
        rc = _refusal_case(case["plan_refusal_case"])
        headers = {k: v for k, v in rc["headers"].items() if k.lower() != "content-type"}
        headers["Retry-After"] = "1"  # the exporter would otherwise wait out its timeout on a 429
        world.org.route("POST", "/v1/traces", body=rc["body"], status=rc["status"], headers=headers)
        monkeypatch.setenv("SUPERBASED_EXPORT_TIMEOUT_MS", "800")
    world.polls = ["approved_with_grant"]
    code, out, err = _run(["--online", "--key-only"])
    assert code == want["exit"], out + err
    pos = 0
    for line in want["lines"]:
        i = out.find(line, pos)
        assert i >= 0, (line, out)
        pos = i + len(line)
    for bad in want.get("no_line_contains", []):
        assert bad not in out
    assert world.cred.exists() is want["file_written"]
    assert bool([r for r in world.org.requests if r["path"] == "/v1/traces"]) is want["hello_sent"]


@pytest.mark.parametrize("case", cases(SETUP, "next_steps"))
def test_next_steps(case):
    if case["language"] != "python":
        pytest.skip("the TypeScript runner's case")
    out = io.StringIO()
    run = cli._Run(cli.parser().parse_args(["--json"]), {}, cli.Deps(), cli.Output(cli.Secrets(), json_mode=True, stdout=out, stderr=io.StringIO()), cli.Secrets())
    run.next_steps(detect.Detection(language="python", entries=(case["entry"],)))
    (ev,) = [json.loads(line) for line in out.getvalue().splitlines()]
    assert ev["phase"] == "next"
    assert ev["init_line"] == case["want"]["init_line"]
    assert case["want"]["where"] in ev["where"]


def _secrecy_cases():
    path = os.path.join(CONTRACT, SETUP)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return [pytest.param(c, j, id=f"{c['name']}-{'json' if j else 'plain'}") for c in data["secrecy"]["cases"] for j in (True, False)]


@pytest.mark.parametrize("case, json_mode", _secrecy_cases())
def test_secrecy(case, json_mode, world, monkeypatch, caplog):
    fakes = load(os.path.join("fixtures", "setup", "secrecy-fakes.json"))
    scenario = case["scenario"]
    flags = list(scenario.get("flags") or [])
    if scenario.get("sdk_file") == "valid":
        write_file(world.cred, [fakes["sdk_key"], "gateway_url=" + world.org.url, "destination=online",
                                "dashboard_url=https://u-k7x2.superbased.app", "expires_at=2027-04-15T08:00:30Z"])
    else:
        _script(world, scenario)
        flags = ["--online"]
    if scenario.get("hello") == "not_seen":
        world.arrive_after = 10 ** 6
    if scenario.get("write") == "fails":
        def read_only(path):
            raise OSError(30, "Read-only file system")

        monkeypatch.setattr(store, "_make_dirs", read_only)
    children = []
    d = _deps(install=lambda cmd, cwd: children.append((list(cmd), dict(os.environ))) or (0, ""))
    if json_mode:
        flags.append("--json")
    raised = []
    with caplog.at_level(logging.DEBUG):
        try:
            code, out, err = _run(flags, d)
        except BaseException as exc:  # noqa: BLE001 - the exception channel
            raised.append(f"{exc!r} {exc}")
            raise
    channels = {
        "stdout": out,
        "stderr": err,
        "json": "\n".join(line for line in out.splitlines() if line.startswith("{")),
        "log": "\n".join(f"{r.getMessage()} {r.args!r}" for r in caplog.records),
        "exception": "\n".join(raised),
        "argv": "\n".join(f"{c} {e}" for c, e in children),
    }
    secrets = [fakes[k] for k in ("sdk_key", "sdk_key_secret", "device_code", "redeem_secret", "key_grant")]
    redeems = [r for r in world.org.requests if r["path"] == "/api/agent/sdk-credential/grant"]
    secrets += [r["body"]["redeem_secret"] for r in redeems]
    for ch in case["want"]["channels"]:
        for v in secrets:
            assert v not in channels[ch], (ch, code)
    _no_ai_gateway(out + err)


def _forbidden():
    path = os.path.join(CONTRACT, SETUP)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)["no_ai_gateway"]["forbidden"]


def _no_ai_gateway(text):
    low = text.lower()
    for word in _forbidden():
        assert word.lower() not in low, (word, text[max(0, low.find(word.lower()) - 120): low.find(word.lower()) + 60])


def test_no_r165_in_the_setup_sources():
    forbidden = load(SETUP)["no_r165"]["forbidden_in_source"]
    folder = os.path.join(HERE, "..", "superbased_sdk", "_setup")
    names = sorted(n for n in os.listdir(folder) if n.endswith(".py"))
    assert "cli.py" in names and "cloud.py" in names
    for name in names:
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            src = f.read()
        for word in forbidden:
            assert word not in src, (name, word)


def test_no_ai_gateway_in_the_setup_sources():
    folder = os.path.join(HERE, "..", "superbased_sdk", "_setup")
    for name in sorted(n for n in os.listdir(folder) if n.endswith(".py")):
        with open(os.path.join(folder, name), encoding="utf-8") as f:
            _no_ai_gateway(f.read())


def test_key_only_runs_destination_credential_and_hello(world):
    """The lead's ruling for --key-only (Go and Java get the key file): no
    Python detection, install or init line; the hello is still sent and its
    link printed. setup-cases.json destination_plan's --key-only case lists
    destination, approve, credential and done; hello sits between them."""
    want = [c for c in load(SETUP)["destination_plan"]["cases"] if "--key-only" in c["flags"]][0]["want"]["phases"]
    code, out, err = _run(["--key-only", "--json"])
    assert code == P.EXIT_DONE, out + err
    phases = []
    for line in out.splitlines():
        ph = json.loads(line)["phase"]
        if ph not in phases:
            phases.append(ph)
    it = iter(phases)
    assert all(p in it for p in want), (want, phases)  # in order
    assert "hello" in phases and not {"detect", "install", "next"} & set(phases)
    assert "trajectories?trace=" in json.loads(out.splitlines()[-1])["trace_url"]
