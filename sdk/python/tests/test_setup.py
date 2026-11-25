"""superbased-sdk setup (plan 3.5 to 3.8): the planner's tables (one case
per row), detection, the online device sign-in against stub servers
serving sdk/contract/fixtures/setup/*.json, the local enable, the hello and
its arrival, --status, --forget, --key-only, and the boundaries (standard
library only, never imported by the runtime, never the machine's credential
routes)."""

import ast
import base64
import copy
import hashlib
import io
import json
import os
import re
import subprocess
import sys

import pytest

import superbased_sdk as sb
from superbased_sdk import _credfile
from superbased_sdk._setup import cli, cloud, detect, hello, store
from superbased_sdk._setup import plan as P

HERE = os.path.dirname(__file__)
PKG = os.path.join(HERE, "..", "superbased_sdk")
CONTRACT = os.environ.get("SUPERBASED_CONTRACT_DIR") or os.path.join(HERE, "..", "..", "contract")
FIXTURES = os.path.join(CONTRACT, "fixtures", "setup")


def fixture(name):
    path = os.path.join(FIXTURES, name + ".json")
    if not os.path.exists(path):
        pytest.skip("sdk/contract/fixtures/setup is not present (lane L0)")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# --- the phase table (with --key-only) ------------------------------------------------


@pytest.mark.parametrize(
    "key_only, want",
    [
        (False, ("detect", "destination", "install", "credential", "hello", "next_steps")),
        (True, ("destination", "credential", "hello")),
    ],
)
def test_phases(key_only, want):
    assert P.phases(key_only) == want


# --- the destination table: one case per row --------------------------------------------

F = P.Facts
ROW_CASES = [
    (F(flag="local", answered=True, apps_on=True), "local_on", "local"),
    (F(flag="local", answered=True, apps_on=False), "local_off", "local"),
    (F(flag="local", answered=False, on_path=True), "local_not_running", ""),
    (F(flag="local", answered=False, on_path=False), "local_no_observer", ""),
    (F(answered=True, signed_in=True, apps_on=True), "signed_in_both", "both"),
    (F(flag="online", answered=True, signed_in=True, apps_on=True), "signed_in_online_flag", "online"),
    (F(flag="both", answered=True, signed_in=True, apps_on=True), "signed_in_both", "both"),
    (F(flag="both", answered=True, signed_in=True, apps_on=False), "signed_in_both_off", "both"),
    (F(answered=True, signed_in=True, apps_on=False), "signed_in_online", "online"),
    (F(flag="online", held=True), "online_reuse", "online"),
    (F(flag="online", held=True, replace=True), "online", "online"),
    (F(flag="online"), "online", "online"),
    (F(flag="both", held=True, answered=True, apps_on=True), "both_reuse_on", "both"),
    (F(flag="both", held=True, answered=True, apps_on=False), "both_reuse_off", "both"),
    (F(flag="both", held=True, answered=False), "both_reuse_no_machine", "both"),
    (F(flag="both", answered=True, apps_on=True), "both_on", "both"),
    (F(flag="both", answered=True, apps_on=False, replace=True, held=True), "both_off", "both"),
    (F(flag="both", answered=False), "both_no_machine", "both"),
    (F(held=True, answered=True, apps_on=True), "reuse", "held"),
    (F(replace=True, held=True), "replace", "held_or_online"),
    (F(answered=True, apps_on=True, terminal=True), "machine_on_ask", "ask"),
    (F(answered=True, apps_on=True, terminal=False), "machine_on", "local"),
    (F(answered=True, apps_on=False), "machine_off", "local"),
    (F(answered=False, on_path=True), "not_running", ""),
    (F(answered=False, on_path=True, terminal=True), "not_running_ask", "ask_online"),
    (F(answered=False, on_path=False), "no_observer", "online"),
]


@pytest.mark.parametrize("facts, row, dest", ROW_CASES)
def test_destination_rows(facts, row, dest):
    c = P.choose(facts)
    assert (c.row, c.destination) == (row, dest)


def test_every_destination_row_has_a_case():
    assert {r.id for r in P.DESTINATION_ROWS} == {row for _, row, _ in ROW_CASES}


def test_destination_row_details():
    assert P.choose(F(flag="local", answered=True, apps_on=False)).enable
    assert not P.choose(F(answered=True, signed_in=True, apps_on=True)).device_flow  # R10: no file when signed in
    assert P.choose(F(answered=True, signed_in=True, apps_on=True)).machine_key
    stop = P.choose(F(flag="local"))
    assert (stop.stop, stop.exit_code) == (P.STOP_INSTALL_OBSERVER, P.EXIT_ENVIRONMENT)
    assert P.after_ask_online("online").device_flow and P.after_ask_online("").exit_code == P.EXIT_ENVIRONMENT
    assert P.choose(F()).device_flow and P.choose(F(answered=True, apps_on=False)).enable
    assert P.after_ask("both").device_flow and P.after_ask("local").destination == "local"


# --- the device flow's answer tables ------------------------------------------------------

A = P.Answer


@pytest.mark.parametrize(
    "answer, action, code",
    [
        (A(200, state="pending"), P.CONTINUE, 0),
        (A(200, state="approved", ready=False, grant=False), P.CONTINUE, 0),
        (A(200, state="approved", ready=True, grant=True), P.REDEEM, 0),
        (A(200, state="declined"), P.STOP, P.EXIT_WAITING),
        (A(200, state="expired"), P.STOP, P.EXIT_WAITING),
        (A(409, code="key_grant_already_delivered"), P.STOP, P.EXIT_WAITING),
        (A(409, code="key_grant_window_closed"), P.STOP, P.EXIT_WAITING),
        (A(429, code="rate_limited"), P.WAIT, 0),
        (A(401, code="unauthorized"), P.STOP, P.EXIT_WAITING),
        (A(404, code="not_found"), P.STOP, P.EXIT_WAITING),
        (A(0), P.WAIT, 0),
        (A(503), P.WAIT, 0),
        (A(418), P.STOP, P.EXIT_ENVIRONMENT),
    ],
)
def test_poll_rows(answer, action, code):
    s = P.step(P.POLL_ROWS, answer)
    assert (s.action, s.exit_code) == (action, code)


@pytest.mark.parametrize(
    "answer, action, code",
    [
        (A(201), P.REDEEM, 0),
        (A(201, plan_refusal=True), P.STOP, P.EXIT_REFUSED),
        (A(403, code="plan_required"), P.STOP, P.EXIT_REFUSED),
        (A(403, code="key_grant_refused", reason="not_a_member"), P.STOP, P.EXIT_REFUSED),
        (A(403, code="key_grant_refused", reason="member_inactive"), P.STOP, P.EXIT_REFUSED),
        (A(403, code="key_grant_refused", reason="expired"), P.STOP, P.EXIT_WAITING),
        (A(403, code="key_grant_not_accepted"), P.STOP, P.EXIT_REFUSED),
        (A(404, code="not_supported"), P.STOP, P.EXIT_REFUSED),
        (A(410, code="key_grant_used"), P.STOP, P.EXIT_WAITING),
        (A(429), P.WAIT, 0),
        (A(0), P.WAIT, 0),
        (A(502), P.WAIT, 0),
        (A(400, code="bad_request"), P.STOP, P.EXIT_ENVIRONMENT),
    ],
)
def test_redeem_rows(answer, action, code):
    s = P.step(P.REDEEM_ROWS, answer)
    assert (s.action, s.exit_code) == (action, code)


@pytest.mark.parametrize(
    "answer, action, code",
    [
        (A(201), P.CONTINUE, 0),
        (A(429, code="rate_limited"), P.STOP, P.EXIT_ENVIRONMENT),
        (A(400, code="invalid_purpose"), P.STOP, P.EXIT_ENVIRONMENT),
        (A(400, code="invalid_project_name"), P.STOP, P.EXIT_ENVIRONMENT),
        (A(0), P.STOP, P.EXIT_ENVIRONMENT),
    ],
)
def test_create_rows(answer, action, code):
    s = P.step(P.CREATE_ROWS, answer)
    assert (s.action, s.exit_code) == (action, code)


def test_redeem_pair():
    secret, h = cloud.redeem_pair(lambda n: b"\x01" * n)
    assert len(secret) == 43 and "=" not in secret
    assert h == base64.urlsafe_b64encode(hashlib.sha256(secret.encode("ascii")).digest()).rstrip(b"=").decode()
    assert len(h) == 43


def test_redeem_hash_matches_the_fixture():
    create = fixture("connect-create")
    redeem = fixture("grant-redeem")
    assert cloud.redeem_hash(redeem["request"]["body"]["redeem_secret"]) == create["request"]["body"]["redeem_hash"]


# --- the refusal lines (3.8) -----------------------------------------------------------


@pytest.mark.parametrize(
    "code, upgrade, want_tail",
    [
        ("plan_required", "https://cloud.superbased.app/portal/orgs/x", "Change the plan: https://cloud.superbased.app/portal/orgs/x"),
        ("planea_events_quota_exceeded", "https://cloud.superbased.app/portal/billing", "Ingest resumes 2027-02-01T00:00:00Z. More: https://cloud.superbased.app/portal/billing"),
        ("planea_bytes_quota_exceeded", "", "This is not a plan limit: your organization set this cap itself (Settings > Server > Runtime settings)."),
        ("something_else", "", None),
    ],
)
def test_refusal_lines(code, upgrade, want_tail):
    lines = hello.refusal_lines(code, "The server's  message.", upgrade, "2027-02-01T00:00:00Z")
    assert lines[0] == "The server's message."
    assert (lines[1] if len(lines) > 1 else None) == want_tail
    for line in lines:
        assert "Personal" not in line and "100,000" not in line  # never a plan name or number of setup's own


# --- detection ---------------------------------------------------------------------------

V = detect.ProjectView


@pytest.mark.parametrize(
    "view, lang, mgr, targets, extras, install",
    [
        (V({"pyproject.toml": '[project]\nname="bot"\ndependencies=["openai>=1"]\n', "uv.lock": 'name = "openai"\n'}, tools=("uv",)),
         "python", "uv", ("openai",), ("openai",), ("uv", "add", "superbased-sdk[openai]>=9.9.9")),
        (V({"pyproject.toml": "[tool.poetry]\nname='bot'\n[tool.poetry.dependencies]\nanthropic = '^0.40'\n"}, tools=("poetry",)),
         "python", "poetry", ("anthropic",), ("anthropic",), ("poetry", "add", "superbased-sdk[anthropic]>=9.9.9")),
        (V({"requirements.txt": "langchain-openai\nlanggraph==0.2\n"}, python="/p/.venv/bin/python"),
         "python", "pip", ("langchain",), ("langchain",), ("/p/.venv/bin/python", "-m", "pip", "install", "superbased-sdk[langchain]>=9.9.9")),
        (V({"pdm.lock": 'name = "nothing-read"\n', "pyproject.toml": '[project]\ndependencies = ["mcp", "google-genai"]\n'}, tools=("pdm",)),
         "python", "pdm", ("mcp", "gemini"), ("gemini", "mcp"), ("pdm", "add", "superbased-sdk[gemini,mcp]>=9.9.9")),
        (V({"Pipfile": "[packages]\ncrewai = '*'\n"}, tools=("pipenv",)),
         "python", "pipenv", ("crewai",), ("crewai",), ("pipenv", "install", "superbased-sdk[crewai]>=9.9.9")),
        (V({"requirements.txt": "boto3\n"}), "python", "pip", (), (), ("python3", "-m", "pip", "install", "superbased-sdk>=9.9.9")),
        (V({"requirements.txt": "boto3\n"}, bedrock_in_source=True), "python", "pip", ("bedrock",), ("bedrock",), None),
        (V({"requirements.txt": "openai-agents\n"}), "python", "pip", ("openai-agents",), (), None),
        (V({"requirements.txt": "flask\n"}, installed=("OpenAI", "pydantic_ai_slim", "llama-index-core")), "python", "pip",
         ("openai", "llama-index", "pydantic-ai"), ("llama-index", "openai", "pydantic-ai"), None),
        (V({"pyproject.toml": "[project]\n"}, tools=("uv",)), "python", "pip", (), (), ("python3", "-m", "pip", "install", "superbased-sdk>=9.9.9")),
        (V({"pyproject.toml": "[tool.poetry]\nname='x'\n"}, tools=("poetry",)), "python", "poetry", (), (), ("poetry", "add", "superbased-sdk>=9.9.9")),
        (V({"uv.lock": 'name = "openai"\n', "pyproject.toml": "[project]\n"}, tools=("uv",)), "python", "uv", (), (), ("uv", "add", "superbased-sdk>=9.9.9")),
        (V({"package.json": "{}"}), "typescript", "", (), (), ()),
        (V({"go.mod": "module x"}), "go", "", (), (), ()),
        (V({"pom.xml": "<project/>"}), "java", "", (), (), ()),
        (V({}), "", "", (), (), ()),
        (V({}, entries=("app.py",)), "python", "pip", (), (), None),
    ],
)
def test_detect(view, lang, mgr, targets, extras, install):
    d = detect.detect(view, "9.9.9")
    assert (d.language, d.package_manager, d.targets, d.extras) == (lang, mgr, targets, extras)
    if install is not None:
        assert d.install == install


def test_openai_agents_is_named_only():
    d = detect.detect(V({"requirements.txt": "openai\nopenai-agents\n"}), "1")
    assert d.targets == ("openai", "openai-agents") and d.extras == ("openai",) and d.named_only == ("openai-agents",)


@pytest.mark.parametrize(
    "text, dist, hit",
    [
        ('"openai>=1"', "openai", True),
        ("openai-agents==0.1", "openai", False),
        ("langchain-openai", "openai", False),
        ("openinference-instrumentation-openai", "openai", False),
        ('name = "llama_index_core"', "llama-index-core", True),
        ("LangChain-Core", "langchain-core", True),
    ],
)
def test_mentions(text, dist, hit):
    assert detect._mentions(text, dist) is hit


def test_tool_missing():
    d = detect.detect(V({"uv.lock": ""}, tools=()), "1")
    assert d.tool_missing == "uv"


def test_gather(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "support-bot"\ndependencies = ["boto3"]\n')
    (tmp_path / "app.py").write_text("import boto3\nboto3.client('bedrock-runtime')\n")
    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("")
    calls = []

    def runner(cmd, cwd, timeout):
        calls.append(cmd)
        return 0, json.dumps(["boto3", "anthropic"])

    view = detect.gather(str(tmp_path), runner, lambda n: "/usr/bin/" + n if n == "uv" else None)
    assert view.python == str(venv / "python") and view.bedrock_in_source and view.entries == ("app.py",)
    assert view.installed == ("boto3", "anthropic") and view.tools == ("uv",)
    d = detect.detect(view, "1")
    assert d.targets == ("anthropic", "bedrock") and d.package_manager == "pip"
    assert d.install[0] == str(venv / "python")


# --- the key file writer ------------------------------------------------------------------


def test_store_write_is_owner_only_and_atomic(tmp_path):
    if os.name == "nt":
        pytest.skip("unix modes")
    path = tmp_path / "cfg" / "superbased" / "sdk-credential"
    rec = store.write(str(path), store.lines("ik_1.s3cr3t-value", "https://gw.example.com", "online", "https://board.example.com", "2027-04-15T08:00:30Z"))
    assert rec.usable and rec.destination == "online"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
    assert oct(os.stat(path.parent).st_mode & 0o777) == "0o700"
    assert oct(os.stat(path.parent.parent).st_mode & 0o777) == "0o700"
    assert path.read_text().splitlines() == [
        "ik_1.s3cr3t-value", "gateway_url=https://gw.example.com", "destination=online",
        "dashboard_url=https://board.example.com", "expires_at=2027-04-15T08:00:30Z",
    ]
    assert [p.name for p in path.parent.iterdir()] == ["sdk-credential"]  # no temporary file left


def test_store_replaces_a_symlink_never_its_target(tmp_path):
    if os.name == "nt":
        pytest.skip("unix")
    target = tmp_path / "victim"
    target.write_text("keep me")
    link = tmp_path / "sdk-credential"
    link.symlink_to(target)
    store.write(str(link), store.lines("ik_1.s3cr3t-value", "https://gw.example.com", "online", "", ""))
    assert target.read_text() == "keep me" and not link.is_symlink()


def test_store_matches_the_fixture_file():
    fx = fixture("sdk-credential-file")
    redeem = fixture("grant-redeem")["responses"]["minted"]["body"]
    lines = store.lines(redeem["credential"], redeem["gateway_url"], "online", redeem["dashboard_url"], redeem["expires_at"])
    assert lines == fx["lines"]


# --- the end-to-end runs against stubs ------------------------------------------------------


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(float(s), 0.001)


def deps(**kw):
    base = dict(clock=FakeClock(), open_browser=lambda url: False, which=lambda name: None, terminal=False,
                ask=lambda prompt: "", install=lambda cmd, cwd: (0, ""), arrival_wait=3.0,
                runner=lambda cmd, cwd, timeout: (0, "[]"))  # the project interpreter has nothing installed
    base.update(kw)
    return cli.Deps(**base)


class World:
    """The cloud (stub), the organization's host (stub2) and a project
    folder, wired from the L0 fixture bodies."""

    def __init__(self, stub, stub2, tmp_path, monkeypatch):
        self.cloud, self.org = stub, stub2
        self.create = fixture("connect-create")
        self.poll = fixture("connect-poll")
        self.redeem = fixture("grant-redeem")
        self.fakes = fixture("secrecy-fakes")
        self.project = tmp_path / "support-bot"
        self.project.mkdir()
        (self.project / "pyproject.toml").write_text('[project]\nname = "support-bot"\ndependencies = ["openai>=1"]\n')
        (self.project / "app.py").write_text("print('hi')\n")
        self.cred = tmp_path / "home" / ".config" / "superbased" / "sdk-credential"
        monkeypatch.setenv("SUPERBASED_CREDENTIAL_FILE", str(self.cred))
        monkeypatch.setenv("SUPERBASED_CLOUD_URL", stub.url)
        monkeypatch.chdir(self.project)
        self.polls = ["pending", "approved_not_ready", "approved_with_grant"]
        self.redeem_answer = "minted"
        self.arrive_after = 1
        self.cost_checks = 0
        self.cloud.route("POST", "/v1/connect/requests", self._create)
        req_id = self.create["responses"]["created"]["body"]["request_id"]
        self.cloud.route("GET", "/v1/connect/requests/" + req_id, self._poll)
        self.org.route("POST", "/api/agent/sdk-credential/grant", self._redeem)
        self.org.route("POST", "/v1/traces", body={})
        self.org.route("POST", "/v1/sdk/credential/revoke", self._revoke)

    def _answer(self, resp):
        body = copy.deepcopy(resp["body"])
        return resp["status"], body, {k: v for k, v in resp["headers"].items() if k.lower() != "content-type"}

    def _create(self, req):
        return self._answer(self.create["responses"]["created"])

    def _poll(self, req):
        name = self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]
        status, body, headers = self._answer(self.poll["responses"][name])
        if isinstance(body.get("target"), dict) and body["target"].get("server_url"):
            body["target"]["server_url"] = self.org.url
        return status, body, headers

    def _redeem(self, req):
        status, body, headers = self._answer(self.redeem["responses"][self.redeem_answer])
        if "gateway_url" in body:
            body["gateway_url"] = self.org.url
        return status, body, headers

    def _revoke(self, req):
        return 200, {"api_version": "1", "request_id": "r", "revoked": 1}, {}

    def cost(self, trace_id):
        def answer(req):
            self.cost_checks += 1
            if self.cost_checks < self.arrive_after:
                return 404, {"error": "not_found", "message": "no such trace"}, {}
            return 200, {"api_version": "v1", "trace_id": trace_id, "cost_usd": 0, "spans": [{"span_id": "a"}]}, {}

        return answer

    def arrive(self):
        """Answer the cost read for whatever trace id the hello sends (the
        stub matches exact paths, so its route table matches this one by
        pattern)."""
        world = self

        class Routes(dict):
            def get(self, key, default=None):
                method, path = key
                m = re.fullmatch(r"/v1/sdk/traces/([0-9a-f]{32})/cost", path)
                if method == "GET" and m:
                    return world.cost(m.group(1))
                return dict.get(self, key, default)

        self.org.routes = Routes(self.org.routes)


@pytest.fixture
def world(stub, stub2, tmp_path, monkeypatch):
    w = World(stub, stub2, tmp_path, monkeypatch)
    w.arrive()
    return w


def run(args, d=None):
    out, err = io.StringIO(), io.StringIO()
    code = cli.run(args, deps=d or deps(), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


def test_online_end_to_end(world, monkeypatch):
    installs = []
    d = deps(install=lambda cmd, cwd: installs.append((cmd, cwd)) or (0, "ok"))
    code, out, err = run(["--json"], d)
    assert code == P.EXIT_DONE, out + err
    events = [json.loads(line) for line in out.splitlines()]
    phases = [e["phase"] for e in events]
    assert phases[0] == "detect" and phases[-1] == "done"
    for p in ("destination", "install", "approve", "credential", "hello", "next"):
        assert p in phases, phases
    done = events[-1]
    assert done["exit"] == 0
    (cred,) = [e for e in events if e["phase"] == "credential"]
    assert cred["written"] is True and cred["path"] == str(world.cred)
    assert done["trace_url"].startswith("https://u-k7x2.superbased.app/trajectories?trace=")
    # The install used the project's own tool with the detected extra.
    assert installs and installs[0][0][-1] == "superbased-sdk[openai]>=" + sb.__version__
    # The create body: the fixture's shape, the redeem hash of the secret the redeem sends.
    (create,) = [r for r in world.cloud.requests if r["method"] == "POST"]
    assert set(create["body"]) == set(world.create["request"]["body"])
    assert create["body"]["purpose"] == "sdk_key" and create["body"]["client"] == "superbased-sdk-python"
    assert create["body"]["project_name"] == "support-bot" and "device_public_key" not in create["body"]
    (redeem,) = [r for r in world.org.requests if r["path"] == "/api/agent/sdk-credential/grant"]
    assert set(redeem["body"]) == set(world.redeem["request"]["body"])
    assert cloud.redeem_hash(redeem["body"]["redeem_secret"]) == create["body"]["redeem_hash"]
    assert redeem["body"]["key_grant"] == world.poll["responses"]["approved_with_grant"]["body"]["key_grant"]
    assert redeem["body"]["replaces_key_id"] == ""
    polls = [r for r in world.cloud.requests if r["method"] == "GET"]
    assert all(r["headers"].get("Authorization") == "Bearer " + world.fakes["device_code"] for r in polls)
    # The key file: the fixture's lines, with this stub as the gateway.
    want = list(fixture("sdk-credential-file")["lines"])
    want[1] = "gateway_url=" + world.org.url
    assert world.cred.read_text().splitlines() == want
    # The hello went to the organization with the key and carried only the mark.
    (traces,) = [r for r in world.org.requests if r["path"] == "/v1/traces"]
    assert {k.lower(): v for k, v in traces["headers"].items()}["authorization"] == "Bearer " + world.fakes["sdk_key"]
    assert b"sbo.setup.hello" in traces["raw"]
    assert b"superbased setup: hello from support-bot" in traces["raw"]


def test_online_plain_output(world):
    code, out, err = run(["--no-browser"])
    assert code == 0, out + err
    assert "Approve in your browser: https://cloud.superbased.app/connect/" in out
    assert "(code KTRW-4821)" in out
    assert "Your first trace (your online dashboard): https://u-k7x2.superbased.app/trajectories?trace=" in out
    assert "import superbased_sdk; superbased_sdk.init()" in out and "app.py" in out
    assert P.MESSAGES["approved_not_ready"] in out


def test_key_only_skips_python_detection_install_and_init_line(world, tmp_path, monkeypatch):
    go = tmp_path / "gosvc"
    go.mkdir()
    (go / "go.mod").write_text("module example.com/gosvc\n")
    monkeypatch.chdir(go)
    called = []
    d = deps(runner=lambda *a: called.append(a) or (0, "[]"), install=lambda cmd, cwd: called.append(cmd) or (0, ""))
    code, out, err = run(["--key-only", "--json"], d)
    assert code == 0, out + err
    phases = [json.loads(line)["phase"] for line in out.splitlines()]
    assert "detect" not in phases and "install" not in phases and "next" not in phases
    assert "approve" in phases and "credential" in phases and "hello" in phases and phases[-1] == "done"
    assert called == []
    assert world.cred.exists()
    (create,) = [r for r in world.cloud.requests if r["method"] == "POST"]
    assert create["body"]["project_name"] == "gosvc"


def test_a_go_project_without_key_only_points_to_it(world, tmp_path, monkeypatch):
    go = tmp_path / "gosvc"
    go.mkdir()
    (go / "go.mod").write_text("module x\n")
    monkeypatch.chdir(go)
    code, out, err = run([])
    assert code == P.EXIT_ENVIRONMENT and "--key-only" in out
    assert world.cloud.requests == []


@pytest.mark.parametrize(
    "answer, code, stored, text",
    [
        ("plan_required", P.EXIT_REFUSED, False, "Change the plan: https://cloud.superbased.app/portal/orgs/5d4c3b2a"),
        ("not_a_member", P.EXIT_REFUSED, False, "You are not a member of this team"),
        ("grant_refused", P.EXIT_WAITING, False, "This approval has expired; run setup again"),
        ("not_accepted", P.EXIT_REFUSED, False, "does not take SDK sign-in approvals"),
        ("not_supported", P.EXIT_REFUSED, False, "issues no member SDK keys"),
        ("grant_used", P.EXIT_WAITING, False, "already used"),
        ("minted_month_used", P.EXIT_REFUSED, True, "Ingest resumes 2027-02-01T00:00:00Z. More: https://cloud.superbased.app/portal/billing"),
    ],
)
def test_redeem_answers(world, answer, code, stored, text):
    world.redeem_answer = answer
    got, out, err = run(["--online"])
    assert got == code, out + err
    assert text in out
    assert world.cred.exists() is stored
    # A refused redeem stores nothing; a month already used stores the key but sends no hello.
    assert not [r for r in world.org.requests if r["path"] == "/v1/traces"]


@pytest.mark.parametrize(
    "polls, code, text",
    [
        (["pending", "declined"], P.EXIT_WAITING, "declined"),
        (["expired"], P.EXIT_WAITING, "expired"),
        (["already_delivered"], P.EXIT_WAITING, "already used"),
        (["unauthorized"], P.EXIT_WAITING, "no longer valid"),
        (["not_found"], P.EXIT_WAITING, "no longer valid"),
        (["rate_limited", "approved_with_grant"], P.EXIT_DONE, "Your first trace"),
        (["pending"], P.EXIT_WAITING, "expired"),
    ],
)
def test_poll_answers(world, polls, code, text):
    world.polls = list(polls)
    got, out, err = run(["--online"])
    assert got == code, out + err
    assert text in out


@pytest.mark.parametrize("answer, text", [("rate_limited", "too many connect requests"), ("purpose_not_offered", "does not take SDK sign-in")])
def test_create_answers(world, answer, text):
    world.cloud.route("POST", "/v1/connect/requests", lambda req: world._answer(world.create["responses"][answer]))
    code, out, err = run(["--online"])
    assert code == P.EXIT_ENVIRONMENT and text in out


def test_not_seen_in_time_prints_the_link(world):
    world.arrive_after = 10 ** 6
    code, out, err = run(["--online"])
    assert code == P.EXIT_NOT_SEEN, out + err
    assert "Sent, not seen yet on your online dashboard: https://u-k7x2.superbased.app/trajectories?trace=" in out


@pytest.mark.parametrize(
    "status, body, text",
    [
        (429, {"error": "planea_events_quota_exceeded", "message": "This month's allowance is used.", "quota": {"resets_at": "2027-02-01T00:00:00Z"},
               "upgrade_url": "https://cloud.superbased.app/portal/billing"}, "Ingest resumes 2027-02-01T00:00:00Z. More: https://cloud.superbased.app/portal/billing"),
        (429, {"error": "planea_bytes_quota_exceeded", "message": "The cap is reached."}, "your organization set this cap itself"),
        (403, {"error": "plan_required", "message": "Not in this plan.", "upgrade_url": "https://cloud.superbased.app/portal/orgs/x"},
         "Change the plan: https://cloud.superbased.app/portal/orgs/x"),
        (401, {"error": "unauthorized", "message": "bad key"}, "did not accept the SDK key"),
    ],
)
def test_hello_refusals(world, status, body, text, monkeypatch):
    monkeypatch.setenv("SUPERBASED_EXPORT_TIMEOUT_MS", "800")  # the exporter retries a 429 until its timeout
    world.org.route("POST", "/v1/traces", body=body, status=status, headers={"Retry-After": "1"})
    code, out, err = run(["--online"])
    assert code == P.EXIT_REFUSED, out + err
    assert text in out


def test_a_valid_key_file_is_used_again(world):
    assert run(["--online"])[0] == 0
    creates = len([r for r in world.cloud.requests if r["method"] == "POST"])
    sb._reset_for_tests()
    code, out, err = run([])
    assert code == 0, out + err
    assert len([r for r in world.cloud.requests if r["method"] == "POST"]) == creates  # no second device flow
    assert P.MESSAGES[P.NOTE_REUSE] in out


def test_replace_sends_the_old_key_id(world):
    assert run(["--online"])[0] == 0
    sb._reset_for_tests()
    world.polls = ["approved_with_grant"]
    code, out, err = run(["--online", "--replace"])
    assert code == 0, out + err
    redeems = [r for r in world.org.requests if r["path"] == "/api/agent/sdk-credential/grant"]
    assert redeems[-1]["body"]["replaces_key_id"] == "00000000000000000000000000000001"


def test_replace_with_local_is_a_usage_error(world):
    assert run(["--local", "--replace"])[0] == P.EXIT_USAGE


def test_a_bad_flag_is_exit_4_not_waiting():
    code, out, err = run(["--nope"])
    assert code == P.EXIT_ENVIRONMENT == P.EXIT_USAGE and "--nope" in out
    code, out, err = run(["--local", "--online", "--json"])
    assert code == P.EXIT_ENVIRONMENT
    assert json.loads(out.splitlines()[-1])["phase"] == "error"


# --- this computer (3.7) ---------------------------------------------------------------------


class Machine:
    def __init__(self, stub, monkeypatch, *, enabled=False, signed_in=False, turn_on_after=0):
        self.stub = stub
        self.on = enabled
        self.signed_in = signed_in
        self.status_reads = 0
        self.turn_on_after = turn_on_after
        self.enables = []
        monkeypatch.setenv("SUPERBASED_DISCOVER", "1")
        monkeypatch.setenv("SUPERBASED_NODE_URL", stub.url)
        stub.route("GET", "/api/sdk/destination", self._discovery)
        stub.route("GET", "/api/apps/status", self._status)
        stub.route("POST", "/api/apps/enable", self._enable)
        stub.route("POST", "/v1/traces", body={})
        orig = stub.routes
        machine = self

        class Routes(dict):
            def get(self, key, default=None):
                method, path = key
                if method == "GET" and re.fullmatch(r"/api/obs/trace/[0-9a-f]{32}", path):
                    return (200, {"trace_id": path.rsplit("/", 1)[1]}, {})
                return dict.get(self, key, default)

        stub.routes = Routes(orig)

    def _discovery(self, req):
        return 200, {
            "api_version": 1, "destination": "both" if self.signed_in else "local", "source": "config", "configured": "",
            "signed_in": self.signed_in,
            "local": {"enabled": self.on, "otlp_traces_url": self.stub.url + "/v1/traces"}, "online": {}, "warnings": [],
        }, {}

    def _status(self, req):
        self.status_reads += 1
        if self.turn_on_after and self.status_reads > self.turn_on_after:
            self.on = True
        return 200, {"on": self.on, "consent": {"sentence": "AI Apps keeps traces on this computer only."}, "confirm_token": "t" * 64}, {}

    def _enable(self, req):
        self.enables.append(req)
        self.on = True
        return 200, {"outcome": "on", "ok": True, "message": "AI Apps is on"}, {}


def test_local_terminal_yes_turns_it_on(stub, tmp_path, monkeypatch):
    m = Machine(stub, monkeypatch, enabled=False)
    (tmp_path / "requirements.txt").write_text("anthropic\n")
    monkeypatch.chdir(tmp_path)
    d = deps(terminal=True, ask=lambda prompt: "y")
    code, out, err = run([], d)
    assert code == P.EXIT_DONE, out + err
    (req,) = m.enables
    assert req["body"] == {"source": "sdk-setup"}
    assert req["headers"]["X-Observer-Confirm"] == "t" * 64 and "sb_remote_confirm=" + "t" * 64 in req["headers"]["Cookie"]
    assert "AI Apps keeps traces on this computer only." in out
    assert f"Your first trace (this computer): {stub.url}/apps/traces?trace=" in out


def test_local_terminal_no_changes_nothing(stub, tmp_path, monkeypatch):
    m = Machine(stub, monkeypatch, enabled=False)
    (tmp_path / "requirements.txt").write_text("\n")
    monkeypatch.chdir(tmp_path)
    code, out, err = run([], deps(terminal=True, ask=lambda prompt: "n"))
    assert code == P.EXIT_WAITING and m.enables == [] and "setup --online" in out


def test_local_no_terminal_no_browser_prints_the_page(stub, tmp_path, monkeypatch):
    m = Machine(stub, monkeypatch, enabled=False)
    (tmp_path / "requirements.txt").write_text("\n")
    monkeypatch.chdir(tmp_path)
    code, out, err = run([])
    assert code == P.EXIT_WAITING and m.enables == []
    assert f"{stub.url}/apps?enable=1&from=setup" in out and "observer apps on" in out


def test_local_no_terminal_opens_the_page_and_waits_for_the_click(stub, tmp_path, monkeypatch):
    m = Machine(stub, monkeypatch, enabled=False, turn_on_after=3)
    (tmp_path / "requirements.txt").write_text("\n")
    monkeypatch.chdir(tmp_path)
    opened = []
    code, out, err = run([], deps(open_browser=lambda url: opened.append(url) or True))
    assert code == P.EXIT_DONE, out + err
    assert opened == [f"{stub.url}/apps?enable=1&from=setup"] and m.enables == []


def test_local_on_no_terminal_is_local_and_says_how_to_add_online(stub, tmp_path, monkeypatch):
    Machine(stub, monkeypatch, enabled=True)
    (tmp_path / "requirements.txt").write_text("\n")
    monkeypatch.chdir(tmp_path)
    code, out, err = run([])
    assert code == 0 and P.MESSAGES[P.NOTE_ADD_ONLINE] in out


def test_signed_in_online_says_how_to_send_online_only():
    c = P.choose(F(flag="online", answered=True, signed_in=True, apps_on=True))
    assert P.NOTE_ONLINE_ONLY_ENV in c.notes and "SUPERBASED_DESTINATION=online" in P.MESSAGES[P.NOTE_ONLINE_ONLY_ENV]


def test_signed_in_machine_writes_no_file(stub, tmp_path, monkeypatch):
    Machine(stub, monkeypatch, enabled=True, signed_in=True)
    (tmp_path / "requirements.txt").write_text("\n")
    monkeypatch.chdir(tmp_path)
    code, out, err = run(["--online", "--no-install"])
    assert P.MESSAGES[P.NOTE_ALREADY_SIGNED_IN] in out
    assert "Approve in your browser" not in out
    assert not os.path.exists(os.environ["SUPERBASED_CREDENTIAL_FILE"])


@pytest.mark.parametrize("on_path, text", [(True, "observer start"), (False, "install.sh")])
def test_local_without_a_running_observer_stops(on_path, text, tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("\n")
    monkeypatch.chdir(tmp_path)
    code, out, err = run(["--local"], deps(which=lambda n: "/usr/bin/observer" if on_path else None))
    assert code == P.EXIT_ENVIRONMENT and text in out


def test_self_hosted_org_url(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, err = run(["--org-url", "https://observer.example.com"])
    assert code == P.EXIT_ENVIRONMENT and "SUPERBASED_API_KEY" in out and "hosted organizations" in out


# --- --status and --forget ---------------------------------------------------------------------


def test_status_never_prints_the_key(world):
    assert run(["--online"])[0] == 0
    sb._reset_for_tests()
    code, out, err = run(["--status", "--json"])
    assert code == 0
    ev, done = [json.loads(line) for line in out.splitlines()]
    assert done == {"phase": "done", "trace_url": "", "exit": 0}
    assert ev["phase"] == "status" and ev["sdk_file"]["state"] == "used" and ev["destination"] == "online"
    assert ev["credential_source"] == "sdk_file"
    assert world.fakes["sdk_key_secret"] not in out + err


def test_forget_revokes_with_the_key_and_removes_the_file(world):
    assert run(["--online"])[0] == 0
    code, out, err = run(["--forget"])
    assert code == 0 and not world.cred.exists()
    (rv,) = [r for r in world.org.requests if r["path"] == "/v1/sdk/credential/revoke"]
    assert rv["headers"]["Authorization"] == "Bearer " + world.fakes["sdk_key"]
    assert "Revoked SDK key 00000000000000000000000000000001." in out


def test_forget_removes_the_file_even_when_the_revoke_fails(world):
    assert run(["--online"])[0] == 0
    world.org.route("POST", "/v1/sdk/credential/revoke", body={"error": "unauthorized", "message": "the SDK key is not valid"}, status=401)
    code, out, err = run(["--forget"])
    assert code == 0 and not world.cred.exists() and "already revoked" in out


def test_forget_with_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, out, err = run(["--forget"])
    assert code == 0 and "nothing to forget" in out


# --- secrecy (plan 3.5, SDKQS-4) and no AI gateway (SDKQS-10) ---------------------------------

AI_GATEWAY = re.compile(r"AI gateway|ai[_-]gateway|aigateway|SUPERBASED_AI_GATEWAY|gateway_endpoint|gateway_base_url|openai_client|anthropic_client|/ai/", re.IGNORECASE)

SCENARIOS = [
    (["--json"], {}),
    ([], {}),
    (["--online", "--json"], {"redeem_answer": "plan_required"}),
    (["--online"], {"redeem_answer": "minted_month_used"}),
    (["--online"], {"redeem_answer": "not_a_member"}),
    (["--online", "--json"], {"polls": ["declined"]}),
    (["--online"], {"arrive_after": 10 ** 6}),
    (["--key-only", "--json"], {}),
]


@pytest.mark.parametrize("args, setup", SCENARIOS)
def test_secrecy_and_names(world, args, setup, caplog):
    import logging

    for k, v in setup.items():
        setattr(world, k, v)
    secrets_seen = []
    real_secrets = cli.Secrets

    class Watch(real_secrets):
        def __init__(self):
            super().__init__()
            secrets_seen.append(self)

    cli.Secrets = Watch
    try:
        with caplog.at_level(logging.DEBUG):
            code, out, err = run(args)
    finally:
        cli.Secrets = real_secrets
    logs = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
    everything = out + err + logs
    for name, value in world.fakes.items():
        if name.startswith("_"):
            continue
        assert value not in everything, f"{name} leaked (exit {code})"
    redeems = [r for r in world.org.requests if r["path"] == "/api/agent/sdk-credential/grant"]
    for r in redeems:
        assert r["body"]["redeem_secret"] not in everything
    assert all(s.hits == 0 for s in secrets_seen), "the guard had to redact something setup wrote"
    hit = AI_GATEWAY.search(everything)
    assert not hit, everything[max(0, hit.start() - 200): hit.end() + 80]
    if "--json" in args:
        for line in out.splitlines():
            json.loads(line)


def test_an_exception_never_carries_a_secret(world, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("write failed for ik_1." + "FAKE-sdk-key-secret-for-contract-tests-only")

    monkeypatch.setattr(store, "write", boom)
    code, out, err = run(["--online"])
    assert code == P.EXIT_UNEXPECTED
    assert "FAKE-sdk-key-secret-for-contract-tests-only" not in out + err
    assert "[redacted]" in out  # the guard caught what the bug put in the message


def test_setup_sources_never_name_the_ai_gateway_or_the_machine_credential_route():
    for name in sorted(os.listdir(os.path.join(PKG, "_setup"))):
        if not name.endswith(".py"):
            continue
        src = open(os.path.join(PKG, "_setup", name), encoding="utf-8").read()
        assert not AI_GATEWAY.search(src), (name, AI_GATEWAY.search(src))
        assert "/api/sdk/credential" not in src, name
        # Never an argv that runs Observer's key verbs (R-165, SDKQS-8).
        assert not re.search(r"""["']sign-in["']|["']use-key["']|["']sign-out["']""", src), name


# --- boundaries --------------------------------------------------------------------------------


def _imports(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield 0, a.name
        elif isinstance(node, ast.ImportFrom):
            yield node.level, node.module or ""


# Standard-library modules newer than the oldest Python this test runs on
# (3.10). setup imports each one under `except ImportError` and has a
# fallback, so it still runs where the module is missing: tomllib is 3.11+
# (detect.py's `_pyproject_names` falls back to matching known names).
_LATER_STDLIB = {"tomllib"}


def test_setup_is_standard_library_only():
    if sys.version_info < (3, 10):
        pytest.skip("sys.stdlib_module_names is 3.10+")
    for name in sorted(os.listdir(os.path.join(PKG, "_setup"))):
        if not name.endswith(".py"):
            continue
        for level, mod in _imports(os.path.join(PKG, "_setup", name)):
            top = mod.split(".")[0]
            if level > 0 or top == "superbased_sdk" or top == "__future__":
                continue
            assert top in sys.stdlib_module_names or top in _LATER_STDLIB, (name, mod)


def test_the_runtime_never_imports_setup():
    for name in sorted(os.listdir(PKG)):
        if not name.endswith(".py") or name == "__main__.py":
            continue
        for level, mod in _imports(os.path.join(PKG, name)):
            assert "_setup" not in mod, (name, mod)
    code = "import sys, superbased_sdk as sb; sb.init(destination='local'); assert not [m for m in sys.modules if m.startswith('superbased_sdk._setup')]; print('ok')"
    env = {k: v for k, v in os.environ.items() if not k.startswith("SUPERBASED_")}
    env.update({"SUPERBASED_DISCOVER": "0", "SUPERBASED_INSTRUMENT": "off", "PYTHONPATH": os.path.abspath(os.path.join(HERE, ".."))})
    r = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stderr


def test_entry_points():
    pyproject = open(os.path.join(HERE, "..", "pyproject.toml"), encoding="utf-8").read()
    assert re.search(r'^\[project\.scripts\]\nsuperbased-sdk = "superbased_sdk\._setup:main"$', pyproject, re.M)
    env = dict(os.environ, PYTHONPATH=os.path.abspath(os.path.join(HERE, "..")))
    r = subprocess.run([sys.executable, "-m", "superbased_sdk", "setup", "--help"], env=env, capture_output=True, text=True, timeout=60, check=False)
    assert r.returncode == 0 and "--key-only" in r.stdout and "--forget" in r.stdout
    assert cli.main(["nope"]) == P.EXIT_USAGE


# --- lead rulings from lane L6's report -----------------------------------------------------


@pytest.mark.parametrize(
    "security_set, owner_is_user, refused, text",
    [
        (True, True, False, ""),
        (True, False, True, "owned by another account"),
        (True, None, True, "cannot read back the owner"),
        (False, True, True, "cannot set this user as the owner"),
        (False, None, True, "cannot set this user as the owner"),
    ],
)
def test_windows_write_decision(security_set, owner_is_user, refused, text):
    """The Windows writer sets the owner to this user with the DACL and reads
    it back: an elevated prompt's file owned by Administrators is refused,
    with the fix, instead of left for every reader to refuse."""
    why = store.windows_write_decision(security_set, owner_is_user, "C:\\Users\\me\\AppData\\Local\\superbased\\sdk-credential")
    assert bool(why) is refused
    assert text in why
    if refused:
        assert "not elevated" in why


def test_every_windows_write_row_has_a_case():
    covered = {(True, True), (True, False), (True, None), (False, "any")}
    assert {(r[0], r[1]) for r in store.WINDOWS_WRITE_ROWS} == covered


@pytest.mark.parametrize(
    "state, usable, expired, want",
    [
        ("valid", True, False, True),
        ("valid", True, True, False),  # expired: like a missing file, a new device flow
        ("valid", False, False, False),  # no usable address
        ("refused", False, False, False),  # refused: like a missing file
        ("absent", False, False, False),
    ],
)
def test_held_rows(state, usable, expired, want):
    assert P.held(state, usable, expired) is want


@pytest.mark.parametrize("expired, flows", [(True, True), (False, False)])
@pytest.mark.parametrize("args", [[], ["--key-only"]])
def test_a_rerun_replaces_an_expired_file_without_replace(world, expired, flows, args):
    """An expired key file is treated like a missing one (no --replace
    needed); a valid one skips the device flow."""
    when = "2020-01-01T00:00:00Z" if expired else "2099-01-01T00:00:00Z"
    world.cred.parent.mkdir(parents=True, exist_ok=True)
    world.cred.write_text(f"ik_old.old-secret-value\ngateway_url={world.org.url}\ndestination=online\nexpires_at={when}\n")
    os.chmod(world.cred, 0o600)
    code, out, err = run(args)
    assert code == 0, out + err
    creates = [r for r in world.cloud.requests if r["method"] == "POST"]
    assert bool(creates) is flows
    redeems = [r for r in world.org.requests if r["path"] == "/api/agent/sdk-credential/grant"]
    if flows:
        assert redeems[0]["body"]["replaces_key_id"] == ""
        assert world.cred.read_text().splitlines()[0] == world.fakes["sdk_key"]


def test_a_refused_file_gets_a_new_key(world):
    world.cred.parent.mkdir(parents=True, exist_ok=True)
    world.cred.write_text(f"ik_old.old-secret-value\ngateway_url={world.org.url}\ndestination=online\n")
    os.chmod(world.cred, 0o644)
    code, out, err = run(["--key-only"])
    assert code == 0, out + err
    assert [r for r in world.cloud.requests if r["method"] == "POST"]
    assert oct(os.stat(world.cred).st_mode & 0o777) == "0o600"
