#!/usr/bin/env python3
"""AI Apps live end-to-end runner (the playbook in docs/planea-e2e-playbook.md).

Stands up a THROWAWAY superbased machine (fake HOME, scratch ports, hooks
auto-registration off) and, for --destination online|both, a throwaway org
server (PostgreSQL, dev auth, OTLP trace gateway, the SDK signed in). Runs the
chatbots under examples/ai-apps against real providers on the cheap models
only (OpenAI gpt-5-nano; Anthropic claude-haiku-5-5 at low effort, as the
examples are written), checks each run with examples/ai-apps/verify.py, and
writes report.md and report.json.

--dry-run does all the setup (binaries, daemon, org, sign-in, virtualenvs,
node_modules) and, per example and destination, runs a canary in the
example's own environment instead of the chatbot: the SDK starts, every
instrumentor the example uses loads, and one synthetic trace with fixed usage
goes through ingest and verify.py. No provider is contacted (not even the
model-list probe) and provider keys are not passed to the canary.

Standard library only. Keys come from OPENAI_API_KEY / ANTHROPIC_API_KEY in the
environment; they are passed to an example process and to the provider host,
and nowhere else: never printed, never written (every log and the report go
through redact()). A missing key or an unreachable provider host is a SKIP
with the reason, never a pass.

  scripts/planea-e2e/run.sh --dry-run
  scripts/planea-e2e/run.sh --frameworks openai,langgraph --providers openai
  scripts/planea-e2e/run.sh --destination both --frameworks sdk-direct
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import http.cookiejar as cookiejar
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
EXAMPLES = REPO / "examples" / "ai-apps"
VERIFY = EXAMPLES / "verify.py"

# The ports a developer's real superbased uses. Nothing here may bind or call them.
RESERVED_PORTS = {4317, 4318, 4328, 8081, 8443, 8820, 8821, 8823, 8840}

# A superbased answering on one of these means this is a developer's own
# machine with a live install: the runner refuses (unless --allow-live-host).
LIVE_HOST_PORTS = (8081, 8820)

# The spend cap (--max-spend) is an ESTIMATE from the providers' reported
# usage, not a provider-side limit. A live case that leaves no usage record
# (a crash, a timeout, a malformed run.json) is charged this worst-case amount
# instead of $0, and so is each sdk-direct experiment (2 small model calls the
# runner cannot see the usage of).
WORST_CASE_CASE_USD = 0.01
EXPERIMENT_USD = 0.01
# A broken setup otherwise fails (and pays for) every remaining live case.
MAX_CONSECUTIVE_LIVE_FAILURES = 3

# TypeScript examples run `node chatbot.ts`: type stripping is on by default
# only from Node 22.18 (P-35).
MIN_NODE = (22, 18)

# The only models the examples (and this runner) use. Rates are list prices in
# $ per million tokens: input, output, cache read, cache write. They are used
# for the run's approximate spend, for verify.py --price, and to price the
# throwaway machine and org (the shipped price book lists gpt-5-nano at $0,
# finding L-10, so without a local price every gpt-5-nano cost reads $0).
PROVIDERS = {
    "openai": {
        "model": "gpt-5-nano", "verify_model": "gpt-5-nano", "key_env": "OPENAI_API_KEY",
        "host": "api.openai.com", "probe": "https://api.openai.com/v1/models",
        "rates": (0.05, 0.40, 0.005, 0.0),
    },
    "anthropic": {
        "model": "claude-haiku-5-5", "verify_model": "claude-haiku", "key_env": "ANTHROPIC_API_KEY",
        "host": "api.anthropic.com", "probe": "https://api.anthropic.com/v1/models",
        "rates": (0.10, 0.50, 0.01, 0.125),
    },
}

# superbased_sdk extras per framework (sdk/python/pyproject.toml).
PY_EXTRAS = {
    "openai": "openai", "anthropic": "anthropic", "langgraph": "langgraph", "openai-agents": "openai-agents",
    "llama-index": "llama-index", "pydantic-ai": "pydantic-ai", "crewai": "crewai,openai", "sdk-direct": "",
}


@dataclasses.dataclass(frozen=True)
class Example:
    """One runnable chatbot under examples/ai-apps."""

    path: str  # relative to examples/ai-apps
    framework: str
    provider: str
    lang: str  # a LANGS key: python | typescript | go | java
    targets: tuple  # what the example passes to instrument()
    ts_modules: tuple = ()  # (target, module spec JSON) for the TypeScript canary
    special: str = ""  # "" | crewai | sdk-direct
    # An OPEN finding this example is expected to show, named in the report
    # beside a FAIL. Remove it when the finding is fixed (L-03, L-07, A-04
    # were fixed by lanes LF-2 / LF-4 before this runner was written).
    known: str = ""
    machine_only: bool = False  # the example pins destination local

    @property
    def dir(self) -> Path:
        return EXAMPLES / self.path


def _m(**kw) -> tuple:
    """TypeScript instrument() modules: target (underscores for dashes) -> module spec."""
    return tuple((k.replace("_", "-"), json.dumps(v)) for k, v in kw.items())


# The table every --frameworks/--providers choice is filtered from. A new
# example is one row here (and its directory).
CATALOG = [
    Example("openai/python", "openai", "openai", "python", ("openai",)),
    Example("openai/typescript", "openai", "openai", "typescript", ("openai",), _m(openai="openai")),
    Example("anthropic/python", "anthropic", "anthropic", "python", ("anthropic",)),
    Example("anthropic/typescript", "anthropic", "anthropic", "typescript", ("anthropic",),
            _m(anthropic="@anthropic-ai/sdk")),
    Example("langgraph/python", "langgraph", "openai", "python", ("langgraph",)),
    Example("langgraph/python-anthropic", "langgraph", "anthropic", "python", ("langgraph",)),
    Example("langgraph/typescript", "langgraph", "openai", "typescript", ("langgraph",),
            _m(langchain="@langchain/core/callbacks/manager")),
    Example("langgraph/typescript-anthropic", "langgraph", "anthropic", "typescript", ("langgraph",),
            _m(langchain="@langchain/core/callbacks/manager")),
    Example("openai-agents/python", "openai-agents", "openai", "python", ("openai-agents",)),
    Example("openai-agents/python-anthropic", "openai-agents", "anthropic", "python", ("openai-agents",)),
    Example("openai-agents/typescript", "openai-agents", "openai", "typescript", ("openai-agents",),
            _m(openai_agents="@openai/agents")),
    Example("llama-index/python", "llama-index", "openai", "python", ("llama-index",)),
    Example("llama-index/python-anthropic", "llama-index", "anthropic", "python", ("llama-index",)),
    Example("pydantic-ai/python", "pydantic-ai", "openai", "python", ("pydantic-ai",)),
    Example("pydantic-ai/python-anthropic", "pydantic-ai", "anthropic", "python", ("pydantic-ai",)),
    Example("crewai/python", "crewai", "openai", "python", ("crewai", "openai"), special="crewai"),
    Example("vercel-ai/typescript", "vercel-ai", "openai", "typescript", ("vercel-ai",),
            _m(vercel_ai={"ai": "ai", "otel": "@ai-sdk/otel"})),
    Example("sdk-direct/python", "sdk-direct", "openai", "python", (), special="sdk-direct"),
    Example("sdk-direct/python-anthropic", "sdk-direct", "anthropic", "python", (), special="sdk-direct"),
    Example("sdk-direct/go", "sdk-direct", "openai", "go", (), special="sdk-direct"),
    Example("sdk-direct/java", "sdk-direct", "openai", "java", (), special="sdk-direct"),
]
FRAMEWORKS = sorted({e.framework for e in CATALOG})

# ---------------------------------------------------------------- redaction

_SECRETS: list[str] = []
# (pattern, replacement): every match is replaced, so a secret the runner never
# registered (a key in a provider's error text, a password in a DSN some log
# line prints) still does not survive.
_SECRET_PATTERNS = [
    (re.compile(r"sk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_\-]{16,}"), "<redacted>"),
    (re.compile(r"sbo-vk-[A-Za-z0-9_\-]{8,}"), "<redacted>"),
    (re.compile(r"\b[0-9a-f]{12,}\.[A-Za-z0-9_\-]{20,}\b"), "<redacted>"),  # <key_id>.<secret> SDK/ingest credentials
    (re.compile(r"#token=[^\s\"']+"), "<redacted>"),  # a first-run / set-password link
    (re.compile(r"(?i)(x-api-key|authorization)\s*[:=]\s*(?:bearer\s+)?\S+"), r"\1: <redacted>"),
    # scheme://user:password@host (a PostgreSQL DSN): keep the user, drop the password.
    (re.compile(r"(://[^:/\s@]+:)[^@\s/]+@"), r"\1<redacted>@"),
]


def add_secret(value: str) -> None:
    if value and len(value) >= 8 and value not in _SECRETS:
        _SECRETS.append(value)


def redact(text: str) -> str:
    """Every string that is printed, logged or written goes through here."""
    if not text:
        return text
    for s in sorted(_SECRETS, key=len, reverse=True):
        text = text.replace(s, "<redacted>")
    for p, repl in _SECRET_PATTERNS:
        text = p.sub(repl, text)
    return text


def log(msg: str) -> None:
    print(redact(f"[planea-e2e {time.strftime('%H:%M:%S')}] {msg}"), file=sys.stderr, flush=True)


# ---------------------------------------------------------------- helpers


class SetupError(Exception):
    """The run cannot continue (a throwaway daemon or org did not come up)."""


def free_port() -> int:
    for _ in range(50):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port not in RESERVED_PORTS:
            return port
    raise SetupError("no free scratch port")


def http(method: str, url: str, body=None, headers=None, opener=None, timeout=15) -> tuple[int, str]:
    """A loopback HTTP call that never goes through a proxy."""
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    op = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e)


def run(cmd: list, *, cwd=None, env=None, timeout=600, log_path: Path | None = None, input_text=None) -> tuple[int, str]:
    """Run a command, capture stdout+stderr, write the redacted output to log_path."""
    try:
        p = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout, input=input_text,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        code, out = p.returncode, p.stdout or ""
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        code, out = 124, out + f"\n[planea-e2e] timed out after {timeout}s"
    except FileNotFoundError as e:
        code, out = 127, str(e)
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(redact(f"$ {' '.join(shlex.quote(str(c)) for c in cmd)}\n{out}\n[exit {code}]\n\n"))
    return code, out


def wait_http(url: str, ok, deadline_s: float, proc: subprocess.Popen | None = None) -> bool:
    end = time.time() + deadline_s
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        code, body = http("GET", url, timeout=3)
        if ok(code, body):
            return True
        time.sleep(0.5)
    return False


def field(out: str, name: str) -> str:
    for line in out.splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip() == name:
            return v.strip()
    return ""


# The parent environment variables a child process (the throwaway daemon and
# org, a chatbot, a canary, verify.py) may inherit. An ALLOW-list (P-27): an
# inherited CHATBOT_MODEL, OPENAI_BASE_URL, SUPERBASED_* or anything else a
# framework reads cannot change what a case runs or what it costs. Everything
# a case needs on top (its destination, its provider key, CHATBOT_MODEL) is
# set explicitly by the runner.
CHILD_ENV_ALLOW = frozenset({
    "PATH", "HOME", "LANG", "LANGUAGE", "TZ", "TERM", "TMPDIR", "TMP", "TEMP", "USER", "LOGNAME", "SHELL",
    # the network proxy (a cloud session's egress) and its CA bundle
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    # uv / pip / npm caches and their TLS settings
    "UV_CACHE_DIR", "UV_NATIVE_TLS", "UV_SYSTEM_CERTS", "PIP_CACHE_DIR", "PIP_CERT", "PIP_CONFIG_FILE", "PIP_INDEX_URL",
    "PIP_DISABLE_PIP_VERSION_CHECK", "NPM_CONFIG_CACHE", "npm_config_cache", "NPM_CONFIG_USERCONFIG",
    "npm_config_proxy", "npm_config_https_proxy", "npm_config_noproxy",
    # Go's module and build caches and its module proxy (the Go examples are
    # built at install time; nothing reads these at run time)
    "GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY", "GONOPROXY", "GOSUMDB", "GONOSUMDB", "GOPRIVATE", "GOTOOLCHAIN",
    # the JDK (a cloud session puts its proxy and trust store in JAVA_TOOL_OPTIONS) and Maven
    "JAVA_HOME", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "MAVEN_OPTS",
})
CHILD_ENV_ALLOW_PREFIXES = ("LC_",)


def base_env(parent: dict | None = None) -> dict:
    """The child environment: only the allow-listed parent variables, plus
    loopback in NO_PROXY so a call to the throwaway daemon or org never goes
    through a proxy."""
    parent = os.environ if parent is None else parent
    env = {k: v for k, v in parent.items() if k in CHILD_ENV_ALLOW or k.startswith(CHILD_ENV_ALLOW_PREFIXES)}
    for k in ("NO_PROXY", "no_proxy"):
        cur = env.get(k, "")
        env[k] = ",".join(x for x in (cur, "127.0.0.1", "localhost") if x)
    return env


def git_info() -> dict:
    def g(*a: str) -> str:
        code, out = run(["git", "-C", str(REPO), *a], timeout=30)
        return out.strip() if code == 0 else ""
    return {"sha": g("rev-parse", "HEAD"), "branch": g("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": bool(g("status", "--porcelain", "--untracked-files=no"))}


def verify_args_from_sh(example: Example) -> list[str]:
    """The verify.py flags the example's own verify.sh passes, so the runner
    checks exactly what a developer running ./verify.sh would."""
    sh = example.dir / "verify.sh"
    for line in sh.read_text().splitlines():
        if "verify.py run.json" in line and line.strip().startswith("exec"):
            parts = shlex.split(line.split("verify.py run.json", 1)[1])
            return [p for p in parts if p not in ("$@", "${args[@]}")]
    return []


def strip_flag(args: list[str], flag: str) -> list[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a == flag:
            skip = True
            continue
        out.append(a)
    return out


# ---------------------------------------------------------------- binaries


def build_binaries(work: Path, bin_dir: str | None) -> tuple[Path, Path]:
    if bin_dir:
        b = Path(bin_dir).resolve()
        obs, org = b / "observer", b / "observer-org"
        for p in (obs, org):
            if not p.exists():
                raise SetupError(f"--bin: {p} does not exist")
        return obs, org
    out = work / "bin"
    out.mkdir(parents=True, exist_ok=True)
    for name in ("observer", "observer-org"):
        log(f"building {name} from the checkout (a few minutes on a cold cache)")
        code, txt = run(["go", "build", "-o", str(out / name), f"./cmd/{name}"], cwd=REPO, timeout=1800,
                        log_path=work / "logs" / "build.log")
        if code != 0:
            raise SetupError(f"go build ./cmd/{name} failed (exit {code}); see logs/build.log")
    return out / "observer", out / "observer-org"


# ---------------------------------------------------------------- the machine

MACHINE_CONFIG = """[observer]
db_path = "{db}"

[observer.hooks]
auto_register = false

[components]
add = ["obs"]

[observability]
enabled = true

[observability.admission]
enabled = true
mode = "enforce"

# The sdk-direct examples' turn 3 ("Tell me about competitor pricing.") is
# refused by this deterministic criterion; no judge model is called.
[[observability.admission.criterion]]
id = "topics"
type = "denied_topics"
topics = ["competitor pricing"]
decision = "deny"
severity = "high"

[ingest.otel]
grpc_addr = "127.0.0.1:{grpc}"
http_addr = "127.0.0.1:{http}"

[pricing.feed]
enabled = false

[security.deps]
index_download = false

# The shipped price book lists gpt-5-nano at $0 (finding L-10). List price.
[intelligence.pricing.models."gpt-5-nano"]
input = 0.05
output = 0.40
cache_read = 0.005
"""

ADMIT_PROBE = "Tell me about competitor pricing."
SUPPORT_PROMPT = "You are a terse support bot for {{ company }}. Answer in one sentence. Returns are accepted within 30 days."


class Machine:
    """The throwaway observer daemon."""

    def __init__(self, binary: Path, work: Path):
        self.bin = binary
        self.dir = work / "machine"
        self.home = self.dir / "h"
        self.cfg = self.dir / "config.toml"
        self.otlp_port, self.grpc_port = free_port(), free_port()
        self.dash_port, self.proxy_port = free_port(), free_port()
        self.dash_url = f"http://127.0.0.1:{self.dash_port}"
        self.otlp_url = f"http://127.0.0.1:{self.otlp_port}/v1/traces"
        self.proc: subprocess.Popen | None = None
        self.logs = work / "logs"
        self.signed_in = False
        self.sign_in_note = ""
        self.sdk_key = ""

    def env(self) -> dict:
        env = base_env()
        env.update({
            "HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_DATA_HOME": str(self.home / ".local" / "share"), "XDG_CACHE_HOME": str(self.home / ".cache"),
            "OBSERVER_CROSSMOUNT_DISABLE": "1",
        })
        return env

    def cli(self, *args: str, timeout=120, input_text=None) -> tuple[int, str]:
        return run([str(self.bin), *args, "--config", str(self.cfg)], cwd=self.dir, env=self.env(),
                   timeout=timeout, log_path=self.logs / "machine-cli.log", input_text=input_text)

    def start(self) -> None:
        (self.home / ".observer").mkdir(parents=True, exist_ok=True)
        db = self.home / ".observer" / "observer.db"
        self.cfg.write_text(MACHINE_CONFIG.format(db=db, grpc=self.grpc_port, http=self.otlp_port))
        self._spawn()
        log(f"machine ready: dashboard {self.dash_url}, OTLP {self.otlp_url} (HOME {self.home})")
        code, out = self.cli("obs", "prompts", "create", "support-system", "--label", "production",
                             "--text", SUPPORT_PROMPT)
        if code != 0:
            log(f"machine: prompt create failed (exit {code}); sdk-direct falls back to its default prompt")

    def _spawn(self) -> None:
        self.logs.mkdir(parents=True, exist_ok=True)
        f = open(self.logs / "machine-daemon.log", "a")
        self.proc = subprocess.Popen(
            [str(self.bin), "start", "--config", str(self.cfg), "--port", str(self.proxy_port),
             "--dashboard-addr", f"127.0.0.1:{self.dash_port}", "--no-open", "--no-crossmount"],
            cwd=self.dir, env=self.env(), stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        if not wait_http(self.dash_url + "/api/obs/enabled", lambda c, b: c == 200 and '"enabled":true' in b.replace(" ", ""),
                         120, self.proc):
            raise SetupError("the throwaway machine did not come up with app observability on; see logs/machine-daemon.log")

    def restart(self) -> None:
        self.stop()
        self._spawn()

    def stop(self) -> None:
        stop_proc(self.proc)
        self.proc = None


def stop_proc(p: subprocess.Popen | None) -> None:
    if p is None or p.poll() is not None:
        return
    try:
        os.killpg(p.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        p.terminate()
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            p.kill()



# ---------------------------------------------------------------- PostgreSQL

def split_dsn_password(dsn: str) -> tuple[str, str]:
    """A postgres:// URL without its password, and the password. psql gets the
    first on its command line and the second in PGPASSWORD (P-29): argv shows
    in `ps` and in the runner's command log, the environment does not. The
    password is also registered with redact()."""
    if not dsn:
        return dsn, ""
    u = urllib.parse.urlsplit(dsn)
    if u.password is None:
        return dsn, ""
    host = u.hostname or ""
    if ":" in host:  # an IPv6 literal
        host = f"[{host}]"
    netloc = (urllib.parse.quote(u.username or "", safe="") + "@" if u.username else "") + host
    if u.port:
        netloc += f":{u.port}"
    password = urllib.parse.unquote(u.password)
    add_secret(password)
    add_secret(u.password)
    return urllib.parse.urlunsplit((u.scheme, netloc, u.path, u.query, u.fragment)), password


def psql_env(password: str) -> dict:
    env = base_env()
    if password:
        env["PGPASSWORD"] = password
    return env


class Postgres:
    """The org server's database. observer-org serves PostgreSQL only (SQLite is
    refused outside Go test fixtures, internal/orgserver/db/runtime_sqlite.go),
    so the throwaway org gets a private cluster on a scratch loopback port, or a
    new database on the server --org-pg-dsn names (dropped at the end)."""

    def __init__(self, work: Path, admin_dsn: str = ""):
        self.work = work
        self.admin_dsn = admin_dsn
        self.dsn = ""
        self.data = None
        self.bin = None
        self.prefix: list = []
        self.dbname = "pe2e_" + secrets.token_hex(4)

    @staticmethod
    def bin_dir() -> Path:
        p = shutil.which("initdb")
        if p:
            return Path(p).parent
        dirs = sorted(Path("/usr/lib/postgresql").glob("*/bin"), key=lambda d: int(d.parent.name) if d.parent.name.isdigit() else 0,
                      reverse=True)
        for d in dirs:
            if (d / "initdb").exists():
                return d
        raise SetupError("no PostgreSQL found for the throwaway org: put initdb/pg_ctl (PostgreSQL 16+) on PATH, "
                         "or pass --org-pg-dsn postgres://... (a server the run may create a database on)")

    def start(self) -> None:
        logp = self.work / "logs" / "postgres.log"
        if self.admin_dsn:
            admin = self.admin_dsn
        else:
            self.bin = self.bin_dir()
            port = free_port()
            # A cluster dir of its own: initdb refuses root, so as root the
            # cluster runs as the postgres account, which must own the dir.
            self.data = Path(tempfile.mkdtemp(prefix="pe2e-pg-"))
            if os.geteuid() == 0:
                runner = shutil.which("runuser")
                if not runner:
                    raise SetupError("running as root without runuser: cannot start a private PostgreSQL; pass --org-pg-dsn")
                self.prefix = [runner, "-u", "postgres", "--"]
                shutil.chown(self.data, "postgres", "postgres")
            data = self.data / "data"
            code, _ = run([*self.prefix, str(self.bin / "initdb"), "-D", str(data), "-A", "trust", "-U", "e2e",
                           "-E", "UTF8", "--no-sync"], timeout=300, log_path=logp)
            if code != 0:
                raise SetupError("initdb failed; see logs/postgres.log")
            opts = (f"-p {port} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' -c fsync=off "
                    "-c synchronous_commit=off -c full_page_writes=off -c max_connections=200")
            code, _ = run([*self.prefix, str(self.bin / "pg_ctl"), "-D", str(data), "-o", opts,
                           "-l", str(self.data / "server.log"), "-w", "-t", "60", "start"], timeout=120, log_path=logp)
            if code != 0:
                raise SetupError("pg_ctl start failed; see logs/postgres.log")
            admin = f"postgres://e2e@127.0.0.1:{port}/postgres?sslmode=disable"
        psql = str(self.bin / "psql") if self.bin and (self.bin / "psql").exists() else (shutil.which("psql") or "")
        if not psql:
            raise SetupError("psql not found (needed to create the org database)")
        admin_argv, password = split_dsn_password(admin)
        code, _ = run([psql, admin_argv, "-v", "ON_ERROR_STOP=1", "-c", f"CREATE DATABASE {self.dbname}"], timeout=60,
                      env=psql_env(password), log_path=logp)
        if code != 0:
            raise SetupError("CREATE DATABASE failed; see logs/postgres.log")
        u = urllib.parse.urlsplit(admin)
        # The org server reads this DSN from its environment (never argv).
        self.dsn = urllib.parse.urlunsplit((u.scheme, u.netloc, "/" + self.dbname, u.query, u.fragment))
        self._psql, self._admin, self._password = psql, admin_argv, password
        log(f"postgres: database {self.dbname} ({'private cluster' if self.data else 'on --org-pg-dsn'})")

    def stop(self) -> None:
        logp = self.work / "logs" / "postgres.log"
        if self.data is not None:
            run([*self.prefix, str(self.bin / "pg_ctl"), "-D", str(self.data / "data"), "-m", "fast", "-w", "stop"],
                timeout=120, log_path=logp)
            shutil.rmtree(self.data, ignore_errors=True)
            self.data = None
        elif self.dsn:
            run([self._psql, self._admin, "-c", f"DROP DATABASE IF EXISTS {self.dbname} WITH (FORCE)"], timeout=60,
                env=psql_env(self._password), log_path=logp)
        self.dsn = ""


# ---------------------------------------------------------------- the org

ORG_CONFIG = """[server]
listen = "127.0.0.1:{dash}"
external_url = "http://127.0.0.1:{dash}"
state_dir = "{dir}/state"
session_key_path = "{dir}/session.key"
log_level = "info"
dev_auth = true

[auth]
providers = ["local"]

[scim]
auth_token_path = "{dir}/scim.token"

[bearer]
signing_key_path = "{dir}/bearer.key"

[dashboard]
admin_emails = ["{admin}"]

[pricing_feed]
enabled = false

# The first-run setup link is a live credential (ledger SETUP-1): keep it out
# of the log the runner copies next to the report.
[setup]
log_token = false

[gateway]
enabled = true
listen = "127.0.0.1:{gw}"
grpc_listen = "127.0.0.1:{gwgrpc}"

# The embedded durable log provisions its whole size up front and refuses to
# start when the work directory's disk has less free space (the 10 GiB default
# on a box whose /tmp is a small tmpfs). A throwaway org writes a few MB.
[log]
max_bytes_gb = 1
"""

ORG_ADMIN = "e2e-admin@example.com"
ORG_DEV = "e2e-dev@example.com"
ORG_WORKSPACE = "e2e-l2"


class Org:
    """The throwaway org server: role all on a throwaway PostgreSQL, dev auth, OTLP trace gateway."""

    def __init__(self, binary: Path, work: Path, dsn: str):
        self.bin = binary
        self.dsn = dsn
        self.dir = work / "org"
        self.cfg = self.dir / "config.toml"
        self.dash_port, self.gw_port, self.gw_grpc = free_port(), free_port(), free_port()
        self.dash_url = f"http://127.0.0.1:{self.dash_port}"
        self.gateway_url = f"http://127.0.0.1:{self.gw_port}"
        self.proc: subprocess.Popen | None = None
        self.logs = work / "logs"
        self.credential = ""
        self.opener = None

    def env(self) -> dict:
        env = base_env()
        env.update({"HOME": str(self.dir / "h"), "OBSERVER_CONTROL_STORE_DSN": self.dsn,
                    "OBSERVER_DATA_STORE_DSN": self.dsn})
        return env

    def cli(self, *args: str, timeout=120) -> tuple[int, str]:
        return run([str(self.bin), *args, "--config", str(self.cfg)], cwd=self.dir, env=self.env(),
                   timeout=timeout, log_path=self.logs / "org-cli.log")

    def start(self) -> None:
        (self.dir / "state").mkdir(parents=True, exist_ok=True)
        (self.dir / "h").mkdir(parents=True, exist_ok=True)
        write_org_secrets(self.dir)
        self.cfg.write_text(ORG_CONFIG.format(dash=self.dash_port, dir=self.dir, admin=ORG_ADMIN,
                                              gw=self.gw_port, gwgrpc=self.gw_grpc))
        code, out = self.cli("migrate", timeout=300)
        if code != 0:
            raise SetupError(f"observer-org migrate failed (exit {code}); see logs/org-cli.log")
        f = open(self.logs / "org-serve.log", "a")
        self.proc = subprocess.Popen([str(self.bin), "serve", "--config", str(self.cfg)], cwd=self.dir,
                                     env=self.env(), stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        if not wait_http(self.dash_url + "/readyz", lambda c, b: c == 200, 120, self.proc):
            raise SetupError("the throwaway org server did not become ready; see logs/org-serve.log")
        log(f"org ready: dashboard {self.dash_url}, trace gateway {self.gateway_url}")

        for args in (("users", "create", ORG_ADMIN, "--kind", "dashboard", "--role", "admin"),):
            code, out = self.cli(*args)
            if code != 0:
                raise SetupError(f"observer-org {' '.join(args[:2])} failed; see logs/org-cli.log")
        code, out = self.cli("new-service-account", "--name", "planea-e2e")
        sa = field(out, "sa_id")
        if code != 0 or not sa:
            raise SetupError("observer-org new-service-account printed no sa_id; see logs/org-cli.log")
        code, out = self.cli("new-ingest-credential", "--sa-id", sa, "--workspace-id", ORG_WORKSPACE,
                             "--signals", "traces", "--sdk-scopes", "admit,sdk:read,sdk:write,sdk:eval")
        self.credential = field(out, "credential")
        if code != 0 or "." not in self.credential:
            raise SetupError("observer-org new-ingest-credential printed no credential; see logs/org-cli.log")
        add_secret(self.credential)
        self._admin_session()
        for ws in (ORG_WORKSPACE, "default"):  # default: the workspace sign-in keys land in (L-23)
            self._capture_policy(ws)
        for prov in PROVIDERS.values():
            self._price(prov["model"], prov["rates"])

    def _admin_session(self) -> None:
        jar = cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPCookieProcessor(jar))
        code, page = http("GET", self.dash_url + "/auth/dev/login", opener=self.opener)
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', page)
        if code != 200 or not m:
            raise SetupError(f"org dev-auth form: HTTP {code}, no csrf field")
        form = urllib.parse.urlencode({"email": ORG_ADMIN, "csrf_token": m.group(1)}).encode()
        code, body = http("POST", self.dash_url + "/auth/dev/login", body=form, opener=self.opener,
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        if code != 200:
            raise SetupError(f"org dev-auth login: HTTP {code}")

    def api(self, method: str, path: str, body=None) -> tuple[int, str]:
        return http(method, self.dash_url + path, body=body, opener=self.opener)

    def _capture_policy(self, ws: str) -> None:
        code, body = self.api("PUT", "/api/org/gateway/capture-policy", {
            "workspace_id": ws, "environment_id": "", "level": "full_redacted",
            "max_attrs": 64, "max_bytes": 16384, "max_depth": 4, "max_nodes": 64, "body_max_bytes": 16384})
        if code != 200:
            log(f"org: capture policy for workspace {ws}: HTTP {code} {body[:200]}")

    def _price(self, model: str, rates: tuple) -> None:
        body = {"model": model, "input_per_mtok": rates[0], "output_per_mtok": rates[1],
                "cache_read_per_mtok": rates[2], "source": "list"}
        if rates[3]:
            body["cache_write_per_mtok"] = rates[3]
        code, txt = self.api("POST", "/api/org/pricing", body)
        if code not in (200, 201):
            log(f"org: price row for {model}: HTTP {code} {txt[:200]}")

    def sign_in(self, machine: Machine) -> None:
        """Enrol the throwaway machine as a developer and run `observer sdk sign-in`."""
        code, out = self.cli("users", "create", ORG_DEV, "--kind", "developer")
        m = re.search(r"\(user_id ([^)\s]+)\)", out)
        uid = m.group(1) if m else ""
        if code != 0 or not uid:
            machine.sign_in_note = "observer-org users create printed no user id; see logs/org-cli.log"
            return
        code, out = self.cli("new-enrolment-token", "--user-id", uid)
        token = field(out, "token")
        if code != 0 or not token:
            machine.sign_in_note = "observer-org new-enrolment-token printed no token; see logs/org-cli.log"
            return
        add_secret(token)
        code, out = machine.cli("org", "enroll", self.dash_url, token, "--wire-clients=false", timeout=180, input_text="")
        if code != 0:
            machine.sign_in_note = f"observer org enroll failed (exit {code}); see logs/machine-cli.log"
            return
        code, out = machine.cli("sdk", "sign-in", timeout=120, input_text="")
        if code != 0:
            machine.sign_in_note = f"observer sdk sign-in failed (exit {code}); see logs/machine-cli.log"
            return
        code, out = machine.cli("sdk", "status", "--json")
        try:
            online = json.loads(out[out.index("{"):]).get("online") or {}
        except (ValueError, AttributeError):
            online = {}
        # The sign-in key reads back only its own workspace's traces, so the
        # org checks of a signed-in run use it (never printed: add_secret).
        cred = online.get("credential_file") or ""
        try:
            machine.sdk_key = Path(cred).read_text().splitlines()[0].strip() if cred else ""
        except OSError:
            machine.sdk_key = ""
        add_secret(machine.sdk_key)
        machine.signed_in = code == 0 and bool(machine.sdk_key)
        machine.sign_in_note = (f"signed in (enrolled as a developer, `observer sdk sign-in`; key workspace "
                                f"`{online.get('workspace_id')}`, capture level `{online.get('capture_level')}`)"
                                if machine.signed_in else "sdk status showed no SDK key after sign-in")

    def stop(self) -> None:
        stop_proc(self.proc)
        self.proc = None


def write_org_secrets(d: Path) -> None:
    """The org config's session key, bearer signing key (Ed25519 PKCS#8) and SCIM token."""
    seed = secrets.token_bytes(32)
    # PKCS#8 for Ed25519: a fixed 16-byte prefix plus the 32-byte seed (RFC 8410).
    der = bytes.fromhex("302e020100300506032b657004220420") + seed
    import base64
    pem = "-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(der).decode() + "\n-----END PRIVATE KEY-----\n"
    for name, data in (("bearer.key", pem.encode()), ("session.key", secrets.token_bytes(32)),
                       ("scim.token", base64.urlsafe_b64encode(secrets.token_bytes(24)).rstrip(b"="))):
        p = d / name
        p.write_bytes(data)
        p.chmod(0o600)


# ---------------------------------------------------------------- environments


def find_python() -> str:
    for c in ("python3.12", "python3.13", "python3.11", "python3.10", "python3"):
        if shutil.which(c):
            return c
    raise SetupError("no Python 3.10-3.13 interpreter on PATH")


def py_env(example: Example, cache: Path, logs: Path) -> tuple[Path | None, str]:
    """A virtualenv per example (cached by its requirements), the SDK installed
    EDITABLE from the checkout so every run tests the tree as it is."""
    req = example.dir / "requirements.txt"
    extra = PY_EXTRAS.get(example.framework, "")
    key = hashlib.sha256((req.read_text() + "|" + extra + "|" + str(REPO)).encode()).hexdigest()[:12]
    venv = cache / "venvs" / f"{example.path.replace('/', '_')}-{key}"
    py = venv / "bin" / "python"
    stamp = venv / ".planea-e2e-ok"
    sdk = str(REPO / "sdk" / "python") + (f"[{extra}]" if extra else "")
    log_path = logs / "install" / f"{example.path.replace('/', '_')}.log"
    if stamp.exists():
        # Refresh only the editable SDK (cheap), in case its dependencies changed.
        code, _ = pip_install(py, ["-e", sdk], log_path)
        return (py, "") if code == 0 else (None, f"SDK reinstall failed (exit {code}); see {log_path.name}")
    shutil.rmtree(venv, ignore_errors=True)
    venv.parent.mkdir(parents=True, exist_ok=True)
    uv = shutil.which("uv")
    interp = find_python()
    cmd = [uv, "venv", "--python", interp, str(venv)] if uv else [interp, "-m", "venv", str(venv)]
    code, _ = run(cmd, timeout=300, env=base_env(), log_path=log_path)
    if code != 0:
        return None, f"virtualenv failed (exit {code}); see {log_path.name}"
    code, _ = pip_install(py, ["-e", sdk, "-r", str(req)], log_path)
    if code != 0:
        return None, f"pip install failed (exit {code}); see install/{log_path.name}"
    stamp.write_text(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    return py, ""


def pip_install(py: Path, args: list, log_path: Path) -> tuple[int, str]:
    uv = shutil.which("uv")
    if uv:
        # No --prerelease=disallow: CrewAI needs opentelemetry-semantic-conventions 0.66b2 (LC-05).
        return run([uv, "pip", "install", "--python", str(py), *args], timeout=1800, env=base_env(), log_path=log_path)
    return run([str(py), "-m", "pip", "install", "-q", *args], timeout=1800, env=base_env(), log_path=log_path)


_TS_SDK_BUILT: dict = {}


def ts_env(example: Example, logs: Path) -> tuple[bool, str]:
    """Build the TypeScript SDK once per run (L-15: install it in its own folder
    first), then install the example's node_modules in place (gitignored).
    npm ci when the example has a lockfile, so the checkout stays clean."""
    sdk = REPO / "sdk" / "typescript"
    log_path = logs / "install" / f"{example.path.replace('/', '_')}.log"
    if "ok" not in _TS_SDK_BUILT:
        lp = logs / "install" / "sdk-typescript.log"
        code, _ = run(["npm", "ci" if (sdk / "package-lock.json").exists() else "install", "--no-audit", "--no-fund"],
                      cwd=sdk, timeout=1200, env=base_env(), log_path=lp)
        if code == 0:
            code, _ = run(["npm", "run", "build"], cwd=sdk, timeout=600, env=base_env(), log_path=lp)
        _TS_SDK_BUILT["ok"] = code == 0
    if not _TS_SDK_BUILT["ok"]:
        return False, "building sdk/typescript failed; see install/sdk-typescript.log"
    if (example.dir / "package-lock.json").exists():
        cmd = ["npm", "ci", "--no-audit", "--no-fund"]
    else:
        cmd = ["npm", "install", "--no-audit", "--no-fund", "--no-save", "--package-lock=false"]
    code, _ = run(cmd, cwd=example.dir, timeout=1200, env=base_env(), log_path=log_path)
    return (code == 0), ("" if code == 0 else f"npm install failed (exit {code}); see install/{log_path.name}")


def ts_install_dirs(example: Example) -> list:
    """Where ts_env runs npm: a node_modules there that is a symlink (a Windows
    worktree's junction into the main checkout, the 2026-11-15 incident class)
    would have `npm ci` delete through it into another tree."""
    return [REPO / "sdk" / "typescript" / "node_modules", example.dir / "node_modules"]


def node_version_error() -> str:
    code, out = run(["node", "--version"], timeout=30)
    m = re.match(r"v(\d+)\.(\d+)", out.strip())
    if code != 0 or not m:
        return f"node --version failed (exit {code})"
    have = (int(m.group(1)), int(m.group(2)))
    if have < MIN_NODE:
        return (f"node {out.strip()} is too old: the TypeScript examples run `node chatbot.ts`, which needs "
                f"Node {MIN_NODE[0]}.{MIN_NODE[1]}+ (type stripping on by default)")
    return ""


# Go 1.21 is the first release that fetches the toolchain a go.mod asks for
# (the Go examples and sdk/go say `go 1.25.0`).
MIN_GO = (1, 21)
# The Java SDK and example compile with `maven.compiler.release` 17.
MIN_JAVA = 17


def go_version_error() -> str:
    code, out = run(["go", "env", "GOVERSION"], timeout=120)
    m = re.match(r"go(\d+)\.(\d+)", out.strip())
    if code != 0 or not m:
        return f"go env GOVERSION failed (exit {code})"
    if (int(m.group(1)), int(m.group(2))) < MIN_GO:
        return (f"{out.strip()} is too old: the Go examples need Go {MIN_GO[0]}.{MIN_GO[1]}+ "
                "(to fetch the toolchain their go.mod asks for)")
    return ""


def java_version_error() -> str:
    code, out = run(["java", "-version"], timeout=60)
    m = re.search(r'version "(\d+)(?:\.(\d+))?', out)
    if code != 0 or not m:
        return f"java -version failed (exit {code})"
    major = int(m.group(1))
    if major == 1 and m.group(2):  # 1.8 and older
        major = int(m.group(2))
    if major < MIN_JAVA:
        return f"java {major} is too old: the Java SDK and example need Java {MIN_JAVA}+"
    if not shutil.which("javac"):
        return ("java is a runtime without a compiler (no javac on PATH): the Java example and its canary "
                f"need a JDK {MIN_JAVA}+")
    return ""


def _slug(example: Example) -> str:
    return example.path.replace("/", "_")


# The canary is compiled INSIDE the Go example's own module through an
# overlay, at a package path that does not exist on disk (nothing is written
# into the example tree).
GO_CANARY_PKG = "internal/planeae2ecanary"


def go_env(example: Example, cache: Path, logs: Path) -> tuple[Path | None, str]:
    """Build the Go example's commands (chatbot, experiment) and the canary
    into a bin dir in the cache. The example's go.mod has a `replace` to
    sdk/go in this checkout, so every run builds against the SDK as it is;
    Go's own build cache keeps a rebuild cheap."""
    log_path = logs / "install" / f"{_slug(example)}.log"
    bin_dir = cache / "go" / _slug(example)
    shutil.rmtree(bin_dir, ignore_errors=True)  # never run a binary a failed build left behind
    bin_dir.mkdir(parents=True, exist_ok=True)
    env = dict(base_env(), GOFLAGS="-mod=readonly")
    cmds = sorted(p.parent.name for p in example.dir.glob("*/main.go"))
    code, _ = run(["go", "build", "-o", str(bin_dir) + os.sep, *[f"./{c}" for c in cmds]], cwd=example.dir,
                  timeout=1800, env=env, log_path=log_path)
    if code != 0:
        return None, f"go build failed (exit {code}); see install/{log_path.name}"
    src = HERE / "canary.go"
    copy = bin_dir / "canary-src" / "main.go"
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(src.read_text().replace("//go:build ignore\n", "", 1))
    overlay = bin_dir / "canary-src" / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(example.dir / GO_CANARY_PKG / "main.go"): str(copy)}}))
    code, _ = run(["go", "build", f"-overlay={overlay}", "-o", str(bin_dir / "planea-e2e-canary"),
                   "./" + GO_CANARY_PKG], cwd=example.dir, timeout=1800, env=env, log_path=log_path)
    if code != 0:
        return None, f"go build of the canary failed (exit {code}); see install/{log_path.name}"
    return bin_dir, ""


_JAVA_SDK_BUILT: dict = {}


def mvn(cache: Path, *args: str) -> list:
    """Maven, batch mode, against a local repository in the cache: the SDK
    installed from this checkout never lands in the developer's ~/.m2."""
    return ["mvn", "-B", "-q", f"-Dmaven.repo.local={cache / 'm2'}", *args]


def java_env(example: Example, cache: Path, logs: Path) -> tuple[str | None, str]:
    """Install sdk/java from the checkout once per run (it is not on Maven
    Central yet), then compile the example in place (target/ is gitignored)
    and resolve its classpath. The handle is that classpath: the chatbot,
    the experiment and the canary all run with plain `java -cp`."""
    if "ok" not in _JAVA_SDK_BUILT:
        lp = logs / "install" / "sdk-java.log"
        code, _ = run(mvn(cache, "-f", str(REPO / "sdk" / "java" / "pom.xml"), "install", "-DskipTests"),
                      timeout=1800, env=base_env(), log_path=lp)
        _JAVA_SDK_BUILT["ok"] = code == 0
    if not _JAVA_SDK_BUILT["ok"]:
        return None, "installing sdk/java failed; see install/sdk-java.log"
    log_path = logs / "install" / f"{_slug(example)}.log"
    cp_file = cache / "java" / f"{_slug(example)}.classpath"
    cp_file.parent.mkdir(parents=True, exist_ok=True)
    cp_file.unlink(missing_ok=True)
    code, _ = run(mvn(cache, "compile", "dependency:build-classpath", f"-Dmdep.outputFile={cp_file}"),
                  cwd=example.dir, timeout=1800, env=base_env(), log_path=log_path)
    if code != 0 or not cp_file.exists():
        return None, f"mvn compile failed (exit {code}); see install/{log_path.name}"
    return os.pathsep.join([str(example.dir / "target" / "classes"), cp_file.read_text().strip()]), ""


def java_install_dirs(example: Example) -> list:
    """Where Maven writes in the checkout: a symlinked target/ would have it
    write into another tree."""
    return [REPO / "sdk" / "java" / "target", example.dir / "target"]


# ---------------------------------------------------------------- languages


def _py_install(ex: Example, cache: Path, logs: Path):
    return py_env(ex, cache, logs)


def _ts_install(ex: Example, cache: Path, logs: Path):
    ok, err = ts_env(ex, logs)
    return (ex.dir if ok else None), err


def _py_script(ex: Example, handle, name: str) -> list:
    return [str(handle), name]


def _ts_script(ex: Example, handle, name: str) -> list:
    return ["node", name]


def _go_script(ex: Example, handle, name: str) -> list:
    # name is the command's main.go (chatbot/main.go): run its built binary.
    return [str(Path(handle) / Path(name).parent.name)]


def _java_script(ex: Example, handle, name: str) -> list:
    # name is the class's source file under src/main/java: run that class.
    cls = Path(name).relative_to("src/main/java").with_suffix("")
    return ["java", "-cp", str(handle), ".".join(cls.parts)]


def _py_canary(ex: Example, handle, case_dir: Path, spec: dict) -> tuple[list, Path]:
    cmd = [str(handle), str(HERE / "canary.py"), "--targets", ",".join(spec["targets"]), "--service", spec["service"],
           "--model", spec["model"], "--provider", spec["provider"], "--out", spec["out"]]
    if spec.get("admit_probe"):
        cmd += ["--admit-probe", spec["admit_probe"]]
    return cmd, case_dir


def _ts_canary(ex: Example, handle, case_dir: Path, spec: dict) -> tuple[list, Path]:
    cdir = case_dir / "canary"
    cdir.mkdir(exist_ok=True)
    shutil.copy(HERE / "canary.mjs", cdir / "canary.mjs")
    link = cdir / "node_modules"  # in the work dir, never an install target
    if not link.exists():
        link.symlink_to(ex.dir / "node_modules")
    js = {k: v for k, v in spec.items() if k != "admit_probe"}
    js["modules"] = {k: json.loads(v) for k, v in ex.ts_modules}
    return ["node", str(cdir / "canary.mjs"), json.dumps(js)], cdir


def _go_canary(ex: Example, handle, case_dir: Path, spec: dict) -> tuple[list, Path]:
    cmd = [str(Path(handle) / "planea-e2e-canary"), "-service", spec["service"], "-model", spec["model"],
           "-provider", spec["provider"], "-out", spec["out"]]
    if spec.get("admit_probe"):
        cmd += ["-admit-probe", spec["admit_probe"]]
    return cmd, case_dir


def _java_canary(ex: Example, handle, case_dir: Path, spec: dict) -> tuple[list, Path]:
    # The JDK's single-file source launcher: compiled in memory against the
    # example's classpath, nothing written anywhere.
    js = {k: spec[k] for k in ("service", "model", "provider", "out")}
    js["admit_probe"] = spec.get("admit_probe", "")
    return ["java", "-cp", str(handle), str(HERE / "Canary.java"), json.dumps(js)], case_dir


@dataclasses.dataclass(frozen=True)
class Lang:
    """How the runner handles one language (P-31). A new language (Go, Java:
    lane E3) is one row in LANGS plus its catalog rows; nothing else in the
    runner branches on a language."""

    entry: str  # the chatbot's entry file in the example directory
    tools: tuple  # commands that must be on PATH (run.sh checks only the selected languages')
    install: object  # (example, cache, logs) -> (handle | None, error)
    script: object  # (example, handle, file) -> argv running that file of the example, in its directory
    canary: object  # (example, handle, case_dir, spec) -> (argv, cwd)
    preflight: object = None  # () -> "" or why this machine cannot run the language
    install_dirs: object = None  # (example) -> dirs the install writes; a symlink there is refused
    files: tuple = ()  # other files every example directory of this language has
    experiment: str = ""  # the sdk-direct experiment's entry file, run after a live local case


LANGS = {
    "python": Lang(entry="chatbot.py", tools=("python3",), install=_py_install, script=_py_script, canary=_py_canary,
                   files=("requirements.txt",), experiment="experiment.py"),
    "typescript": Lang(entry="chatbot.ts", tools=("node", "npm"), install=_ts_install, script=_ts_script,
                       canary=_ts_canary, preflight=node_version_error, install_dirs=ts_install_dirs,
                       files=("package.json",)),
    # Each command is a main package (chatbot/, experiment/) built at install;
    # go.mod has a `replace` to sdk/go in this checkout.
    "go": Lang(entry="chatbot/main.go", tools=("go",), install=go_env, script=_go_script, canary=_go_canary,
               preflight=go_version_error, files=("go.mod", "go.sum"), experiment="experiment/main.go"),
    # Maven (sdk/java/pom.xml): the SDK installed from the checkout into the
    # cache's own local repository, the example compiled in place.
    "java": Lang(entry="src/main/java/example/Chatbot.java", tools=("java", "mvn"), install=java_env,
                 script=_java_script, canary=_java_canary, preflight=java_version_error,
                 install_dirs=java_install_dirs, files=("pom.xml",),
                 experiment="src/main/java/example/Experiment.java"),
}


# ---------------------------------------------------------------- providers


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The probe carries the provider key: a redirect is never followed (it
    would send the key's header to wherever the redirect points)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - urllib hook
        return None


def probe_opener() -> urllib.request.OpenerDirector:
    """The environment's proxy (a cloud session's egress) and no redirect handler."""
    return urllib.request.build_opener(_NoRedirect())


def provider_error_body(body: str) -> bool:
    """A provider's own JSON error ({"error": ...}, Anthropic's {"type":
    "error", "error": ...}), as opposed to a proxy's or firewall's page."""
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    return isinstance(doc, dict) and "error" in doc


def probe_provider(name: str, dry_run: bool, opener=None) -> dict:
    """Is the key set, is the host reachable, does the provider accept the key?
    A GET of the model list: no tokens, no spend. The key goes only to the
    provider's own host, and never on a redirect.

    A dry run makes NO connection at all (P-25): the provider is reported
    "not used (dry run)" and the key, if set, is only registered with redact().
    """
    p = PROVIDERS[name]
    key = os.environ.get(p["key_env"], "")
    st = {"model": p["model"], "key_env": p["key_env"], "key_set": bool(key), "reachable": None, "usable": False,
          "reason": ""}
    if key:
        add_secret(key)
    if dry_run:
        st["reason"] = "not used (dry run)"
        return st
    hdrs = {}
    if key:
        hdrs = {"Authorization": f"Bearer {key}"} if name == "openai" else {"x-api-key": key,
                                                                             "anthropic-version": "2023-06-01"}
    req = urllib.request.Request(p["probe"], headers=hdrs)
    op = opener or probe_opener()
    body = ""
    try:
        with op.open(req, timeout=10) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            body = e.read().decode("utf-8", "replace")[:4096]
        except OSError:
            body = ""
    except (urllib.error.URLError, OSError) as e:
        code = 0
        st["reason"] = f"{p['host']} unreachable: {getattr(e, 'reason', e)}"
    if code:
        # 401 without a key is the expected "reachable" answer. A 403 is the
        # provider only when the body is the provider's own JSON error; the
        # default cloud environment's proxy answers 403 for a blocked host (P-33).
        provider_403 = code == 403 and provider_error_body(body)
        st["reachable"] = code in (200, 401, 404, 405) or provider_403
        if 300 <= code < 400:
            st["reason"] = f"{p['host']} answered a redirect (HTTP {code}); not followed with the key"
        elif code == 403 and not provider_403:
            st["reason"] = f"{p['host']} blocked by this environment (HTTP 403 with no provider error body)"
        elif not st["reachable"]:
            st["reason"] = f"{p['host']} answered HTTP {code} (blocked by this environment's network policy?)"
    else:
        st["reachable"] = False
    if not key:
        st["reason"] = st["reason"] or f"{p['key_env']} is not set"
        if not st["reason"].startswith(p["key_env"]):
            st["reason"] = f"{p['key_env']} is not set; " + st["reason"]
    elif st["reachable"]:
        if code == 200:
            st["usable"] = True
        else:
            st["reason"] = f"{p['host']} refused the key (HTTP {code})"
    return st


# ---------------------------------------------------------------- one case


@dataclasses.dataclass
class Result:
    example: str
    framework: str
    provider: str
    lang: str
    destination: str
    mode: str
    status: str = "skip"  # pass | fail | skip
    reason: str = ""
    checks: list = dataclasses.field(default_factory=list)
    tokens: dict = dataclasses.field(default_factory=dict)
    est_cost_usd: float = 0.0
    # What the case counts against --max-spend: est_cost_usd, or the
    # worst-case amount when a live case left no usage record, plus the
    # sdk-direct experiment's flat charge.
    charged_usd: float = 0.0
    stored_cost_usd: dict = dataclasses.field(default_factory=dict)
    duration_s: float = 0.0
    known: str = ""
    notes: list = dataclasses.field(default_factory=list)
    log: str = ""


def est_cost(calls: list, rates: tuple) -> float:
    rin, rout, rread, rwrite = rates
    total = 0.0
    for c in calls:
        if "input" not in c:
            continue
        read, write = c.get("cached", 0) or 0, c.get("cache_write", 0) or 0
        total += ((c["input"] - read - write) * rin + c.get("output", 0) * rout + read * rread + write * rwrite) / 1e6
    return total


def sum_tokens(calls: list) -> dict:
    t = {"input": 0, "output": 0, "cached": 0, "cache_write": 0, "reasoning": 0, "calls": 0}
    for c in calls:
        if "input" not in c:
            continue
        t["calls"] += 1
        for k in ("input", "output", "cached", "cache_write", "reasoning"):
            t[k] += c.get(k, 0) or 0
    return t


def parse_checks(out: str, target: str) -> list:
    checks = []
    for line in out.splitlines():
        for word, ok in (("PASS ", True), ("FAIL ", False), ("ok   ", True)):
            if line.startswith(word):
                checks.append({"ok": ok, "target": target, "what": line[len(word):].strip()})
    return checks


def org_read_key(dest: str, machine: Machine, org: Org) -> str:
    """The key verify.py reads the org with: the one the run exported with
    (keys read back only their own workspace's traces)."""
    if dest == "both" and machine.signed_in:
        return machine.sdk_key
    return org.credential


def stored_costs(trace_ids: list, machine: Machine | None, org: Org | None, check_machine: bool, check_org: bool,
                 org_key: str = "") -> dict:
    out = {}
    if check_machine and machine:
        total, seen = 0.0, 0
        for tid in trace_ids:
            code, body = http("GET", f"{machine.dash_url}/api/obs/trace/{tid}")
            if code == 200:
                seen += 1
                total += (json.loads(body).get("trace") or {}).get("cost_usd") or 0.0
        out["machine"] = round(total, 10) if seen else None
    if check_org and org:
        total, seen = 0.0, 0
        for tid in trace_ids:
            code, body = http("GET", f"{org.gateway_url}/v1/sdk/traces/{tid}/cost",
                              headers={"Authorization": "Bearer " + (org_key or org.credential)})
            if code == 200:
                seen += 1
                total += sum((s.get("cost_usd") or 0.0) for s in (json.loads(body).get("spans") or []))
        out["org"] = round(total, 10) if seen else None
    return out


def case_env(ex: Example, dest: str, machine: Machine, org: Org | None, run_out: Path, run_id: str,
             with_key: bool) -> tuple[dict, list]:
    env = machine.env()  # fake HOME: an SDK never finds a real ~/.observer key file
    notes = []
    env.update({
        "SUPERBASED_NODE_URL": machine.dash_url,
        # L-01: with a destination set the SDK does not ask the machine for its
        # receiver; name it, so nothing ever goes to a real :4318.
        "SUPERBASED_OTLP_ENDPOINT": machine.otlp_url,
        "SUPERBASED_SERVICE_NAME": f"e2e-{ex.path.replace('/', '-')}-{dest}",
        "RUN_ID": run_id, "RUN_OUT": str(run_out), "PYTHONUNBUFFERED": "1",
        "ANTHROPIC_OPEN_TELEMETRY": "false",
        # Set explicitly (P-27): an example that reads it (CrewAI) runs the
        # model the spend estimate is priced at, whatever the parent had.
        "CHATBOT_MODEL": PROVIDERS[ex.provider]["model"],
    })
    if dest == "local":
        env["SUPERBASED_DESTINATION"] = "local"
    elif dest == "online":
        env.update({"SUPERBASED_DESTINATION": "online", "SUPERBASED_ORG_URL": org.gateway_url,
                    "SUPERBASED_API_KEY": org.credential})
    elif dest == "both":
        if not machine.signed_in:  # signed in: no destination set, the machine's default (both) and its key
            env.update({"SUPERBASED_DESTINATION": "both", "SUPERBASED_ORG_URL": org.gateway_url,
                        "SUPERBASED_API_KEY": org.credential})
            notes.append("both via an ingest credential (sign-in did not complete: " + machine.sign_in_note + ")")
    if with_key:
        k = PROVIDERS[ex.provider]["key_env"]
        env[k] = os.environ[k]
    return env, notes


def read_run_record(run_out: Path) -> tuple[dict | None, str]:
    """The run.json a chatbot or canary wrote, or why there is none. A
    malformed record is a FAIL of that case, never a crash of the run (P-34)."""
    if not run_out.exists():
        return None, "the run wrote no run.json"
    try:
        rec = json.loads(run_out.read_text())
    except (ValueError, OSError) as e:
        return None, f"run.json is not valid JSON ({type(e).__name__}: {e})"
    if not isinstance(rec, dict):
        return None, "run.json is not a JSON object"
    return rec, ""


def export_counters(diag: dict) -> tuple[int, int]:
    """failed_exports and dropped_spans, in the Python or TypeScript spelling."""
    failed = diag.get("failed_exports") or diag.get("failedExports") or 0
    dropped = diag.get("dropped_spans") or diag.get("droppedSpans") or 0
    return failed, dropped


def destination_check(diag: dict, dest: str) -> dict | None:
    """The destination the SDK resolved equals the case's. Without it a
    `both` run that fell back to local shows only as an org 404 (seen once in
    the E1 dry run under strace). None when the record does not say."""
    got = diag.get("destination")
    if not got:
        return None
    src = diag.get("destination_source") or diag.get("destinationSource") or "?"
    return {"ok": got == dest, "target": "sdk", "what": f"SDK destination {got!r} (source {src}), want {dest!r}"}


def crewai_org_checks(org, session_id: str, expect_tokens: int | None, wait_s: float = 30,
                      sleep=time.sleep) -> list:
    """The CrewAI run on the org. Its root span is the CrewAI instrumentor's,
    so the chatbot has no trace id to hand verify.py; the org's admin
    trace-groups rollup (by session) finds the run by the session id the
    runner set, and checks it has an ok trace, tokens and a cost."""
    path = "/api/org/obs/trace-groups?by=session&days=1"
    row, code = None, 0
    end = time.time() + wait_s
    while True:
        code, body = org.api("GET", path)
        if code == 200:
            try:
                groups = json.loads(body).get("groups") or []
            except (ValueError, AttributeError):
                groups = []
            row = next((g for g in groups if g.get("group_key") == session_id), None)
        if row or time.time() >= end:
            break
        sleep(1)
    checks = [{"ok": row is not None, "target": "org",
               "what": f"org has the session {session_id} (trace-groups by session, HTTP {code})"}]
    if row is None:
        return checks
    checks.append({"ok": (row.get("trace_count") or 0) >= 1 and not row.get("error_count"), "target": "org",
                   "what": f"traces {row.get('trace_count')}, errors {row.get('error_count')}"})
    tok = row.get("total_tokens") or 0
    if expect_tokens is not None:
        checks.append({"ok": tok == expect_tokens, "target": "org",
                       "what": f"total tokens {tok} equal CrewAI's prompt + completion {expect_tokens}"})
    else:
        checks.append({"ok": tok > 0, "target": "org", "what": f"total tokens {tok}"})
    cost = row.get("total_cost_usd") or 0.0
    checks.append({"ok": cost > 0, "target": "org", "what": f"total cost ${cost:.8f}"})
    return checks


def charge(r: "Result", mode: str) -> float:
    """What a finished case counts against --max-spend (P-28): its estimated
    cost, or a worst-case amount when it left no usage record, plus a flat
    amount for the sdk-direct experiment's calls."""
    if mode != "live" or r.status == "skip":
        return 0.0
    if r.tokens.get("calls"):
        amount = r.est_cost_usd
    else:
        amount = WORST_CASE_CASE_USD
        r.notes.append(f"no usage record: charged a worst-case ${WORST_CASE_CASE_USD:.2f} against --max-spend")
    if r.framework == "sdk-direct" and r.destination == "local":
        amount += EXPERIMENT_USD
    return round(amount, 8)


def run_case(ex: Example, dest: str, mode: str, machine: Machine, org: Org | None, work: Path,
             interp: dict, provider_state: dict) -> Result:
    r = Result(ex.path, ex.framework, ex.provider, ex.lang, dest, mode, known=ex.known)
    t0 = time.time()
    slug = f"{ex.path.replace('/', '_')}-{dest}"
    case_dir = work / "runs" / slug
    case_dir.mkdir(parents=True, exist_ok=True)
    log_path = work / "logs" / "runs" / f"{slug}.log"
    r.log = str(log_path.relative_to(work))
    run_out = case_dir / "run.json"
    run_out.unlink(missing_ok=True)  # a --work reuse must not read the last run's record (P-34)
    run_id = f"{int(time.time())}{secrets.token_hex(2)}"
    prov = PROVIDERS[ex.provider]
    lang = LANGS[ex.lang]

    if ex.machine_only and dest == "online":
        r.reason = "the example pins destination local; no online run"
        return r
    if mode == "live" and not provider_state[ex.provider]["usable"]:
        r.reason = provider_state[ex.provider]["reason"] or "provider not usable"
        return r
    handle = interp.get(ex.path)
    if not handle:
        r.reason = interp.get(ex.path + "#err", "environment not installed")
        r.status = "fail"
        return r

    env, r.notes = case_env(ex, dest, machine, org, run_out, run_id, with_key=(mode == "live"))
    check_machine = dest in ("local", "both")
    check_org = dest in ("online", "both") and not ex.machine_only
    if ex.machine_only and dest == "both":
        r.notes.append("machine copy only: the example pins destination local")

    vargs = verify_args_from_sh(ex)
    if ex.provider == "openai":
        vargs = strip_flag(vargs, "--price") + ["--price", ",".join(str(x) for x in prov["rates"])]

    # ---- run the chatbot (live) or the canary (dry run)
    if mode == "dry-run":
        vargs = strip_flag(strip_flag(vargs, "--llm-spans"), "--ignore-span") + ["--llm-spans", "1"]
        vargs = strip_flag(vargs, "--model") + ["--model", prov["model"]]
        vargs = strip_flag(vargs, "--price") + ["--price", ",".join(str(x) for x in prov["rates"])]
        spec = {"targets": list(ex.targets), "service": env["SUPERBASED_SERVICE_NAME"], "model": prov["model"],
                "provider": ex.provider, "out": str(run_out),
                "admit_probe": ADMIT_PROBE if ex.special == "sdk-direct" else ""}
        cmd, cwd = lang.canary(ex, handle, case_dir, spec)
        code, out = run(cmd, cwd=cwd, env=env, timeout=300, log_path=log_path)
        r.checks.append({"ok": code == 0, "target": "canary",
                         "what": f"SDK init and instrument({', '.join(ex.targets) or 'nothing'}) clean, synthetic trace exported (exit {code})"})
    elif ex.special == "crewai":
        return run_crewai_live(ex, r, env, machine, org, handle, log_path, check_machine, check_org, t0)
    else:
        cmd = lang.script(ex, handle, lang.entry)
        code, out = run(cmd, cwd=ex.dir, env=env, timeout=900, log_path=log_path)
        r.checks.append({"ok": code == 0, "target": "run", "what": f"{lang.entry} exited {code}"})

    rec, why = read_run_record(run_out)
    if rec is None:
        r.status = "fail"
        r.reason = f"{why}; see {r.log}"
        r.duration_s = round(time.time() - t0, 1)
        return r
    calls = rec.get("calls") or []
    if mode == "live":
        r.tokens = sum_tokens(calls)
        r.est_cost_usd = est_cost(calls, prov["rates"])
    if ex.special == "sdk-direct" and mode == "live":
        vargs = strip_flag(vargs, "--llm-spans") + ["--llm-spans", str(len([c for c in calls if "input" in c]))]
        verdicts = rec.get("verdicts") or []
        r.notes.append("admit verdicts: " + ", ".join(f"turn {v.get('turn')} {v.get('decision')}"
                                                       + (f" ({v.get('degraded')})" if v.get("degraded") else "")
                                                       for v in verdicts))
        if dest == "local":
            denied = [v for v in verdicts if v.get("turn") == 3 and not v.get("allowed")]
            r.checks.append({"ok": bool(denied), "target": "machine",
                             "what": "machine admission refused turn 3 (denied_topics, decision deny)"})
    for v in rec.get("verdicts") or []:
        if mode == "dry-run" and v.get("probe"):
            r.notes.append(f"admit({v['probe']!r}): {v.get('decision')} mode={v.get('mode')!r}"
                           + (f" degraded={v.get('degraded')!r}" if v.get("degraded") else ""))
            if dest == "local":
                r.checks.append({"ok": v.get("allowed") is False, "target": "machine",
                                 "what": "machine admission refuses the denied topic (no judge, no provider call)"})
    dcheck = destination_check(rec.get("diagnostics") or {}, dest)
    if dcheck:
        r.checks.append(dcheck)
    failed, dropped = export_counters(rec.get("diagnostics") or {})
    r.checks.append({"ok": not failed, "target": "sdk", "what": f"SDK failed_exports = {failed}"})
    r.checks.append({"ok": not dropped, "target": "sdk", "what": f"SDK dropped_spans = {dropped}"})

    venv_env = dict(env)
    venv_env.pop(PROVIDERS[ex.provider]["key_env"], None)  # verify.py never needs a provider key
    if check_machine:
        code, vout = run([sys.executable, str(VERIFY), str(run_out), "--target", "machine", "--node", machine.dash_url,
                          *vargs], env=venv_env, timeout=300, log_path=log_path)
        r.checks += parse_checks(vout, "machine")
        r.checks.append({"ok": code == 0, "target": "machine", "what": f"verify.py --target machine exited {code}"})
    if check_org:
        # The same flags as the machine check (verify.py's org target reads
        # every priced span; --ignore-span applies to the machine only).
        oargs = vargs
        oenv = dict(venv_env, SUPERBASED_API_KEY=org_read_key(dest, machine, org))
        code, vout = run([sys.executable, str(VERIFY), str(run_out), "--target", "org", "--org-url", org.gateway_url,
                          *oargs], env=oenv, timeout=300, log_path=log_path)
        r.checks += parse_checks(vout, "org")
        r.checks.append({"ok": code == 0, "target": "org", "what": f"verify.py --target org exited {code}"})

    if ex.special == "sdk-direct" and mode == "live" and dest == "local" and lang.experiment:
        ecode, eout = run(lang.script(ex, handle, lang.experiment), cwd=ex.dir, env=env, timeout=600, log_path=log_path)
        r.checks.append({"ok": ecode == 0, "target": "machine",
                         "what": f"{lang.experiment} (2 items, fail_under 0.5) exited {ecode}"})
        m = re.search(r"pass_rate[^0-9]*([0-9.]+)", eout)
        if m:
            r.notes.append(f"experiment pass_rate {m.group(1)} (2 extra model calls, not in the token count; "
                           f"charged a flat ${EXPERIMENT_USD:.2f} against --max-spend)")

    # Dry runs too: the canary's synthetic usage is priced like a live call.
    r.stored_cost_usd = stored_costs(rec.get("trace_ids") or [], machine, org, check_machine, check_org,
                                     org_read_key(dest, machine, org) if org else "")
    r.status = "pass" if r.checks and all(c["ok"] for c in r.checks) else "fail"
    if r.status == "fail" and not r.reason:
        r.reason = "; ".join(f"[{c['target']}] {c['what']}" for c in r.checks if not c["ok"])[:600]
    r.duration_s = round(time.time() - t0, 1)
    return r


def run_crewai_live(ex: Example, r: Result, env: dict, machine: Machine, org: Org | None, handle,
                    log_path: Path, check_machine: bool, check_org: bool, t0: float) -> Result:
    """CrewAI writes no run.json: the token totals come from the "crewai
    usage" line it prints, the machine copy is checked by its own verify.sh
    and the org copy by its session (crewai_org_checks). The example honours
    SUPERBASED_DESTINATION, so it runs on every destination (Q4)."""
    prov = PROVIDERS[ex.provider]
    env["CHATBOT_SESSION_ID"] = f"crewai-{env['RUN_ID']}"
    code, out = run(LANGS[ex.lang].script(ex, handle, LANGS[ex.lang].entry), cwd=ex.dir, env=env, timeout=900,
                    log_path=log_path)
    r.checks.append({"ok": code == 0, "target": "run", "what": f"chatbot.py exited {code}"})
    m = re.search(r"crewai usage: requests=(\d+) prompt=(\d+) completion=(\d+)", out)
    calls = [{"input": int(m.group(2)), "output": int(m.group(3))}] if m else []
    r.tokens = sum_tokens(calls)
    if m:
        r.tokens["calls"] = int(m.group(1))
    r.est_cost_usd = est_cost(calls, prov["rates"])
    if check_machine:
        venv_bin = str(Path(handle).parent)
        venv_env = dict(env, OBSERVER_API=machine.dash_url, PATH=venv_bin + os.pathsep + env.get("PATH", ""))
        venv_env.pop(prov["key_env"], None)  # the check never needs the provider key
        if m:
            venv_env.update({"EXPECT_INPUT_TOKENS": m.group(2), "EXPECT_OUTPUT_TOKENS": m.group(3)})
        vcode, vout = run(["bash", str(ex.dir / "verify.sh"), env["CHATBOT_SESSION_ID"]], cwd=ex.dir,
                          env=venv_env, timeout=180, log_path=log_path)
        r.checks += parse_checks(vout, "machine")
        r.checks.append({"ok": vcode == 0, "target": "machine", "what": f"crewai verify.sh exited {vcode}"})
    if check_org and org is not None:
        expect = int(m.group(2)) + int(m.group(3)) if m else None
        r.checks += crewai_org_checks(org, env["CHATBOT_SESSION_ID"], expect)
    r.status = "pass" if r.checks and all(c["ok"] for c in r.checks) else "fail"
    if r.status == "fail" and not r.reason:
        r.reason = "; ".join(f"[{c['target']}] {c['what']}" for c in r.checks if not c["ok"])[:600]
    r.duration_s = round(time.time() - t0, 1)
    return r


# ---------------------------------------------------------------- report


def write_report(out_dir: Path, meta: dict, results: list) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    totals = {"pass": 0, "fail": 0, "skip": 0, "est_spend_usd": 0.0, "input_tokens": 0, "output_tokens": 0}
    for r in results:
        totals[r.status] += 1
        totals["est_spend_usd"] += r.est_cost_usd
        totals["input_tokens"] += r.tokens.get("input", 0)
        totals["output_tokens"] += r.tokens.get("output", 0)
    totals["est_spend_usd"] = round(totals["est_spend_usd"], 6)
    doc = dict(meta, totals=totals, results=[dataclasses.asdict(r) for r in results])
    (out_dir / "report.json").write_text(redact(json.dumps(doc, indent=2, default=str)) + "\n")

    L = []
    L.append(f"# AI Apps live e2e: {meta['mode']} run, {meta['started']}")
    L.append("")
    g = meta["git"]
    L.append(f"Tree `{g['branch']}` at `{g['sha'][:12]}`{' (uncommitted changes)' if g['dirty'] else ''}. "
             f"Destinations: {', '.join(meta['destinations'])}. Duration {meta['duration_s']} s.")
    L.append("")
    verdict = "PASS" if totals["fail"] == 0 and totals["pass"] > 0 else ("NOTHING RAN" if totals["pass"] == 0 and totals["fail"] == 0 else "FAIL")
    L.append(f"**{verdict}**: {totals['pass']} passed, {totals['fail']} failed, {totals['skip']} skipped. "
             f"Approximate provider spend: ${totals['est_spend_usd']:.6f} "
             f"({totals['input_tokens']:,} input / {totals['output_tokens']:,} output tokens, at list prices). "
             f"Charged against --max-spend ${meta.get('max_spend', 0):.2f}: ${meta.get('charged_usd', 0):.6f} "
             "(adds a worst-case amount per live case with no usage record and per sdk-direct experiment; "
             "an estimate, not a provider-side limit).")
    if meta["mode"] == "dry-run":
        L.append("")
        L.append("Dry run: no provider was called. Each case ran a canary in the example's own environment "
                 "(SDK init, every instrumentor the example uses, one synthetic trace with fixed usage) and "
                 "verify.py checked it on the destinations.")
    L.append("")
    L.append("## Setup")
    L.append("")
    L.append("| Part | Value |")
    L.append("|---|---|")
    m = meta["machine"]
    L.append(f"| Machine | throwaway HOME, dashboard `{m['dashboard']}`, OTLP `{m['otlp']}`, hooks auto-register off, pricing feed off, gpt-5-nano priced at list locally |")
    if meta.get("org"):
        o = meta["org"]
        L.append(f"| Org | PostgreSQL (throwaway), dev auth, dashboard `{o['dashboard']}`, trace gateway `{o['gateway']}`, workspaces `{ORG_WORKSPACE}` and `default` at L2, list price rows for both models |")
        L.append(f"| Sign-in | {o['sign_in']}. `both` cases then set no destination: the SDK takes the machine's default (both) and its key file |")
    for name, st in meta["providers"].items():
        state = "usable" if st["usable"] else ("not used (dry run)" if meta["mode"] == "dry-run" else "SKIPPED")
        host = {None: "not contacted", True: "reachable", False: "NOT reachable"}[st["reachable"]]
        reason = st["reason"] if st["reason"] and st["reason"] != state else ""
        L.append(f"| {name} | model `{st['model']}`, key {'set' if st['key_set'] else 'NOT set'}, "
                 f"host {host}: {state}{' (' + reason + ')' if reason else ''} |")
    L.append("")
    L.append("## Results")
    L.append("")
    L.append("| Example | Provider | Destination | Result | Checks | Tokens in/out | Est. cost | Stored cost (machine / org) | Time |")
    L.append("|---|---|---|---|---|---|---|---|---|")
    for r in results:
        ok = sum(1 for c in r.checks if c["ok"])
        res = {"pass": "PASS", "fail": "**FAIL**", "skip": "SKIP"}[r.status]
        tok = f"{r.tokens.get('input', 0):,}/{r.tokens.get('output', 0):,}" if r.tokens else "-"
        sc = r.stored_cost_usd
        stored = " / ".join("n/a" if k not in sc else ("missing" if sc[k] is None else f"${sc[k]:.8f}")
                            for k in ("machine", "org"))
        L.append(f"| `{r.example}` | {r.provider} | {r.destination} | {res} | {ok}/{len(r.checks)} | {tok} | "
                 f"{'$%.8f' % r.est_cost_usd if r.tokens else '-'} | {stored} | {r.duration_s}s |")
    L.append("")
    for r in results:
        if r.status == "pass" and not r.notes and not r.known:
            continue
        L.append(f"### `{r.example}` ({r.provider}, {r.destination}): {r.status.upper()}")
        L.append("")
        if r.reason:
            L.append(f"- Reason: {r.reason}")
        if r.known:
            L.append(f"- Known open finding for this example: {r.known}")
        for n in r.notes:
            L.append(f"- {n}")
        for c in r.checks:
            if not c["ok"]:
                L.append(f"- FAIL [{c['target']}] {c['what']}")
        if r.log:
            L.append(f"- Log: `{r.log}` (beside this report)")
        L.append("")
    L.append("## Filing findings")
    L.append("")
    L.append("A FAIL that is not a known finding: reproduce it with `--frameworks <name> --providers <p> "
             "--destination <d> --keep`, read the case log, and write it up as in "
             "`docs/plans/plane-a-sdk-buildout/reviews/live-chatbot-e2e-2026-11-20.md` (id, severity, "
             "seen live, cause, fix, owner). See docs/planea-e2e-playbook.md.")
    (out_dir / "report.md").write_text(redact("\n".join(L)) + "\n")


def copy_logs(src: Path, dst: Path) -> None:
    """Copy the work directory's logs next to the report, each through
    redact() (the daemon and org logs are written by the processes directly)."""
    for f in src.rglob("*"):
        if f.is_file():
            target = dst / f.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(redact(f.read_text(errors="replace")))


# ---------------------------------------------------------------- main


def select(frameworks: str, providers: list, langs: list) -> list:
    want = FRAMEWORKS if frameworks in ("", "all") else [f.strip() for f in frameworks.split(",") if f.strip()]
    unknown = [f for f in want if f not in FRAMEWORKS]
    if unknown:
        raise SystemExit(f"--frameworks: unknown {unknown}; known: {', '.join(FRAMEWORKS)}")
    bad = [x for x in langs if x not in LANGS]
    if bad:
        raise SystemExit(f"--langs: unknown {bad}; known: {', '.join(LANGS)}")
    return [e for e in CATALOG if e.framework in want and e.provider in providers and e.lang in langs]


def required_tools(langs: list, prebuilt_bin: bool) -> list:
    """What run.sh checks on PATH: go (unless --bin) and the selected languages' tools."""
    tools = [] if prebuilt_bin else ["go"]
    for name in langs:
        for t in LANGS[name].tools:
            if t not in tools:
                tools.append(t)
    return tools


def real_homes() -> list:
    """The account's real home directories ($HOME and the password database's)."""
    homes = {os.path.expanduser("~")}
    try:
        import pwd
        homes.add(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, AttributeError):
        pass
    return sorted(h for h in homes if h)


def loopback_answers(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def host_refusals(examples: list, allow_live_host: bool, platform: str | None = None, homes: list | None = None,
                  port_open=None) -> list:
    """Why this host must not run the playbook (P-30), empty when it may.

    Always refused: a platform other than Linux or macOS (process groups, the
    fake HOME, `runuser`), and a node_modules the install would write into
    that is a symlink (`npm ci` deletes through it into another tree).
    Refused unless --allow-live-host: a real ~/.observer/observer.db, or a
    superbased answering on 127.0.0.1:8081 or :8820 (a developer's own
    machine with a live install).
    """
    platform = sys.platform if platform is None else platform
    homes = real_homes() if homes is None else homes
    port_open = port_open or loopback_answers
    out = []
    if not (platform.startswith("linux") or platform == "darwin"):
        out.append(f"platform {platform!r}: the runner runs on Linux or macOS only (a cloud session or a throwaway box)")
    for ex in examples:
        dirs = LANGS[ex.lang].install_dirs
        for d in (dirs(ex) if dirs else []):
            if Path(d).is_symlink():
                msg = f"{d} is a symlink: `npm ci` would delete through it into another tree; remove the link first"
                if msg not in out:
                    out.append(msg)
    if allow_live_host:
        return out
    for h in homes:
        db = Path(h) / ".observer" / "observer.db"
        if db.exists():
            out.append(f"{db} exists: this looks like a developer's own machine (pass --allow-live-host to run anyway)")
    for port in LIVE_HOST_PORTS:
        if port_open(port):
            out.append(f"127.0.0.1:{port} answers: a superbased looks live here (pass --allow-live-host to run anyway)")
    return out


def redact_in_place(root: Path) -> int:
    """--keep (P-37): the kept work directory's logs and run records go
    through redact() like the copies beside the report. The daemon and org
    write their logs directly, so without this a kept work dir holds
    unredacted text. Binary files (databases, keys) are left as they are."""
    n = 0
    for sub in ("logs", "runs"):
        base = root / sub
        if not base.is_dir():
            continue
        # os.walk never follows a symlink (a TypeScript canary's node_modules
        # link points back into the checkout).
        for dirpath, _dirs, files in os.walk(base):
            for name in files:
                f = Path(dirpath) / name
                if f.is_symlink():
                    continue
                n += _redact_file(f)
    return n


def _redact_file(f: Path) -> int:
    try:
        text = f.read_text()
    except (UnicodeDecodeError, OSError):
        return 0
    red = redact(text)
    if red == text:
        return 0
    f.write_text(red)
    return 1


def run_cases(examples: list, destinations: list, mode: str, max_spend: float, runner, results: list) -> list:
    """Run every (example, destination) case through runner, appending to
    results as it goes (an interrupt keeps what ran).

    - A case that raises is that case's FAIL, never the end of the run (P-34).
    - Each finished live case is charged (charge()) and no new live case
      starts once the charged total reaches max_spend (P-28).
    - After MAX_CONSECUTIVE_LIVE_FAILURES live failures in a row the rest are
      skipped: a broken setup would otherwise fail, and pay for, every case.
    """
    spent, streak = 0.0, 0
    for ex in examples:
        for dest in destinations:
            stop = ""
            if mode == "live" and spent >= max_spend:
                stop = f"--max-spend ${max_spend:.2f} reached (estimated ${spent:.4f})"
            elif mode == "live" and streak >= MAX_CONSECUTIVE_LIVE_FAILURES:
                stop = (f"stopped after {MAX_CONSECUTIVE_LIVE_FAILURES} consecutive live failures "
                        "(read the first failing case's log)")
            if stop:
                r = Result(ex.path, ex.framework, ex.provider, ex.lang, dest, mode, known=ex.known, reason=stop)
            else:
                log(f"case {ex.path} -> {dest}")
                try:
                    r = runner(ex, dest)
                except (SetupError, KeyboardInterrupt):
                    raise
                except Exception as e:  # noqa: BLE001 - one bad case must not end the run
                    r = Result(ex.path, ex.framework, ex.provider, ex.lang, dest, mode, known=ex.known,
                               status="fail", reason=f"runner error in this case: {type(e).__name__}: {e}")
                r.charged_usd = charge(r, mode)
                spent += r.charged_usd
                if mode == "live" and r.status == "fail":
                    streak += 1
                elif r.status == "pass":
                    streak = 0
            log(f"  {r.status.upper()}{': ' + r.reason if r.reason else ''}")
            results.append(r)
    return results


def parse_args(argv: list) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="run.sh", description=__doc__.split("\n\n")[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--frameworks", default="all", help=f"all, or a comma list of: {', '.join(FRAMEWORKS)}")
    p.add_argument("--providers", default="openai,anthropic", help="comma list: openai, anthropic")
    p.add_argument("--langs", default=",".join(LANGS), help=f"comma list: {', '.join(LANGS)}")
    p.add_argument("--destination", default="local", choices=("local", "online", "both", "all"),
                   help="local: the throwaway machine only; online/both also start a throwaway org; all = the three")
    p.add_argument("--dry-run", action="store_true", help="set everything up and verify with a canary; no provider call")
    p.add_argument("--out", help="report directory (default scripts/planea-e2e/out/<UTC timestamp>)")
    p.add_argument("--work", help="work directory (default a new short temp dir; removed unless --keep)")
    p.add_argument("--cache", default=os.path.join(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"), "planea-e2e"),
                   help="where the per-example virtualenvs are cached")
    p.add_argument("--bin", help="a directory with prebuilt observer and observer-org (default: build from the checkout)")
    p.add_argument("--org-pg-dsn", default="",
                   help="for online/both: an admin postgres:// DSN to create the org's database on "
                        "(default PLANEA_E2E_PG_DSN, else a private cluster from initdb/pg_ctl)")
    p.add_argument("--keep", action="store_true", help="keep the work directory (logs, databases)")
    p.add_argument("--max-spend", type=float, default=0.50,
                   help="stop starting new live cases once the ESTIMATED spend reaches this many dollars (default "
                        "0.50); not a provider-side limit: set a project budget on the key too")
    p.add_argument("--allow-live-host", action="store_true",
                   help="run even with a real ~/.observer/observer.db or a superbased answering on :8081/:8820 "
                        "(never on Windows, never with a symlinked node_modules)")
    p.add_argument("--print-tools", action="store_true", help=argparse.SUPPRESS)  # run.sh: the tools to check
    a = p.parse_args(argv)
    a.providers = [x.strip() for x in a.providers.split(",") if x.strip()]
    a.langs = [x.strip() for x in a.langs.split(",") if x.strip()]
    for x in a.providers:
        if x not in PROVIDERS:
            raise SystemExit(f"--providers: unknown {x!r} (openai, anthropic)")
    a.destinations = ["local", "online", "both"] if a.destination == "all" else [a.destination]
    return a


def main(argv: list) -> int:
    a = parse_args(argv)
    if a.print_tools:
        select(a.frameworks, a.providers, a.langs)  # validates --langs
        print(" ".join(required_tools(a.langs, bool(a.bin))))
        return 0
    mode = "dry-run" if a.dry_run else "live"
    started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    t0 = time.time()
    examples = select(a.frameworks, a.providers, a.langs)
    if not examples:
        log("no example matches the selection")
        return 2
    refusals = host_refusals(examples, a.allow_live_host)
    for lang in sorted({ex.lang for ex in examples}):
        check = LANGS[lang].preflight
        why = check() if check else ""
        if why:
            refusals.append(why)
    if refusals:
        # Before any work dir, build, port or provider: nothing is touched.
        for why in refusals:
            log(f"REFUSED: {why}")
        return 2
    if a.org_pg_dsn and urllib.parse.urlsplit(a.org_pg_dsn).password is not None:
        split_dsn_password(a.org_pg_dsn)  # registers the password with redact()
        log("warning: --org-pg-dsn carries a password, which `ps` shows on this command line; "
            "prefer PLANEA_E2E_PG_DSN in the environment")
    out_dir = Path(a.out) if a.out else HERE / "out" / started.replace(":", "")
    work = Path(a.work) if a.work else Path(tempfile.mkdtemp(prefix="pe2e-"))
    work.mkdir(parents=True, exist_ok=True)
    (work / "logs").mkdir(exist_ok=True)
    cache = Path(a.cache)
    log(f"{mode}: {len(examples)} example(s) x {', '.join(a.destinations)}; work {work}; report {out_dir}")

    providers = {p: probe_provider(p, a.dry_run) for p in a.providers}
    for p, st in providers.items():
        log(f"provider {p}: key {'set' if st['key_set'] else 'not set'}, "
            f"{'usable' if st['usable'] else 'not usable: ' + st['reason']}")

    machine = org = pg = None
    results: list = []
    meta = {"mode": mode, "started": started, "git": git_info(), "destinations": a.destinations,
            "frameworks": a.frameworks, "providers": providers, "machine": {}, "org": None}
    rc = 0
    try:
        obs_bin, org_bin = build_binaries(work, a.bin)
        machine = Machine(obs_bin, work)
        machine.start()
        meta["machine"] = {"dashboard": machine.dash_url, "otlp": machine.otlp_url}
        if any(d in ("online", "both") for d in a.destinations):
            pg = Postgres(work, a.org_pg_dsn or os.environ.get("PLANEA_E2E_PG_DSN", ""))
            pg.start()
            org = Org(org_bin, work, pg.dsn)
            org.start()
            org.sign_in(machine)
            log(f"sign-in: {machine.sign_in_note}")
            if machine.signed_in:
                machine.restart()  # the daemon re-reads its SDK key and default destination
            meta["org"] = {"dashboard": org.dash_url, "gateway": org.gateway_url, "sign_in": machine.sign_in_note}

        interp: dict = {}
        for ex in examples:
            if a.dry_run is False and not providers[ex.provider]["usable"]:
                continue  # no install for a provider that will be skipped anyway
            log(f"install {ex.path}")
            handle, err = LANGS[ex.lang].install(ex, cache, work / "logs")
            interp[ex.path], interp[ex.path + "#err"] = handle, err
            if handle is None:
                log(f"  {err}")

        run_cases(examples, a.destinations, mode, a.max_spend,
                  lambda ex, dest: run_case(ex, dest, mode, machine, org, work, interp, providers), results)
    except SetupError as e:
        log(f"SETUP FAILED: {e}")
        meta["setup_error"] = str(e)
        rc = 2
    except KeyboardInterrupt:
        log("interrupted")
        meta["setup_error"] = "interrupted"
        rc = 130
    finally:
        if org:
            org.stop()
        if pg:
            pg.stop()
        if machine:
            machine.stop()
        meta["duration_s"] = round(time.time() - t0, 1)
        meta["work_dir"] = str(work) if a.keep else "(removed)"
        meta["charged_usd"] = round(sum(r.charged_usd for r in results), 6)
        meta["max_spend"] = a.max_spend
        write_report(out_dir, meta, results)
        if meta.get("setup_error"):
            with open(out_dir / "report.md", "a") as f:
                f.write(redact(f"\n## Setup error\n\n{meta['setup_error']}\n"))
        copy_logs(work / "logs", out_dir / "logs")
        if a.keep:
            n = redact_in_place(work)
            log(f"work directory kept: {work} (logs and run records redacted in place: {n} file(s) changed)")
        else:
            shutil.rmtree(work, ignore_errors=True)
    log(f"report: {out_dir / 'report.md'}")
    if rc:
        return rc
    if any(r.status == "fail" for r in results):
        return 1
    if not any(r.status == "pass" for r in results):
        return 4  # nothing ran: every case skipped
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
