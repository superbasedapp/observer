#!/usr/bin/env python3
"""The one-command quickstart, live: `setup` on a fresh sign-up (lane L8).

docs/planea-e2e-playbook.md "The setup run" is the runbook. This runner makes
a throwaway project (Python or Node), runs the SDK's own `setup` command in it
the way a coding agent would (`--online --json`, no terminal), shows the
person the approval line `setup` prints, and checks what the plan promises
(docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md, sections 2.1, 3.4,
3.5 and 3.8):

- setup exits 0 with a `done` phase whose `trace_url` is the organization's
  `/trajectories?trace=<32 hex>`;
- the key file exists, is a regular file readable by this user alone, in a
  folder only this user can open (Windows: present, ownership not checked);
- no line setup printed, no `--json` object and nothing the app printed holds
  anything shaped like an SDK key, and no `--json` object carries a secret's
  field name (`key`, `device_code`, `redeem_secret`, `key_grant`);
- nothing setup printed names the AI gateway (SDKQS-10);
- the one init line setup printed starts the app, and on a terminal the app
  prints its own first-trace link once;
- a second run with the key in place asks for no approval; `--status` names
  what is configured; `--forget` revokes the key and removes the file.

The runner never reads the key file's content: it checks the file's mode and
owner with stat() and finds leaks by the key's SHAPE in what was printed. It
never answers an approval itself: the person approves in their own browser.

Standard library only. It runs on Linux, macOS and Windows (no pty on
Windows: the first-trace line, which needs a terminal, is not checked there).

  python3 scripts/planea-e2e/setup_run.py --lang python
  python3 scripts/planea-e2e/setup_run.py --lang typescript --approve-timeout 1200
  python3 scripts/planea-e2e/setup_run.py --lang python --setup-cmd "python -m superbased_sdk setup"
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

# How each language's setup is started when --setup-cmd is not given: the
# published package, as the prompt and the docs say (plan 3.5, 3.9).
SETUP_CMD = {
    "python": ["uvx", "superbased-sdk", "setup"],
    "typescript": ["npx", "--yes", "@superbased/sdk", "setup"],
}

# The tool each language needs on PATH before anything runs.
NEEDS = {
    "python": ["python3"],
    "typescript": ["node", "npm"],
}

# A string shaped like an SDK key: `<key_id>.<secret>`, the key id 32 lower
# hex (sdk/contract/fixtures/setup/sdk-credential-file.json). Anything that
# matches in printed output is a leak, whatever key it is.
KEY_SHAPE = re.compile(r"\b[0-9a-f]{32}\.[A-Za-z0-9_\-]{16,}")

# A --json object must never carry one of these field names (plan 3.5
# "Output"; setup-cases.json "secrecy").
SECRET_FIELDS = frozenset({"key", "api_key", "secret", "device_code", "redeem_secret", "key_grant"})

# setup sets up the ingest gateway only and never names the AI gateway
# (plan 3.4, SDKQS-10; setup-cases.json "no AI gateway").
AI_GATEWAY_WORDS = re.compile(r"ai[ _-]?gateway|SUPERBASED_AI_GATEWAY|gateway_endpoint|gatewayEndpoint|/ai/", re.I)

# The link setup prints when the trace arrived: the organization's dashboard,
# its trajectories page, one trace id (plan 2.1, 3.8).
TRACE_URL = re.compile(r"^https://[a-z0-9][a-z0-9-]*\.superbased\.app/trajectories\?trace=[0-9a-f]{32}$")

# The line the SDK prints for a process's first trace (plan 3.8, ruling R12).
FIRST_TRACE_LINE = re.compile(r"superbased: first trace from this process: (\S+)")

# setup's exit codes (plan 3.5; contract sdk-api-surface.md section 17 adds 1)
# and what each means for this run.
EXIT_MEANING = {
    0: "done: the trace arrived",
    1: "an unexpected error in setup itself (details on its stderr)",
    2: "waiting for a person: the approval expired or was declined, or the grant window closed",
    3: "refused: plan, membership or allowance (the server's message is printed)",
    4: "environment: no supported language, or the package manager failed",
    5: "sent, not seen within 60 s",
}

# The throwaway project for each language. The app sends one span of its
# own; its model library is installed but never called (no provider key).
PY_PROJECT = """[project]
name = "{name}"
version = "0.0.1"
requires-python = ">=3.9"
dependencies = ["openai>=1.0"]
"""
PY_APP = """# The setup run's app (scripts/planea-e2e/setup_run.py). setup's init line
# goes above this comment.
import superbased_sdk as sb

with sb.span("setup-run request"):
    pass
sb.shutdown()
"""
NODE_PACKAGE = {"version": "0.0.1", "private": True, "type": "commonjs", "main": "app.js",
                "dependencies": {"openai": "^4.0.0"}}
NODE_APP = """// The setup run's app (scripts/planea-e2e/setup_run.py). setup's init line
// goes above this comment.
const sb = require("@superbased/sdk");
sb.withSpan("setup-run request", () => {});
sb.shutdown().then(() => {});
"""


@dataclasses.dataclass
class Check:
    """One line of the report."""

    name: str
    ok: bool
    detail: str = ""
    warn: bool = False  # a WARN never fails the run

    def word(self) -> str:
        if self.ok:
            return "PASS"
        return "WARN" if self.warn else "FAIL"


@dataclasses.dataclass
class Run:
    """One setup invocation, as captured."""

    argv: list
    code: int
    out: str
    err: str
    phases: list


def redact(text: str) -> str:
    """Replace anything shaped like an SDK key, so a leak is reported, never copied."""
    return KEY_SHAPE.sub("<KEY-SHAPED STRING REDACTED>", text)


def parse_phases(stdout: str) -> list:
    """The --json objects setup printed, one per line; other lines are ignored."""
    phases = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            phases.append(obj)
    return phases


def secret_fields(obj, path="") -> list:
    """Every field of a --json object (nested too) whose name is a secret's."""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            where = f"{path}.{k}" if path else str(k)
            if str(k).lower() in SECRET_FIELDS:
                found.append(where)
            found.extend(secret_fields(v, where))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(secret_fields(v, f"{path}[{i}]"))
    return found


def leak_checks(label: str, texts: list, phases: list) -> list:
    """The secrecy and no-AI-gateway checks over one run's output."""
    joined = "\n".join(texts)
    shaped = KEY_SHAPE.findall(joined)
    fields = [f for p in phases for f in secret_fields(p)]
    gw = sorted({m.group(0) for m in AI_GATEWAY_WORDS.finditer(joined)})
    return [
        Check(f"{label}: nothing printed is shaped like an SDK key", not shaped,
              f"{len(shaped)} key-shaped string(s)" if shaped else ""),
        Check(f"{label}: no --json object carries a secret's field", not fields, ", ".join(fields)),
        Check(f"{label}: nothing printed names the AI gateway", not gw, ", ".join(gw)),
    ]


def phase(phases: list, name: str):
    """The last --json object of that phase, or None."""
    hit = None
    for p in phases:
        if p.get("phase") == name:
            hit = p
    return hit


def credential_path(env: dict, system: str = os.name) -> Path:
    """Where setup writes the key file for this environment (plan 3.4)."""
    if env.get("SUPERBASED_CREDENTIAL_FILE"):
        return Path(env["SUPERBASED_CREDENTIAL_FILE"])
    if system == "nt":
        return Path(env["LOCALAPPDATA"]) / "superbased" / "sdk-credential"
    base = env.get("XDG_CONFIG_HOME") or str(Path(env["HOME"]) / ".config")
    return Path(base) / "superbased" / "sdk-credential"


def file_checks(path: Path, system: str = os.name) -> list:
    """The key file's shape, from stat() alone: its content is never read."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return [Check("the key file exists", False, str(path))]
    checks = [Check("the key file exists", True, str(path)),
              Check("the key file is a regular file, not a link", stat.S_ISREG(st.st_mode))]
    if system == "nt":
        checks.append(Check("the key file's owner (not checked on Windows)", True, "", warn=True))
        return checks
    checks.append(Check("the key file is readable by this user alone", st.st_mode & 0o077 == 0,
                        oct(st.st_mode & 0o777)))
    checks.append(Check("the key file is owned by this user", st.st_uid == os.getuid()))
    dst = os.stat(path.parent)
    checks.append(Check("its folder is open to this user alone", dst.st_mode & 0o077 == 0,
                        oct(dst.st_mode & 0o777)))
    return checks


def init_line(phases: list) -> str:
    """The one init line setup printed (its next-steps phase), or ""."""
    p = phase(phases, "next") or phase(phases, "next_steps") or {}
    for key in ("init_line", "line", "init"):
        v = p.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def make_project(root: Path, lang: str, name: str) -> Path:
    """A throwaway project with one model library and an app that sends one span."""
    proj = root / name
    proj.mkdir(parents=True)
    if lang == "python":
        (proj / "pyproject.toml").write_text(PY_PROJECT.format(name=name))
        (proj / "app.py").write_text(PY_APP)
        subprocess.run([sys.executable, "-m", "venv", str(proj / ".venv")], check=True)
    else:
        pkg = dict(NODE_PACKAGE, name=name)
        (proj / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
        (proj / "app.js").write_text(NODE_APP)
    return proj


def add_init_line(proj: Path, lang: str, line: str) -> Path:
    """Put setup's init line at the top of the app, as the agent would."""
    app = proj / ("app.py" if lang == "python" else "app.js")
    app.write_text(line + "\n" + app.read_text())
    return app


def child_env(scratch: Path) -> dict:
    """The environment setup and the app run in: a scratch HOME and config,
    no machine to find, no CI marker, no key of the caller's."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("SUPERBASED_") and k not in ("CI", "OTEL_SERVICE_NAME")}
    home = scratch / "home"
    home.mkdir(exist_ok=True)
    env["HOME"] = str(home)
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    if os.name == "nt":
        env["USERPROFILE"] = str(home)
        env["LOCALAPPDATA"] = str(home / "AppData" / "Local")
    # No superbased on this port: setup and the SDK find no machine.
    env["SUPERBASED_NODE_URL"] = "http://127.0.0.1:9"
    return env


def run_setup(argv: list, cwd: Path, env: dict, timeout: float, on_line=None) -> Run:
    """Run setup with no terminal (as an agent does), streaming stdout so the
    approval line reaches the person while setup waits."""
    # stderr goes to a file, so a chatty stderr can never fill its pipe and
    # stall setup while this loop waits on stdout.
    errf = tempfile.TemporaryFile(mode="w+")
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=errf, text=True)
    out_lines = []
    # A setup that goes quiet past the deadline is killed, so the loop below
    # always ends (a read blocks until the process writes or exits).
    watchdog = threading.Timer(timeout, proc.kill)
    watchdog.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            out_lines.append(line)
            if on_line:
                on_line(line)
        proc.wait()
    finally:
        watchdog.cancel()
    errf.seek(0)
    err = errf.read()
    errf.close()
    out = "".join(out_lines)
    return Run(argv=argv, code=proc.returncode, out=out, err=err or "", phases=parse_phases(out))


def show_approval(line: str) -> None:
    """Print setup's approval line for the person, loudly. Only the URL and the
    user code are shown; both are safe to show (plan 3.6)."""
    obj = parse_phases(line)
    # setup reports the approval more than once (the address first, then
    # states such as approved_not_ready): only the one with the address is shown.
    if obj and obj[0].get("phase") == "approve" and obj[0].get("approve_url"):
        url, code = obj[0]["approve_url"], obj[0].get("user_code", "")
        print(f"\n==> APPROVE IN YOUR BROWSER: {url}  (code {code})", flush=True)
        print("==> Sign up with a fresh address, check the code, click Approve.\n", flush=True)


def run_app(proj: Path, lang: str, env: dict) -> tuple:
    """Run the app once. On a unix terminal (a pty) so the first-trace line can
    print; elsewhere plainly. Returns (exit code, output, had a terminal)."""
    argv = [str(proj / ".venv" / "bin" / "python"), "app.py"] if lang == "python" else ["node", "app.js"]
    if os.name == "nt" and lang == "python":
        argv[0] = str(proj / ".venv" / "Scripts" / "python.exe")
    if os.name != "nt":
        import pty  # unix only

        master, slave = pty.openpty()
        proc = subprocess.Popen(argv, cwd=proj, env=env, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        chunks = []
        while True:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append(data)
        proc.wait(timeout=120)
        os.close(master)
        return proc.returncode, b"".join(chunks).decode("utf-8", "replace"), True
    cp = subprocess.run(argv, cwd=proj, env=env, capture_output=True, text=True, timeout=120)
    return cp.returncode, cp.stdout + cp.stderr, False


def summarize(checks: list) -> str:
    """The run's verdict: FAIL when any non-warning check failed."""
    return "FAIL" if any(not c.ok and not c.warn for c in checks) else "PASS"


def report_md(meta: dict, checks: list) -> str:
    """The human report (every value already redacted)."""
    lines = ["# setup run", ""]
    for k, v in meta.items():
        lines.append(f"- {k}: {v}")
    lines += ["", f"Verdict: **{summarize(checks)}**", "", "| Check | Result | Detail |", "|---|---|---|"]
    for c in checks:
        lines.append(f"| {c.name} | {c.word()} | {redact(c.detail)} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lang", choices=sorted(SETUP_CMD), required=True)
    ap.add_argument("--setup-cmd", help="the command that starts setup (default: the published package, uvx or npx)")
    ap.add_argument("--approve-timeout", type=float, default=900.0,
                    help="seconds to wait for the person's approval and the first trace (default 900)")
    ap.add_argument("--keep-key", action="store_true", help="skip setup --forget at the end (the key stays live)")
    ap.add_argument("--out", help="report folder (default scripts/planea-e2e/out/setup-<UTC>)")
    a = ap.parse_args(argv)

    for tool in NEEDS[a.lang]:
        if not shutil.which(tool):
            print(f"setup-run: {tool} is not on PATH", file=sys.stderr)
            return 2
    base = shlex.split(a.setup_cmd) if a.setup_cmd else list(SETUP_CMD[a.lang])
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = Path(a.out) if a.out else HERE / "out" / f"setup-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="sbo-setup-run-"))
    env = child_env(scratch)
    name = f"sbo-setup-run-{a.lang}-{stamp.lower()}"
    proj = make_project(scratch, a.lang, name)
    keyfile = credential_path(env)
    checks = []
    texts = []

    print(f"setup-run: project {proj}", flush=True)
    first = run_setup(base + ["--online", "--json"], proj, env, a.approve_timeout + 120, on_line=show_approval)
    texts += [first.out, first.err]
    done = phase(first.phases, "done") or {}
    checks.append(Check("setup exits 0 (the trace arrived)", first.code == 0,
                        f"exit {first.code}: {EXIT_MEANING.get(first.code, 'unknown')}"))
    asked = [p for p in first.phases if p.get("phase") == "approve" and p.get("approve_url")]
    checks.append(Check("setup asked for one approval", len(asked) == 1, f"{len(asked)} approval address(es)"))
    url = str(done.get("trace_url", ""))
    checks.append(Check("its done phase links the trace on the organization", bool(TRACE_URL.match(url)), url))
    checks += file_checks(keyfile)

    line = init_line(first.phases)
    checks.append(Check("setup printed the one init line", bool(line), line))
    if line and first.code == 0:
        add_init_line(proj, a.lang, line)
        code, app_out, tty = run_app(proj, a.lang, env)
        texts.append(app_out)
        checks.append(Check("the app runs with the init line", code == 0, f"exit {code}"))
        links = FIRST_TRACE_LINE.findall(app_out)
        if tty:
            checks.append(Check("on a terminal the app prints its first-trace link once", len(links) == 1,
                                ", ".join(links)))
        else:
            checks.append(Check("the first-trace link (needs a terminal; not checked here)", True, "", warn=True))

    again = run_setup(base + ["--online", "--json"], proj, env, 180)
    texts += [again.out, again.err]
    checks.append(Check("a second run asks for no approval", again.code == 0 and phase(again.phases, "approve") is None,
                        f"exit {again.code}"))
    status = run_setup(base + ["--status", "--json"], proj, env, 60)
    texts += [status.out, status.err]
    checks.append(Check("setup --status answers", status.code == 0, f"exit {status.code}"))

    if not a.keep_key:
        forget = run_setup(base + ["--forget", "--json"], proj, env, 60)
        texts += [forget.out, forget.err]
        checks.append(Check("setup --forget revokes the key", forget.code == 0, f"exit {forget.code}"))
        checks.append(Check("setup --forget removes the key file", not keyfile.exists(), str(keyfile)))

    all_phases = first.phases + again.phases + status.phases
    checks += leak_checks("all runs", texts, all_phases)

    meta = {"language": a.lang, "setup command": " ".join(base), "project": name,
            "started (UTC)": stamp, "key kept": "yes" if a.keep_key else "no (setup --forget)"}
    (out / "report.md").write_text(report_md(meta, checks))
    (out / "report.json").write_text(json.dumps(
        {"meta": meta, "verdict": summarize(checks),
         "checks": [dict(dataclasses.asdict(c), detail=redact(c.detail)) for c in checks]}, indent=2) + "\n")
    (out / "setup.log").write_text(redact("\n".join(texts)))
    if a.keep_key:
        # The key is live and its file is in the scratch HOME: keep both, so
        # the person can revoke it later with setup --forget from there.
        print(f"setup-run: the key file stays in {keyfile} (run setup --forget with HOME={env['HOME']})")
    else:
        shutil.rmtree(scratch, ignore_errors=True)
    print(report_md(meta, checks))
    print(f"setup-run: report in {out}")
    return 0 if summarize(checks) == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
