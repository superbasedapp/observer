"""``superbased-sdk setup``: the one command (plan 3.5 to 3.8;
sdk-api-surface.md section 17).

``uvx superbased-sdk setup``, ``pipx run superbased-sdk setup`` or
``python -m superbased_sdk setup``. The planner (``plan``) decides; this
module executes: detect, choose the destination, install, get the
credential (the online device sign-in) or turn AI Apps on (local), send
the hello span and wait for it, then print the one init line.

It sets up the ingest gateway only, nothing else (SDKQS-10), never prints
the SDK key, the device code or the redeem secret (every write passes the
``out.Secrets`` guard), never installs Observer (ruling R8), never edits a
source file (ruling R5), and never calls the machine's SDK credential
routes or its key-minting and key-installing CLI verbs (R-165, SDKQS-8).

``--json`` writes one JSON object per phase on stdout (``detect``,
``destination``, ``install``, ``enable``, ``approve``, ``credential``,
``hello``, ``next``), and every run ends with ``done`` (``trace_url``,
``exit``) or ``error`` (``code``, ``message``, ``exit``).
"""

from __future__ import annotations

import argparse
import os
import platform as _platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import traceback
import unicodedata
import webbrowser
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

from .. import _config, _credfile, _destination, _http
from . import cloud, detect, hello, local, store
from . import plan as P
from .out import Output, Secrets, capture_sdk_logs

DOCS_URL = "https://superbased.app/docs/sdk/python"
KEYS_DOCS_URL = "https://superbased.app/docs/sdk/keys-and-scopes"
INIT_LINE = "import superbased_sdk; superbased_sdk.init()"
KEY_SENTENCE = "Traces need this SDK key, and nothing else."


def _version() -> str:
    from .. import __version__

    return __version__


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Any:  # argparse's own exit 2 would read as "waiting for a person"
        raise _UsageError(message)


def parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="superbased-sdk setup",
        description=(
            "Set up superbased tracing for this project: detect the model libraries, install the SDK, "
            "get an SDK key with one browser approval (online) or turn AI Apps on (this computer), "
            "send one hello span and print a link to it."
        ),
    )
    where = p.add_mutually_exclusive_group()
    where.add_argument("--local", dest="flag", action="store_const", const=P.LOCAL, help="send traces to this computer's Observer only")
    where.add_argument("--online", dest="flag", action="store_const", const=P.ONLINE, help="send traces to your online dashboard only")
    where.add_argument("--both", dest="flag", action="store_const", const=P.BOTH, help="send traces to this computer and your online dashboard")
    p.add_argument("--key-only", action="store_true", help="only get the SDK key (or check this computer) and send the hello: for Go and Java projects")
    p.add_argument("--replace", action="store_true", help="with --online or --both: get a new SDK key even though one is stored (the old one is revoked)")
    p.add_argument("--forget", action="store_true", help="revoke the stored SDK key and remove its file")
    p.add_argument("--status", action="store_true", help="say what is configured (never the key)")
    p.add_argument("--json", action="store_true", help="one JSON object per phase on stdout (for agents); people lines go to stderr")
    p.add_argument("--team", metavar="SLUG", default="", help="preselect this team's dashboard on the approval page")
    p.add_argument("--org-url", metavar="URL", default="", help="a self-hosted organization (setup gets keys for hosted ones only)")
    p.add_argument("--dir", "--project", dest="dir", metavar="PATH", default="", help="the project folder (default: the current folder)")
    p.add_argument("--no-install", action="store_true", help="print the install command instead of running it")
    p.add_argument("--no-browser", action="store_true", help="never open a browser; print the address instead")
    p.add_argument("--cloud-url", default="", help=argparse.SUPPRESS)
    p.set_defaults(flag="")
    return p


def _open_browser(url: str) -> bool:
    """Open ``url`` in a browser when this computer has a desktop; never a
    console browser that would take over the terminal."""
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        return bool(webbrowser.open(url, new=2))
    except Exception:  # noqa: BLE001
        return False


def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return ""


@dataclass
class Deps:
    """The I/O seams (the tests replace them)."""

    http: Callable[..., _http.Response] = _http.request
    clock: cloud.Clock = field(default_factory=cloud.Clock)
    open_browser: Callable[[str], bool] = _open_browser
    which: Callable[[str], Optional[str]] = shutil.which
    runner: detect.Runner = detect.run
    terminal: Optional[bool] = None
    ask: Callable[[str], str] = _ask
    install: Optional[Callable[[Sequence[str], str], Tuple[int, str]]] = None
    arrival_wait: float = hello.ARRIVAL_WAIT
    enable_poll_for: float = local.POLL_FOR


def main(argv: Optional[Sequence[str]] = None) -> int:
    """The console entry (``superbased-sdk``): ``superbased-sdk setup [flags]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "setup":
        args = args[1:]
    elif args and args[0] not in ("-h", "--help") and not args[0].startswith("-"):
        sys.stderr.write(f"superbased-sdk: unknown command {args[0]!r}; the command is `superbased-sdk setup`\n")
        return P.EXIT_USAGE
    return run(args)


def run(argv: Sequence[str], *, env: Optional[Mapping[str, str]] = None, deps: Optional[Deps] = None, stdout: Any = None, stderr: Any = None) -> int:
    """One setup run; the exit code (sdk-api-surface.md section 17)."""
    env = dict(os.environ if env is None else env)
    deps = deps or Deps()
    secrets = Secrets()
    out = Output(secrets, json_mode="--json" in argv, stdout=stdout, stderr=stderr)
    try:
        args = parser().parse_args(list(argv))
    except _UsageError as exc:
        return _stop(out, "usage", f"superbased-sdk setup: {exc}", P.EXIT_USAGE)
    except SystemExit as exc:  # --help
        return int(exc.code or 0)
    with capture_sdk_logs(out):
        try:
            return _Run(args, env, deps, out, secrets).go()
        except store.StoreError as exc:
            return _stop(out, "file_write", str(exc), P.EXIT_ENVIRONMENT)
        except KeyboardInterrupt:
            return _stop(out, "interrupted", "stopped", P.EXIT_WAITING)
        except Exception as exc:  # noqa: BLE001 - a setup bug: exit 1, the stack on stderr only
            out.warn(traceback.format_exc())
            return _stop(out, "unexpected", f"setup failed: {type(exc).__name__}: {exc}", P.EXIT_UNEXPECTED)


def _stop(out: Output, code: str, message: str, exit_code: int) -> int:
    """Say why the run ends and end it with an ``error`` event."""
    if message:
        out.say(message)
    out.event("error", code=code, message=message, exit=exit_code)
    return exit_code


def machine_name() -> str:
    """The host name: control and bidi characters removed, trimmed, at
    most 64 characters (the connect flow's rule)."""
    raw = socket.gethostname() or "unknown"
    clean = "".join(c for c in raw if unicodedata.category(c) not in ("Cc", "Cf"))
    return clean.strip()[:64] or "unknown"


def _arch() -> str:
    return re.sub(r"[^a-z0-9_]", "", (_platform.machine() or "").lower())[:16] or "unknown"


def _os() -> str:
    return re.sub(r"[^a-z0-9_]", "", sys.platform.lower())[:16] or "unknown"


class _Stop(Exception):
    """An early end of the run: the error event's code, message and exit."""

    def __init__(self, code: str, message: str, exit_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.exit_code = exit_code


class _Run:
    def __init__(self, args: argparse.Namespace, env: Dict[str, str], deps: Deps, out: Output, secrets: Secrets) -> None:
        self.a = args
        self.env = env
        self.d = deps
        self.out = out
        self.secrets = secrets
        self.root = os.path.abspath(args.dir or os.getcwd())
        self.node_url = (env.get("SUPERBASED_NODE_URL") or _destination.DEFAULT_NODE_URL).strip().rstrip("/")
        self.terminal = deps.terminal if deps.terminal is not None else (_isatty(sys.stdin) and _isatty(sys.stdout))
        if args.json:
            self.terminal = False
        self.held_path, self.held_problem = _credfile.default_path(env)
        self.held = _credfile.read(self.held_path, env=env) if self.held_path else _credfile.Record()
        self.dashboard = ""

    def go(self) -> int:
        try:
            return self._go()
        except _Stop as stop:
            return _stop(self.out, stop.code, stop.message, stop.exit_code)

    def _go(self) -> int:
        a = self.a
        if a.org_url:
            self.org_url()
        if a.status:
            return self.status()
        if a.forget:
            return self.forget()
        if a.replace and a.flag == P.LOCAL:
            raise _Stop("usage", "--replace gets a new SDK key; it goes with --online or --both, not --local", P.EXIT_USAGE)
        phases = P.phases(a.key_only)
        project = _config.find_project(self.root, home=_config._user_home())
        svc, svc_source = _config.service_name_ladder(None, self.env, project)
        project_name = _config.normalize_service_name(svc) or _config.DEFAULT_SERVICE_NAME

        det: Optional[detect.Detection] = None
        if P.DETECT in phases:
            det = detect.detect(detect.gather(self.root, self.d.runner, self.d.which), _version())
            self.check_language(det)
            libs = ", ".join(det.targets) or "none found (one added later is traced on its first import)"
            self.out.say(f"Python project ({det.package_manager}). Model libraries: {libs}.")
            self.out.event(
                "detect",
                language=det.language,
                package_manager=det.package_manager,
                targets=list(det.targets),
                extras=list(det.extras),
                entries=list(det.entries),
                service_name=svc,
                service_name_source=svc_source,
            )
        self.out.say(f"Service name: {svc} (from the {_SOURCE_WORDS.get(svc_source, svc_source)}).")

        choice, dest, answered = self.destination()

        if P.INSTALL in phases and det is not None:
            self.install(det)

        if choice.enable:
            self.enable()
        if choice.device_flow:
            self.device_flow(dest, project_name)

        hello_dest = dest
        if dest == P.BOTH and not answered:
            hello_dest = P.ONLINE  # no machine here yet: the hello checks the online copy
        code, links = self.hello(hello_dest, svc)

        if P.NEXT_STEPS in phases and det is not None:
            self.next_steps(det)
        else:
            self.out.say("Your app's SDK reads this setup by itself: no environment variable is needed.")
        trace_url = links.get(P.ONLINE) or links.get(P.LOCAL) or ""
        self.out.event("done", trace_url=trace_url, trace_urls=links, exit=code)
        return code

    # --- self-hosted (ruling R3) ---------------------------------------------------------

    def org_url(self) -> None:
        from urllib.parse import urlsplit

        try:
            host = (urlsplit(self.a.org_url).hostname or "").lower()
        except ValueError:
            host = ""
        if host == "superbased.app" or host.endswith(".superbased.app"):
            self.out.say("--org-url is not needed for a hosted organization: you choose the dashboard on the approval page.")
            return
        raise _Stop(
            "self_hosted",
            "This organization is self-hosted: setup gets SDK keys for hosted organizations only. Use an admin-issued key "
            "in SUPERBASED_API_KEY (with SUPERBASED_ORG_URL), or sign Observer in on a machine that runs it; "
            f"see {KEYS_DOCS_URL}",
            P.EXIT_ENVIRONMENT,
        )

    # --- phase 1 ------------------------------------------------------------------------------

    def check_language(self, det: detect.Detection) -> None:
        if det.language == detect.PYTHON:
            return
        msg = {
            detect.NODE: "This is a Node project: run `npx @superbased/sdk setup` here instead.",
            detect.GO: "This is a Go project: run `uvx superbased-sdk setup --key-only` to get the SDK key the Go SDK reads.",
            detect.JAVA: "This is a Java project: run `uvx superbased-sdk setup --key-only` to get the SDK key the Java SDK reads.",
        }.get(
            det.language,
            "No Python project found here (no pyproject.toml, requirements.txt or .py file). Run setup in the project folder, "
            "or with --key-only for another language.",
        )
        self.out.event("detect", language=det.language or None)
        raise _Stop("no_supported_language", msg, P.EXIT_ENVIRONMENT)

    # --- phase 2 ------------------------------------------------------------------------------

    def destination(self) -> Tuple[P.Choice, str, bool]:
        body: Optional[Dict[str, Any]] = None
        if _config.env_flag(self.env, ("SUPERBASED_DISCOVER",), True):
            body, _err = _destination.discover(self.node_url, self.d.http)
        answered = body is not None
        raw_local = (body or {}).get("local")
        local_info: Dict[str, Any] = raw_local if isinstance(raw_local, dict) else {}
        facts = P.Facts(
            flag=self.a.flag,
            answered=answered,
            signed_in=bool((body or {}).get("signed_in")),
            apps_on=bool(local_info.get("enabled") is True),
            on_path=bool(self.d.which("observer")),
            held=P.held(self.held.state, self.held.usable, self.held.expired()),
            replace=self.a.replace,
            terminal=self.terminal,
        )
        choice = P.choose(facts)
        if choice.destination == P.ASK:
            raw = self.d.ask("AI Apps is on here. Send traces to this computer only, or also to your online dashboard? [local/both] (local): ")
            choice = P.after_ask(P.read_answer(P.ASK, raw))
        elif choice.destination == P.ASK_ONLINE:
            raw = self.d.ask("Observer is installed but not running. Set up your online dashboard instead? [y/N] ")
            choice = P.after_ask_online(P.read_answer(P.ASK_ONLINE, raw))
        if self.held.state == _credfile.REFUSED:
            self.out.warn(self.held.error)
        if choice.stop:
            msg = P.stop_message(choice.stop, windows=os.name == "nt")
            self.out.event("destination", row=choice.row, stop=choice.stop)
            raise _Stop(choice.stop, msg, choice.exit_code)
        dest = choice.destination
        if dest in (P.HELD, P.HELD_OR_ONLINE):
            dest = self.held.destination if self.held.state == _credfile.VALID and self.held.destination else P.ONLINE
        for note in choice.notes:
            self.out.say(P.MESSAGES[note])
        self.out.say(f"Destination: {_DEST_WORDS[dest]}.")
        if dest in (P.ONLINE, P.BOTH) and (self.env.get("SUPERBASED_API_KEY") or "").strip() and not choice.machine_key:
            self.out.say("Note: SUPERBASED_API_KEY is set in this shell; an app started from it uses that key, not the one setup stores.")
        self.out.event(
            "destination",
            destination=dest,
            row=choice.row,
            device_flow=choice.device_flow,
            enable=choice.enable,
            notes=list(choice.notes),
        )
        return choice, dest, answered

    # --- phase 3 ------------------------------------------------------------------------------

    def install(self, det: detect.Detection) -> None:
        cmd = list(det.install)
        shown = shlex.join(cmd)
        if self.a.no_install:
            self.out.say(f"Install (not run, --no-install): {shown}")
            self.out.event("install", command=cmd, ran=False)
            return
        if det.tool_missing:
            self.out.event("install", command=cmd, ran=False)
            raise _Stop("package_manager_missing", f"This project uses {det.tool_missing}, which is not on PATH. Install it, or run: {shown}", P.EXIT_ENVIRONMENT)
        self.out.say(f"Installing: {shown}")
        code, tail = (self.d.install or _install)(cmd, self.root)
        if code != 0:
            for line in tail.splitlines()[-15:]:
                self.out.say("  " + line)
            self.out.event("install", command=cmd, ran=True, ok=False)
            raise _Stop("install_failed", f"The install failed (exit {code}). Run it yourself and then setup again: {shown}", P.EXIT_ENVIRONMENT)
        self.out.event("install", command=cmd, ran=True, ok=True)

    # --- phase 4, local (3.7) -------------------------------------------------------------------

    def enable(self) -> None:
        st = local.status(self.d.http, self.node_url)
        if not st.answered:
            raise _Stop("enable_unavailable", "This computer's Observer did not answer its AI Apps status; is it a current version?", P.EXIT_ENVIRONMENT)
        if st.on:
            return
        if self.terminal:
            if st.consent:
                self.out.say(st.consent)
            raw = self.d.ask("Turn on AI Apps on this computer? [y/N] ")
            if raw.strip().lower() not in ("y", "yes"):
                self.out.event("enable", state="declined")
                raise _Stop("enable_declined", P.MESSAGES["enable_declined"], P.EXIT_WAITING)
            r = local.enable(self.d.http, self.node_url, st.token)
            if not r.ok:
                self.out.event("enable", state="failed")
                raise _Stop("enable_failed", f"AI Apps could not be turned on: {r.message}" + (f" {r.fix}" if r.fix else ""), P.EXIT_ENVIRONMENT)
            self.out.say("AI Apps is on.")
            self.out.event("enable", state="on", by="terminal")
            return
        url = local.page_url(self.node_url)
        opened = (not self.a.no_browser) and self.d.open_browser(url)
        if not opened:
            self.out.event("enable", state="waiting", url=url)
            raise _Stop(
                "enable_waiting",
                f"Turn on AI Apps on this computer: open {url} and click Turn on (or run `observer apps on`). Then run setup again.",
                P.EXIT_WAITING,
            )
        self.out.say(f"Opened {url}: click Turn on there to let this computer receive traces. Waiting for it...")
        self.out.event("enable", state="opened", url=url)
        deadline = self.d.clock.monotonic() + self.d.enable_poll_for
        while self.d.clock.monotonic() < deadline:
            self.d.clock.sleep(local.POLL_EVERY)
            if local.status(self.d.http, self.node_url).on:
                self.out.say("AI Apps is on.")
                self.out.event("enable", state="on", by="dashboard")
                return
        raise _Stop("enable_waiting", "AI Apps is still off. Turn it on (the page above, or `observer apps on`) and run setup again.", P.EXIT_WAITING)

    # --- phase 4, online (3.6) ------------------------------------------------------------------

    def device_flow(self, dest: str, project_name: str) -> None:
        base, problem = cloud.cloud_base(self.env, self.a.cloud_url)
        if problem:
            raise _Stop("cloud_url", f"The cloud address is not usable: {problem}", P.EXIT_ENVIRONMENT)
        if not self.held_path:
            raise _Stop("no_key_path", self.held_problem or "there is no place for the SDK key on this computer", P.EXIT_ENVIRONMENT)
        secret, rhash = cloud.redeem_pair()
        self.secrets.add(secret)
        body = {
            "purpose": cloud.PURPOSE,
            "client": cloud.CLIENT,
            "client_version": _version(),
            "project_name": project_name,
            "machine_name": machine_name(),
            "os": _os(),
            "arch": _arch(),
            "target_hint": self.a.team or "",
            "redeem_hash": rhash,
        }
        created, st, resp = cloud.create(self.d.http, base, body)
        if created is None:
            msg = cloud.server_message(resp) if resp.status else P.MESSAGES.get(st.message, "")
            raise _Stop(cloud._code(resp, "code") or st.message or "create_failed", f"Could not start the sign-in at {base}: {msg}", st.exit_code)
        self.secrets.add(created.device_code)
        self.out.say(f"Approve in your browser: {created.approve_url}  (code {created.user_code})")
        self.out.say(f"Sign in or sign up, check that the page shows code {created.user_code}, and click Approve. {KEY_SENTENCE}")
        self.out.event("approve", approve_url=created.approve_url, user_code=created.user_code, verify_url=created.verify_url, expires_in=created.expires_in)
        if not self.a.no_browser and self.d.open_browser(created.approve_url):
            self.out.say("Opened your browser.")

        deadline = self.d.clock.monotonic() + created.expires_in
        interval = max(1.0, created.interval)
        said_ready = False
        while True:
            if self.d.clock.monotonic() >= deadline:
                raise _Stop("expired", P.MESSAGES["expired"], P.EXIT_WAITING)
            self.d.clock.sleep(interval)
            pr = cloud.poll_once(self.d.http, base, created)
            if pr.response is not None and isinstance(pr.response.body, dict):
                interval = max(1.0, cloud._num(pr.response.body.get("interval"), interval))
            if pr.step.action == P.REDEEM:
                break
            if pr.step.action == P.STOP:
                body_now = pr.response.body if pr.response is not None and isinstance(pr.response.body, dict) else {}
                state = str(body_now.get("status") or "")
                code = state if state in ("declined", "expired") else (cloud._code(pr.response, "code") if pr.response is not None else "")
                raise _Stop(code or pr.step.message or "stopped", P.MESSAGES.get(pr.step.message, ""), pr.step.exit_code)
            if pr.step.action == P.WAIT and pr.response is not None:
                self.d.clock.sleep(cloud.retry_after(pr.response, interval))
            if pr.step.message == "approved_not_ready" and not said_ready:
                said_ready = True
                self.out.say(P.MESSAGES["approved_not_ready"])
                self.out.event("approve", state="approved_not_ready")

        self.secrets.add(pr.grant)
        target = pr.target
        problem = _destination.gateway_problem(target.server_url)
        if problem:
            raise _Stop("bad_server_url", f"The cloud named an organization address setup cannot use ({problem}).", P.EXIT_ENVIRONMENT)
        self.out.say(f"Approved for {target.display_name or target.slug or target.server_url}.")
        self.out.event("approve", state="approved", dashboard=target.slug, kind=target.kind)

        replaces = self.held.key_id if self.a.replace and self.held.state == _credfile.VALID else ""
        rr = cloud.redeem_once(self.d.http, target.server_url, pr.grant, secret, body["machine_name"], replaces)
        if rr.step.action == P.WAIT:  # a 429 (or no answer) is retried once, after Retry-After
            self.d.clock.sleep(cloud.retry_after(rr.response, 2.0) if rr.response is not None else 2.0)
            rr = cloud.redeem_once(self.d.http, target.server_url, pr.grant, secret, body["machine_name"], replaces)
            if rr.step.action == P.WAIT:
                raise _Stop("rate_limited", "The organization is busy (rate limited); run setup again in a minute. No SDK key was stored.", P.EXIT_ENVIRONMENT)
        if rr.minted is None:
            self.redeem_refused(rr)
        minted = rr.minted
        assert minted is not None
        self.secrets.add(minted.key)
        problem = _destination.gateway_problem(minted.gateway_url)
        if problem:
            raise _Stop("bad_gateway_url", f"The organization answered a gateway address setup cannot use ({problem}); no key was stored.", P.EXIT_ENVIRONMENT)
        dashboard = minted.dashboard_url if minted.dashboard_url and not _credfile.dashboard_problem(minted.dashboard_url) else ""
        rec = store.write(self.held_path, store.lines(minted.key, minted.gateway_url, dest, dashboard, minted.expires_at))
        self.held = rec
        self.dashboard = dashboard
        expiry = f" It expires {minted.expires_at};" if minted.expires_at else ""
        self.out.say(
            f"Stored the SDK key for this user in {self.held_path} (it is never printed).{expiry} "
            "revoke it on the dashboard, or with setup --forget."
        )
        self.out.event(
            "credential",
            written=True,
            path=self.held_path,
            key_id=minted.key_id,
            gateway_url=minted.gateway_url,
            dashboard_url=dashboard,
            expires_at=minted.expires_at,
            destination=dest,
        )
        if minted.plan_refusal:
            refusal = minted.plan_refusal
            raw_quota = refusal.get("quota")
            quota: Dict[str, Any] = raw_quota if isinstance(raw_quota, dict) else {}
            lines = hello.refusal_lines(
                str(refusal.get("error") or ""),
                str(refusal.get("message") or ""),
                str(refusal.get("upgrade_url") or ""),
                str(quota.get("resets_at") or ""),
            )
            raise _Stop(str(refusal.get("error") or "plan_refusal"), "\n".join(lines), P.EXIT_REFUSED)

    def redeem_refused(self, rr: cloud.RedeemResult) -> None:
        resp = rr.response
        body = resp.body if resp is not None and isinstance(resp.body, dict) else {}
        code = str(body.get("error") or "")
        message = str(body.get("message") or "").strip()
        if code == "plan_required":
            lines = hello.refusal_lines(code, message, str(body.get("upgrade_url") or ""))
        else:
            lines = [message or P.MESSAGES.get(rr.step.message) or (cloud.server_message(resp) if resp is not None else "no answer")]
        lines.append("No SDK key was stored.")
        raise _Stop(code or rr.step.message or "redeem_failed", "\n".join(lines), rr.step.exit_code)

    # --- phase 5 (3.8) ----------------------------------------------------------------------------

    def hello(self, dest: str, svc: str) -> Tuple[int, Dict[str, str]]:
        sent = hello.send(dest, svc, self.env)
        links: Dict[str, str] = {}
        try:
            self.out.event("hello", trace_id=sent.trace_id, service_name=svc, destination=dest)
            for w in sent.warnings:
                self.out.warn(w)
            if sent.refusal:
                raise _Stop(sent.refusal_code or "plan_refusal", "\n".join(sent.refusal), P.EXIT_REFUSED)
            if sent.unauthorized:
                raise _Stop("unauthorized", "The organization did not accept the SDK key. Run setup --online --replace to get a new one.", P.EXIT_REFUSED)
            plan = sent.plan
            if plan is None or not plan.exporters:
                raise _Stop("not_sent", "Nothing could be sent: " + (plan.degraded if plan is not None and plan.degraded else "no destination"), P.EXIT_ENVIRONMENT)
            self.out.say(f"Sent a hello span (trace {sent.trace_id}). Waiting for it to arrive...")
            sides = hello.wait_for_arrival(
                self.d.http, plan, sent.trace_id, sleep=self.d.clock.sleep, monotonic=self.d.clock.monotonic, wait=self.d.arrival_wait
            )
            bases = {P.LOCAL: plan.node_url, P.ONLINE: self.dashboard or plan.dashboard_url}
            code = P.EXIT_DONE
            for name, state in sides.items():
                url = hello.link(name, bases.get(name, ""), sent.trace_id)
                if url:
                    links[name] = url
                where = "this computer" if name == P.LOCAL else "your online dashboard"
                if state == "yes":
                    self.out.say(f"Your first trace ({where}): {url}" if url else f"Your first trace arrived on {where} (trace {sent.trace_id}).")
                elif state == "unauthorized":
                    raise _Stop("unauthorized", "The organization did not accept the SDK key. Run setup --online --replace to get a new one.", P.EXIT_REFUSED)
                else:
                    self.out.say(f"Sent, not seen yet on {where}: {url or sent.trace_id}")
                    code = P.EXIT_NOT_SEEN
            self.out.event("hello", state="arrival", sides=sides, trace_urls=links)
            return code, links
        finally:
            hello.stop_sdk()

    # --- phase 6 ----------------------------------------------------------------------------------

    def next_steps(self, det: detect.Detection) -> None:
        where = det.entries[0] if det.entries else "the module that starts your app"
        self.out.say("")
        self.out.say(f"Next: add this line near the top of {where}:")
        self.out.say(f"    {INIT_LINE}")
        self.out.say("Then run the app once: on a terminal it prints a link to its own first trace.")
        more = [
            "wrap the request handler with @superbased_sdk.observe(kind=superbased_sdk.AGENT)",
            "set the end user with superbased_sdk.propagate_attributes(user=<an opaque id>)",
        ]
        if "openai-agents" in det.named_only:
            more.append(
                "to trace OpenAI Agents SDK runs, call superbased_sdk.init(instrument=[\"openai\", \"openai-agents\"]) "
                "and install superbased-sdk[openai-agents] (this stops the Agents SDK uploading its own traces to OpenAI)"
            )
        self.out.say("Later, to make it richer: " + "; ".join(more) + f". Docs: {DOCS_URL}")
        self.out.event("next", init_line=INIT_LINE, where=where, more=more, docs=DOCS_URL)

    # --- --status and --forget ----------------------------------------------------------------------

    def status(self) -> int:
        rec = self.held
        if rec.state == _credfile.VALID:
            exp = f", expires {rec.expires_at}" if rec.expires_at else ""
            self.out.say(f"SDK key file: {rec.path} (key {rec.key_id} for {rec.gateway_url or 'no address'}, destination {rec.destination or 'not set'}{exp})")
            warn = _credfile.expiry_warning(rec)
            if warn:
                self.out.say(warn)
        elif rec.state == _credfile.REFUSED:
            self.out.say(f"SDK key file: {rec.error}")
        else:
            self.out.say(f"SDK key file: none ({self.held_path or self.held_problem})")
        body: Optional[Dict[str, Any]] = None
        if _config.env_flag(self.env, ("SUPERBASED_DISCOVER",), True):
            body, _err = _destination.discover(self.node_url, self.d.http)
        machine: Dict[str, Any] = {"answered": body is not None, "node_url": self.node_url}
        if body is not None:
            raw_info = body.get("local")
            info: Dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            machine.update(signed_in=bool(body.get("signed_in")), apps_on=info.get("enabled") is True)
            self.out.say(
                f"This computer: Observer at {self.node_url}, AI Apps {'on' if machine['apps_on'] else 'off'}, "
                f"{'signed in' if machine['signed_in'] else 'not signed in'}."
            )
        else:
            self.out.say(f"This computer: no Observer answering at {self.node_url}.")
        s = _config.Settings.resolve(self.env)
        p = _destination.resolve(s, self.env, fetch=self.d.http)
        self.out.say(f"Apps started here send to: {p.destination} (from {p.source}); credential: {p.credential_source or 'none'}.")
        for w in p.warnings:
            self.out.say("  " + w)
        if p.degraded:
            self.out.say("  " + p.degraded)
        file_facts: Dict[str, Any] = dict(p.sdk_file) if p.sdk_file else {"path": self.held_path, "state": "absent", "reason": ""}
        file_facts.update(key_id=rec.key_id, expires_at=rec.expires_at, destination=rec.destination)
        self.out.event(
            "status",
            sdk_file=file_facts,
            machine=machine,
            destination=p.destination,
            destination_source=p.source,
            credential_source=p.credential_source,
            warnings=list(p.warnings),
        )
        self.out.event("done", trace_url="", exit=P.EXIT_DONE)
        return P.EXIT_DONE

    def forget(self) -> int:
        rec = self.held
        if rec.state == _credfile.ABSENT:
            self.out.say(f"No SDK key file at {self.held_path}; nothing to forget.")
            self.out.event("forget", removed=False, revoked=False)
            self.out.event("done", trace_url="", exit=P.EXIT_DONE)
            return P.EXIT_DONE
        revoked = False
        if rec.usable:
            self.secrets.add(rec.key)
            ok, resp = cloud.revoke(self.d.http, rec.gateway_url, rec.key)
            revoked = ok
            if ok:
                note = f"Revoked SDK key {rec.key_id}."
            elif resp.status == 401:
                note = f"SDK key {rec.key_id} was already revoked or is not valid."
            else:
                note = (
                    f"Could not revoke SDK key {rec.key_id} ({cloud.server_message(resp)}); it stays valid until "
                    f"{rec.expires_at or 'it expires'}: revoke it on the dashboard."
                )
        else:
            note = "The key in the file could not be used, so it was not revoked; revoke it on the dashboard if it is still listed."
        removed = store.remove(rec.path)
        self.out.say(note)
        self.out.say(f"Removed {rec.path}." if removed else f"{rec.path} was already gone.")
        self.out.event("forget", key_id=rec.key_id or None, revoked=revoked, removed=removed)
        self.out.event("done", trace_url="", exit=P.EXIT_DONE)
        return P.EXIT_DONE


_SOURCE_WORDS = {
    _config.NAME_ARGUMENT: "argument",
    _config.NAME_ENV: "environment",
    _config.NAME_MANIFEST: "project's pyproject.toml",
    _config.NAME_ENTRY_DIR: "project folder's name",
    _config.NAME_DEFAULT: "default; set SUPERBASED_SERVICE_NAME to name it",
}

_DEST_WORDS = {
    P.LOCAL: "this computer only",
    P.ONLINE: "your online dashboard",
    P.BOTH: "this computer and your online dashboard",
}


def _isatty(stream: Any) -> bool:
    try:
        return bool(stream is not None and stream.isatty())
    except Exception:  # noqa: BLE001
        return False


def _install(cmd: Sequence[str], cwd: str) -> Tuple[int, str]:
    """Run the install with the project's own tool. A ``VIRTUAL_ENV`` that
    is setup's own (``uvx``) is not handed on; the child gets no secret
    (the key is never in this process's environment or argv)."""
    env = dict(os.environ)
    venv = env.get("VIRTUAL_ENV", "")
    if venv and os.path.abspath(venv) == os.path.abspath(sys.prefix):
        env.pop("VIRTUAL_ENV", None)
    try:
        r = subprocess.run(list(cmd), cwd=cwd, env=env, capture_output=True, text=True, timeout=900, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    return r.returncode, (r.stdout or "") + (r.stderr or "")
