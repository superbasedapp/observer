"""SuperBased Observer — Hermes Agent plugin bridge.

Fires `observer hook hermes <event>` on each relevant Hermes hook so the
observer daemon can ingest Hermes activity in real time, and gates every
tool call through Observer's guard (pre_tool_call).

Design constraints:

- Capture events are fire-and-forget: 0.5 s subprocess timeout
  (TIMEOUT_SECONDS below), every exception swallowed, stdout ignored.
  Observer being absent / down / slow never affects a capture event.
  The first capture after the observer binary changed (an update: its
  size or modification time differs from the one this plugin last saw
  answer in time, kept in hermes-plugin-seen beside the config) gets
  FIRST_CAPTURE_TIMEOUT_SECONDS instead, so the event is not dropped while
  the new binary warms up (SHR-2); once it answers in time the steady 0.5 s
  bound returns. A slow first answer is retried with the longer bound on
  the next event, at most FIRST_CAPTURE_TRIES times per binary, so a
  binary that never answers costs the steady bound again after that.
- pre_tool_call is a GATE (hook-parity audit 2026-10-02, Lane A7; operator
  decision 2026-10-02 reversed the old "never block" invariant for this one
  hook). Observer answers in its plugin dialect ({"decision": "allow" |
  "deny" | "ask", "reason", "enforced"}); deny becomes Hermes'
  {"action": "block", "message"} (the message becomes the tool result) and
  ask becomes {"action": "approve", "message"} (Hermes' own human-approval
  prompt). Observer is told to finish below GATE_TIMEOUT_SECONDS
  (--max-runtime), so its own fail-closed answer wins. When Observer does
  not answer at all (missing, hung, garbage), the call is blocked with a
  reason ONLY while guard enforcement is in force, and proceeds otherwise.
  "In force" is read only to TIGHTEN: a recent reply's `enforced: true`
  hint, or the daemon's guard-posture.json while it is FRESH (written
  within the posture window, not dated in the future, not older than
  config.toml: the T-050 rule the Go hook applies), so a stopped daemon
  cannot keep failures closed forever and an `enforced: false` hint never
  opens what the posture closes. Either way the failure is appended to
  guard-hookfail.jsonl for the daemon with its outcome (fail_closed or
  fail_open, T-049). Hermes itself fails a pre_tool_call that outlives
  plugins.hook_callback_timeout (30 s default) CLOSED.

Environment overrides (read at plugin load time):
- OBSERVER_BIN     Path to the observer binary. `observer init --hermes`
                   substitutes the running binary's absolute path into
                   the default value below at install time so PATH
                   manipulation isn't required. Setting OBSERVER_BIN in
                   the operator's environment still wins — useful when
                   the agent and observer live under different `bin/`
                   paths.
- OBSERVER_CONFIG  Path to observer config.toml. Defaults to empty (the
                   observer falls back to its standard discovery). Set
                   this if the agent and observer run under different
                   home directories.

Hooks registered (subset of hermes_cli/plugins.py VALID_HOOKS — see
docs/hermes-adapter-plan.md §17.1.F for the rationale on each pick):

- on_session_start  — captures session UUID, model, source, CWD.
- on_session_end    — captures end_reason and ended_at.
- post_tool_call    — captures the tool name, args, result, duration_ms.
                      Fires AFTER the tool returns so the result is
                      available; the assistant message that initiated
                      the call lands in the SQLite backfill path
                      separately.
- post_api_request  — captures upstream API usage (input/output/cache/
                      reasoning tokens) per call. The plan originally
                      targeted post_llm_call but reality (§17.1.F.1)
                      showed that hook carries no usage payload at all;
                      post_api_request is the right capture surface.
- subagent_stop     — captures sub-agent completion (duration, status,
                      summary) for cross-thread analytics.
- pre_tool_call     — the guard tool gate (see Design constraints).
"""

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone

OBSERVER_BIN = os.environ.get("OBSERVER_BIN", "{{OBSERVER_BIN_DEFAULT}}")
OBSERVER_CONFIG = os.environ.get("OBSERVER_CONFIG", "")
TIMEOUT_SECONDS = 0.5
# The bound for the first capture after the observer binary changed (SHR-2).
FIRST_CAPTURE_TIMEOUT_SECONDS = 5.0
SEEN_FILE = "hermes-plugin-seen"
FIRST_CAPTURE_TRIES = 3
_SEEN = [None]  # the binary identity last seen answering in time, loaded lazily
_FIRST_TRIES = {}  # identity -> first-capture attempts made in this process

# pre_tool_call gate budget: the plugin's own deadline, and the margin
# observer is told to finish inside (--max-runtime).
GATE_TIMEOUT_SECONDS = 10.0
GATE_MARGIN_SECONDS = 1.5
FAIL_TIMEOUT = ("Observer could not evaluate this call in time; it is blocked because guard "
                "enforcement is on. Retry, or ask your admin if this repeats.")
FAIL_ERROR = ("Observer could not evaluate this call because of an internal error; it is blocked "
              "because guard enforcement is on. Retry, or ask your admin if this repeats.")
POSTURE_SCHEMA = 1
# Posture freshness (T-050): guardposture.MaxAge and MaxFutureSkew. A Go
# test (embed_test.go) pins these to the Go constants.
POSTURE_MAX_AGE_SECONDS = 180
POSTURE_SKEW_SECONDS = 60
HINT_TTL_SECONDS = 600
_ENFORCED_HINT = {}  # cap -> (enforced, monotonic time) from the last observer reply
_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def _observer_dir():
    if OBSERVER_CONFIG:
        return os.path.dirname(os.path.abspath(OBSERVER_CONFIG))
    return os.path.join(os.path.expanduser("~"), ".observer")


def _config_file():
    if OBSERVER_CONFIG:
        return os.path.abspath(OBSERVER_CONFIG)
    return os.path.join(_observer_dir(), "config.toml")


def _parse_rfc3339(s):
    """Seconds since the epoch for an RFC 3339 time (any fraction length),
    or None."""
    m = _RFC3339.match(s or "") if isinstance(s, str) else None
    if not m:
        return None
    try:
        dt = datetime(*(int(m.group(i)) for i in range(1, 7)), tzinfo=timezone.utc)
    except ValueError:
        return None
    zone = m.group(8)
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        dt -= sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
    return dt.timestamp() + float(m.group(7) or 0)


def _posture_fresh(p):
    """The T-050 rule: written within the window, not dated in the future,
    not older than config.toml."""
    at = _parse_rfc3339(p.get("written_at"))
    if at is None:
        return False
    now = time.time()
    if now - at > POSTURE_MAX_AGE_SECONDS or at - now > POSTURE_SKEW_SECONDS:
        return False
    try:
        if os.stat(_config_file()).st_mtime > at:
            return False
    except OSError:
        pass  # no config file: nothing changed after the posture was written
    return True


def _posture_closed(cap):
    """True when the daemon's guard-posture.json says cap fails closed and
    is FRESH. Read only to TIGHTEN a failure (never to open one): its MAC is
    not checked here, observer's own answer (which does check it) wins."""
    try:
        with open(os.path.join(_observer_dir(), "guard-posture.json"), encoding="utf-8") as f:
            p = json.load(f)
        return (isinstance(p, dict) and p.get("schema") == POSTURE_SCHEMA and p.get("enforced") is True
                and isinstance(p.get("gate_caps"), list) and cap in p["gate_caps"]
                and _posture_fresh(p))
    except (OSError, ValueError):
        return False


def _fails_closed(cap):
    """Tighten only: a recent enforced:true hint closes, and so does a fresh
    posture; an enforced:false hint opens nothing."""
    hint = _ENFORCED_HINT.get(cap)
    if hint is not None and hint[0] and time.monotonic() - hint[1] < HINT_TTL_SECONDS:
        return True
    return _posture_closed(cap)


def _spool(event, cap, session_id, kind, outcome):
    try:
        line = json.dumps({
            "tool": "hermes", "event": event[:256], "cap": cap, "session_id": (session_id or "")[:256],
            "kind": kind, "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "outcome": outcome,
        })
        fd = os.open(os.path.join(_observer_dir(), "guard-hookfail.jsonl"),
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (line + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, ValueError):
        pass


def _gate(event, cap, payload):
    """Run the observer gate for event; return its decision dict
    ({"decision", "reason"}), applying the failure rule when observer gives
    no answer."""
    cmd = [OBSERVER_BIN, "hook", "hermes", event,
           "--max-runtime", "%dms" % int((GATE_TIMEOUT_SECONDS - GATE_MARGIN_SECONDS) * 1000)]
    if OBSERVER_CONFIG:
        cmd.extend(["--config", OBSERVER_CONFIG])
    kind = "unparseable"
    try:
        proc = subprocess.run(cmd, input=json.dumps(payload), capture_output=True, text=True,
                              timeout=GATE_TIMEOUT_SECONDS, check=False)
        for line in reversed((proc.stdout or "").splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                reply = json.loads(line)
            except ValueError:
                continue
            if isinstance(reply, dict):
                if isinstance(reply.get("enforced"), bool):
                    _ENFORCED_HINT[cap] = (reply["enforced"], time.monotonic())
                return reply
    except subprocess.TimeoutExpired:
        kind = "timeout"
    except (FileNotFoundError, OSError, ValueError):
        kind = "crash"
    if _fails_closed(cap):
        _spool(event, cap, payload.get("session_id"), kind, "fail_closed")
        return {"decision": "deny", "reason": FAIL_TIMEOUT if kind == "timeout" else FAIL_ERROR}
    # T-049: a fail-open failure is a guard event too.
    _spool(event, cap, payload.get("session_id"), kind, "fail_open")
    return {"decision": "allow"}


def _bin_identity():
    """The observer binary's size and modification time ("" when it cannot
    be read): a change means an update, whose first run may be slow."""
    path = OBSERVER_BIN
    if not os.path.isabs(path):
        path = shutil.which(path) or ""
    try:
        st = os.stat(path)
    except (OSError, ValueError):
        return ""
    return "%d:%d" % (st.st_size, st.st_mtime_ns)


def _seen_identity():
    if _SEEN[0] is None:
        try:
            with open(os.path.join(_observer_dir(), SEEN_FILE), encoding="utf-8") as f:
                _SEEN[0] = f.read(128).strip()
        except (OSError, ValueError):
            _SEEN[0] = ""
    return _SEEN[0]


def _note_seen(ident):
    _SEEN[0] = ident
    try:
        fd = os.open(os.path.join(_observer_dir(), SEEN_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, (ident + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except (OSError, ValueError):
        pass


def _capture_timeout():
    """(bound, identity): the steady bound while the binary is the one last
    seen answering in time, else the first-capture bound (SHR-2)."""
    ident = _bin_identity()
    if not ident or ident == _seen_identity() or _FIRST_TRIES.get(ident, 0) >= FIRST_CAPTURE_TRIES:
        return TIMEOUT_SECONDS, ident
    _FIRST_TRIES[ident] = _FIRST_TRIES.get(ident, 0) + 1
    return FIRST_CAPTURE_TIMEOUT_SECONDS, ident


def _fire(event_name, payload):
    """Run `observer hook hermes <event>` with payload on stdin. Fire-and-forget."""
    cmd = [OBSERVER_BIN, "hook", "hermes", event_name]
    if OBSERVER_CONFIG:
        cmd.extend(["--config", OBSERVER_CONFIG])
    bound, ident = _capture_timeout()
    try:
        subprocess.run(
            cmd,
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=bound,
            check=False,
        )
        if ident and ident != _seen_identity():
            _note_seen(ident)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        # ValueError covers json.dumps failures on non-serialisable payload
        # parts (rare but possible for tool args that wrap third-party
        # objects); the rest cover subprocess + env failures. A capture event
        # never affects the host Hermes tool (only the pre_tool_call gate
        # can), so every exception class lands in the same swallow.
        pass


def _safe_json(value):
    """Return value if it's already JSON-shaped, else stringify it."""
    if value is None:
        return None
    if isinstance(value, (dict, list, str, int, float, bool)):
        return value
    return str(value)


def register(ctx):
    """Hermes plugin entry point.

    Called once by the plugin loader at agent startup. Registers callbacks
    for the lifecycle hooks observer ingests.
    """

    def on_session_start(session_id=None, model=None, source=None, **kwargs):
        if not session_id:
            return
        _fire("session_start", {
            "event": "session_start",
            "session_id": session_id,
            "model": model or "",
            "source": source or "",
            "cwd": os.getcwd(),
            "started_at": time.time(),
            # pid/ppid let observer seed its process<->session bridge for
            # direct attribution. os.getpid() is THIS long-lived Hermes
            # agent process — the one that opens provider API sockets — so
            # observer registers it directly; os.getppid() is sent for
            # diagnostics only (observer never seeds the parent shell).
            # Additive fields: older observers ignore unknown keys, and a
            # newer observer tolerates their absence from an older plugin.
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "telemetry_schema_version": kwargs.get("telemetry_schema_version", ""),
        })

    def on_session_end(session_id=None, end_reason=None, **kwargs):
        if not session_id:
            return
        _fire("session_end", {
            "event": "session_end",
            "session_id": session_id,
            "end_reason": end_reason or "",
            # cwd is REQUIRED — observer's store layer drops events with
            # empty ProjectRoot (`if e.ProjectRoot == "" { continue }`)
            # to avoid an FK violation on the project upsert. The Hermes
            # on_session_end hook doesn't surface cwd in its kwargs, so
            # we capture os.getcwd() at end-time. Validation 2026-06-06
            # caught session_end rows being silently dropped pre-fix.
            "cwd": os.getcwd(),
            "ended_at": time.time(),
            "telemetry_schema_version": kwargs.get("telemetry_schema_version", ""),
        })

    def post_tool_call(session_id=None, tool_name=None, args=None, result=None,
                       duration_ms=0, tool_call_id=None, task_id=None, **kwargs):
        if not session_id or not tool_name:
            return
        # result can be a dict (structured per §17.1 C) or a string. Coerce
        # to a string for the Go side, which parses with json.Unmarshal.
        if isinstance(result, (dict, list)):
            result_str = json.dumps(result)
        elif result is None:
            result_str = ""
        else:
            result_str = str(result)
        _fire("tool_call", {
            "event": "tool_call",
            "session_id": session_id,
            "task_id": task_id or "",
            "tool_call_id": tool_call_id or "",
            "tool_name": tool_name,
            "args": _safe_json(args) or {},
            "result": result_str,
            "duration_ms": int(duration_ms) if duration_ms is not None else 0,
            "cwd": os.getcwd(),
            "timestamp": time.time(),
            "telemetry_schema_version": kwargs.get("telemetry_schema_version", ""),
        })

    def post_api_request(session_id=None, model=None, provider=None,
                         usage=None, api_call_count=0, finish_reason=None,
                         api_duration=0, **kwargs):
        if not session_id or not usage:
            return
        _fire("api_request", {
            "event": "api_request",
            "session_id": session_id,
            "model": model or "",
            "provider": provider or "",
            "usage": _safe_json(usage) or {},
            "api_call_count": int(api_call_count) if api_call_count is not None else 0,
            "finish_reason": finish_reason or "",
            "api_duration": float(api_duration) if api_duration is not None else 0,
            # cwd is REQUIRED for the same reason as on_session_end —
            # observer's store layer needs a non-empty ProjectRoot to
            # upsert the owning project before the token row can land.
            # Validation 2026-06-06 caught api_request token rows being
            # silently dropped pre-fix even though the usage block was
            # populated.
            "cwd": os.getcwd(),
            "timestamp": time.time(),
            "telemetry_schema_version": kwargs.get("telemetry_schema_version", ""),
        })

    def subagent_stop(parent_session_id=None, child_summary=None,
                      child_status=None, duration_ms=0, **kwargs):
        if not parent_session_id:
            return
        _fire("subagent_stop", {
            "event": "subagent_stop",
            "session_id": parent_session_id,
            "child_summary": child_summary or "",
            "child_status": child_status or "",
            "duration_ms": int(duration_ms) if duration_ms is not None else 0,
            # cwd required (same reason as the other event callbacks).
            "cwd": os.getcwd(),
            "timestamp": time.time(),
            "telemetry_schema_version": kwargs.get("telemetry_schema_version", ""),
        })

    def pre_tool_call(tool_name=None, args=None, task_id=None, session_id=None,
                      tool_call_id=None, **kwargs):
        if not tool_name:
            return None
        verdict = _gate("pre_tool_call", "tool_gate", {
            "host": "hermes",
            "event": "pre_tool_call",
            "session_id": session_id or "",
            "cwd": os.getcwd(),
            "pid": os.getpid(),
            "tool_name": tool_name,
            "tool_input": _safe_json(args) or {},
            "call_id": tool_call_id or "",
        })
        decision = str(verdict.get("decision") or "").lower()
        reason = verdict.get("reason") or "Blocked by the SuperBased Observer guard."
        if decision in ("deny", "block"):
            return {"action": "block", "message": reason}
        if decision == "ask":
            return {"action": "approve", "message": reason}
        return None

    ctx.register_hook("on_session_start", on_session_start)
    ctx.register_hook("on_session_end", on_session_end)
    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("post_api_request", post_api_request)
    ctx.register_hook("subagent_stop", subagent_stop)
    ctx.register_hook("pre_tool_call", pre_tool_call)
