"""The setup planner (plan 3.5): pure decision tables, no I/O.

Every decision ``setup`` makes is a row here, walked top-down; the CLI only
executes the result. The inputs are plain facts, so each table is tested
without a network (one case per row):

- ``PHASES``: which phases run (``--key-only`` keeps the destination, the
  credential or enable step and the hello, and drops the Python detection,
  the install and the init line: Go and Java projects get the key file);
- ``DESTINATION_ROWS``: the destination plan from the flags and the
  machine's state (the plan's five rows, each flag, and the reuse of a valid
  SDK-held file);
- ``POLL_ROWS``, ``REDEEM_ROWS``, ``CREATE_ROWS``: each answer of the device
  flow (3.6) to a state and an exit code;
- the exit codes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

# --- exit codes (plan 3.5) ------------------------------------------------------------

EXIT_DONE = 0  # the hello trace arrived
EXIT_UNEXPECTED = 1  # a bug (the stack on stderr only, never a secret)
EXIT_WAITING = 2  # waiting for a person: declined, expired, not clicked, a y/N said no; a re-run continues
EXIT_REFUSED = 3  # refused: the plan, not a member, no member keys, the month used, a key not accepted
EXIT_ENVIRONMENT = 4  # no supported language, the package manager failed, a self-hosted org, rate limited, bad flags
EXIT_NOT_SEEN = 5  # sent, not seen within the wait (the link is still printed)
EXIT_USAGE = EXIT_ENVIRONMENT  # setup-cases.json: two destination flags exit 4

# --- phases ---------------------------------------------------------------------------

DETECT = "detect"
DESTINATION = "destination"
INSTALL = "install"
CREDENTIAL = "credential"  # the device sign-in (online) or the enable (local)
HELLO = "hello"
NEXT_STEPS = "next_steps"

# (phase, runs under --key-only)
PHASES: Tuple[Tuple[str, bool], ...] = (
    (DETECT, False),
    (DESTINATION, True),
    (INSTALL, False),
    (CREDENTIAL, True),
    (HELLO, True),
    (NEXT_STEPS, False),
)


def phases(key_only: bool) -> Tuple[str, ...]:
    """The phases a run executes, in order."""
    return tuple(p for p, in_key_only in PHASES if in_key_only or not key_only)


# --- the destination plan --------------------------------------------------------------

LOCAL = "local"
ONLINE = "online"
BOTH = "both"
HELD = "held"  # the valid SDK-held file's own destination
HELD_OR_ONLINE = "held_or_online"  # a replace: the file's destination, else online
ASK = "ask"  # ask on the terminal: this computer only, or also online
ASK_ONLINE = "ask_online"  # ask on the terminal: Observer is not running; set up online instead?

# Stops (the run ends before the credential phase, with the exit code).
STOP_START_OBSERVER = "start_observer"
STOP_INSTALL_OBSERVER = "install_observer"
STOP_NOT_RUNNING = "observer_not_running_no_terminal"
STOP_NOT_RUNNING_DECLINED = "observer_not_running_declined"

# Notes (printed beside the plan).
NOTE_ALREADY_SIGNED_IN = "already_signed_in"
NOTE_ADD_ONLINE = "add_online"
NOTE_ONLINE_ALTERNATIVE = "online_alternative"
NOTE_OBSERVER_NOT_RUNNING = "observer_not_running"
NOTE_NO_MACHINE = "no_machine"
NOTE_REUSE = "reuse_key_file"
NOTE_ONLINE_ONLY_ENV = "online_only_env"


@dataclass(frozen=True)
class Facts:
    """The planner's inputs. ``flag``: ``""``, ``local``, ``online`` or
    ``both``. ``answered``: this machine's Observer answered discovery;
    ``signed_in`` and ``apps_on`` come from that answer. ``on_path``:
    ``observer`` is on PATH. ``held``: a usable SDK-held key file exists.
    ``terminal``: a person can answer a question here."""

    flag: str = ""
    answered: bool = False
    signed_in: bool = False
    apps_on: bool = False
    on_path: bool = False
    held: bool = False
    replace: bool = False
    terminal: bool = False


@dataclass(frozen=True)
class Choice:
    """The planner's answer: the destination (or ``held``, ``ask``), whether
    the device sign-in runs, whether the local enable is needed, and a stop
    or notes."""

    row: str
    destination: str = ""
    device_flow: bool = False
    enable: bool = False
    machine_key: bool = False  # the machine's own sign-in key serves online (R10)
    stop: str = ""
    exit_code: int = EXIT_DONE
    notes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Row:
    """One destination row: ``when`` maps a Facts field to the value (or the
    tuple of values) it must have; absent fields match anything."""

    id: str
    when: Mapping[str, Any]
    choice: Choice = field(default_factory=lambda: Choice(row=""))


_ANY_ONLINE_FLAG = ("", ONLINE, BOTH)

DESTINATION_ROWS: Tuple[Row, ...] = (
    # --local: this computer only.
    Row("local_on", {"flag": LOCAL, "answered": True, "apps_on": True}, Choice("local_on", LOCAL)),
    Row("local_off", {"flag": LOCAL, "answered": True, "apps_on": False}, Choice("local_off", LOCAL, enable=True)),
    Row(
        "local_not_running",
        {"flag": LOCAL, "answered": False, "on_path": True},
        Choice("local_not_running", stop=STOP_START_OBSERVER, exit_code=EXIT_ENVIRONMENT),
    ),
    Row(
        "local_no_observer",
        {"flag": LOCAL, "answered": False, "on_path": False},
        Choice("local_no_observer", stop=STOP_INSTALL_OBSERVER, exit_code=EXIT_ENVIRONMENT),
    ),
    # Row 1: Observer is signed in. Its own key serves online; no device
    # flow, no SDK-held file (R10).
    Row(
        "signed_in_online_flag",
        {"flag": ONLINE, "answered": True, "signed_in": True},
        Choice("signed_in_online_flag", ONLINE, machine_key=True, notes=(NOTE_ALREADY_SIGNED_IN, NOTE_ONLINE_ONLY_ENV)),
    ),
    Row(
        "signed_in_both",
        {"flag": ("", BOTH), "answered": True, "signed_in": True, "apps_on": True},
        Choice("signed_in_both", BOTH, machine_key=True, notes=(NOTE_ALREADY_SIGNED_IN,)),
    ),
    Row(
        "signed_in_both_off",
        {"flag": BOTH, "answered": True, "signed_in": True, "apps_on": False},
        Choice("signed_in_both_off", BOTH, enable=True, machine_key=True, notes=(NOTE_ALREADY_SIGNED_IN,)),
    ),
    Row(
        "signed_in_online",
        {"flag": "", "answered": True, "signed_in": True, "apps_on": False},
        Choice("signed_in_online", ONLINE, machine_key=True, notes=(NOTE_ALREADY_SIGNED_IN,)),
    ),
    # --online.
    Row("online_reuse", {"flag": ONLINE, "held": True, "replace": False}, Choice("online_reuse", ONLINE, notes=(NOTE_REUSE,))),
    Row("online", {"flag": ONLINE}, Choice("online", ONLINE, device_flow=True)),
    # --both.
    Row(
        "both_reuse_on",
        {"flag": BOTH, "held": True, "replace": False, "answered": True, "apps_on": True},
        Choice("both_reuse_on", BOTH, notes=(NOTE_REUSE,)),
    ),
    Row(
        "both_reuse_off",
        {"flag": BOTH, "held": True, "replace": False, "answered": True, "apps_on": False},
        Choice("both_reuse_off", BOTH, enable=True, notes=(NOTE_REUSE,)),
    ),
    Row(
        "both_reuse_no_machine",
        {"flag": BOTH, "held": True, "replace": False, "answered": False},
        Choice("both_reuse_no_machine", BOTH, notes=(NOTE_REUSE, NOTE_NO_MACHINE)),
    ),
    Row("both_on", {"flag": BOTH, "answered": True, "apps_on": True}, Choice("both_on", BOTH, device_flow=True)),
    Row("both_off", {"flag": BOTH, "answered": True, "apps_on": False}, Choice("both_off", BOTH, device_flow=True, enable=True)),
    Row("both_no_machine", {"flag": BOTH, "answered": False}, Choice("both_no_machine", BOTH, device_flow=True, notes=(NOTE_NO_MACHINE,))),
    # No flag: a valid SDK-held file is used again (no device flow) unless
    # --replace asks for a new key.
    Row("reuse", {"flag": "", "held": True, "replace": False}, Choice("reuse", HELD, notes=(NOTE_REUSE,))),
    Row("replace", {"flag": "", "replace": True}, Choice("replace", HELD_OR_ONLINE, device_flow=True)),
    # Rows 2 to 5 of the plan's table.
    Row("machine_on_ask", {"flag": "", "answered": True, "apps_on": True, "terminal": True}, Choice("machine_on_ask", ASK)),
    Row(
        "machine_on",
        {"flag": "", "answered": True, "apps_on": True, "terminal": False},
        Choice("machine_on", LOCAL, notes=(NOTE_ADD_ONLINE,)),
    ),
    Row(
        "machine_off",
        {"flag": "", "answered": True, "apps_on": False},
        Choice("machine_off", LOCAL, enable=True, notes=(NOTE_ONLINE_ALTERNATIVE,)),
    ),
    Row(
        "not_running_ask",
        {"flag": "", "answered": False, "on_path": True, "terminal": True},
        Choice("not_running_ask", ASK_ONLINE),
    ),
    Row(
        "not_running",
        {"flag": "", "answered": False, "on_path": True, "terminal": False},
        Choice("not_running", stop=STOP_NOT_RUNNING, exit_code=EXIT_ENVIRONMENT),
    ),
    Row("no_observer", {"flag": "", "answered": False, "on_path": False}, Choice("no_observer", ONLINE, device_flow=True)),
)


# Whether a key file counts as held (Facts.held), walked top-down: (file
# state, usable (a key and its address), expired) -> held. An expired or
# refused file is treated like a missing one, so a plain re-run of setup (or
# setup --key-only, the readers' fix text) gets a new key with no --replace;
# a valid one skips the device flow.
HELD_ROWS: Tuple[Tuple[str, Optional[bool], Optional[bool], bool], ...] = (
    ("valid", True, False, True),
    ("valid", True, True, False),
    ("valid", False, None, False),
    ("refused", None, None, False),
    ("absent", None, None, False),
)


def held(state: str, usable: bool, expired: bool) -> bool:
    """Facts.held from the key file's read: only a valid, usable, unexpired
    file is held."""
    for st, use, exp, out in HELD_ROWS:
        if st == state and (use is None or use == usable) and (exp is None or exp == expired):
            return out
    return False


def _matches(when: Mapping[str, Any], facts: Facts) -> bool:
    for name, want in when.items():
        have = getattr(facts, name)
        if isinstance(want, tuple):
            if have not in want:
                return False
        elif have != want:
            return False
    return True


def choose(facts: Facts) -> Choice:
    """The first destination row that matches ``facts``."""
    for row in DESTINATION_ROWS:
        if _matches(row.when, facts):
            return row.choice
    raise ValueError(f"no destination row for {facts!r}")  # a table gap is a bug; the tests cover every row


def after_ask(answer: str) -> Choice:
    """Row 2's question: ``local`` (the default) or ``both`` (also online:
    the device sign-in runs)."""
    if answer == BOTH:
        return Choice("machine_on_ask_both", BOTH, device_flow=True)
    return Choice("machine_on_ask_local", LOCAL, notes=(NOTE_ADD_ONLINE,))


def after_ask_online(answer: str) -> Choice:
    """Row 4's question (Observer installed, not running): ``online`` sets
    up online; anything else stops with how to start Observer."""
    if answer == ONLINE:
        return Choice("not_running_online", ONLINE, device_flow=True)
    return Choice("not_running_declined", stop=STOP_NOT_RUNNING_DECLINED, exit_code=EXIT_ENVIRONMENT)


def stop_message(stop: str, windows: bool = False) -> str:
    """What setup says when the destination phase stops it (the installer
    line for the person when Observer is not installed, ruling R8)."""
    msg = MESSAGES[stop]
    if stop == STOP_INSTALL_OBSERVER:
        msg += "\n    " + (INSTALL_OBSERVER_LINE_WINDOWS if windows else INSTALL_OBSERVER_LINE)
    return msg


def read_answer(question: str, raw: str) -> str:
    """A person's typed answer to ``question`` (``ASK`` or ``ASK_ONLINE``)
    as the planner's word."""
    w = raw.strip().lower()
    if question == ASK:
        return BOTH if w in ("both", "b", "online", "o", "also") else LOCAL
    return ONLINE if w in ("online", "o", "y", "yes") else ""


# --- the plan as setup-cases.json destination_plan states it ----------------------------

CRED_DEVICE_FLOW = "device_flow"
CRED_MACHINE = "machine"
CRED_SDK_FILE = "sdk_file"
CRED_NONE = "none"


@dataclass(frozen=True)
class Outcome:
    """What a run does after the destination phase: ``plan`` (None when it
    stops), the credential, the approval the person gives, whether the key
    file is written, and the exit when it stops."""

    plan: Optional[str]
    credential: str
    approval: str
    writes_file: bool
    exit: Optional[int] = None
    message: str = ""


def outcome(facts: Facts, answer: Optional[str] = None, held_destination: str = "") -> Outcome:
    """The destination phase from facts and the one answer a person gives
    (row 2's or row 4's question, or row 3's y/N), as a pure function."""
    choice = choose(facts)
    asked = False
    if choice.destination == ASK:
        asked = True
        choice = after_ask(read_answer(ASK, answer or ""))
    elif choice.destination == ASK_ONLINE:
        asked = True
        choice = after_ask_online(read_answer(ASK_ONLINE, answer or ""))
    if choice.stop:
        return Outcome(None, CRED_NONE, "ask" if asked else "none", False, choice.exit_code, stop_message(choice.stop))
    dest = choice.destination
    if dest == HELD:
        dest = held_destination or ONLINE
    elif dest == HELD_OR_ONLINE:
        dest = held_destination or ONLINE
    if choice.machine_key:
        cred = CRED_MACHINE
    elif choice.device_flow:
        cred = CRED_DEVICE_FLOW
    elif NOTE_REUSE in choice.notes:
        cred = CRED_SDK_FILE
    else:
        cred = CRED_NONE
    if choice.device_flow and choice.enable:
        approval = "enable_and_browser"
    elif choice.device_flow:
        approval = "browser"
    elif choice.enable:
        approval = "enable_prompt" if facts.terminal else "enable_browser"
    elif asked:
        approval = "ask"
    else:
        approval = "none"
    if choice.enable and facts.terminal and (answer or "").strip().lower() not in ("y", "yes"):
        return Outcome(None, cred, approval, False, EXIT_WAITING, MESSAGES["enable_declined"])
    notes = " ".join(MESSAGES[n] for n in choice.notes)
    return Outcome(dest, cred, approval, choice.device_flow, None, notes)


# --- the device flow's answers (3.6) ------------------------------------------------------

CONTINUE = "continue"  # keep polling
WAIT = "wait"  # keep polling after Retry-After
REDEEM = "redeem"  # the grant is here: redeem it
STOP = "stop"  # the run ends with the row's exit code


@dataclass(frozen=True)
class Answer:
    """One HTTP answer as the tables see it."""

    status: int = 0  # 0: no answer (transport)
    code: str = ""  # the body's error code (create and poll: ``code``; redeem: ``error``)
    state: str = ""  # poll: the body's ``status``
    ready: bool = False  # poll: target.ready
    grant: bool = False  # poll: a key_grant is present
    plan_refusal: bool = False  # redeem 201: the month's allowance is used
    reason: str = ""  # redeem key_grant_refused: the closed reason


@dataclass(frozen=True)
class Step:
    action: str
    exit_code: int = EXIT_DONE
    message: str = ""  # a key into MESSAGES ("" when the server's own message is printed)


# (status or None, code or None, state or None, extra predicate, step)
_Rule = Tuple[Optional[int], Optional[str], Optional[str], Optional[str], Step]

POLL_ROWS: Tuple[_Rule, ...] = (
    (200, None, "pending", None, Step(CONTINUE)),
    (200, None, "approved", "grant_ready", Step(REDEEM)),
    (200, None, "approved", None, Step(CONTINUE, message="approved_not_ready")),
    (200, None, "declined", None, Step(STOP, EXIT_WAITING, "declined")),
    (200, None, "expired", None, Step(STOP, EXIT_WAITING, "expired")),
    (409, "key_grant_already_delivered", None, None, Step(STOP, EXIT_WAITING, "already_delivered")),
    (409, "key_grant_window_closed", None, None, Step(STOP, EXIT_WAITING, "window_closed")),
    (429, None, None, None, Step(WAIT)),
    (401, None, None, None, Step(STOP, EXIT_WAITING, "run_again")),
    (404, None, None, None, Step(STOP, EXIT_WAITING, "run_again")),
    (409, None, None, None, Step(STOP, EXIT_WAITING, "run_again")),
    (0, None, None, None, Step(WAIT)),  # no answer: try again (bounded by the request's life)
    (None, None, None, "server_error", Step(WAIT)),
    (None, None, None, None, Step(STOP, EXIT_ENVIRONMENT, "unexpected")),
)

REDEEM_ROWS: Tuple[_Rule, ...] = (
    (201, None, None, "plan_refusal", Step(STOP, EXIT_REFUSED, "month_used")),
    (201, None, None, None, Step(REDEEM)),
    (403, "plan_required", None, None, Step(STOP, EXIT_REFUSED, "plan_required")),
    (403, "key_grant_refused", None, "membership", Step(STOP, EXIT_REFUSED)),
    (403, "key_grant_refused", None, None, Step(STOP, EXIT_WAITING, "run_again")),
    (403, "key_grant_not_accepted", None, None, Step(STOP, EXIT_REFUSED)),
    (404, "not_supported", None, None, Step(STOP, EXIT_REFUSED)),
    (410, "key_grant_used", None, None, Step(STOP, EXIT_WAITING)),
    (429, None, None, None, Step(WAIT)),
    (0, None, None, None, Step(WAIT)),
    (None, None, None, "server_error", Step(WAIT)),
    (None, None, None, None, Step(STOP, EXIT_ENVIRONMENT, "unexpected")),
)

CREATE_ROWS: Tuple[_Rule, ...] = (
    (201, None, None, None, Step(CONTINUE)),
    (429, None, None, None, Step(STOP, EXIT_ENVIRONMENT)),
    (400, "invalid_purpose", None, None, Step(STOP, EXIT_ENVIRONMENT)),
    (0, None, None, None, Step(STOP, EXIT_ENVIRONMENT, "no_network")),
    (None, None, None, None, Step(STOP, EXIT_ENVIRONMENT)),
)

# Grant refusals about who the person is: a re-run cannot help (exit 3).
MEMBERSHIP_REASONS = frozenset({"not_a_member", "member_inactive", "wrong_org"})

_EXTRA = {
    "grant_ready": lambda a: a.grant and a.ready,
    "plan_refusal": lambda a: a.plan_refusal,
    "server_error": lambda a: a.status >= 500,
    # A refusal about who the person is (a re-run cannot help) against one
    # about the grant itself (expired, used, a bad signature: a re-run can).
    "membership": lambda a: a.reason in MEMBERSHIP_REASONS,
}



def step(rows: Tuple[_Rule, ...], answer: Answer) -> Step:
    """The first row of ``rows`` that matches ``answer``."""
    for status, code, state, extra, out in rows:
        if status is not None and answer.status != status:
            continue
        if code is not None and answer.code != code:
            continue
        if state is not None and answer.state != state:
            continue
        if extra is not None and not _EXTRA[extra](answer):
            continue
        return out
    return Step(STOP, EXIT_ENVIRONMENT, "unexpected")


# --- the messages setup writes itself (never a plan name or number of its own) -------------

MESSAGES: Dict[str, str] = {
    "approved_not_ready": "Approved. Your dashboard is being set up; this takes a few seconds.",
    "declined": "The request was declined in the browser. Nothing was changed; run setup again to start over.",
    "expired": "The approval expired before it was approved; run setup again.",
    "already_delivered": "This approval was already used; run setup again.",
    "window_closed": "Your dashboard took longer than the approval lasts; run setup again.",
    "run_again": "This sign-in request is no longer valid; run setup again.",
    "unexpected": "The server gave an answer setup does not understand.",
    "no_network": "Could not reach the server.",
    "enable_declined": "AI Apps stays off. Turn it on later with `observer apps on`, or run setup --online to send traces to your online dashboard instead.",
    "plan_required": "",
    "month_used": "",
    NOTE_ALREADY_SIGNED_IN: "Observer is already signed in, so your apps use its key for your online dashboard; setup stores no key of its own.",
    NOTE_ADD_ONLINE: "Traces go to this computer. To also send them to your online dashboard, run setup --online.",
    NOTE_ONLINE_ALTERNATIVE: "Or send traces to your online dashboard instead: run setup --online.",
    NOTE_OBSERVER_NOT_RUNNING: "Observer is installed but not running; start it with `observer start` to keep traces on this computer. Setting up online instead.",
    NOTE_NO_MACHINE: "Observer is not running on this computer, so only the online copy is sent until it runs.",
    NOTE_REUSE: "Using the SDK key setup stored before (setup --online --replace gets a new one).",
    NOTE_ONLINE_ONLY_ENV: (
        "Apps started here still follow this computer's default destination; set SUPERBASED_DESTINATION=online "
        "where the app runs to send its traces online only."
    ),
    STOP_START_OBSERVER: "Observer is installed but not running. Start it with `observer start`, then run setup --local again.",
    STOP_NOT_RUNNING: (
        "Observer is installed but not running. To keep traces on this computer, start it with `observer start` "
        "and run setup again; to send them to your online dashboard instead, run setup --online."
    ),
    STOP_NOT_RUNNING_DECLINED: "Start Observer with `observer start` and run setup again (or run setup --online).",
    STOP_INSTALL_OBSERVER: "Observer is not installed on this computer. To keep traces here, install it with the line below, then run setup --local again (or run setup without --local to send traces to your online dashboard).",
}

# The installer line for the person (ruling R8: setup never installs
# Observer itself; scripts/install.sh, F13).
INSTALL_OBSERVER_LINE = "curl -fsSL https://superbased.app/install.sh | sh -s -- --apps --service"
INSTALL_OBSERVER_LINE_WINDOWS = (
    "curl.exe -fsSLo install.ps1 https://superbased.app/install.ps1 && "
    "powershell -ExecutionPolicy Bypass -File install.ps1 -Apps"
)
