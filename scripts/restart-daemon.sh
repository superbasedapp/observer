#!/usr/bin/env bash
# restart-daemon.sh — safely restart the Observer daemon when AI clients
# route their API traffic through the proxy (ANTHROPIC_BASE_URL → :PORT).
#
# WHY THIS EXISTS (2026-06-20 burn): the daemon IS the proxy. If you kill
# it while a live Claude Code / Codex session points ANTHROPIC_BASE_URL /
# codex base_url at :PORT, that session's next API call dies with
# ConnectionRefused — including the very session running the restart.
# The safe order, per the operator's rule, is:
#
#     route OFF  →  restart daemon  →  route ON
#
# This script does the whole thing as ONE atomic run (sub-second proxy
# downtime), so no inter-turn API call lands in the down-window, and it
# flips the claude-code route off first as belt-and-suspenders.
#
# SESSIONS LAUNCHED BY THE DAEMON (2026-09-02 burn): a session started
# through a launcher (`observer claude`, `observer codex`, a dashboard
# terminal) is a process-tree DESCENDANT of the daemon. SIGTERM to the
# daemon then takes THIS script down mid-relaunch, leaving `db.Open: ping:
# context canceled` in the log and the route restored onto a dead port. So
# the script DETECTS that case (ancestry walk of the :PORT listener pid +
# the OBSERVER_DAEMON_CHILD marker) and REFUSES by default: the daemon owns
# the pty of every dashboard terminal / launcher session (internal/termsession),
# so stopping it kills that whole session — Claude Code included — even though
# a detached re-exec of this script survives and completes the restart
# (seen 2026-09-03: the relaunch succeeded, the operator's session was gone).
# `--detach` opts IN to that trade (setsid nohup … --detached; the restart
# completes, THIS session dies); `--detached` is the internal re-entry marker.
#
# Usage:
#   scripts/restart-daemon.sh                       # plain safe restart
#   scripts/restart-daemon.sh --build               # `go build` the binary first, then restart
#   scripts/restart-daemon.sh --compression on      # enable conversation compression, then restart
#   scripts/restart-daemon.sh --compression off     # disable it, then restart
#   scripts/restart-daemon.sh --no-route-toggle     # don't touch settings.json (rely on atomic relaunch only)
#   scripts/restart-daemon.sh --detach              # daemon-launched session: restart detached anyway (THIS session will be killed)
#   scripts/restart-daemon.sh --no-detach           # (default) refuse when daemon-launched instead of killing the session
#   scripts/restart-daemon.sh --dry-run             # print the plan (incl. the detach decision) and exit
#   scripts/restart-daemon.sh --port 8820
#
# Idempotent and conservative: backs up every file it edits, never uses
# `pgrep observer` (that self-matches the caller's argv), finds the daemon
# strictly by the listening :PORT socket, and restores the route even on
# failure paths.
set -euo pipefail

# Preserve the ORIGINAL argv verbatim so the detached re-exec re-runs the
# exact same invocation (minus the one-shot --detached marker we prepend).
ORIG_ARGS=("$@")

PORT=8820
COMPRESSION=""          # "", "on", or "off"
ROUTE_TOGGLE=1
BUILD=0
DRY_RUN=0
NO_DETACH=1
DETACHED=0
SETTINGS="${HOME}/.claude/settings.json"
CONFIG="${OBSERVER_CONFIG:-${HOME}/.observer/config.toml}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${REPO_ROOT}/bin/observer"
LOG="/tmp/obs.log"
DETACH_LOG="/tmp/restart-daemon.log"

usage() { sed -n '2,45p' "$0"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --compression) COMPRESSION="${2:-}"; shift 2 ;;
    --no-route-toggle) ROUTE_TOGGLE=0; shift ;;
    --build) BUILD=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --no-detach) NO_DETACH=1; shift ;;
    --detach) NO_DETACH=0; shift ;;
    --detached) DETACHED=1; shift ;;   # internal: the detached re-exec sets this
    --port) PORT="${2:-8820}"; shift 2 ;;
    --bin) BIN="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

log() { printf '[restart-daemon] %s\n' "$*"; }

daemon_pid() { ss -ltnp 2>/dev/null | grep ":${PORT} " | grep -oP 'pid=\K[0-9]+' | head -1; }
port_up()    { ss -ltn 2>/dev/null | grep -q ":${PORT} "; }

# proxy_ready reports whether the proxy is serving — it prefers the
# unauthenticated liveness endpoint (internal/proxy serveHealthz: 200,
# no auth, no DB, no upstream) so "ready" means the HTTP handler answers,
# not merely that the socket is bound. Falls back to the socket check when
# curl is absent.
proxy_ready() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 2 "http://127.0.0.1:${PORT}/-/healthz" >/dev/null 2>&1
    return
  fi
  port_up
}

# proc_ppid <pid> → parent pid (empty + non-zero on failure). Pure bash: it
# strips through the LAST ") " of /proc/<pid>/stat so a comm containing
# spaces/parens can't shift the field, then takes the ppid field. Avoids a
# sed|awk pipe (SIGPIPE-safe under `set -o pipefail`).
proc_ppid() {
  local stat
  stat="$(cat /proc/"$1"/stat 2>/dev/null)" || return 1
  [[ -n "$stat" ]] || return 1
  stat="${stat##*) }"
  # shellcheck disable=SC2086  # deliberate word-split of the stat fields
  set -- $stat
  printf '%s' "${2:-}"
}

# pid_is_descendant <pid> <ancestor> → 0 if <ancestor> appears on <pid>'s
# ppid chain (bounded walk, cycle/PID-1 guarded).
pid_is_descendant() {
  local cur="$1" ancestor="$2" guard=0
  [[ -n "$ancestor" && -n "$cur" ]] || return 1
  while [[ -n "$cur" && "$cur" != "0" && "$cur" != "1" && $guard -lt 64 ]]; do
    [[ "$cur" == "$ancestor" ]] && return 0
    cur="$(proc_ppid "$cur")" || return 1
    guard=$((guard + 1))
  done
  return 1
}

# script_is_daemon_launched reports whether THIS script is running inside a
# session the daemon spawned — so stopping the daemon would take it down.
# Primary signal: our own ppid chain includes the :PORT listener pid.
# Fallback: the infallible OBSERVER_DAEMON_CHILD marker the daemon sets on
# every child (survives the OOB-env scrub; see cmd/observer/terminal_launch.go).
script_is_daemon_launched() {
  local dpid="$1"
  if [[ -n "$dpid" ]] && pid_is_descendant "$$" "$dpid"; then
    return 0
  fi
  [[ "${OBSERVER_DAEMON_CHILD:-}" == "1" ]]
}

DPID="$(daemon_pid || true)"
DAEMON_LAUNCHED=0
if script_is_daemon_launched "$DPID"; then DAEMON_LAUNCHED=1; fi

# --- 0. dry-run: print the plan (incl. the detach decision) and exit ---
if [[ "$DRY_RUN" -eq 1 ]]; then
  log "DRY RUN — no changes will be made"
  log "  port                : $PORT"
  log "  binary              : $BIN ($([[ -x "$BIN" ]] && echo executable || echo MISSING))"
  log "  build first (--build): $([[ "$BUILD" -eq 1 ]] && echo yes || echo no)"
  log "  compression flip    : ${COMPRESSION:-<none>}"
  log "  route toggle        : $([[ "$ROUTE_TOGGLE" -eq 1 ]] && echo on || echo off) ($SETTINGS)"
  log "  daemon pid on :$PORT : ${DPID:-<none listening>}"
  log "  this script's pid   : $$ (OBSERVER_DAEMON_CHILD=${OBSERVER_DAEMON_CHILD:-<unset>})"
  log "  daemon-launched?    : $([[ "$DAEMON_LAUNCHED" -eq 1 ]] && echo YES || echo no)"
  if [[ "$DAEMON_LAUNCHED" -eq 1 && "$NO_DETACH" -eq 0 && "$DETACHED" -eq 0 ]]; then
    log "  plan                : would re-exec DETACHED (setsid nohup $0 --detached ${ORIG_ARGS[*]}) → log $DETACH_LOG — and THIS session would be killed with the daemon"
  elif [[ "$DAEMON_LAUNCHED" -eq 1 && "$DETACHED" -eq 0 ]]; then
    log "  plan                : would REFUSE (daemon-launched session; pass --detach to accept losing this session, or run from an outside shell)"
  else
    log "  plan                : would run in-place (route off → stop → checkpoint → relaunch → verify → route on)"
  fi
  exit 0
fi

# --- 0b. self-detach when daemon-launched (so SIGTERM can't kill this run) ---
if [[ "$DAEMON_LAUNCHED" -eq 1 && "$DETACHED" -eq 0 ]]; then
  if [[ "$NO_DETACH" -eq 1 ]]; then
    echo "ERROR: this session is a descendant of the daemon (pid=${DPID:-?}). The daemon owns" >&2
    echo "       this session's pty, so stopping it KILLS this session (the restart itself" >&2
    echo "       would still complete when re-exec'd detached). Run the restart from a shell" >&2
    echo "       the daemon did not spawn (plain terminal / \`observer claude\` outside the" >&2
    echo "       dashboard), or pass --detach to accept losing this session." >&2
    exit 1
  fi
  log "daemon-launched session detected (pid=${DPID:-?}); --detach given — re-executing DETACHED. This session WILL be killed with the daemon; the restart completes on its own."
  setsid nohup "$0" --detached "${ORIG_ARGS[@]}" >"$DETACH_LOG" 2>&1 </dev/null &
  log "detached restart is running in the background — follow it with:  tail -f $DETACH_LOG"
  exit 0
fi

# --- 0c. optional rebuild BEFORE anything else (a compile error aborts clean) ---
if [[ "$BUILD" -eq 1 ]]; then
  log "building: go build -o $BIN ./cmd/observer  (in $REPO_ROOT)"
  ( cd "$REPO_ROOT" && go build -o "$BIN" ./cmd/observer ) || { echo "ERROR: build failed — not restarting" >&2; exit 1; }
  log "build OK"
fi

[[ -x "$BIN" ]] || { echo "ERROR: observer binary not found/executable: $BIN (run 'make build' or pass --build)" >&2; exit 1; }

# --- 1. optional compression config flip (no effect until the restart) ---
if [[ -n "$COMPRESSION" ]]; then
  case "$COMPRESSION" in on) want=true ;; off) want=false ;; *) echo "ERROR: --compression must be on|off" >&2; exit 2 ;; esac
  [[ -f "$CONFIG" ]] || { echo "ERROR: config not found: $CONFIG" >&2; exit 1; }
  cp "$CONFIG" "${CONFIG}.bak.restart"
  # Flip ONLY the [compression.conversation].enabled key — i.e. the first
  # `enabled =` line after that header and before the next subsection.
  python3 - "$CONFIG" "$want" <<'PY'
import re, sys
path, want = sys.argv[1], sys.argv[2]
lines = open(path).read().splitlines(keepends=True)
out, in_sec, done = [], False, False
for ln in lines:
    s = ln.strip()
    if s.startswith('[compression.conversation]'):
        in_sec = True
    elif s.startswith('[') and s != '[compression.conversation]':
        in_sec = False
    if in_sec and not done and re.match(r'enabled\s*=', s):
        ln = re.sub(r'(enabled\s*=\s*)(true|false)', r'\g<1>'+want, ln)
        done = True
    out.append(ln)
open(path, 'w').write(''.join(out))
print('conversation.enabled ->', want, '(changed)' if done else '(KEY NOT FOUND)')
PY
  log "compression set to '$COMPRESSION' in $CONFIG (backup: ${CONFIG}.bak.restart)"
fi

# --- 2. route OFF (save current claude-code ANTHROPIC_BASE_URL, remove it) ---
SAVED_ROUTE=""
restore_route() {
  [[ "$ROUTE_TOGGLE" -eq 1 ]] || return 0
  [[ -n "$SAVED_ROUTE" ]] || { log "no prior route to restore (was unset)"; return 0; }
  python3 - "$SETTINGS" "$SAVED_ROUTE" <<'PY'
import json, sys
path, url = sys.argv[1], sys.argv[2]
d = json.load(open(path)); d.setdefault('env', {})['ANTHROPIC_BASE_URL'] = url
json.dump(d, open(path, 'w'), indent=2)
PY
  log "route RESTORED: ANTHROPIC_BASE_URL=$SAVED_ROUTE"
}
trap 'restore_route' EXIT

if [[ "$ROUTE_TOGGLE" -eq 1 && -f "$SETTINGS" ]]; then
  cp "$SETTINGS" "${SETTINGS}.bak.restart"
  SAVED_ROUTE="$(python3 - "$SETTINGS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); print(d.get('env', {}).get('ANTHROPIC_BASE_URL', ''))
PY
)"
  if [[ -n "$SAVED_ROUTE" ]]; then
    python3 - "$SETTINGS" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d.get('env', {}).pop('ANTHROPIC_BASE_URL', None)
json.dump(d, open(sys.argv[1], 'w'), indent=2)
PY
    log "route OFF: removed ANTHROPIC_BASE_URL (was $SAVED_ROUTE; backup ${SETTINGS}.bak.restart)"
  else
    log "route already unset in settings.json"
  fi
fi

# --- 3. stop daemon (graceful, by :PORT socket only) ---
PID="$(daemon_pid || true)"
if [[ -n "$PID" ]]; then
  log "stopping daemon pid=$PID on :$PORT (SIGTERM)"
  kill -TERM "$PID" 2>/dev/null || true
  for _ in $(seq 1 40); do port_up || break; sleep 0.25; done
  if port_up; then log "WARN: :$PORT still listening after 10s; aborting before relaunch"; exit 1; fi
  log "daemon stopped"
else
  log "no daemon listening on :$PORT (will just start one)"
fi

# --- 3b. checkpoint WAL while down (best-effort) ---
DB="$(dirname "$CONFIG")/observer.db"
if command -v sqlite3 >/dev/null && [[ -f "$DB" ]]; then
  sqlite3 "$DB" "PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
  log "WAL checkpointed ($DB)"
fi

# --- 4. relaunch + verify up ---
# Readiness window is generous (45s): a cold start runs pending DB
# migrations + upstream prewarms before the proxy listener binds, which can
# push past a tighter window and trip a false ERROR (observed 2026-06-29 on
# the migration-053 + prewarm start). Readiness is the /-/healthz probe
# (proxy_ready), so "up" means the HTTP handler answers, not just a bound socket.
log "relaunching: $BIN start --no-open  (log: $LOG)"
setsid nohup "$BIN" start --no-open >"$LOG" 2>&1 </dev/null &
for _ in $(seq 1 180); do proxy_ready && break; sleep 0.25; done
if ! proxy_ready; then
  log "ERROR: daemon did not come up on :$PORT within 45s — see $LOG"
  tail -n 20 "$LOG" || true
  exit 1
fi
NEWPID="$(daemon_pid || true)"
log "daemon UP on :$PORT (pid=$NEWPID)"

# --- 4b. post-relaunch sanity: the new daemon must be a FRESH process ---
# (a) it must NOT be a descendant of the old daemon's process tree — a
#     genuine relaunch is reparented to init by setsid; a NEWPID still under
#     the old $PID means we never actually restarted.
if [[ -n "$PID" && -n "$NEWPID" ]] && pid_is_descendant "$NEWPID" "$PID"; then
  log "ERROR: new pid=$NEWPID is still a child of the old daemon tree (pid=$PID) — restart did not take"
  exit 1
fi
# (b) the daemon's own log must not end on a fatal `Error:` line (cobra prints
#     `Error: …` on a failed start, e.g. `db.Open: ping: context canceled`).
LAST_LOG_LINE="$(tail -n 1 "$LOG" 2>/dev/null || true)"
if [[ "$LAST_LOG_LINE" == Error:* ]]; then
  log "ERROR: $LOG ends on a fatal line: $LAST_LOG_LINE"
  exit 1
fi

# --- 5. route restored by the EXIT trap ---
log "done. proxy down-window was the stop→up gap above (typically <1s)."
