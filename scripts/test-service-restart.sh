#!/usr/bin/env bash
# test-service-restart.sh - throwaway-daemon smoke test for the safe restart,
# `observer service restart` (SR-12, lane sr-restart).
#
# It routes Claude Code through a throwaway daemon in a fake HOME (high
# ports, [observer.hooks] auto_register = false), so it never touches the
# real home, the real daemon or :8820, then checks that the restart:
#   - takes the route off before the proxy goes down and never leaves it on
#     while the proxy is down (a 20ms watcher samples both),
#   - restarts the daemon (with no service manager: in place, same pid, a
#     new process image, so started_at changes),
#   - puts the route back byte for byte and leaves no hold journal.
# Linux only (it reads the daemon's lock file and uses setsid / curl).
#
# Usage: scripts/test-service-restart.sh path/to/observer
set -u
BIN="${1:?usage: scripts/test-service-restart.sh path/to/observer}"
ROOT="$(mktemp -d)"
export HOME="$ROOT/home"
mkdir -p "$HOME/.observer" "$HOME/.claude"
PROXY=18920
DASH=18921
CFG="$HOME/.observer/config.toml"
cat >"$CFG" <<EOF
[observer]
db_path = "$HOME/.observer/observer.db"

[observer.hooks]
auto_register = false

[proxy]
port = $PROXY

[dashboard]
addr = "127.0.0.1:$DASH"
EOF
echo '{"env":{"KEEP_ME":"1"},"model":"x"}' >"$HOME/.claude/settings.json"
unset OBSERVER_DAEMON_CHILD

say() { printf '[smoke] %s\n' "$*"; }
healthz() { curl -fsS -m 1 "http://127.0.0.1:$PROXY/-/healthz" >/dev/null 2>&1; }
# daemon_pid reads the running daemon's pid from its start lock beside the
# database (observer-<pid>.lock); `ss -p` cannot name it in every container.
daemon_pid() { ls "$HOME/.observer"/observer-*.lock 2>/dev/null | sed -n 's/.*observer-\([0-9][0-9]*\)\.lock$/\1/p' | head -1; }
started_at() { curl -fsS -m 2 "http://127.0.0.1:$DASH/api/status" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("started_at",""))' 2>/dev/null; }

say "route Claude Code through the fake proxy (observer init, route only)"
"$BIN" init --claude-code --skip-hooks --skip-mcp --config "$CFG" 2>&1 | sed 's/^/    /'
cp "$HOME/.claude/settings.json" "$ROOT/settings.before"
grep -q ANTHROPIC_BASE_URL "$ROOT/settings.before" || { say "FAIL: init wrote no route"; exit 1; }

say "start the throwaway daemon"
setsid nohup "$BIN" start --no-open --config "$CFG" >"$ROOT/daemon.log" 2>&1 </dev/null &
for _ in $(seq 1 240); do healthz && break; sleep 0.25; done
healthz || { say "FAIL: daemon did not come up"; tail -n 30 "$ROOT/daemon.log"; exit 1; }
for _ in $(seq 1 120); do [ -n "$(started_at)" ] && break; sleep 0.25; done
PID_BEFORE="$(daemon_pid)"
SA_BEFORE="$(started_at)"
say "daemon pid $PID_BEFORE started_at $SA_BEFORE"

say "dry run"
"$BIN" service restart --dry-run --config "$CFG" 2>&1 | sed 's/^/    /'
cmp -s "$HOME/.claude/settings.json" "$ROOT/settings.before" || { say "FAIL: the dry run changed settings.json"; exit 1; }

say "watch the route and the proxy while the restart runs"
( while :; do
    if grep -q ANTHROPIC_BASE_URL "$HOME/.claude/settings.json" 2>/dev/null; then r=on; else r=off; fi
    if healthz; then p=up; else p=down; fi
    echo "$r $p"
    sleep 0.02
  done ) >"$ROOT/watch.log" &
WATCH=$!

say "observer service restart"
"$BIN" service restart --config "$CFG" 2>&1 | sed 's/^/    /'
RC=${PIPESTATUS[0]}
sleep 0.3
kill "$WATCH" 2>/dev/null; wait "$WATCH" 2>/dev/null

PID_AFTER="$(daemon_pid)"
SA_AFTER="$(started_at)"
say "exit $RC; daemon pid $PID_AFTER started_at $SA_AFTER"
say "route/proxy states seen: $(sort "$ROOT/watch.log" | uniq -c | tr '\n' ';')"

fail=0
[ "$RC" -eq 0 ] || { say "FAIL: restart exited $RC"; fail=1; }
cmp -s "$HOME/.claude/settings.json" "$ROOT/settings.before" || { say "FAIL: settings.json differs after the restart"; diff "$ROOT/settings.before" "$HOME/.claude/settings.json"; fail=1; }
grep -q "^on down" "$ROOT/watch.log" && { say "FAIL: the route was on while the proxy was down"; fail=1; }
grep -q "^off" "$ROOT/watch.log" || { say "NOTE: the watcher never saw the route off (restart faster than the 20ms poll)"; }
[ -n "$PID_BEFORE" ] && [ "$PID_BEFORE" = "$PID_AFTER" ] && say "in-place restart kept pid $PID_AFTER (a new process image: started_at changed)"
[ -n "$SA_AFTER" ] && [ "$SA_AFTER" != "$SA_BEFORE" ] || { say "FAIL: started_at did not change (no new process image)"; fail=1; }
[ -e "$HOME/.observer/route-hold.json" ] && { say "FAIL: hold journal left behind"; fail=1; }

say "stop the throwaway daemon"
[ -n "$PID_AFTER" ] && kill -TERM "$PID_AFTER" 2>/dev/null
for _ in $(seq 1 120); do healthz || break; sleep 0.25; done
for _ in $(seq 1 80); do [ -n "$PID_AFTER" ] && kill -0 "$PID_AFTER" 2>/dev/null || break; sleep 0.25; done
[ -n "$PID_AFTER" ] && kill -0 "$PID_AFTER" 2>/dev/null && { say "the daemon did not stop; SIGKILL"; kill -KILL "$PID_AFTER"; }
grep -E "auto-register|rewrote hook" "$ROOT/daemon.log" | head -3
rm -rf "$ROOT"
[ "$fail" -eq 0 ] && say "PASS" || say "FAILED"
exit "$fail"
