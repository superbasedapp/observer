#!/usr/bin/env bash
# test-npm-postinstall.sh: hermetic test for npm/observer/bin/postinstall.js
# (T-753, T-756, U7). The postinstall only PRINTS a restart hint when an
# `observer start` process still runs a replaced @superbased binary; it never
# restarts, writes or fails. A fixture /proc (OBSERVER_POSTINSTALL_PROC_ROOT)
# stands in for the real one and OBSERVER_POSTINSTALL_INSTALLED_BINARY names
# the binary the install put in place, so nothing outside a mktemp dir is
# read. Needs bash and node. POSTINSTALL_SCRIPT runs the cases against another
# copy of the script (used to show a red run against the previous version).
#
# Usage: scripts/test-npm-postinstall.sh     Exit 0 = all cases pass.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${POSTINSTALL_SCRIPT:-$REPO_ROOT/npm/observer/bin/postinstall.js}"
command -v node >/dev/null 2>&1 || { echo "SKIP: node not installed"; exit 0; }
[[ "$(uname -s)" == Linux ]] || { echo "SKIP: the stale-daemon look runs only on Linux"; exit 0; }
NEXT_LINE='Installed. Next: observer start (opens your dashboard, where you sign in)'

T="$(mktemp -d "${TMPDIR:-/tmp}/npm-postinstall-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT
pass=0 fail=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }
bad() { fail=$((fail + 1)); echo "FAIL $*"; }

PROC="$T/proc"
proc() { # proc <pid> <exe link target> <argv...>  (into $PROC)
  local d="$PROC/$1"; shift
  mkdir -p "$d"
  ln -s "$1" "$d/exe"; shift
  printf '%s\0' "$@" >"$d/cmdline"
}
NPM=/usr/lib/node_modules/@superbased
proc 4101 "$NPM/.observer-linux-x64-0HMzYhs4/bin/observer (deleted)" "$NPM/observer-linux-x64/bin/observer" start
proc 4102 "$NPM/observer-linux-x64/bin/observer" "$NPM/observer-linux-x64/bin/observer" start
proc 4103 "$NPM/.observer-linux-x64-0HMzYhs4/bin/observer (deleted)" observer hook claude-code PreToolUse
proc 4104 "/home/u/.local/bin/observer (deleted)" /home/u/.local/bin/observer start
proc 4105 "/usr/bin/node (deleted)" node start
# T-756: npm 10 renames the old package dir aside and runs postinstall BEFORE
# deleting it, so the daemon's exe is the retired dot-dir path with no
# "(deleted)" yet (rc.4 roll, node 5: .observer-linux-x64-0HMzYhs4).
proc 4106 "$NPM/.observer-linux-x64-0HMzYhs4/bin/observer" "$NPM/observer-linux-x64/bin/observer" start
# An @superbased observer binary that is not the one this install put in place.
proc 4107 "/home/u/.npm-global/lib/node_modules/@superbased/observer-linux-x64/bin/observer" observer start
mkdir -p "$PROC/self"
INSTALLED="$NPM/observer-linux-x64/bin/observer"

run() { # run <proc root>: stderr+stdout in $T/out, status in $rc
  # setsid: no controlling terminal, so the note goes to stderr (the script
  # prefers /dev/tty because npm hides lifecycle-script output).
  setsid -w env -i PATH="$PATH" HOME="$T" OBSERVER_POSTINSTALL_PROC_ROOT="$1" \
    OBSERVER_POSTINSTALL_INSTALLED_BINARY="$INSTALLED" node "$SCRIPT" >"$T/out" 2>&1 </dev/null
  rc=$?
}
command -v setsid >/dev/null 2>&1 || { echo "SKIP: setsid not installed"; exit 0; }

# U7: none of these runs under the systemd unit, so the hint names only the
# `observer start` restart path (no `observer service upgrade` for a user
# with no unit).
run "$PROC"
if [[ $rc -eq 0 ]] && grep -q "(pids 4101, 4106, 4107)" "$T/out" && grep -q 'run `observer start` again' "$T/out" \
  && grep -q "turn the proxy route off" "$T/out" && ! grep -q "410[2-5]" "$T/out" && ! grep -q "service upgrade" "$T/out" \
  && ! grep -qF "$NEXT_LINE" "$T/out"; then
  ok "daemons on a deleted, a retired (npm 10 rename-aside) and a not-installed @superbased binary get the observer start restart hint only; current, hook, non-npm and non-observer processes do not"
else bad "stale daemon hint (rc=$rc)"; cat "$T/out"; fi

# With the installed binary unknown (not resolvable), the deleted and retired
# shapes still count; a live binary elsewhere is not flagged on a guess.
got="$(node -e 'const m = require(process.argv[1]); console.log(m.staleDaemons(process.argv[2], "").join(","))' "$SCRIPT" "$PROC" 2>&1)"
if [[ "$got" == "4101,4106" ]]; then ok "installed binary unknown: deleted and retired-dir daemons only"
else bad "installed binary unknown: got '$got', want '4101,4106'"; fi

# U7: a daemon inside the observer systemd unit (its cgroup names
# observer.service) gets only the `observer service upgrade` line.
PROC="$T/unitproc"
proc 4108 "$NPM/.observer-linux-x64-0HMzYhs4/bin/observer (deleted)" "$NPM/observer-linux-x64/bin/observer" start
echo "0::/user.slice/user-1000.slice/user@1000.service/app.slice/observer.service" >"$PROC/4108/cgroup"
mkdir -p "$PROC/self"
run "$PROC"
if [[ $rc -eq 0 ]] && grep -q "observer service upgrade" "$T/out" && ! grep -q 'observer start` again' "$T/out"; then
  ok "a daemon under the systemd unit gets only the service upgrade line"
else bad "unit daemon hint (rc=$rc)"; cat "$T/out"; fi
PROC="$T/proc"

rm -rf "$PROC/4101" "$PROC/4106" "$PROC/4107"
run "$PROC"
if [[ $rc -eq 0 ]] && [[ "$(cat "$T/out")" == "$NEXT_LINE" ]]; then ok "no stale daemon: only the next-step line"; else bad "next-step line when nothing is stale (rc=$rc)"; cat "$T/out"; fi

run "$T/no-such-proc"
if [[ $rc -eq 0 ]] && [[ "$(cat "$T/out")" == "$NEXT_LINE" ]]; then ok "an unreadable /proc never fails the install (next-step line only)"; else bad "unreadable proc (rc=$rc)"; cat "$T/out"; fi

echo
echo "postinstall.js: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
