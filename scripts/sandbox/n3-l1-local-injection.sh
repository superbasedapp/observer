#!/usr/bin/env bash
# N3-L1: credential injection for a LOCAL sandboxed run (lane N3, SBX-NET-2).
#
# Operator-attended. Run on Linux or WSL2 with the Observer daemon running
# (proxy on 127.0.0.1:${OBSERVER_PROXY_PORT:-8820}), the component
# terminals.sandbox.credentials selected, and YOUR Anthropic key stored
# beforehand with the existing flow, which reads it without echo:
#
#   observer sandbox credentials add anthropic
#
# A lane is set up only on a covered tier (proxy_only, or internet with the
# gateway's provider-host block on, which bwrap and oci-runc turn on for a
# proxy-routed claude run) and only in place of a key variable the
# launching env already sets. The script launches with a placeholder value
# (not a key) in ANTHROPIC_API_KEY so the helper has a variable to replace.
#
# This script never reads, prints or logs the key. It checks only that:
#   1. EVERY in-box process's ANTHROPIC_API_KEY holds a sentinel (it prints
#      yes or no, never a value); one process holding any other value fails
#      the check, whatever the others hold. An in-box process is one of
#      your user's that carries the sandbox marker AND runs in a pid
#      namespace nested below this script's (bwrap's --unshare-pid, a
#      container's own namespace; read from the NSpid line of
#      /proc/<pid>/status). The host helper (observer sandbox-host for
#      bwrap, observer sandbox-oci-host for oci-runc) and bwrap's outer
#      process carry the marker too but run outside the box, in the host's
#      namespace: the helper holds the launch placeholder (lane FU10,
#      F-047), so they are counted apart (OUTSIDE_MARKED, reported) and
#      never judged. A nested process of yours whose environment cannot be
#      read is counted (UNREADABLE_IN_BOX) and fails the check, so it can
#      never pass by skipping a process (audit FU10-A6);
#   2. the run's injection record has lane "local" while the run is live;
#   3. one model turn of the sandboxed run lands an api_turns row;
#   4. no api_turns row and no daemon log line carries an Anthropic key
#      shape (a pattern match, not a comparison with your key);
#   5. the run's turns landed on its NATIVE session, the id its transcript
#      and relayed hooks use (lane FU3, F-003: the proxy folds an injected
#      local run's turn onto a session its own hooks started), not on the
#      run namespace rsbx-<run>-...: of the new api_turns rows of THIS run
#      (its namespace, a session the run claimed fresh, or a session its
#      stored terminal run is correlated with), at least one exists, none
#      is rsbx-, and each one's session has a sessions row. The fresh claims
#      are what the product writes for an injected local run
#      (~/.observer/sandbox-cred/fresh/<run>.json, removed when the run
#      ends, so it is read while the run lives; the proxy folds a turn onto
#      a session only when it is in that list). A sandboxed CLI run gets no
#      terminal_run_session row (lane FU10, F-047), so the correlation half
#      only ever matches a dashboard run. Run it in a directory with no other live
#      session of the same project: a session the node recorded before the
#      run stays in the run's namespace by design (audit FU3-A1).
# It writes a receipt (JSON) to the path in RECEIPT.
#
# Sampling (tracker F-054): a `-p` oci-runc container lives about 3 s, so
# the sweep starts with the run, repeats every 0.2 s for the run's whole
# life (up to 180 s), and reads each process's status with shell builtins
# and its environment with one `grep -z` on the file, never a fork per
# process for the depth and owner and never a read of another user's
# environment. The receipt records how many sweeps ran. GNU grep (for -z)
# is required.
#
# Usage: scripts/sandbox/n3-l1-local-injection.sh [profile]
#   profile: the local sandbox backend (default bwrap; oci-runc also works)
set -euo pipefail

PROFILE="${1:-bwrap}"
PORT="${OBSERVER_PROXY_PORT:-8820}"
OBS_DIR="${OBSERVER_DIR:-$HOME/.observer}"
DB="${OBSERVER_DB:-$OBS_DIR/observer.db}"
LOG="${OBSERVER_LOG:-$OBS_DIR/observer.log}"
RECEIPT="${RECEIPT:-n3-l1-receipt-$(date -u +%Y%m%dT%H%M%SZ).json}"
SENTINEL_PREFIX="obsbx-sentinel-v1-"
# Not a key: only gives the helper a variable to replace (lane N3 never
# adds one).
PLACEHOLDER="n3-l1-placeholder-not-a-key"

say() { printf 'n3-l1: %s\n' "$*"; }
fail() { say "FAIL: $*"; write_receipt "failed" "$*"; exit 1; }

write_receipt() {
	local status="$1" note="$2"
	printf '{"check":"N3-L1","status":"%s","profile":"%s","note":"%s","sentinel_in_box":"%s","outside_box_marked_reads":"%s","unreadable_in_box_reads":"%s","record_lane_local":"%s","api_turns_new":"%s","key_shape_in_rows":"%s","key_shape_in_log":"%s","session_fold":"%s","sweeps":"%s","at":"%s"}\n' \
		"$status" "$PROFILE" "$note" "${SENTINEL_OK:-unknown}" "${OUTSIDE_MARKED:-unknown}" "${UNREADABLE_IN_BOX:-unknown}" "${LANE_OK:-unknown}" "${TURNS_NEW:-unknown}" \
		"${ROWS_LEAK:-unknown}" "${LOG_LEAK:-unknown}" "${FOLD_OK:-unknown}" "${SWEEPS:-unknown}" "$(date -u +%FT%TZ)" >"$RECEIPT"
	say "receipt: $RECEIPT"
}

command -v observer >/dev/null || fail "observer is not on PATH"
command -v sqlite3 >/dev/null || fail "sqlite3 is not on PATH"
command -v claude >/dev/null || fail "claude (Claude Code) is not on PATH"
printf 'a=1\0' | grep -qz '^a=' 2>/dev/null || fail "grep has no -z (GNU grep is required)"
[ "$(uname -s)" = "Linux" ] || fail "run this on Linux or WSL2"

say "checking the proxy on 127.0.0.1:$PORT"
curl -fsS -o /dev/null "http://127.0.0.1:$PORT/-/healthz" || fail "the daemon's proxy does not answer on $PORT"

say "checking a stored anthropic key (the list never shows a key)"
observer sandbox credentials list | grep -Eq '^anthropic +key stored' ||
	fail "no anthropic key stored; run: observer sandbox credentials add anthropic"

BEFORE=$(sqlite3 "$DB" "SELECT COUNT(*) FROM api_turns;")
LAST_ROWID=$(sqlite3 "$DB" "SELECT COALESCE(MAX(rowid),0) FROM api_turns;")

# The sandboxed run: one non-interactive turn. It is started in the
# background so the box env and the record can be checked while it lives.
say "starting a sandboxed claude-code run on $PROFILE"
ANTHROPIC_API_KEY="$PLACEHOLDER" observer claude --observer-sandbox "$PROFILE" -p "Reply with the single word ok." >/dev/null 2>&1 &
RUN_PID=$!

# 1 and 2: while the run lives, look at EVERY in-box process (it carries
# the sandbox marker and runs in a pid namespace other than this script's;
# see the header) and at its key variable's prefix only. A process
# whose variable holds anything but a sentinel is counted (never printed),
# and one such process fails the check even when another holds a
# sentinel. The sweep keeps going for the run's whole life so a process
# started later is seen too. It starts at once, before any check below,
# and repeats every 0.2 s (F-054).
SENTINEL_SEEN=0
OTHER_SEEN=0
OUTSIDE_MARKED=0
LANE_OK=no
RUN_ID=""
TRID=""
FRESH_IDS=""
UNREADABLE_IN_BOX=0
SWEEPS=0
# proc_facts STATUS sets P_UID (the real uid) and P_DEPTH (the process's
# pid-namespace depth: the number of ids on its NSpid line, readable for
# every process unlike ns/pid, minus one) from /proc/<pid>/status with
# shell builtins only, so a sweep forks nothing per process for them. Both
# stay empty when the process is gone. The redirection comes after the
# 2>/dev/null, so a vanished file prints nothing (the old sweep's input
# redirection came first and printed about 470 Permission denied lines,
# F-054), and the function never fails, so under set -e a vanished
# process cannot end the script. This script's own depth is the host's: a
# deeper process runs in a nested pid namespace (a box); one at the host's
# depth is outside every box, whatever marker it carries.
proc_facts() {
	P_UID=""
	P_DEPTH=""
	local k a rest
	while read -r k a rest; do
		case "$k" in
		Uid:) P_UID=$a ;;
		NSpid:)
			# shellcheck disable=SC2086 # split the ids on purpose
			set -- $a $rest
			P_DEPTH=$(($# - 1))
			break
			;;
		esac
	done 2>/dev/null <"$1" || true
}
# env_has FILE PATTERN: the NUL-separated environment FILE has a variable
# matching PATTERN (one grep, no value read into a variable, no message
# for a file that cannot be read).
env_has() { grep -qsz -- "$2" "$1"; }
# env_readable FILE: the environment FILE can be read (grep answers 2 only
# when it cannot read it).
env_readable() {
	local rc=0
	grep -csz -- '' "$1" >/dev/null || rc=$?
	[ "$rc" -ne 2 ]
}
proc_facts /proc/self/status
HOST_DEPTH=$P_DEPTH
[ -n "$HOST_DEPTH" ] || fail "cannot read this shell's NSpid line (/proc/self/status)"
MY_UID=$(id -u)
SAMPLE_UNTIL=$((SECONDS + 180))
while [ "$SECONDS" -lt "$SAMPLE_UNTIL" ]; do
	SWEEPS=$((SWEEPS + 1))
	for st in /proc/[0-9]*/status; do
		pdir=${st%/status}
		envf=$pdir/environ
		proc_facts "$st"
		[ -n "$P_DEPTH" ] || continue # the process is gone
		# Only your own processes: the box and the host helper run as your
		# user, and another user's environment cannot be read anyway.
		[ "$P_UID" = "$MY_UID" ] || continue
		if [ "$P_DEPTH" -le "$HOST_DEPTH" ]; then
			# The host helper or bwrap's outer process: outside the box.
			if env_has "$envf" '^OBSERVER_SANDBOX='; then
				OUTSIDE_MARKED=$((OUTSIDE_MARKED + 1))
			fi
			continue
		fi
		# One of your boxed processes whose environment cannot be read
		# could hold anything: it is counted, and any count fails check 1
		# (audit FU10-A6). A process that ended meanwhile is not counted.
		if ! env_readable "$envf"; then
			if [ -d "$pdir" ]; then UNREADABLE_IN_BOX=$((UNREADABLE_IN_BOX + 1)); fi
			continue
		fi
		if env_has "$envf" '^OBSERVER_SANDBOX='; then
			# A prefix match only: the value is never read into a variable.
			if env_has "$envf" "^ANTHROPIC_API_KEY=$SENTINEL_PREFIX"; then
				SENTINEL_SEEN=$((SENTINEL_SEEN + 1))
			elif env_has "$envf" '^ANTHROPIC_API_KEY=.'; then
				OTHER_SEEN=$((OTHER_SEEN + 1))
			fi
		fi
	done
	for recf in "$OBS_DIR"/sandbox-cred/runs/*.json; do
		[ -f "$recf" ] || continue
		if grep -qs '"lane":"local"' "$recf"; then
			LANE_OK=yes
			# The run's id (the record's file name) and its stored terminal
			# run (from its relay record), for check 5's scope.
			RUN_ID=$(basename "$recf" .json)
			TRID=$(grep -o '"terminal_run_id":"[^"]*"' "$OBS_DIR/sandbox-relay/runs/$RUN_ID.json" 2>/dev/null | cut -d'"' -f4 || true)
			# The sessions this run claimed fresh (the fold's list), kept
			# while the run lives; never printed.
			fresh=$(grep -o '"[^"]*"' "$OBS_DIR/sandbox-cred/fresh/$RUN_ID.json" 2>/dev/null | tr -d '"' | tr '\n' ' ' || true)
			if [ -n "$fresh" ]; then FRESH_IDS="$fresh"; fi
		fi
	done
	kill -0 "$RUN_PID" 2>/dev/null || break
	sleep 0.2
done
wait "$RUN_PID" || say "the run exited non-zero (checked below by its api_turns row)"
if [ "$OTHER_SEEN" -gt 0 ]; then
	SENTINEL_OK="no-a-process-held-a-non-sentinel-value"
elif [ "$UNREADABLE_IN_BOX" -gt 0 ]; then
	SENTINEL_OK="no-an-in-box-process-could-not-be-read-$UNREADABLE_IN_BOX"
elif [ "$SENTINEL_SEEN" -gt 0 ]; then
	SENTINEL_OK=yes
else
	SENTINEL_OK=no
fi

# 3: the turn landed.
AFTER=$(sqlite3 "$DB" "SELECT COUNT(*) FROM api_turns;")
TURNS_NEW=$((AFTER - BEFORE))

# 4: no key shape in the new rows or the daemon log (pattern only).
# Every column of the new rows, piped to a count (never to the terminal).
ROWS_LEAK=$(sqlite3 -list "$DB" "SELECT * FROM api_turns WHERE rowid > $LAST_ROWID;" | grep -Ec 'sk-ant-[A-Za-z0-9_-]{8,}' || true)
if [ -f "$LOG" ]; then
	if grep -Eq 'sk-ant-[A-Za-z0-9_-]{8,}' "$LOG"; then LOG_LEAK=yes; else LOG_LEAK=no; fi
else
	LOG_LEAK="no log file at $LOG"
fi

# 5: the session fold (F-003), scoped to THIS run's rows: those in the
# run's namespace (rsbx-<run>...), those on a session the run claimed fresh
# (the fold's own list, read while the run lived) and those on a session
# the run's stored terminal run is correlated with (terminal_run_session,
# which only a dashboard run gets). Counts only; no session id is printed.
# A label starting with "fail-" fails the check.
RUN_ROWS=0
RUN_NS=0
NO_SESSION_ROW=0
# Every id goes into SQL: keep only the shapes a run or session id takes.
case "$RUN_ID" in *[!A-Za-z0-9._-]*) RUN_ID="" ;; esac
case "$TRID" in *[!A-Za-z0-9._-]*) TRID="" ;; esac
FRESH_SQL="''"
for sid in $FRESH_IDS; do
	case "$sid" in *[!A-Za-z0-9._:-]*) continue ;; esac
	FRESH_SQL="$FRESH_SQL,'$sid'"
done
if [ -n "$RUN_ID" ]; then
	SCOPE="rowid > $LAST_ROWID AND (session_id LIKE 'rsbx-$RUN_ID%' OR session_id IN ($FRESH_SQL) OR session_id IN (SELECT session_id FROM terminal_run_session WHERE run_id = '$TRID'))"
	RUN_ROWS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM api_turns WHERE $SCOPE;")
	RUN_NS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM api_turns WHERE $SCOPE AND session_id LIKE 'rsbx-%';")
	NO_SESSION_ROW=$(sqlite3 "$DB" "SELECT COUNT(*) FROM api_turns a WHERE $SCOPE AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id = a.session_id);")
fi
if [ -z "$RUN_ID" ]; then
	FOLD_OK="fail-run-not-identified"
elif [ "$RUN_ROWS" -lt 1 ]; then
	FOLD_OK="fail-no-turn-of-this-run"
elif [ "$RUN_NS" -gt 0 ]; then
	FOLD_OK="fail-run-namespace-rows-$RUN_NS"
elif [ "$NO_SESSION_ROW" -gt 0 ]; then
	FOLD_OK="fail-rows-on-an-unrecorded-session-$NO_SESSION_ROW"
else
	FOLD_OK=native
fi

say "sentinel in box: $SENTINEL_OK ($SWEEPS sweeps, $SENTINEL_SEEN in-box process reads, $UNREADABLE_IN_BOX in-box reads that could not be read, $OUTSIDE_MARKED marked reads outside the box not judged); record lane local: $LANE_OK; new api_turns rows: $TURNS_NEW; key shape in rows: $ROWS_LEAK; in log: $LOG_LEAK; session fold: $FOLD_OK"
if [ "$SENTINEL_OK" = "yes" ] && [ "$LANE_OK" = "yes" ] && [ "$TURNS_NEW" -ge 1 ] && [ "$ROWS_LEAK" = "0" ] && [ "$LOG_LEAK" != "yes" ] && [ "$FOLD_OK" = "native" ]; then
	write_receipt "passed" "local run injected"
	say "PASS"
else
	fail "see the line above"
fi
