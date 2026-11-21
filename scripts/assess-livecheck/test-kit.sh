#!/usr/bin/env bash
# test-kit.sh: hermetic test of the security assessments live-check kit
# (scripts/assess-livecheck/collect.sh, preflight.sh, negative-controls.json).
#
# No node, no agent, no real home: everything runs in a private mktemp dir with
# processes this test starts itself. The live run of 2026-11-15 found the kit
# stale in four places; each has a case here so the next one fails a test and not
# an attended run:
#
#   argv        the fixture-server matcher counts only a python interpreter whose
#               argv[1] is server.py (the box's own processes carry the task text,
#               which names server.py, and pgrep -f counted them);
#   decoys      the same, against real processes (a python process that only
#               MENTIONS server.py, a process whose argv ends in it);
#   detach      preflight's spawn_detached outlives the shell that started it, in
#               a session of its own, and the pid file holds the command's own pid;
#   controls    negative-controls.json renders to complete launch bodies, every
#               placeholder filled, nothing but the control's own members changed,
#               and the tripwire digest never equals the plan's;
#   port file   host-checks --wait-for believes a fresh port file only;
#   clean       preflight.sh clean removes a scratch root that holds a read-only tree (a Go
#               module cache, found by the live run of 2026-11-16), reports a failure with
#               the marker kept, and still refuses a root outside sbo-scratch/assess-live,
#               a root without the marker and a symbolic-link root, changing nothing.
#
# The controls' rules against the real launch route are pinned by a Go test
# (TestAssessKitControlsMatchTheRoute, internal/intelligence/dashboard).
#
# Usage: scripts/assess-livecheck/test-kit.sh   Needs bash, jq, python3 and /proc
# (Linux or WSL). Exit 0 = every case passes; SKIP (exit 0) where a tool is missing.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -d /proc/self ] || { echo "SKIP: needs /proc"; exit 0; }
for need in jq python3 setsid; do
	command -v "$need" >/dev/null 2>&1 || { echo "SKIP: $need not found"; exit 0; }
done

T="$(mktemp -d "${TMPDIR:-/tmp}/assess-kit-test.XXXXXX")"
[ -n "$T" ] && [ -d "$T" ] || { echo "FAIL: mktemp"; exit 1; }
PIDS=()
cleanup() {
	local p
	for p in "${PIDS[@]}"; do kill -KILL "$p" 2>/dev/null || true; done
	# The clean cases leave read-only trees behind on purpose (the refused roots): open them first.
	[ -n "$T" ] && [ "$T" != "/" ] && [ -d "$T" ] && chmod -R u+rwX -- "$T" 2>/dev/null
	[ -n "$T" ] && [ "$T" != "/" ] && [ -d "$T" ] && rm -rf -- "$T"
}
trap cleanup EXIT

FAILS=0 CASES=0
ok() { CASES=$((CASES + 1)); }
fail() {
	CASES=$((CASES + 1))
	FAILS=$((FAILS + 1))
	echo "FAIL: $*"
}

export ASSESS_LIVE_ROOT="$T/root"
# shellcheck source=collect.sh
source "$HERE/collect.sh"

# ---- argv: the matcher, row by row -------------------------------------------------
while IFS='|' read -r want a0 a1 name; do
	[ -n "$name" ] || continue
	if fixture_argv "$a0" "$a1"; then got=yes; else got=no; fi
	if [ "$got" = "$want" ]; then ok; else fail "fixture_argv $name: want $want, got $got ($a0 $a1)"; fi
done <<'EOF'
yes|python3|server.py|the start command of the launch file
yes|python3|./server.py|a relative path
yes|/usr/bin/python3.12|/work/notesapp/server.py|an absolute interpreter and script
yes|python|server.py|a bare python
no|python3|-c|the interpreter with -c, the task text coming later
no|python3|other_server.py|a file that only ends in server.py
no|observer|sandbox-host|the box's own process
no|bwrap|--unshare-user|the sandbox
no|claude|server.py|an agent that was handed the name
no|bash|server.py|a shell that was handed the name
no|node|server.py|a different interpreter
no|python3|server.pyc|a compiled name
no||server.py|no argv0
no|python3||no argv1
EOF

# ---- decoys: real processes --------------------------------------------------------
mkdir -p "$T/app"
printf 'import time\ntime.sleep(60)\n' >"$T/app/server.py"
(cd "$T/app" && exec python3 server.py) &
REAL=$!
PIDS+=("$REAL")
# A python process that mentions server.py only inside its arguments, and a shell whose argv
# carries the whole task text (what the box's processes look like).
python3 -c 'import time; time.sleep(60)' "the task: start python3 server.py and test it" &
DECOY1=$!
PIDS+=("$DECOY1")
bash -c 'sleep 60' observer sandbox-host --task "run python3 server.py" &
DECOY2=$!
PIDS+=("$DECOY2")
sleep 0.5
found=" $(fixture_pids | tr '\n' ' ')"
case "$found" in *" $REAL "*) ok ;; *) fail "the fixture server (pid $REAL) was not found: $found" ;; esac
case "$found" in *" $DECOY1 "*) fail "a python process that only mentions server.py was counted (pid $DECOY1)" ;; *) ok ;; esac
case "$found" in *" $DECOY2 "*) fail "a process whose argv carries the task text was counted (pid $DECOY2)" ;; *) ok ;; esac
kill -KILL "$REAL" 2>/dev/null
wait "$REAL" 2>/dev/null
found=" $(fixture_pids | tr '\n' ' ')"
case "$found" in *" $REAL "*) fail "a stopped server is still counted" ;; *) ok ;; esac

# ---- valid_port ------------------------------------------------------------------
for row in "1:yes" "18081:yes" "65535:yes" "0:no" "65536:no" "abc:no" ":no" "80a:no"; do
	p=${row%%:*} want=${row##*:}
	if valid_port "$p"; then got=yes; else got=no; fi
	if [ "$got" = "$want" ]; then ok; else fail "valid_port '$p': want $want, got $got"; fi
done

# ---- port file: wait_for_port ------------------------------------------------------
now=$(date +%s)
printf '4242 %s\n' "$now" >"$T/fresh.port"
printf '4243 %s\n' "$((now - 3600))" >"$T/stale.port"
printf 'hello world\n' >"$T/junk.port"
printf '70000 %s\n' "$now" >"$T/range.port"
printf '4244\n' >"$T/nostamp.port"
for row in "fresh:4242" "stale:" "junk:" "range:" "nostamp:" "absent:"; do
	f=${row%%:*} want=${row##*:}
	got=$(wait_for_port "$T/$f.port" 1 || true)
	if [ "$got" = "$want" ]; then ok; else fail "wait_for_port $f: want '$want', got '$got'"; fi
done
# A file that appears while waiting is picked up.
(sleep 1; printf '4245 %s\n' "$(date +%s)" >"$T/late.port") &
got=$(wait_for_port "$T/late.port" 5 || true)
if [ "$got" = 4245 ]; then ok; else fail "wait_for_port late: want 4245, got '$got'"; fi

# ---- controls: negative-controls.json ----------------------------------------------
if jq -e . "$CONTROLS" >/dev/null 2>&1; then ok; else fail "$CONTROLS is not valid JSON"; fi
plan_digest=$(printf 'a%.0s' $(seq 1 64))
trip=$(tripwire_digest "$plan_digest")
if [ "$trip" != "$plan_digest" ] && [ "${#trip}" -eq 64 ] && [ "${trip:1}" = "${plan_digest:1}" ]; then ok; else fail "tripwire_digest of a digest starting with a: $trip"; fi
zero=$(printf '0%.0s' $(seq 1 64))
trip=$(tripwire_digest "$zero")
if [ "$trip" != "$zero" ] && [ "${#trip}" -eq 64 ]; then ok; else fail "tripwire_digest of a digest starting with 0: $trip"; fi
values=$(jq -nc --arg d "$(tripwire_digest "$plan_digest")" \
	'{project_root_hash: "h1", run_id: "20261115-ab12cd", tool: "claude-code", target: "http://localhost:3000/", tripwire_digest: $d, needs: "some-tool"}')
dup=$(jq -r '[.controls[].id] | length - (unique | length)' "$CONTROLS")
if [ "$dup" = 0 ]; then ok; else fail "control ids are not unique"; fi
base_keys=$(jq -c '.base | keys' "$CONTROLS")
for cid in $(jq -r '.controls[].id' "$CONTROLS"); do
	body=$(render_body "$cid" "$values") || { fail "control $cid does not render"; continue; }
	if printf '%s' "$body" | grep -q '"@'; then fail "control $cid left a placeholder unfilled: $body"; else ok; fi
	# Every member of the base is there, and nothing is there that neither the base nor the control names.
	want_keys=$(jq -c --arg id "$cid" '(.base | keys) + (.controls[] | select(.id == $id) | .set | keys) | unique' "$CONTROLS")
	got_keys=$(printf '%s' "$body" | jq -c 'keys')
	if [ "$got_keys" = "$want_keys" ]; then ok; else fail "control $cid: members $got_keys, want $want_keys"; fi
	# The members that name the run are the plan's, whatever the control changes.
	for k in project_root_hash run_id; do
		if [ "$(printf '%s' "$body" | jq -r --arg k "$k" '.[$k]')" = "$(printf '%s' "$values" | jq -r --arg k "$k" '.[$k]')" ]; then ok; else fail "control $cid changed $k"; fi
	done
	# Every control but BASE changes something, and only what it declares.
	if [ "$cid" != BASE ]; then
		changed=$(jq -n --argjson b "$(render_body BASE "$values")" --argjson c "$body" '[$c | to_entries[] | select($b[.key] != .value) | .key] | length')
		declared=$(jq -r --arg id "$cid" '.controls[] | select(.id == $id) | .set | length' "$CONTROLS")
		if [ "$changed" -ge 1 ] && [ "$changed" -le "$declared" ]; then ok; else fail "control $cid changes $changed member(s) of BASE, declares $declared"; fi
	fi
done
# BASE is exactly the body the live check calls accepted: a tool, a digest and the confirmed target.
base=$(render_body BASE "$values")
for k in assessment project_root_hash run_id tool target confirm_target prompt_sha256; do
	if printf '%s' "$base" | jq -e --arg k "$k" 'has($k)' >/dev/null; then ok; else fail "BASE has no $k member"; fi
done
if [ "$(printf '%s' "$base" | jq -r .tool)" = claude-code ]; then ok; else fail "BASE tool is not the plan's agent"; fi
if [ "$(printf '%s' "$base" | jq -r .prompt_sha256)" != "$plan_digest" ]; then ok; else fail "BASE carries the plan's real digest: a control could start a terminal"; fi
# No control sends the old, wrong agent id or a sandbox member other than the one E6 tests.
if jq -e '[.base, (.controls[].set)] | map(tostring) | any(test("\"claude\""))' "$CONTROLS" >/dev/null; then fail "a control names the tool claude"; else ok; fi

# ---- detach: preflight's spawn_detached --------------------------------------------
(
	export ASSESS_LIVE_ROOT="$T/root2"
	# shellcheck source=preflight.sh
	source "$HERE/preflight.sh"
	spawn_detached "$T/spawn.pid" "$T/spawn.log" sleep 60
) || fail "spawn_detached returned an error"
if [ -s "$T/spawn.pid" ]; then
	spid=$(cat "$T/spawn.pid")
	PIDS+=("$spid")
	if kill -0 "$spid" 2>/dev/null; then ok; else fail "the detached command did not survive the shell that started it (pid $spid)"; fi
	if [ "$(tr '\0' ' ' <"/proc/$spid/cmdline" 2>/dev/null)" = "sleep 60 " ]; then ok; else fail "the pid file does not hold the command's own pid (cmdline: $(tr '\0' ' ' <"/proc/$spid/cmdline" 2>/dev/null))"; fi
	mysid=$(awk '{print $6}' /proc/self/stat)
	hissid=$(awk '{print $6}' "/proc/$spid/stat" 2>/dev/null)
	if [ -n "$hissid" ] && [ "$hissid" != "$mysid" ]; then ok; else fail "the detached command shares this shell's session ($hissid)"; fi
else
	fail "spawn_detached wrote no pid file"
fi

# ---- clean: preflight.sh clean -----------------------------------------------------
# mk_root <root>: a fake scratch root with the marker and what the live run left behind: a Go
# module cache the way Go writes it (directories r-x, files r--) inside the throwaway home.
mk_root() {
	local r=$1 m
	m="$r/home/go/pkg/mod/example.com/m@v1.0.0"
	mkdir -p "$m/sub" "$r/projects/notesapp" "$r/results"
	printf 'security assessments live check scratch root\n' >"$r/.assess-live-root"
	printf 'package m\n' >"$m/m.go"
	printf 'package sub\n' >"$m/sub/s.go"
	printf 'kept until clean\n' >"$r/projects/notesapp/server.py"
	chmod -R a-w "$r/home/go"
}
# run_clean <root>: preflight's cmd_clean against that root in a shell of its own (die exits it);
# sets CLEAN_RC and CLEAN_OUT (both streams).
run_clean() {
	CLEAN_OUT=$(
		export ASSESS_LIVE_ROOT="$1"
		# shellcheck source=preflight.sh
		source "$HERE/preflight.sh"
		cmd_clean 2>&1
	)
	CLEAN_RC=$?
}

# The fixture is what it claims to be: a plain rm -rf fails on it (it cannot for uid 0, where the
# read-only bits do not bind; the removal case below then proves less, and says so).
mk_root "$T/plain/sbo-scratch/assess-live"
if [ "$(id -u)" -eq 0 ]; then
	echo "NOTE: running as uid 0, read-only bits do not bind: the clean cases prove less than as a user"
	ok
elif rm -rf "$T/plain/sbo-scratch/assess-live" 2>/dev/null; then
	fail "the read-only fixture was removed by a plain rm -rf: it does not reproduce the live failure"
else
	ok
fi

# A root with a read-only tree is removed, completely, with the marker.
root="$T/a/sbo-scratch/assess-live"
mk_root "$root"
run_clean "$root"
if [ "$CLEAN_RC" -eq 0 ]; then ok; else fail "clean of a root with a read-only tree exited $CLEAN_RC: $CLEAN_OUT"; fi
if [ ! -e "$root" ]; then ok; else fail "clean left $root behind: $(find "$root" -mindepth 1 | head -n 3 | tr '\n' ' ')"; fi
case "$CLEAN_OUT" in *"removed $root"*) ok ;; *) fail "clean did not say it removed the root: $CLEAN_OUT" ;; esac
case "$CLEAN_OUT" in *"Permission denied"*) fail "clean reported Permission denied: $CLEAN_OUT" ;; *) ok ;; esac

# The path guard still refuses a root outside sbo-scratch/assess-live, even one that carries the
# marker, and it runs BEFORE the tree is made writable: nothing is removed or changed.
root="$T/b/elsewhere/root"
mk_root "$root"
mod="$root/home/go/pkg/mod/example.com/m@v1.0.0"
before=$(stat -c %a "$mod")
run_clean "$root"
if [ "$CLEAN_RC" -ne 0 ]; then ok; else fail "clean accepted a root outside sbo-scratch/assess-live"; fi
case "$CLEAN_OUT" in *"not under sbo-scratch/assess-live"*) ok ;; *) fail "clean's refusal does not name the path guard: $CLEAN_OUT" ;; esac
if [ -f "$root/.assess-live-root" ] && [ -f "$mod/m.go" ] && [ -f "$root/projects/notesapp/server.py" ]; then ok; else fail "the refused root lost files"; fi
if [ "$(stat -c %a "$mod")" = "$before" ]; then ok; else fail "the path guard ran after the chmod: $mod went from $before to $(stat -c %a "$mod")"; fi

# A root with the right path but no marker is refused; nothing is removed or changed.
root="$T/c/sbo-scratch/assess-live"
mk_root "$root"
rm -f "$root/.assess-live-root"
run_clean "$root"
if [ "$CLEAN_RC" -ne 0 ]; then ok; else fail "clean accepted a root without the marker"; fi
case "$CLEAN_OUT" in *"lacks the marker"*) ok ;; *) fail "clean's refusal does not name the marker: $CLEAN_OUT" ;; esac
if [ -f "$root/projects/notesapp/server.py" ]; then ok; else fail "the root without a marker lost files"; fi

# A symbolic link standing in for the root is refused; the directory it points at is untouched.
root="$T/d/real/sbo-scratch/assess-live"
mk_root "$root"
mkdir -p "$T/d/link/sbo-scratch"
ln -s "$root" "$T/d/link/sbo-scratch/assess-live"
run_clean "$T/d/link/sbo-scratch/assess-live"
if [ "$CLEAN_RC" -ne 0 ]; then ok; else fail "clean accepted a symbolic link as the root"; fi
case "$CLEAN_OUT" in *"symbolic link"*) ok ;; *) fail "clean's refusal does not name the link: $CLEAN_OUT" ;; esac
if [ -f "$root/.assess-live-root" ] && [ -f "$root/projects/notesapp/server.py" ]; then ok; else fail "the root behind the link lost files"; fi

# A removal that fails is reported (non-zero, what is left named) and keeps the marker, so a second
# clean still works once the cause is gone. The stand-in rm fails for -rf only.
root="$T/e/sbo-scratch/assess-live"
mk_root "$root"
mkdir -p "$T/fakebin"
printf '#!/bin/sh\ncase "$*" in *-rf*) echo "rm: simulated failure" >&2; exit 1 ;; esac\nexec /bin/rm "$@"\n' >"$T/fakebin/rm"
chmod +x "$T/fakebin/rm"
CLEAN_OUT=$(
	export PATH="$T/fakebin:$PATH"
	export ASSESS_LIVE_ROOT="$root"
	# shellcheck source=preflight.sh
	source "$HERE/preflight.sh"
	cmd_clean 2>&1
)
CLEAN_RC=$?
if [ "$CLEAN_RC" -ne 0 ]; then ok; else fail "clean exited 0 although the removal failed"; fi
case "$CLEAN_OUT" in *"NOT fully removed"*"$root/"*) ok ;; *) fail "clean's failure report does not say what is left: $CLEAN_OUT" ;; esac
if [ -f "$root/.assess-live-root" ]; then ok; else fail "the marker is gone after a failed clean: a second clean would refuse"; fi
run_clean "$root"
if [ "$CLEAN_RC" -eq 0 ] && [ ! -e "$root" ]; then ok; else fail "the second clean did not finish the job (exit $CLEAN_RC): $CLEAN_OUT"; fi

echo
if [ "$FAILS" -eq 0 ]; then
	echo "OK: $CASES cases"
	exit 0
fi
echo "FAILED: $FAILS of $CASES cases"
exit 1
