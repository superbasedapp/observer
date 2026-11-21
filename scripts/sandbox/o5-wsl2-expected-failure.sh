#!/usr/bin/env bash
# o5-wsl2-expected-failure.sh: lane O5's WSL2 check (live register row
# O5-L2), an EXPECTED FAILURE: on WSL2 the openshell row is refused by
# design, and this script passes only when the refusal is the documented
# one.
#
# The documented outcome (lane O0's O0-L2 receipts,
# docs/plans/openshell/build/o0-receipts.md; docs/sandbox-openshell.md
# "What you need"): on WSL2 with runc linked against libseccomp 2.5.1,
# Docker's default seccomp profile answers ENOSYS for the Landlock
# syscalls, so OpenShell's supervisor fails closed at box start while
# `openshell doctor check` still says ok (upstream issue 4133). Observer
# therefore refuses the row on WSL2 with verdict unsupported_platform and a
# reason naming WSL2 and ENOSYS. The refusal a user sees comes from the
# selector's platform rule S3, which reads the reason from the registry
# row's own HostRefusals (live check O5-L2 2026-11-01 found S3's generic
# text there before the row declared it); the openshell probe's row P1
# carries the same reason as defence in depth and stops the probe ladder
# on WSL2 before any OpenShell command runs.
#
# Run it on the operator's WSL2 laptop as a normal user, over a FRESH
# Observer state dir: the script refuses an existing ~/.observer unless
# --observer-dir names a throwaway one. It starts no daemon, launches no
# box, writes no AI tool's config and never edits a gateway config (it does
# run the runtime canary container when its image is already here, a fact
# below). It writes ONE receipt on every exit with no secret and no address
# in it.
#
# What it checks:
#   wsl2_detected          the kernel says WSL2 (/proc/version names
#                          microsoft), or the script refuses (exit 2): on
#                          any other host this row proves nothing;
#   row_refused_unsupported_platform
#                          `observer sandbox status --json` with openshell
#                          listed and its component on reports the row
#                          unavailable with verdict unsupported_platform
#                          (the status command must itself exit 0);
#   reason_names_wsl2      that row's reason names WSL2 and the ENOSYS
#                          cause (the row's own WSL2 reason, not the
#                          selector's generic "does not run on wsl2");
#   no_run_dir_made        no run dir appeared, across the status call,
#                          under the row's state dir in the Observer dir the
#                          status used (the configured database's dir, so
#                          --observer-dir) nor under ~/.observer's. Status
#                          never makes a run dir by design, so this guards
#                          against a launch being started from the refusal
#                          path; it cannot show on its own that no OpenShell
#                          command ran (the probe ladder's P1 stops before
#                          any command on WSL2, pinned by the unit test
#                          TestOpenShellProbeLadder, not by this receipt).
# The script passes only when all four were judged pass and it ran to its
# end: an early stop records `aborted` and fails, never exits 0.
# And, as facts only (never judged, since the row is refused on WSL2 and
# the product never runs them): the runtime canary's own answer when Docker and the
# supervisor image ghcr.io/nvidia/openshell/supervisor:0.1.6 are already on
# this machine (expected "-1 38", ENOSYS; the script never pulls an image),
# and `openshell doctor check`'s first line when the CLI is installed.
#
# Usage:
#   scripts/sandbox/o5-wsl2-expected-failure.sh [--observer PATH] [--out DIR]
#       [--observer-dir DIR]
#
#   --observer PATH      the observer binary (a static build, CGO_ENABLED=0;
#                        default: build one from this tree)
#   --out DIR            where the receipt goes (default: the current dir)
#   --observer-dir DIR   a throwaway Observer state dir to use instead of
#                        ~/.observer (it must not exist yet)
#
# Exit 0 when every check passed (the documented refusal), 1 when one
# failed or did not run, 2 on a precondition the host does not meet.
# shellcheck disable=SC2015,SC2329
set -euo pipefail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROW="O5-L2"
OUT="$PWD"
RECEIPT="$OUT/o5-wsl2-expected-failure-o5-l2-$STAMP.json"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OBSERVER=""
OBSDIR="$HOME/.observer"
OBSDIR_MADE=0
WORK=""

declare -A R
R[schema]="observer-o5-wsl2/1"
R[row]="$ROW"
R[started]="$STAMP"
FAIL=0
RECEIPT_WRITTEN=0
EXIT_CODE=""
# COMPLETED is set only after the last step; HELP only by --help. A run
# that stops anywhere else fails (O5 audit finding O5-A1).
COMPLETED=0
HELP=0
# JUDGED are the checks a pass needs, each judged pass.
JUDGED="wsl2_detected row_refused_unsupported_platform reason_names_wsl2 no_run_dir_made"

json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\r'/\\r}"
	s="${s//$'\t'/\\t}"
	s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
	printf '"%s"\n' "$s"
}
write_receipt() {
	if ! { : >"$RECEIPT"; } 2>/dev/null; then
		RECEIPT="$HOME/$(basename "$RECEIPT")"
		R[receipt.fallback]="the --out dir was not writable; written to the home dir"
	fi
	{
		echo "{"
		local first=1 k
		for k in $(printf '%s\n' "${!R[@]}" | sort); do
			[ "$first" = 1 ] || echo ","
			first=0
			printf '  %s: %s' "$(json_escape "$k")" "$(json_escape "${R[$k]}")"
		done
		echo
		echo "}"
	} >"$RECEIPT"
	RECEIPT_WRITTEN=1
	echo "receipt: $RECEIPT"
}
judge() {
	R["check.$1"]="$2"
	[ -n "${3:-}" ] && R["check.$1.detail"]="$3"
	[ "$2" = pass ] || FAIL=1
	return 0
}
refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	EXIT_CODE=2
	exit 2
}
cleanup() {
	local rc=$? c
	set +e
	[ -n "$EXIT_CODE" ] || EXIT_CODE=$rc
	if [ "$HELP" = 1 ]; then exit 0; fi
	if [ "$EXIT_CODE" != 2 ]; then
		# Any stop before the end is a failed run, whatever was judged so
		# far, and every check a pass needs must be present and pass (O5
		# audit finding O5-A1: an abort after the first check exited 0).
		if [ "$COMPLETED" = 0 ]; then
			R[aborted]="the script stopped early (exit $rc); the checks after the last one recorded did not run"
			FAIL=1
		fi
		for c in $JUDGED; do
			if [ -z "${R[check.$c]:-}" ]; then
				R["check.$c"]="not_run"
				R["check.$c.detail"]="not judged: the script stopped before this check"
				FAIL=1
			elif [ "${R[check.$c]}" != pass ]; then
				FAIL=1
			fi
		done
	fi
	R[completed]="$([ "$COMPLETED" = 1 ] && echo yes || echo no)"
	if [ "$OBSDIR_MADE" = 1 ] && [ -d "$OBSDIR" ] && [ -n "$WORK" ]; then
		mv "$OBSDIR" "$WORK/observer-dir" && R[cleanup.observer_dir]="moved to the work dir"
	fi
	R[finished]="$(date -u +%Y%m%dT%H%M%SZ)"
	[ "$RECEIPT_WRITTEN" = 1 ] || write_receipt
	if [ "$EXIT_CODE" = 2 ]; then exit 2; fi
	exit "$FAIL"
}
trap cleanup EXIT

while [ $# -gt 0 ]; do
	case "$1" in
	--observer) [ $# -ge 2 ] || refuse "--observer needs a path"; OBSERVER="$2"; shift 2 ;;
	--out)
		[ $# -ge 2 ] || refuse "--out needs a directory"
		OUT="$2"
		RECEIPT="$OUT/o5-wsl2-expected-failure-o5-l2-$STAMP.json"
		shift 2
		;;
	--observer-dir) [ $# -ge 2 ] || refuse "--observer-dir needs a path"; OBSDIR="$2"; shift 2 ;;
	-h | --help) sed -n '2,62p' "$0"; RECEIPT_WRITTEN=1; HELP=1; exit 0 ;;
	*) refuse "unknown argument $1" ;;
	esac
done
# The config names the database by an absolute path.
case "$OBSDIR" in /*) ;; *) OBSDIR="$PWD/$OBSDIR" ;; esac

[ "$(id -u)" != 0 ] || refuse "run as a normal user, not root"
[ "$(uname -s)" = Linux ] || refuse "this row runs inside a WSL2 distro (Linux)"
if grep -qi microsoft /proc/version 2>/dev/null; then
	judge wsl2_detected pass
else
	refuse "this host is not WSL2 (/proc/version names no microsoft kernel); O5-L2 proves nothing here, run O5-L1 instead"
fi
R[host.kernel]="$(uname -r)"
command -v python3 >/dev/null || refuse "python3 is needed to read the status JSON"
[ -e "$OBSDIR" ] && refuse "$OBSDIR exists; pass --observer-dir with a throwaway path that does not exist yet"
WORK="$(mktemp -d "${HOME}/o5-wsl2-XXXXXX")"
chmod 700 "$WORK"

if [ -z "$OBSERVER" ]; then
	command -v go >/dev/null || refuse "no --observer and no go toolchain to build one"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/observer-bin" ./cmd/observer) || refuse "go build failed"
	OBSERVER="$WORK/observer-bin"
fi
OBSERVER="$(readlink -f "$OBSERVER")"
# `observer --version` prints "observer version <v>"; the receipt keeps <v>.
R[observer.version]="$({ "$OBSERVER" --version 2>/dev/null || true; } | awk 'NR == 1 { print $NF }')"
[ -n "${R[observer.version]}" ] || R[observer.version]=unknown

mkdir -p "$OBSDIR"
OBSDIR_MADE=1
CONFIG="$OBSDIR/config.toml"
cat >"$CONFIG" <<EOF
[observer]
db_path = "$OBSDIR/observer.db"

[observer.hooks]
auto_register = false

[terminal.sandbox]
enabled = true
backends = ["bwrap", "openshell"]

[components]
add = ["terminals.sandbox.openshell"]
EOF

# run_dirs DIR prints the run dirs under the row's state dir in the Observer
# dir DIR, one per line, sorted (nothing when there are none).
run_dirs() { find "$1/sandbox-openshell/runs" -mindepth 1 -maxdepth 1 2>/dev/null | sort || true; }
HOME_OBS="$HOME/.observer"
both_run_dirs() {
	run_dirs "$OBSDIR"
	[ "$HOME_OBS" = "$OBSDIR" ] || run_dirs "$HOME_OBS"
}
RUNS_BEFORE="$(both_run_dirs | sort)"

# The status call: its exit code is recorded, and its stdout is read from a
# file, so a status that fails never makes this script abort or read two
# JSON documents (O5 audit finding O5-A1).
STATUS_RC=0
"$OBSERVER" sandbox status --json --config "$CONFIG" >"$WORK/status.json" 2>"$WORK/status.err" || STATUS_RC=$?
R[status.exit]="$STATUS_RC"
ROWJSON="$(python3 -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    for b in d.get("backends") or []:
        if b.get("id")=="openshell":
            print(json.dumps({"available": b.get("available"), "verdict": b.get("verdict",""), "reason": b.get("reason","")})); break
    else:
        print(json.dumps({"absent": True}))
except Exception:
    print(json.dumps({"unreadable": True}))' "$WORK/status.json")"
field() {
	printf '%s' "$ROWJSON" | python3 -I -c 'import json,sys
try:
    print(json.load(sys.stdin).get(sys.argv[1], ""))
except Exception:
    print("")' "$1"
}
R[row.available]="$(field available)"
R[row.verdict]="$(field verdict)"
R[row.reason]="$(field reason | cut -c1-300)"
if [ "$STATUS_RC" = 0 ] && [ "${R[row.available]}" = False ] && [ "${R[row.verdict]}" = unsupported_platform ]; then
	judge row_refused_unsupported_platform pass
else
	judge row_refused_unsupported_platform fail "status exit $STATUS_RC, available ${R[row.available]:-?}, verdict ${R[row.verdict]:-none} (status stderr: $(head -c 200 "$WORK/status.err" | tr '\n' ' '))"
fi
case "${R[row.reason]}" in
*WSL2*ENOSYS*) judge reason_names_wsl2 pass ;;
*) judge reason_names_wsl2 fail "reason: ${R[row.reason]:-none}" ;;
esac
RUNS_AFTER="$(both_run_dirs | sort)"
NEW_RUNS="$(comm -13 <(printf '%s\n' "$RUNS_BEFORE") <(printf '%s\n' "$RUNS_AFTER") | sed '/^$/d' | wc -l | tr -d ' ')"
R[runs.dirs_checked]="the row's state dir under the configured Observer dir$([ "$HOME_OBS" = "$OBSDIR" ] || echo " and under ~/.observer")"
[ "$NEW_RUNS" = 0 ] && judge no_run_dir_made pass || judge no_run_dir_made fail "$NEW_RUNS run dirs appeared across the status call"

# Facts only: what the canary and OpenShell's doctor say here.
IMAGE="ghcr.io/nvidia/openshell/supervisor:0.1.6"
if command -v docker >/dev/null && docker image inspect "$IMAGE" >/dev/null 2>&1; then
	R[fact.canary]="$( { timeout 60 docker run --rm --network none --pull never --read-only --cap-drop ALL \
		--security-opt no-new-privileges:true --user "$(id -u):$(id -g)" \
		--mount "type=bind,source=$OBSERVER,target=/observer-canary,readonly" \
		--entrypoint /observer-canary "$IMAGE" sandbox-openshell-canary 2>&1 || true; } | head -n 1 | cut -c1-200)"
	R[fact.canary.expected]="-1 38 (ENOSYS: Docker's default seccomp profile blocks the Landlock syscalls)"
else
	R[fact.canary]="not run: docker or the supervisor image $IMAGE is not on this machine (the script never pulls)"
fi
if command -v openshell >/dev/null; then
	R[fact.openshell_doctor]="$( (timeout 60 openshell doctor check 2>&1 || true) | head -n 1 | cut -c1-200)"
else
	R[fact.openshell_doctor]="not run: no openshell CLI on PATH"
fi

COMPLETED=1
