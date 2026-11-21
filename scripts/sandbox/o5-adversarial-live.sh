#!/usr/bin/env bash
# o5-adversarial-live.sh: lane O5's live check of the openshell row's
# adversarial rows (live register row O5-L1): the A1 to A13 cases of the
# sandbox plan v2 section 13.12 that need a live host, map in
# docs/plans/openshell/build/o5-sweep.md ("A rows").
#
# Runs unattended on a FRESH native Linux VM (amd64 Ubuntu 24.04, Docker
# Engine with this user in the docker group, OpenShell v0.1.6 from its
# tagged installer, a systemd user manager: an SSH login or lingering) as a
# normal user. It writes ONE receipt on every exit (a bad argument and an
# existing ~/.observer included) with no secret and no address other than
# loopback in it: a provider's resolved address is written only into the
# throwaway workspace for the box to dial, never into the receipt.
#
# It never installs anything, never edits the user's gateway config, never
# reads a key, a token, a certificate or a credential store, never uses a
# provider credential and never prints an environment value.
#
# Two modes, one per invocation, as the earlier lanes' scripts:
#   managed (the default): Observer's private gateway (decision D2). The
#     operator applies nothing.
#   --external: the user's own gateway, with the operator's precondition of
#     scripts/sandbox/o3-openshell-egress-live.sh --external (the
#     bind-mount opt-in and the OCSF export in the gateway's own config;
#     Observer never writes that file, decision D3).
#
# Phase 1 (unless --skip-earlier): the earlier lanes' live scripts, in this
# mode, each with its own receipt under the work dir, recorded here by exit
# code and their A-row checks copied in:
#   managed:  o2-openshell-managed-live.sh (O2-L1), then
#             o3-openshell-egress-live.sh (O3-L1 managed);
#   external: o1b-openshell-live.sh (O1B-L1), then
#             o3-openshell-egress-live.sh --external (O3-L1 external).
# Each of them refuses an existing ~/.observer and moves its own aside on
# exit, so they run back to back; this script's own phase starts after them
# over a fresh ~/.observer of its own.
#
# Phase 2 (one daemon, two boxed runs, Claude Code's launcher with the
# script in the workspace as its "tool", scripts/sandbox/o3probe as the
# in-box client because the default box image has no curl, wget or
# python3):
#   run 1, proxy_only tier:
#     A1   a direct request to api.anthropic.com and to a literal IPv4
#          address it resolves to on the host both fail, judged only on the
#          in-box probe's own outcome line (no line, or its exit 99, is
#          not_run, never a pass); the model proxy answers through the
#          relay;
#     A10  the agent cannot rewrite or delete ~/.claude/settings.json (a
#          protected path, bound read-only), and the host file is unchanged
#          (a fixed seed is written first when the host has none, and
#          removed by the cleanup, so the host half always compares);
#     A2   the daemon is killed with SIGKILL while the box runs, under this
#          SHELL launch (whose host helper does not depend on the daemon;
#          the dashboard-launch case, where the daemon owns the helper, is
#          O1B/O2's helper kill): the box stays (no unreapable state),
#          observer.db passes integrity_check, a restarted daemon serves
#          again, the run ends with the agent's own exit code, and no box
#          of this install is left (the gateway answers the box not found
#          and a list that was read shows none; a failed list or get is
#          never read as gone);
#   run 2, internet tier with the host list "api.github.com":
#     A1   the same two direct provider requests fail on the internet tier,
#          judged the same way;
#   A11  no container image was made by either run (a new image is allowed
#        only when it is an OpenShell image the gateway pulled, tagged from
#        ghcr.io/nvidia/openshell or nvcr.io/nvidia), and no image carries
#        an Observer label.
# Phase 3 (no box):
#   A9   (managed mode) a sandbox status with DOCKER_HOST=tcp://127.0.0.1:9
#        refuses the row with verdict gateway_supervisor_no_docker_access
#        and a reason naming DOCKER_HOST; a symlinked unix socket to the
#        same engine is recorded as a fact (the row compares sockets as
#        files, by design, lane OC; o5-sweep.md "A rows" A9);
#   A12  an openshell CLI that reports another version (a shim ahead on
#        PATH that answers --version with 0.1.5 and runs the real CLI
#        otherwise) refuses the row with a version verdict.
#
# Not in this script (o5-sweep.md "A rows" says where each one lives): A3
# (a host suspend and network cuts need root and a host that survives them;
# owed as operator-attended), A4, A5, A6, A7, A8 and A13 (tests, and the
# earlier scripts' checks copied in).
#
# Judging: each check is pass, fail or not_run with the reason; a not_run
# counts as a failed run, never as a pass.
#
# Usage:
#   scripts/sandbox/o5-adversarial-live.sh [--observer PATH] [--probe PATH]
#       [--out DIR] [--external] [--skip-earlier]
#
#   --observer PATH   the observer binary, a static build (CGO_ENABLED=0;
#                     default: build one from this tree); passed on to every
#                     earlier script
#   --probe PATH      the in-box probe, a static Linux build of
#                     scripts/sandbox/o3probe (default: build one); passed on
#                     to O3-L1
# Without a go toolchain both --observer and --probe are needed.
#   --out DIR         where the receipt goes (default: the current dir)
#   --external        the user's own gateway instead of Observer's private one
#   --skip-earlier    do not run phase 1 (the earlier scripts' receipts are
#                     then not part of this run, and their checks are absent)
#
# Exit 0 when every judged check passed, 1 when one failed or did not run,
# 2 on a precondition the host does not meet (the receipt says which).
# shellcheck disable=SC2015,SC2329
# SC2015: every `COND && judge NAME pass || judge NAME fail` line is safe
# because judge always returns 0. SC2329: cleanup runs from the EXIT trap.
set -euo pipefail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROW="O5-L1"
OUT="$PWD"
RECEIPT="$OUT/o5-adversarial-live-o5-l1-$STAMP.json"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OBSERVER=""
PROBE=""
OBSDIR="$HOME/.observer"
OBSDIR_MADE=0
WORK=""
DASH="http://127.0.0.1:8081"
INSTALL_ID_FILE="$OBSDIR/sandbox-openshell/install-id"
CONFIG="$OBSDIR/config.toml"
MANAGED=1
EARLIER=1
DAEMON_PID=""
HOOK_FILE=""
HOOK_SEEDED=0

declare -A R # receipt fields (strings)
R[schema]="observer-o5-live/1"
R[row]="$ROW"
R[started]="$STAMP"
FAIL=0
RECEIPT_WRITTEN=0
COMPLETED=0
EXIT_CODE=""

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
	local alt
	if ! { : >"$RECEIPT"; } 2>/dev/null; then
		alt="$HOME/$(basename "$RECEIPT")"
		if ! { : >"$alt"; } 2>/dev/null; then
			alt="$(mktemp "${TMPDIR:-/tmp}/o5-adversarial-live-XXXXXX.json")"
		fi
		R[receipt.fallback]="could not write $RECEIPT; written to $alt instead"
		RECEIPT="$alt"
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
judge() { # judge NAME pass|fail DETAIL
	R["check.$1"]="$2"
	[ -n "${3:-}" ] && R["check.$1.detail"]="$3"
	[ "$2" = pass ] || FAIL=1
	return 0
}
not_run() {
	R["check.$1"]="not_run"
	R["check.$1.detail"]="$2"
	FAIL=1
}
refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	EXIT_CODE=2
	exit 2
}
install_id() {
	[ -f "$INSTALL_ID_FILE" ] || return 0
	tr -d '\n' <"$INSTALL_ID_FILE" 2>/dev/null || true
}
gw_short() { local id; id="$(install_id)"; printf '%s' "${id:0:12}"; }
gw_name() { [ -n "$(gw_short)" ] && printf 'observer-%s' "$(gw_short)"; }
gw_unit() { [ -n "$(gw_short)" ] && printf 'observer-openshell-gateway-%s.service' "$(gw_short)"; }
gw_rtdir() { [ -n "$(gw_short)" ] && printf '%s/observer-openshell-%s' "${XDG_RUNTIME_DIR:-/nonexistent}" "$(gw_short)"; }
osh() {
	command -v openshell >/dev/null || return 1
	if [ "$MANAGED" = 1 ]; then
		[ -n "$(gw_short)" ] || return 1
		XDG_CONFIG_HOME="$(gw_rtdir)/cli" openshell -g "$(gw_name)" "$@"
	else
		openshell "$@"
	fi
}
# list_boxes prints this install's boxes, one per line. It FAILS (exit 1,
# nothing printed) when the list could not be read (no install id, the
# gateway not answering, the list command failing), so a failed list is
# never read as "no box left" (O5 audit finding O5-A2).
list_boxes() {
	local id out
	id="$(install_id)"
	[ -n "$id" ] || return 1
	out="$(osh sandbox list --selector "observer.superbased.install=o${id}o" --names 2>/dev/null)" || return 1
	printf '%s\n' "$out" | grep '^sbo-' || true
}
# box_gone NAME: 0 when the gateway answers that the box does not exist
# (the version's exact not-found text, the O1B-L1 pattern); 1 when it is
# still there or the answer is not that one.
box_gone() {
	! osh sandbox get "$1" -o json >/dev/null 2>"$LOG/get-$1.err" &&
		grep -q "Some requested entity was not found" "$LOG/get-$1.err"
}
file_digest() { [ -f "$1" ] && sha256sum "$1" | cut -c1-16 || echo absent; }
# image_ids prints every local image id, one per line, sorted.
image_ids() { docker image ls -q --no-trunc 2>/dev/null | sort -u || true; }

cleanup() {
	local rc=$? left after n ustate
	set +e
	[ -n "$EXIT_CODE" ] || EXIT_CODE=$rc
	if [ "$RECEIPT_WRITTEN" = 0 ] && [ "$rc" != 0 ] && [ "$EXIT_CODE" != 2 ] && [ "$COMPLETED" = 0 ]; then
		R[aborted]="the script stopped early (exit $rc); the checks after the last one recorded did not run"
		FAIL=1
	fi
	if [ "$OBSDIR_MADE" = 1 ]; then
		if left="$(list_boxes)"; then
			left="$(printf '%s' "$left" | tr '\n' ' ')"
			R[cleanup.left_boxes]="${left:-none}"
		else
			left=""
			R[cleanup.left_boxes]="the list could not be read"
		fi
		if [ -n "$left" ]; then
			for n in $left; do osh sandbox delete "$n" >/dev/null 2>&1; done
			after="$(list_boxes | tr '\n' ' ')"
			R[cleanup.after_delete]="${after:-none}"
		fi
	fi
	if [ -n "$DAEMON_PID" ]; then
		kill "$DAEMON_PID" 2>/dev/null
		wait "$DAEMON_PID" 2>/dev/null
	fi
	if [ "$OBSDIR_MADE" = 1 ] && [ "$MANAGED" = 1 ] && [ -n "$(gw_unit)" ]; then
		ustate="$(systemctl --user is-active "$(gw_unit)" 2>/dev/null)"
		if [ "$ustate" != inactive ]; then
			systemctl --user stop "$(gw_unit)" >/dev/null 2>&1
			systemctl --user reset-failed "$(gw_unit)" >/dev/null 2>&1
			R[cleanup.gateway_unit]="was ${ustate:-unknown}; stopped by the cleanup"
		else
			R[cleanup.gateway_unit]="not running"
		fi
		[ -e "$(gw_rtdir)" ] && rm -rf "$(gw_rtdir)" && R[cleanup.gateway_ram_dir]="removed by the cleanup"
	fi
	for n in $(jobs -p); do kill "$n" 2>/dev/null; done
	wait 2>/dev/null
	if [ "$HOOK_SEEDED" = 1 ] && [ -n "$HOOK_FILE" ]; then
		rm -f "$HOOK_FILE" && R[cleanup.hook_seed]="the seeded ~/.claude/settings.json was removed"
	fi
	if [ "$OBSDIR_MADE" = 1 ] && [ -d "$OBSDIR" ] && [ -n "$WORK" ]; then
		mv "$OBSDIR" "$WORK/observer-dir" && R[cleanup.observer_dir]="moved to the work dir"
	fi
	R[finished]="$(date -u +%Y%m%dT%H%M%SZ)"
	R[completed]="$([ "$COMPLETED" = 1 ] && echo yes || echo no)"
	[ "$RECEIPT_WRITTEN" = 1 ] || write_receipt
	if [ "$EXIT_CODE" = 2 ]; then exit 2; fi
	exit "$FAIL"
}
trap cleanup EXIT

while [ $# -gt 0 ]; do
	case "$1" in
	--observer) [ $# -ge 2 ] || refuse "--observer needs a path"; OBSERVER="$2"; shift 2 ;;
	--probe) [ $# -ge 2 ] || refuse "--probe needs a path"; PROBE="$2"; shift 2 ;;
	--out)
		[ $# -ge 2 ] || refuse "--out needs a directory"
		OUT="$2"
		RECEIPT="$OUT/o5-adversarial-live-o5-l1-$STAMP.json"
		shift 2
		;;
	--external) MANAGED=0; shift ;;
	--skip-earlier) EARLIER=0; shift ;;
	-h | --help) sed -n '2,103p' "$0"; RECEIPT_WRITTEN=1; exit 0 ;;
	*) refuse "unknown argument $1" ;;
	esac
done
if ! { [ -d "$OUT" ] && [ -w "$OUT" ]; }; then
	R[receipt.fallback]="--out $OUT is not a writable directory; the receipt goes to $HOME"
	OUT="$HOME"
	RECEIPT="$OUT/o5-adversarial-live-o5-l1-$STAMP.json"
fi
R[mode]="$([ "$MANAGED" = 1 ] && echo managed || echo external)"

# ---- preconditions ----------------------------------------------------------
[ "$(id -u)" != 0 ] || refuse "run as a normal user, not root"
[ "$(uname -s)" = Linux ] || refuse "native Linux only"
if grep -qi microsoft /proc/version 2>/dev/null; then refuse "WSL2 is refused by design (row P1); the WSL2 run is O5-L2 (scripts/sandbox/o5-wsl2-expected-failure.sh)"; fi
for c in python3 curl docker openshell getent sha256sum; do
	command -v "$c" >/dev/null || refuse "$c is not on PATH (this script installs nothing)"
done
if [ "$MANAGED" = 1 ]; then
	command -v openshell-gateway >/dev/null || refuse "openshell-gateway is not on PATH (install the OpenShell v0.1.6 package)"
	command -v systemctl >/dev/null || refuse "systemctl is not on PATH (the managed gateway runs as a systemd user unit)"
	[ -n "${XDG_RUNTIME_DIR:-}" ] || refuse "XDG_RUNTIME_DIR is not set: log in through a systemd session (SSH) or enable lingering"
fi
[ -e "$OBSDIR" ] && refuse "$OBSDIR exists; run this on a throwaway host with no Observer state"
WORK="$(mktemp -d "${HOME}/o5-live-XXXXXX")"
chmod 700 "$WORK"
LOG="$WORK/log"
mkdir -p "$LOG" "$WORK/earlier"
R[host.kernel]="$(uname -r)"
R[host.docker]="$(docker version --format '{{.Server.Version}}' 2>/dev/null | tr -d '\n' || echo unreadable)"
R[host.docker_group]="$(id -nG | tr ' ' '\n' | grep -qx docker && echo true || echo false)"
R[host.openshell_cli]="$( (openshell --version 2>/dev/null || echo unreadable) | head -n 1)"

if [ -z "$OBSERVER" ]; then
	command -v go >/dev/null || refuse "no --observer and no go toolchain to build one"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/observer-bin" ./cmd/observer) || refuse "go build failed"
	OBSERVER="$WORK/observer-bin"
fi
OBSERVER="$(readlink -f "$OBSERVER")"
# `observer --version` prints "observer version <v>"; the receipt keeps <v>.
R[observer.version]="$({ "$OBSERVER" --version 2>/dev/null || true; } | awk 'NR == 1 { print $NF }')"
[ -n "${R[observer.version]}" ] || R[observer.version]=unknown
if [ -z "$PROBE" ]; then
	command -v go >/dev/null || refuse "no --probe and no go toolchain to build the in-box probe"
	(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux go build -o "$WORK/o3probe" ./scripts/sandbox/o3probe) || refuse "go build of the in-box probe failed"
	PROBE="$WORK/o3probe"
fi
PROBE="$(readlink -f "$PROBE")"

# ---- phase 1: the earlier lanes' scripts, in this mode -------------------------
# earlier NAME SCRIPT ARGS...: runs one earlier script into its own out dir,
# records its exit code and receipt, and judges it.
earlier() {
	local name="$1" script="$2" dir="$WORK/earlier/$1" rc=0 rcpt
	shift 2
	mkdir -p "$dir"
	"$HERE/$script" --observer "$OBSERVER" --out "$dir" "$@" >"$LOG/earlier-$name.txt" 2>&1 || rc=$?
	rcpt="$(find "$dir" -maxdepth 1 -name '*.json' | head -n 1)"
	R["earlier.$name.exit"]="$rc"
	R["earlier.$name.receipt"]="${rcpt:-none}"
	if [ "$rc" = 0 ]; then
		judge "earlier_$name" pass
	elif [ "$rc" = 2 ]; then
		not_run "earlier_$name" "$script refused a precondition: $(sed -n 's/^refused: //p' "$LOG/earlier-$name.txt" | head -n 1)"
	else
		judge "earlier_$name" fail "$script exit $rc; its receipt names the failed checks"
	fi
	[ -e "$OBSDIR" ] && refuse "$script left $OBSDIR behind; this script needs a fresh one"
	return 0
}
# earlier_check NAME CHECK AROW: copies one check of an earlier receipt into
# this receipt under the A row it proves.
earlier_check() {
	local rcpt="${R[earlier.$1.receipt]:-none}" v
	[ -f "$rcpt" ] || return 0
	v="$(python3 -I -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("check."+sys.argv[2], "absent"))
except Exception:
    print("unreadable")' "$rcpt" "$2")"
	R["arow.$3.$1.$2"]="$v"
}
if [ "$EARLIER" = 1 ]; then
	if [ "$MANAGED" = 1 ]; then
		earlier o2_l1 o2-openshell-managed-live.sh
		earlier o3_l1 o3-openshell-egress-live.sh --probe "$PROBE"
		earlier_check o2_l1 reaper_removes_killed_run A2
		earlier_check o2_l1 managed_survives_daemon_restart A4
		earlier_check o2_l1 box_gone_after_exit A7
		earlier_check o2_l1 managed_stops_when_not_wanted A7
	else
		earlier o1b_l1 o1b-openshell-live.sh
		earlier o3_l1 o3-openshell-egress-live.sh --external --probe "$PROBE"
		earlier_check o1b_l1 reaper_removes_killed_run A2
		earlier_check o1b_l1 box_gone_after_exit A7
	fi
	earlier_check o3_l1 ocsf_provider_host_row A1
	earlier_check o3_l1 model_proxy_reachable A1
	earlier_check o3_l1 receiver_loopback_only A5
else
	R[earlier]="skipped (--skip-earlier)"
fi

# ---- phase 2: this script's own boxed runs ---------------------------------------
mkdir -p "$OBSDIR"
OBSDIR_MADE=1
WS="$WORK/ws"
mkdir -p "$WS"
cp "$PROBE" "$WS/.o3probe" && chmod 755 "$WS/.o3probe" || refuse "could not place the in-box probe in the workspace"
# A provider's literal IPv4 address, resolved on the host, written only into
# the workspace for the box to dial (never into the receipt).
PROVIDER_IP="$(getent ahostsv4 api.anthropic.com 2>/dev/null | awk 'NR == 1 { print $1 }' || true)"
if [ -n "$PROVIDER_IP" ]; then
	printf '%s\n' "$PROVIDER_IP" >"$WS/.o5-provider-ip"
	R[a1.provider_ip]="resolved on the host (not recorded)"
else
	R[a1.provider_ip]="api.anthropic.com did not resolve on the host"
fi
unset PROVIDER_IP

# write_config TIER [HOSTS]
write_config() {
	{
		printf '[observer]\ndb_path = "%s/observer.db"\n\n[observer.hooks]\nauto_register = false\n\n' "$OBSDIR"
		printf '[terminal.sandbox]\nenabled = true\nbackends = ["openshell"]\negress = "%s"\n' "$1"
		if [ -n "${2:-}" ]; then printf 'egress_allow_hosts = [%s]\n' "$2"; fi
		printf '\n[components]\nadd = ["terminals.sandbox.openshell"]\n'
		if [ "$MANAGED" = 0 ]; then printf '\n[terminal.sandbox.openshell]\ngateway_mode = "external"\n'; fi
	} >"$CONFIG"
}
start_daemon() {
	"$OBSERVER" start >>"$LOG/daemon.log" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 1 60); do
		curl -fsS "$DASH/api/sandbox/refusals?limit=1" >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}
wait_available() {
	local st=""
	for _ in $(seq 1 24); do
		"$OBSERVER" sandbox status >"$LOG/status.txt" 2>&1 || true
		st="$(awk '$1 == "openshell" && NF >= 4 { print $4; exit }' "$LOG/status.txt" 2>/dev/null || true)"
		[ "$st" = available ] && return 0
		sleep 5
	done
	R[phase2.status]="${st:-not shown}"
	return 1
}

AGENT="$WS/agent.sh"
cat >"$AGENT" <<'EOS'
#!/bin/sh
# Prints O5 markers only, never a body, an address or an environment value.
DIR="$(dirname "$0")"
P="$DIR/.o3probe"
BODY="$DIR/.o5-body"
echo "O5:proxied=$( [ -n "${HTTPS_PROXY:-${https_proxy:-}}" ] && echo yes || echo no)"
fetch() { # fetch NAME URL HOST
	if [ ! -x "$P" ]; then echo "O5:$1=none"; return; fi
	: >"$BODY"
	out="$("$P" fetch -o "$BODY" -m 15 "$2" 2>/dev/null)"
	# ran: the probe printed its outcome line, the positive evidence that
	# it made the request (O5 audit finding O5-A2).
	ran=yes
	[ -n "$out" ] || { out="000,000,99"; ran=no; }
	echo "O5:$1_ran=$ran"
	pd=no
	grep -q policy_denied "$BODY" 2>/dev/null && pd=yes
	res=no
	"$P" resolve "$3" >/dev/null 2>&1 && res=yes
	echo "O5:$1=$out,$res,$pd"
}
fetch provider https://api.anthropic.com/ api.anthropic.com
IP="$(head -c 64 "$DIR/.o5-provider-ip" 2>/dev/null | tr -cd '0-9.')"
if [ -n "$IP" ]; then fetch provider_ip "https://$IP/" "$IP"; else echo "O5:provider_ip=none"; fi
if [ -x "$P" ]; then
	: >"$BODY"
	code="$("$P" fetch -noproxy -o "$BODY" -m 10 http://127.0.0.1:8820/-/healthz 2>/dev/null | cut -d, -f1)"
	echo "O5:model_proxy=${code:-000},$( [ "$(cat "$BODY" 2>/dev/null)" = '{"status":"ok"}' ] && echo observer || echo other)"
fi
rm -f "$BODY"
F="$HOME/.claude/settings.json"
if [ -e "$F" ]; then
	if (printf '\n' >>"$F") 2>/dev/null; then echo "O5:hook_write=written"; else echo "O5:hook_write=refused"; fi
	if rm -f "$F" 2>/dev/null && [ ! -e "$F" ]; then echo "O5:hook_delete=deleted"; else echo "O5:hook_delete=refused"; fi
else
	echo "O5:hook_write=absent"
fi
echo "O5:ready=1"
read -r _line
exit 42
EOS
chmod 755 "$AGENT"

# ptyrun OUT: one launch on a PTY; a newline is sent only once OUT.release
# exists, so the host decides when the agent ends. The exit code goes to
# OUT.code.
ptyrun() {
	local out="$1"
	(cd "$WS" && python3 -I - "$OBSERVER" "$AGENT" "$out" <<'PY'
import os, pty, sys, time, select, fcntl, termios, struct
obs, agent, out = sys.argv[1:4]
argv = [obs, "claude", "--claude-path", agent, "--observer-sandbox", "openshell"]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
    os.execv(obs, argv)
log = open(out, "wb")
buf = b""; sent = False; deadline = time.time() + 900
while time.time() < deadline:
    if not sent and b"O5:ready=1" in buf and os.path.exists(out + ".release"):
        os.write(fd, b"\n"); sent = True
    r, _, _ = select.select([fd], [], [], 1)
    if fd in r:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        log.write(chunk); log.flush()
    else:
        try:
            wpid, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if wpid:
            break
try:
    _, status = os.waitpid(pid, 0)
except ChildProcessError:
    status = 0
log.close()
open(out + ".code", "w").write(str(os.waitstatus_to_exitcode(status)))
PY
	)
}
marker() {
	[ -f "$1" ] || return 0
	tr -d '\r' <"$1" | sed -n "s/^.*O5:$2=//p" | head -n 1
}
# reached FACTS: yes when a direct request went through (an HTTP answer, a
# CONNECT 200, or a TLS-level outcome after a connect, with no policy_denied
# body), no when it failed, unknown when the facts show no outcome: the
# probe's exit 99 (it printed nothing, or could not build the request; the
# agent's own fallback is 000,000,99) or a missing field. A1 passes only on
# no; unknown is never a pass (O5 audit finding O5-A2, the same reading as
# O3-L1's verdict table row "000,000,99").
reached() {
	local code connect exitc res pd
	IFS=, read -r code connect exitc res pd <<<"$1"
	[ -n "$code" ] && [ "$code" != none ] || { echo unknown; return; }
	[ -n "$connect" ] && [ -n "$exitc" ] && [ -n "$res" ] && [ -n "$pd" ] || { echo unknown; return; }
	[ "$exitc" = 99 ] && { echo unknown; return; }
	[ "$pd" = yes ] && { echo no; return; }
	if [ "$connect" = 200 ]; then echo yes; return; fi
	if [ "$connect" = 000 ] && [ "$code" != 000 ] && [ "$code" != 403 ]; then echo yes; return; fi
	if [ "$connect" = 000 ] && [ "$code" = 000 ]; then
		case "$exitc" in 0 | 35 | 51 | 52 | 56 | 58 | 60) echo yes; return ;; esac
	fi
	echo no
}
# a1_judge RUN TIER: the two direct provider requests of one run.
a1_judge() {
	local run="$1" tier="$2" v k ran
	for k in provider provider_ip; do
		v="$(marker "$LOG/$run.out" "$k")"
		ran="$(marker "$LOG/$run.out" "${k}_ran")"
		R["$run.$k"]="${v:-absent}"
		R["$run.${k}_ran"]="${ran:-absent}"
		if [ -z "$v" ] || [ "$v" = none ]; then
			not_run "a1_${k}_direct_fails_${tier}" "the agent did not run this request (${v:-no marker}; for provider_ip: ${R[a1.provider_ip]})"
		elif [ "$ran" != yes ]; then
			not_run "a1_${k}_direct_fails_${tier}" "the in-box probe printed no outcome for this request (ran ${ran:-absent}, facts $v): no evidence it made the request"
		else
			case "$(reached "$v")" in
			no) judge "a1_${k}_direct_fails_${tier}" pass ;;
			yes) judge "a1_${k}_direct_fails_${tier}" fail "the request went through: $v" ;;
			*) not_run "a1_${k}_direct_fails_${tier}" "the probe's outcome is unknown: $v" ;;
			esac
		fi
	done
}

write_config proxy_only
start_daemon || refuse "the daemon did not serve its dashboard within 60s"
wait_available || refuse "the openshell row is not available here: ${R[phase2.status]} (see the earlier scripts' receipts)"
IMAGES_BEFORE="$(image_ids)"
mkdir -p "$HOME/.claude"
HOOK_FILE="$HOME/.claude/settings.json"
# A10's host half compares the host file before and after the run, so the
# file must exist: on a fresh host (hooks auto_register is off here) a
# fixed seed is written, and removed again by the cleanup (O5 audit finding
# O5-A3). A file the user already has is left as it is and only compared.
if [ ! -e "$HOOK_FILE" ]; then
	printf '{"o5_seed": "written by O5-L1 before run 1; removed by its cleanup"}\n' >"$HOOK_FILE"
	HOOK_SEEDED=1
	R[a10.host_settings]="seeded by this script (absent before)"
else
	R[a10.host_settings]="present before the run; compared only"
fi
R[a10.host_settings_before]="$(file_digest "$HOOK_FILE")"

# ---- run 1: proxy_only; A1, A10, then A2 (daemon SIGKILL mid-run) ---------------
ptyrun "$LOG/run1.out" &
RUN1=$!
for _ in $(seq 1 240); do
	grep -q "O5:ready=1" "$LOG/run1.out" 2>/dev/null && break
	kill -0 "$RUN1" 2>/dev/null || break
	sleep 1
done
if grep -q "O5:ready=1" "$LOG/run1.out" 2>/dev/null; then
	R[run1.agent_ran]=yes
	a1_judge run1 proxy_only
	MP="$(marker "$LOG/run1.out" model_proxy)"
	R[run1.model_proxy]="${MP:-absent}"
	[ "${MP%%,*}" = 200 ] && [ "${MP#*,}" = observer ] && judge a1_model_proxy_through_relay pass || judge a1_model_proxy_through_relay fail "the model proxy answered ${MP:-nothing}"
	R[a1.api_turns_row]="not judged: a turn that lands an api_turns row needs a working provider credential, which this script never uses (N3-L1 is the operator-attended check that does)"
	HW="$(marker "$LOG/run1.out" hook_write)"
	HD="$(marker "$LOG/run1.out" hook_delete)"
	R[run1.hook_write]="${HW:-absent}"
	R[run1.hook_delete]="${HD:-absent}"
	if [ "$HW" = absent ] || [ -z "$HW" ]; then
		not_run a10_protected_hook_file_read_only "the box had no ~/.claude/settings.json to tamper with (${HW:-no marker})"
	elif [ "$HW" = refused ] && [ "$HD" = refused ]; then
		judge a10_protected_hook_file_read_only pass
	else
		judge a10_protected_hook_file_read_only fail "write ${HW}, delete ${HD:-absent}"
	fi
	# A2: kill the daemon with no chance to clean up, while the box runs.
	# The box is named from a list that was read; a failed list names none
	# (O5 audit finding O5-A2).
	if BOX1="$(list_boxes)"; then
		BOX1="$(printf '%s\n' "$BOX1" | sed -n '1p')"
	else
		BOX1=""
		R[a2.list_before]="the list could not be read"
	fi
	R[a2.box_before]="${BOX1:-none}"
	kill -KILL "$DAEMON_PID" 2>/dev/null || true
	wait "$DAEMON_PID" 2>/dev/null || true
	DAEMON_PID=""
	sleep 3
	if [ -z "$BOX1" ]; then
		not_run a2_box_survives_daemon_kill "no box of run 1 was listed before the kill (${R[a2.list_before]:-the list was empty})"
	elif LB="$(list_boxes)" && printf '%s\n' "$LB" | grep -qx "$BOX1"; then
		judge a2_box_survives_daemon_kill pass
	elif osh sandbox get "$BOX1" -o json >/dev/null 2>&1; then
		judge a2_box_survives_daemon_kill pass "not listed, but the gateway answers a get for it"
	else
		judge a2_box_survives_daemon_kill fail "the box $BOX1 is neither listed nor answered by a get after the daemon was killed"
	fi
	INTEG="$(python3 -I -c 'import sqlite3,sys
try:
    c=sqlite3.connect("file:"+sys.argv[1]+"?mode=ro", uri=True, timeout=10)
    print(c.execute("PRAGMA integrity_check").fetchone()[0])
except Exception as e:
    print("unreadable: "+type(e).__name__)' "$OBSDIR/observer.db")"
	R[a2.integrity_check]="$INTEG"
	[ "$INTEG" = ok ] && judge a2_db_intact_after_daemon_kill pass || judge a2_db_intact_after_daemon_kill fail "integrity_check: $INTEG"
	if start_daemon; then judge a2_daemon_restarts pass; else judge a2_daemon_restarts fail "a restarted daemon did not serve its dashboard within 60s"; fi
	: >"$LOG/run1.out.release"
	wait "$RUN1" || true
	R[run1.exit_code]="$(cat "$LOG/run1.out.code" 2>/dev/null || echo none)"
	[ "${R[run1.exit_code]}" = 42 ] && judge a2_run_ends_with_its_own_code pass || judge a2_run_ends_with_its_own_code fail "exit ${R[run1.exit_code]}, want the agent's 42"
	# No box left: the gateway answers run 1's box not found (the version's
	# exact text) AND a list that was read shows none of the install's. A
	# list or get that fails is never read as "gone" (O5 audit finding
	# O5-A2).
	if [ -z "$BOX1" ]; then
		not_run a2_no_box_left "no box of run 1 was listed before the kill, so there is no box to show gone"
	else
		GONE=0 LAST=""
		for _ in $(seq 1 24); do
			if box_gone "$BOX1"; then
				if LB="$(list_boxes)"; then
					[ -z "$LB" ] && { GONE=1; break; }
					LAST="still listed: $(printf '%s' "$LB" | tr '\n' ' ')"
				else
					LAST="the list could not be read"
				fi
			else
				LAST="the get of $BOX1 did not answer not found: $(head -c 200 "$LOG/get-$BOX1.err" 2>/dev/null | tr '\n' ' ')"
			fi
			sleep 5
		done
		[ "$GONE" = 1 ] && judge a2_no_box_left pass || judge a2_no_box_left fail "after 120s: $LAST"
	fi
else
	R[run1.agent_ran]=no
	R[run1.output_head]="$(tr -d '\r' <"$LOG/run1.out" 2>/dev/null | grep -m 1 -iE 'refused|not available|terminal_sandbox:' | cut -c1-300)"
	for c in a1_provider_direct_fails_proxy_only a1_provider_ip_direct_fails_proxy_only a1_model_proxy_through_relay a10_protected_hook_file_read_only a2_box_survives_daemon_kill a2_db_intact_after_daemon_kill a2_daemon_restarts a2_run_ends_with_its_own_code a2_no_box_left; do
		not_run "$c" "the agent never ran in the box: ${R[run1.output_head]:-no refusal line}"
	done
	: >"$LOG/run1.out.release"
	wait "$RUN1" || true
fi
R[a10.host_settings_after]="$(file_digest "$HOOK_FILE")"
# The host half is judged whenever the agent ran, whatever the box half
# said, and never on a missing file (O5 audit finding O5-A3).
if [ "${R[run1.agent_ran]:-no}" != yes ]; then
	not_run a10_host_hook_file_unchanged "the agent never ran in the box, so nothing tried to change the host file"
elif [ "${R[a10.host_settings_before]}" = absent ]; then
	not_run a10_host_hook_file_unchanged "the host ~/.claude/settings.json was absent before the run, so there was nothing to compare"
elif [ "${R[a10.host_settings_after]}" = "${R[a10.host_settings_before]}" ]; then
	judge a10_host_hook_file_unchanged pass
else
	judge a10_host_hook_file_unchanged fail "before ${R[a10.host_settings_before]}, after ${R[a10.host_settings_after]}"
fi

# ---- run 2: internet tier; A1 again ---------------------------------------------
if [ -n "$DAEMON_PID" ]; then
	kill "$DAEMON_PID" 2>/dev/null || true
	wait "$DAEMON_PID" 2>/dev/null || true
	DAEMON_PID=""
fi
write_config internet '"api.github.com"'
if start_daemon && wait_available; then
	ptyrun "$LOG/run2.out" &
	RUN2=$!
	for _ in $(seq 1 240); do
		grep -q "O5:ready=1" "$LOG/run2.out" 2>/dev/null && break
		kill -0 "$RUN2" 2>/dev/null || break
		sleep 1
	done
	if grep -q "O5:ready=1" "$LOG/run2.out" 2>/dev/null; then
		# a1_judge requires the probe's own outcome line for each request
		# (provider_ran=yes), the run-2 evidence that the probe ran; the
		# proxy facts are recorded beside it (O5 audit finding O5-A2).
		R[run2.proxied]="$(marker "$LOG/run2.out" proxied)"
		R[run2.model_proxy]="$(marker "$LOG/run2.out" model_proxy)"
		a1_judge run2 internet
	else
		R[run2.output_head]="$(tr -d '\r' <"$LOG/run2.out" 2>/dev/null | grep -m 1 -iE 'refused|not available|terminal_sandbox:' | cut -c1-300)"
		not_run a1_provider_direct_fails_internet "the agent never ran in the box: ${R[run2.output_head]:-no refusal line}"
		not_run a1_provider_ip_direct_fails_internet "the agent never ran in the box"
	fi
	: >"$LOG/run2.out.release"
	wait "$RUN2" || true
else
	not_run a1_provider_direct_fails_internet "the daemon or the row was not ready for the internet run (${R[phase2.status]:-dashboard down})"
	not_run a1_provider_ip_direct_fails_internet "the daemon or the row was not ready for the internet run"
fi

# ---- A11: no image made ------------------------------------------------------------
for _ in $(seq 1 24); do
	LB="" && LB="$(list_boxes)" && [ -z "$LB" ] && break
	sleep 5
done
IMAGES_AFTER="$(image_ids)"
NEW="$(comm -13 <(printf '%s\n' "$IMAGES_BEFORE") <(printf '%s\n' "$IMAGES_AFTER") | sed '/^$/d')"
LABELLED="$(docker image ls -q --filter label=observer.superbased.run 2>/dev/null | tr '\n' ' ')"
BAD=""
for id in $NEW; do
	tags="$(docker image inspect --format '{{join .RepoTags " "}}' "$id" 2>/dev/null || true)"
	case " $tags" in
	*" ghcr.io/nvidia/openshell/"* | *" nvcr.io/nvidia/"*) R[a11.new_image.${id:7:12}]="pulled: $tags" ;;
	*) BAD="$BAD ${id:7:12}(${tags:-untagged})" ;;
	esac
done
R[a11.new_images]="$(printf '%s\n' "$NEW" | sed '/^$/d' | wc -l | tr -d ' ')"
if [ -z "$BAD" ] && [ -z "$LABELLED" ]; then judge a11_no_image_made pass; else judge a11_no_image_made fail "new untagged or foreign images:${BAD:- none}; Observer-labelled: ${LABELLED:-none}"; fi

# ---- phase 3: no box; A9 and A12 -----------------------------------------------------
# status_row VAR=VALUE...: the openshell row of `observer sandbox status
# --json` run with the given environment, as "available verdict"; the row's
# reason goes to $LOG/status_row.reason. A status that fails reads as
# "unreadable" and never stops this script (the output is read from a file,
# not a pipe under pipefail).
status_row() {
	env "$@" "$OBSERVER" sandbox status --json >"$LOG/status_row.json" 2>/dev/null || true
	python3 -I -c 'import json,sys
reason=""
try:
    d=json.load(open(sys.argv[1]))
    for b in d.get("backends") or []:
        if b.get("id")=="openshell":
            reason=b.get("reason") or ""
            print("%s %s" % (b.get("available"), b.get("verdict") or "-")); break
    else:
        print("absent")
except Exception:
    print("unreadable")
open(sys.argv[2], "w").write(reason)' "$LOG/status_row.json" "$LOG/status_row.reason"
}
if [ "$MANAGED" = 1 ]; then
	# A9 must be the docker-access refusal (lifecycle row G9 over the D3
	# docker row), with a reason naming DOCKER_HOST: any other refusal (the
	# gateway not ready, for one) proves nothing about a tcp engine (O5
	# audit finding O5-A3).
	A9="$(status_row DOCKER_HOST=tcp://127.0.0.1:9)"
	R[a9.tcp_docker_host]="$A9"
	A9_NAMES="$(grep -q DOCKER_HOST "$LOG/status_row.reason" 2>/dev/null && echo yes || echo no)"
	R[a9.reason_names_docker_host]="$A9_NAMES"
	if [ "$A9" = "False gateway_supervisor_no_docker_access" ] && [ "$A9_NAMES" = yes ]; then
		judge a9_tcp_docker_host_refused pass
	else
		judge a9_tcp_docker_host_refused fail "the row with DOCKER_HOST=tcp://127.0.0.1:9 read: $A9 (reason names DOCKER_HOST: $A9_NAMES); want False gateway_supervisor_no_docker_access"
	fi
	if [ -S /var/run/docker.sock ]; then
		ln -s /var/run/docker.sock "$WORK/docker-link.sock"
		R[a9.symlinked_socket_fact]="$(status_row DOCKER_HOST="unix://$WORK/docker-link.sock") (the row compares sockets as files, lane OC: a link to the same socket is the same engine)"
	fi
else
	R[a9]="not run in external mode: the user's own gateway owns its engine, Observer passes it no DOCKER_HOST"
fi
mkdir -p "$WORK/shim"
REAL_OSH="$(command -v openshell)"
cat >"$WORK/shim/openshell" <<EOF
#!/bin/sh
case "\$1" in --version) echo "openshell 0.1.5"; exit 0 ;; esac
exec "$REAL_OSH" "\$@"
EOF
chmod 755 "$WORK/shim/openshell"
A12="$(status_row PATH="$WORK/shim:$PATH")"
R[a12.cli_reports_0_1_5]="$A12"
# Since lane FU7 (ledger row OSH-44) the shim, a user-owned file ahead on
# PATH, is refused before its version is read (openshell_binary_untrusted,
# probe row P2 or the managed gateway's row G11t); either refusal passes.
case "$A12" in
False\ openshell_version_mismatch | False\ openshell_untested | False\ openshell_too_old | False\ gateway_binary_version_mismatch | False\ openshell_binary_untrusted) judge a12_untested_version_refused pass ;;
*) judge a12_untested_version_refused fail "the row with a CLI reporting 0.1.5 read: $A12" ;;
esac
# The user-owned shim above now stops at the trust rule, so the version
# refusal itself is shown by a root-owned copy of the same shim (audit
# finding FU7-A8), placed with passwordless sudo in a root-owned dir no
# user can write. Without passwordless sudo it is recorded as not run (a
# fact, not a judged check, so a host without sudo is not failed); the
# unit tests (TestCheckVersion) still pin the version rows.
if sudo -n true 2>/dev/null; then
	ROOT_SHIM_DIR="/usr/local/lib/observer-o5-shim-$STAMP"
	if sudo -n install -d -o root -g root -m 0755 "$ROOT_SHIM_DIR" && sudo -n install -o root -g root -m 0755 "$WORK/shim/openshell" "$ROOT_SHIM_DIR/openshell"; then
		A12R="$(status_row PATH="$ROOT_SHIM_DIR:$PATH")"
		R[a12.root_owned_shim_reports_0_1_5]="$A12R"
		case "$A12R" in
		False\ openshell_version_mismatch | False\ openshell_untested | False\ openshell_too_old | False\ gateway_binary_version_mismatch) judge a12_root_owned_shim_version_refused pass ;;
		*) judge a12_root_owned_shim_version_refused fail "the row with a root-owned CLI reporting 0.1.5 read: $A12R" ;;
		esac
	else
		R[a12.root_owned_shim_reports_0_1_5]="not run: the root-owned shim could not be installed"
	fi
	sudo -n rm -rf "$ROOT_SHIM_DIR" 2>/dev/null || true
else
	R[a12.root_owned_shim_reports_0_1_5]="not run: no passwordless sudo on this host (the version refusal stays covered by the unit tests)"
fi

COMPLETED=1
