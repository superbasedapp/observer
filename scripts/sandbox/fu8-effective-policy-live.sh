#!/usr/bin/env bash
# fu8-effective-policy-live.sh: lane FU8's live check of the gateway policy
# reads (live register row FU8-L1, ledger OSH-40). It grounds the answer
# shapes of the three OpenShell v0.1.6 reads the code makes (`settings get
# --global`, `policy get --global --full -o json`, `policy get <box> --full
# -o json`) and judges the product against a gateway the operator widens on
# purpose. Its first run (2026-11-03) grounded those shapes; lane FU9 made
# the product read them (every unset setting prints as "<unset>", the
# global read answers a revision whose status is loaded or superseded) and
# fixed this script (`settings set` needs --yes on v0.1.6; --managed now
# stops the private gateway and removes its RAM dir on exit).
#
# Runs on a FRESH native Linux VM (amd64 Ubuntu 24.04, Docker Engine with
# this user in the docker group, OpenShell v0.1.6 from its tagged
# installer, a systemd user manager) as a normal user, with python3 and
# either go or a static observer build passed with --observer. NO existing
# ~/.observer (the script makes one and moves it aside on exit).
#
# Default mode is external: the user's own gateway, running, authenticated,
# with README step 1 of docs/sandbox-openshell.md applied in full: the
# bind-mount opt-in, [openshell.drivers.docker.resource_admission]
# enabled = false (0.1.6 refuses a box with a host bind while admission is
# on), and the OCSF export to 127.0.0.1:14317 ([openshell.gateway.otlp] and
# [openshell.gateway.otlp.ocsf], which the box half's internet tier needs;
# tracker F-051). The script changes that gateway's settings and global policy for
# the checks and puts them back on exit (it refuses to start unless the
# settings read manual approval, or unset, with proposals off, or unset).
# Putting a setting back writes its default explicitly (manual, false), so
# a later read shows that value where it showed <unset>; both read the
# same. --managed runs the settings checks against Observer's private
# gateway instead (the database drift half), and on exit stops that
# gateway's transient unit and removes its RAM dir; the box check is
# external only.
#
# It never installs anything, never edits a gateway.toml, never reads a
# key, a token, a certificate or a credential store, and writes ONE receipt
# on every exit with no secret and no address but loopback. Raw answers are
# kept under the work dir for the operator; the receipt holds only their
# shape (exit codes, JSON key names, the two setting values, the first
# line of a failed read).
#
# Checks:
#   shape_settings        `settings get --global` answered, naming both keys
#   shape_global_none     `policy get --global --full -o json` with none
#                         set: the answer the product reads as absent
#   ps_baseline           the openshell row is available (not refused at
#                         row PS or any other row)
#   ps_auto_approval      with proposal_approval_mode = auto the row is
#                         refused gateway_auto_approval
#   ps_proposals          with agent_policy_proposals_enabled = true the row
#                         is refused gateway_policy_proposals
#   ps_global_policy      with a global policy set the row is refused
#                         gateway_global_policy
#   ps_global_deleted     after `policy delete --global` (the revision now
#                         reads superseded) the row reads exactly as it
#                         did at ps_baseline
#   box_not_stopped       (external) a boxed internet run whose policy was
#                         not touched is still running after two of the
#                         watch's 30 s ticks (the effective read parses)
#   box_widened_stopped   (external) after `openshell policy set <box>` adds
#                         a host, the run ends within 90 s and its terminal
#                         names effective_policy_extra_host
#
# Usage: fu8-effective-policy-live.sh [--managed] [--observer PATH] [--out DIR]
# Exit 0 when every judged check passed, 1 when one failed or did not run,
# 2 on a precondition the host does not meet.
# shellcheck disable=SC2015,SC2329
set -euo pipefail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$PWD"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OBSERVER=""
OBSDIR="$HOME/.observer"
OBSDIR_MADE=0
CONFIG="$OBSDIR/config.toml"
INSTALL_ID_FILE="$OBSDIR/sandbox-openshell/install-id"
MANAGED=0
WORK=""
LOG=""
CHANGED_AUTO=0
CHANGED_PROPOSALS=0
CHANGED_GLOBAL=0
DAEMON_PID=""

declare -A R
R[schema]="observer-fu8-live/1"
R[row]="FU8-L1"
R[started]="$STAMP"
FAIL=0
RECEIPT=""
RECEIPT_WRITTEN=0

json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\r'/\\r}"
	s="${s//$'\t'/\\t}"
	s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
	printf '"%s"' "$s"
}
write_receipt() {
	[ -n "$RECEIPT" ] || RECEIPT="$OUT/fu8-effective-policy-live-fu8-l1-$STAMP.json"
	{ : >"$RECEIPT"; } 2>/dev/null || RECEIPT="$HOME/$(basename "$RECEIPT")"
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
not_run() { judge "$1" not_run "$2"; }
refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	exit 2
}
install_id() { [ -f "$INSTALL_ID_FILE" ] && tr -d '\n' <"$INSTALL_ID_FILE" 2>/dev/null || true; }
gw_short() { local id; id="$(install_id)"; printf '%s' "${id:0:12}"; }
osh() {
	if [ "$MANAGED" = 1 ]; then
		[ -n "$(gw_short)" ] || return 1
		XDG_CONFIG_HOME="${XDG_RUNTIME_DIR:-/nonexistent}/observer-openshell-$(gw_short)/cli" openshell -g "observer-$(gw_short)" "$@"
	else
		openshell "$@"
	fi
}
# set_setting KEY VALUE (v0.1.6 refuses a global setting update without
# --yes: "global setting updates require confirmation; pass --yes").
set_setting() { osh settings set --global --key "$1" --value "$2" --yes >>"$LOG/settings-set.log" 2>&1; }
global_delete() { osh policy delete --global --yes >>"$LOG/global.log" 2>&1 || yes | osh policy delete --global >>"$LOG/global.log" 2>&1; }
# stop_private_gateway: in --managed mode, stop Observer's private gateway
# (its transient user unit) and remove its RAM dir (the PKI copy and the
# key file), as the daemon does when no run holds it. Nothing else.
stop_private_gateway() {
	local short unit
	short="$(gw_short)"
	case "$short" in
	[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
	*)
		R[private_gateway]="not stopped: no install id"
		return 0
		;;
	esac
	unit="observer-openshell-gateway-$short.service"
	systemctl --user stop "$unit" >/dev/null 2>&1
	systemctl --user reset-failed "$unit" >/dev/null 2>&1
	R[private_gateway]="stopped $unit"
	if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "$XDG_RUNTIME_DIR/observer-openshell-$short" ]; then
		rm -rf -- "${XDG_RUNTIME_DIR:?}/observer-openshell-$short" && R[private_gateway]="${R[private_gateway]}; RAM dir removed"
	fi
	return 0
}

cleanup() {
	local rc=$?
	set +e
	[ "$CHANGED_AUTO" = 1 ] && set_setting proposal_approval_mode manual
	[ "$CHANGED_PROPOSALS" = 1 ] && set_setting agent_policy_proposals_enabled false
	[ "$CHANGED_GLOBAL" = 1 ] && global_delete
	R[restored]="auto=$CHANGED_AUTO proposals=$CHANGED_PROPOSALS global=$CHANGED_GLOBAL (each 1 was put back)"
	[ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
	[ "$MANAGED" = 1 ] && [ "$OBSDIR_MADE" = 1 ] && stop_private_gateway
	if [ "$OBSDIR_MADE" = 1 ] && [ -d "$OBSDIR" ]; then
		mv "$OBSDIR" "$WORK/observer-dir" 2>/dev/null && R[observer_dir]="moved to the work dir"
	fi
	R[exit]="$rc"
	R[completed]="${R[completed]:-0}"
	[ "$RECEIPT_WRITTEN" = 1 ] || write_receipt
}
trap cleanup EXIT

while [ $# -gt 0 ]; do
	case "$1" in
	--managed) MANAGED=1 ;;
	--observer) OBSERVER="$2"; shift ;;
	--out) OUT="$2"; shift ;;
	*) refuse "unknown argument $1" ;;
	esac
	shift
done
R[mode]="$([ "$MANAGED" = 1 ] && echo managed || echo external)"
[ -d "$OUT" ] && [ -w "$OUT" ] || OUT="$HOME"
[ "$(uname -s)" = Linux ] || refuse "not Linux"
grep -qi microsoft /proc/version 2>/dev/null && refuse "WSL2 (the row is refused there; O5-L2 covers it)"
command -v openshell >/dev/null || refuse "openshell is not on PATH"
command -v python3 >/dev/null || refuse "python3 is missing"
[ -e "$OBSDIR" ] && refuse "$OBSDIR exists; run on a fresh VM"
WORK="$(mktemp -d "$HOME/fu8-live-XXXXXX")"
LOG="$WORK/log"
mkdir -p "$LOG"
R[work_dir]="$WORK"
if [ -z "$OBSERVER" ]; then
	command -v go >/dev/null || refuse "no --observer and no go to build one"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/observer" ./cmd/observer) || refuse "the observer build failed"
	OBSERVER="$WORK/observer"
fi
# `observer --version` prints "observer version <v>"; the receipt keeps <v>.
R[observer_version]="$({ "$OBSERVER" --version 2>/dev/null || true; } | awk 'NR == 1 { print $NF }')"
[ -n "${R[observer_version]}" ] || R[observer_version]=unknown
R[openshell_version]="$(openshell --version 2>/dev/null | head -n 1 || true)"

mkdir -p "$OBSDIR"
OBSDIR_MADE=1
write_config() { # write_config TIER [HOSTS]
	{
		printf '[observer]\ndb_path = "%s/observer.db"\n\n[observer.hooks]\nauto_register = false\n\n' "$OBSDIR"
		printf '[terminal.sandbox]\nenabled = true\nbackends = ["openshell"]\negress = "%s"\n' "$1"
		[ -n "${2:-}" ] && printf 'egress_allow_hosts = [%s]\n' "$2"
		printf '\n[components]\nadd = ["terminals.sandbox.openshell"]\n'
		[ "$MANAGED" = 0 ] && printf '\n[terminal.sandbox.openshell]\ngateway_mode = "external"\n'
		true
	} >"$CONFIG"
}
# status_row: the openshell row of `observer sandbox status --json` as
# "available verdict".
status_row() {
	"$OBSERVER" sandbox status --json >"$LOG/status_row.json" 2>/dev/null || true
	python3 -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    for b in d.get("backends") or []:
        if b.get("id")=="openshell":
            print("%s %s" % (b.get("available"), b.get("verdict") or "-")); break
    else:
        print("absent")
except Exception:
    print("unreadable")' "$LOG/status_row.json"
}
# revision_status FILE: the "status" member of a `policy get --global
# --full -o json` answer (loaded, superseded), or why there is none.
revision_status() {
	python3 -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1]))
    print(d.get("status","no status") if isinstance(d,dict) else "not an object")
except Exception:
    print("not json")' "$1"
}
write_config proxy_only
# A first status starts the private gateway in managed mode (and makes the
# install id); the reads below need it.
R[status.first]="$(status_row)"

# ---- shapes ---------------------------------------------------------------------
set +e
osh settings get --global >"$LOG/settings.out" 2>"$LOG/settings.err"
R[shape.settings.exit]="$?"
osh policy get --global --full -o json >"$LOG/global.out" 2>"$LOG/global.err"
R[shape.global_none.exit]="$?"
set -e
python3 -I - "$LOG" <<'PY' >"$LOG/shape.env"
import json, sys, re
log = sys.argv[1]
def keys(path):
    try:
        d = json.load(open(path))
    except Exception:
        return "not json"
    if isinstance(d, dict):
        return "object:" + ",".join(sorted(d.keys())[:20])
    if isinstance(d, list):
        return "list:%d" % len(d)
    return type(d).__name__
s = open(log + "/settings.out", errors="replace").read()
print("settings_shape=" + keys(log + "/settings.out"))
for k in ("proposal_approval_mode", "agent_policy_proposals_enabled"):
    # v0.1.6 prints an unset value as <unset> (FU8-L1, 2026-11-03).
    m = re.search(k + r"""[\s:=|"']*([<>A-Za-z0-9_]+)""", s)
    print(k + "=" + (m.group(1) if m else "absent"))
print("global_shape=" + keys(log + "/global.out"))
err = open(log + "/global.err", errors="replace").read().strip().splitlines()
print("global_err_first=" + (err[0][:160] if err else ""))
PY
while IFS='=' read -r k v; do R["shape.$k"]="$v"; done <"$LOG/shape.env"
if [ "${R[shape.settings.exit]}" = 0 ] && [ "${R[shape.proposal_approval_mode]}" != absent ] && [ "${R[shape.agent_policy_proposals_enabled]}" != absent ]; then
	judge shape_settings pass
else
	judge shape_settings fail "exit ${R[shape.settings.exit]}, shape ${R[shape.settings_shape]}: the parser needs both keys named"
fi

BASE="$(status_row)"
R[status.baseline]="$BASE"
case "$BASE" in
*gateway_settings_unknown* | *gateway_auto_approval* | *gateway_policy_proposals* | *gateway_global_policy*)
	judge ps_baseline fail "the row read $BASE on an untouched gateway"
	judge shape_global_none fail "see ps_baseline (global read exit ${R[shape.global_none.exit]}, first line: ${R[shape.global_err_first]})"
	;;
True\ *)
	judge ps_baseline pass
	judge shape_global_none pass
	;;
*)
	# Audit FU12-A6: only an available row passes; absent, unreadable or a
	# refusal at another row cannot show PS passing an untouched gateway.
	judge ps_baseline fail "the row is not available: $BASE"
	not_run shape_global_none "the baseline row is not available ($BASE)"
	;;
esac
[ "${R[shape.proposal_approval_mode]}" = auto ] || [ "${R[shape.agent_policy_proposals_enabled]}" = true ] &&
	refuse "the gateway already approves automatically or takes proposals; this check changes them only from the defaults"

# ---- PS rows --------------------------------------------------------------------
if set_setting proposal_approval_mode auto; then
	CHANGED_AUTO=1
	S="$(status_row)"
	R[status.auto]="$S"
	[ "$S" = "False gateway_auto_approval" ] && judge ps_auto_approval pass || judge ps_auto_approval fail "read $S"
	set_setting proposal_approval_mode manual && CHANGED_AUTO=0
else
	not_run ps_auto_approval "settings set failed (see settings-set.log)"
fi
if set_setting agent_policy_proposals_enabled true; then
	CHANGED_PROPOSALS=1
	S="$(status_row)"
	R[status.proposals]="$S"
	[ "$S" = "False gateway_policy_proposals" ] && judge ps_proposals pass || judge ps_proposals fail "read $S"
	set_setting agent_policy_proposals_enabled false && CHANGED_PROPOSALS=0
else
	not_run ps_proposals "settings set failed (see settings-set.log)"
fi
printf 'version: 1\nfilesystem_policy:\n  read_only:\n    - "/usr"\n' >"$WORK/global.yaml"
if osh policy set --global --policy "$WORK/global.yaml" --yes >>"$LOG/global.log" 2>&1 ||
	yes | osh policy set --global --policy "$WORK/global.yaml" >>"$LOG/global.log" 2>&1; then
	CHANGED_GLOBAL=1
	sleep 12 # the global policy applies on the gateway's ~10 s poll
	osh policy get --global --full -o json >"$LOG/global-set.out" 2>/dev/null || true
	R[shape.global_set_status]="$(revision_status "$LOG/global-set.out")"
	S="$(status_row)"
	R[status.global]="$S"
	[ "$S" = "False gateway_global_policy" ] && judge ps_global_policy pass || judge ps_global_policy fail "read $S"
	if global_delete; then
		CHANGED_GLOBAL=0
		sleep 12
		osh policy get --global --full -o json >"$LOG/global-deleted.out" 2>/dev/null || true
		R[shape.global_deleted_status]="$(revision_status "$LOG/global-deleted.out")"
		S="$(status_row)"
		R[status.global_deleted]="$S"
		# Audit FU9-A2: the row must read exactly as it did at the baseline,
		# not merely lack the two verdicts (any other refusal is a fail).
		if [ "$S" = "$BASE" ]; then
			judge ps_global_deleted pass
		else
			judge ps_global_deleted fail "read $S after the delete; the baseline read $BASE"
		fi
	else
		not_run ps_global_deleted "policy delete --global failed (see global.log)"
	fi
else
	not_run ps_global_policy "policy set --global failed (see global.log)"
	not_run ps_global_deleted "no global policy was set"
fi

# ---- the box watch (external) ----------------------------------------------------
if [ "$MANAGED" = 1 ]; then
	R[box]="not run in managed mode: the watch runs for an external gateway"
	R[completed]=1
	exit "$FAIL"
fi
write_config internet '"github.com", "*.npmjs.org"'
WS="$WORK/ws"
mkdir -p "$WS"
cat >"$WS/agent.sh" <<'EOS'
#!/bin/sh
echo "FU8:ready=1"
read -r _line
exit 42
EOS
chmod 755 "$WS/agent.sh"
"$OBSERVER" start >>"$LOG/daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 8
OUTF="$LOG/box.out"
(cd "$WS" && python3 -I - "$OBSERVER" "$WS/agent.sh" "$OUTF" <<'PY'
import os, pty, sys, time, select
obs, agent, out = sys.argv[1:4]
pid, fd = pty.fork()
if pid == 0:
    os.execv(obs, [obs, "claude", "--claude-path", agent, "--observer-sandbox", "openshell"])
log = open(out, "wb"); deadline = time.time() + 600
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 1)
    if fd in r:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        log.write(chunk); log.flush()
    elif os.waitpid(pid, os.WNOHANG)[0]:
        break
try:
    _, st = os.waitpid(pid, 0)
except ChildProcessError:
    st = 0
log.close()
open(out + ".code", "w").write(str(os.waitstatus_to_exitcode(st)))
PY
) &
for _ in $(seq 1 120); do grep -q "FU8:ready=1" "$OUTF" 2>/dev/null && break; sleep 2; done
BOX="$(osh sandbox list --selector "observer.superbased.install=o$(install_id)o" --names 2>/dev/null | grep '^sbo-' | head -n 1 || true)"
if [ -z "$BOX" ] || ! grep -q "FU8:ready=1" "$OUTF" 2>/dev/null; then
	not_run box_not_stopped "the boxed run did not start (see box.out)"
	not_run box_widened_stopped "no box"
	R[completed]=1
	exit 1
fi
osh policy get "$BOX" --full -o json >"$LOG/effective.out" 2>"$LOG/effective.err" || true
R[shape.effective]="$(python3 -I -c 'import json,sys
try:
    d=json.load(open(sys.argv[1])); print("object:"+",".join(sorted(d)[:20]) if isinstance(d,dict) else type(d).__name__)
except Exception: print("not json")' "$LOG/effective.out")"
sleep 70
if [ -f "$OUTF.code" ]; then
	judge box_not_stopped fail "the untouched run ended: $(tr -d '\r' <"$OUTF" | grep -o 'effective_policy_[a-z_]*' | head -n 1)"
	R[completed]=1
	exit 1
fi
judge box_not_stopped pass
PLAN="$(grep -l "\"name\":\"$BOX\"" "$OBSDIR/sandbox-openshell/runs"/*/plan.json 2>/dev/null | head -n 1 || true)"
if [ -z "$PLAN" ]; then
	not_run box_widened_stopped "no run dir names $BOX"
	R[completed]=1
	exit 1
fi
python3 -I - "$(dirname "$PLAN")/policy.yaml" "$WORK/wide.yaml" <<'PY'
import sys
src, dst = sys.argv[1:3]
s = open(src).read()
s = s.replace("    endpoints:\n", '    endpoints:\n      - host: "pastebin.com"\n        ports: [443]\n        enforcement: "enforce"\n', 1)
open(dst, "w").write(s)
PY
if osh policy set "$BOX" --policy "$WORK/wide.yaml" --wait >>"$LOG/box-set.log" 2>&1; then
	for _ in $(seq 1 45); do [ -f "$OUTF.code" ] && break; sleep 2; done
	if [ -f "$OUTF.code" ] && tr -d '\r' <"$OUTF" | grep -q effective_policy_extra_host; then
		judge box_widened_stopped pass
	else
		judge box_widened_stopped fail "ended: $([ -f "$OUTF.code" ] && echo yes || echo no); named: $(tr -d '\r' <"$OUTF" | grep -o 'effective_policy_[a-z_]*' | head -n 1)"
	fi
else
	not_run box_widened_stopped "policy set on the box failed (see box-set.log)"
fi
R[completed]=1
exit "$FAIL"
