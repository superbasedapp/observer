#!/usr/bin/env bash
# o3-openshell-egress-live.sh: lane O3's live check of the openshell row's
# internet tier and refusal audit (live register row O3-L1).
#
# Runs unattended on a throwaway native Linux host (Ubuntu 24.04, Docker,
# OpenShell v0.1.6 CLI and gateway from the OpenShell package, nothing
# pulled by hand), as a normal user, and writes ONE receipt file on every
# exit (a bad argument and an existing ~/.observer included) with no secret
# and no address other than loopback in it.
#
# Two modes. The script never edits the user's gateway config, never
# installs OpenShell, never reads a key, a token, a certificate or a
# credential store, and never prints an environment value.
#
# Managed (the default, gateway_mode left at its default): Observer runs its
# own private gateway and writes that gateway's config itself, the OCSF
# export to the loopback receiver included (lane OC), so the operator
# applies NOTHING: no README step 1 edit, no OCSF keys. The host needs only
# what the OpenShell package installs (the openshell CLI and
# openshell-gateway), Docker with the user in the docker group and a
# systemd user manager (an SSH login, or lingering), exactly as O2-L1
# (o2-openshell-managed-live.sh) does, so the two run back to back on one
# fresh VM (O2-L1 first: its cleanup stops its private gateway and moves
# its ~/.observer aside). The script waits for the private gateway, judges
# that its config carries the export, and reads every box command through
# the private gateway's own registry. On exit it stops the private unit.
#
# External (--external): the run uses the user's own gateway, and the
# OPERATOR applies before the run the gateway config of
# _spikes/openshell/README.md step 1 (allow_driver_config and
# enable_bind_mounts under [openshell.drivers.docker], below the
# [openshell] header with version = 2 that a new file needs) PLUS lane O3's OCSF
# export, in the gateway's own config file
# ($XDG_CONFIG_HOME/openshell/gateway.toml, default
# ~/.config/openshell/gateway.toml), then a gateway restart:
#
#   [openshell.gateway.otlp]
#   endpoint = "http://127.0.0.1:14317"
#
#   [openshell.gateway.otlp.ocsf]
#   enabled = true
#
# What it does: starts an Observer daemon over a fresh ~/.observer (hooks
# auto-registration off, so no AI tool's config is touched) with openshell
# listed on the internet tier and a host list of api.github.com,
# *.githubusercontent.com and *.sslip.io; checks the daemon's OCSF receiver
# listens on loopback only and its marker says the refusal audit is wired;
# launches one sandboxed run whose "tool" is a script in the throwaway
# workspace, using a static probe this script builds from the repo and
# places beside it (finding F-028: the default box image has no curl,
# wget or python3), that records, per target, the HTTP status, the
# proxy's CONNECT status and curl's exit code for the same outcome, whether the name
# resolves in the box and whether the answer is OpenShell's own
# policy_denied body: two positive controls (a listed host, a
# wildcard-listed name), a wildcard's apex that resolves (sslip.io), an
# unlisted host, a model provider's host, a listed host on another port, a
# listed name that resolves to a private address, and the model proxy's
# own health answer; while the box still runs it checks the host helper
# recorded the box's id and reads the refusal audit (GET
# /api/sandbox/refusals on the daemon's loopback dashboard) for the
# denials OpenShell exported; then launches three more times, with a list
# naming a model provider's host, with a host alias and with no list, each
# of which must be refused before a box exists.
#
# Judging: a target counts as REFUSED only on OpenShell's own refusal (a
# CONNECT answered 403, a plain request answered 403 with policy_denied, or
# a transparent connect refused) with the name resolving in the box, and as
# REACHED only when the connection went through (CONNECT 200, or a
# connected answer that is not policy_denied). Anything else is not_run with
# the recorded facts. No refusal check is judged, and no refusal fact is
# written, unless both positive controls were reached in the same run. A
# check whose precondition never happened is not_run with the reason, never
# a fail of what it checks. On exit the script deletes any box still listed
# under this run's install label and moves the throwaway ~/.observer into
# the work dir.
#
# What leaves the host: DNS lookups and connection attempts from inside the
# box to api.github.com, raw.githubusercontent.com, sslip.io,
# 1-1-1-1.sslip.io, 10-0-0-1.sslip.io, example.com and api.anthropic.com
# (OpenShell's proxy refuses all but the listed ones; any name the box looks
# up leaves the host as a DNS query, which the receipt records), and the go
# module downloads of the build when --observer is not given.
#
# Usage:
#   scripts/sandbox/o3-openshell-egress-live.sh [--observer PATH] [--probe PATH] [--out DIR] [--external]
#
#   --observer PATH   the observer binary to test, a static build
#                     (CGO_ENABLED=0, as releases are; default: build one)
#   --probe PATH      the in-box probe, a static Linux build of
#                     scripts/sandbox/o3probe (default: build one)
#   --out DIR         where the receipt goes (default: the current dir)
#   --external        use the user's own gateway (gateway_mode "external")
#                     instead of Observer's private one; see above
#
# Exit 0 when every judged check passed, 1 when one failed or did not run,
# 2 on a precondition the host does not meet (the receipt says which).
# shellcheck disable=SC2015,SC2329
# SC2015: every `COND && judge NAME pass || judge NAME fail` line is safe
# because judge always returns 0. SC2329: cleanup runs from the EXIT trap.
set -euo pipefail

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROW="O3-L1"
OUT="$PWD"
RECEIPT="$OUT/o3-openshell-egress-live-o3-l1-$STAMP.json"
OBSERVER=""
PROBE=""
OBSDIR="$HOME/.observer"
OBSDIR_MADE=0
WORK=""
DASH="http://127.0.0.1:8081"
RECEIVER="127.0.0.1:14317"
INSTALL_ID_FILE="$OBSDIR/sandbox-openshell/install-id"
RUNS_DIR="$OBSDIR/sandbox-openshell/runs"
MARKER="$OBSDIR/sandbox-openshell/ocsf-receiver.json"
CONFIG="$OBSDIR/config.toml"
MANAGED=1

declare -A R # receipt fields (strings)
R[schema]="observer-o3-live/4"
R[row]="$ROW"
R[started]="$STAMP"
FAIL=0
RECEIPT_WRITTEN=0
COMPLETED=0
EXIT_CODE=""

# json_escape renders one JSON string in bash alone, so the receipt is
# valid JSON even on a host with no python3 (audit finding O3-V4): the
# backslash, the quote and the common control characters are escaped,
# every other control byte is dropped.
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
# write_receipt writes the receipt where asked or, when that cannot be
# written (a missing or unwritable --out), in the home dir or the system
# temp dir, and records where (audit finding O3-V4).
write_receipt() {
	local alt
	if ! { : >"$RECEIPT"; } 2>/dev/null; then
		alt="$HOME/$(basename "$RECEIPT")"
		if ! { : >"$alt"; } 2>/dev/null; then
			alt="$(mktemp "${TMPDIR:-/tmp}/o3-openshell-egress-live-XXXXXX.json")"
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
# refusal_line prints the first refusal line of a launch's output ("" when
# there is none), with terminal codes and carriage returns removed.
refusal_line() {
	[ -f "$1" ] || return 0
	tr -d '\r' <"$1" | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' |
		grep -m 1 -iE 'refused|sandboxrelayd:|terminal_sandbox:|not available here|sandboxopenshell:' | sed 's/^[[:space:]]*//' || true
}
# install_id prints this run's install id ("" before the driver minted it).
install_id() {
	[ -f "$INSTALL_ID_FILE" ] || return 0
	tr -d '\n' <"$INSTALL_ID_FILE" 2>/dev/null || true
}
# The private gateway's names for this install (managed mode): name
# observer-<12 hex>, unit observer-openshell-gateway-<12 hex>.service, CLI
# registry in the private RAM dir; "" before the install id exists.
gw_short() { local id; id="$(install_id)"; printf '%s' "${id:0:12}"; }
gw_name() { [ -n "$(gw_short)" ] && printf 'observer-%s' "$(gw_short)"; }
gw_unit() { [ -n "$(gw_short)" ] && printf 'observer-openshell-gateway-%s.service' "$(gw_short)"; }
gw_rtdir() { [ -n "$(gw_short)" ] && printf '%s/observer-openshell-%s' "${XDG_RUNTIME_DIR:-/nonexistent}" "$(gw_short)"; }
# osh runs the openshell CLI against the run's gateway: Observer's private
# one (its name and private registry) in managed mode, the user's own in
# external mode.
osh() {
	command -v openshell >/dev/null || return 1
	if [ "$MANAGED" = 1 ]; then
		[ -n "$(gw_short)" ] || return 1
		XDG_CONFIG_HOME="$(gw_rtdir)/cli" openshell -g "$(gw_name)" "$@"
	else
		openshell "$@"
	fi
}
list_boxes() {
	local id
	id="$(install_id)"
	[ -n "$id" ] || return 0
	osh sandbox list --selector "observer.superbased.install=o${id}o" --names 2>/dev/null | grep '^sbo-' || true
}
# ocsf_export_of FILE prints whether the gateway config FILE exports OCSF
# events to the receiver (present, missing or unreadable), read the way the
# driver reads it: the keys only, never written.
ocsf_export_of() {
	python3 -I - "$1" "http://$RECEIVER" <<'PY' || echo unreadable
import sys, tomllib
path, want = sys.argv[1], sys.argv[2]
try:
    with open(path, "rb") as f:
        c = tomllib.load(f)
except Exception:
    print("unreadable"); sys.exit(0)
o = c.get("openshell", {}).get("gateway", {}).get("otlp", {})
oc = o.get("ocsf", {})
ep = (oc.get("endpoint") or o.get("endpoint") or "").rstrip("/")
print("present" if oc.get("enabled") is True and ep == want else "missing")
PY
}
# tree_digest prints a digest of a directory tree's names, modes, sizes
# and contents ("absent" when it does not exist); it never prints a
# content.
tree_digest() {
	[ -e "$1" ] || { echo absent; return 0; }
	(cd "$1" && find . -printf '%p %m %s\n' 2>/dev/null | sort && find . -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum 2>/dev/null) | sha256sum | cut -c1-16
}
cleanup() {
	local rc=$? left after n
	set +e
	[ -n "$EXIT_CODE" ] || EXIT_CODE=$rc
	if [ "$RECEIPT_WRITTEN" = 0 ] && [ "$rc" != 0 ] && [ "$EXIT_CODE" != 2 ] && [ "$COMPLETED" = 0 ]; then
		R[aborted]="the script stopped early (exit $rc); the checks after the last one recorded did not run"
		FAIL=1
	fi
	left="$(list_boxes | tr '\n' ' ')"
	R[cleanup.left_boxes]="${left:-none}"
	if [ -n "$left" ]; then
		for n in $left; do osh sandbox delete "$n" >/dev/null 2>&1; done
		after="$(list_boxes | tr '\n' ' ')"
		R[cleanup.after_delete]="${after:-none}"
	else
		R[cleanup.after_delete]="not run: no box of this run was left to delete"
	fi
	if [ -n "${DAEMON_PID:-}" ]; then
		kill "$DAEMON_PID" 2>/dev/null
		wait "$DAEMON_PID" 2>/dev/null
	fi
	# Managed: stop the private gateway unit in any state but inactive, reset
	# it, remove its RAM dir (the PKI copy and the env file) and record it,
	# so the host is left as O2-L1 leaves it.
	if [ "$MANAGED" = 1 ] && [ -n "$(gw_unit)" ]; then
		ustate="$(systemctl --user is-active "$(gw_unit)" 2>/dev/null)"
		if [ "$ustate" != inactive ]; then
			systemctl --user stop "$(gw_unit)" >/dev/null 2>&1
			systemctl --user reset-failed "$(gw_unit)" >/dev/null 2>&1
			R[cleanup.gateway_unit]="was ${ustate:-unknown}; stopped by the cleanup"
		else
			R[cleanup.gateway_unit]="not running"
		fi
		if [ -e "$(gw_rtdir)" ]; then
			rm -rf "$(gw_rtdir)" && R[cleanup.gateway_ram_dir]="removed by the cleanup"
		else
			R[cleanup.gateway_ram_dir]="already gone"
		fi
	fi
	for n in $(jobs -p); do kill "$n" 2>/dev/null; done
	wait 2>/dev/null
	rm -f "${HOLD_FILE:-}"
	if [ "$OBSDIR_MADE" = 1 ] && [ -d "$OBSDIR" ] && [ -n "$WORK" ]; then
		mv "$OBSDIR" "$WORK/observer-dir" && R[cleanup.observer_dir]="moved to the work dir"
	fi
	R[finished]="$(date -u +%Y%m%dT%H%M%SZ)"
	R[completed]="$([ "$COMPLETED" = 1 ] && echo yes || echo no)"
	[ "$RECEIPT_WRITTEN" = 1 ] || write_receipt
	if [ "$EXIT_CODE" = 2 ]; then exit 2; fi
	exit "$FAIL"
}
# The trap is in place before anything can exit, so every exit (a bad
# argument and an existing ~/.observer included) writes one receipt.
trap cleanup EXIT

while [ $# -gt 0 ]; do
	case "$1" in
	--observer) [ $# -ge 2 ] || refuse "--observer needs a path"; OBSERVER="$2"; shift 2 ;;
	--probe) [ $# -ge 2 ] || refuse "--probe needs a path"; PROBE="$2"; shift 2 ;;
	--out)
		[ $# -ge 2 ] || refuse "--out needs a directory"
		OUT="$2"
		RECEIPT="$OUT/o3-openshell-egress-live-o3-l1-$STAMP.json"
		shift 2
		;;
	--external) MANAGED=0; shift ;;
	-h | --help) sed -n '2,95p' "$0"; RECEIPT_WRITTEN=1; exit 0 ;;
	*) refuse "unknown argument $1" ;;
	esac
done

if ! { [ -d "$OUT" ] && [ -w "$OUT" ]; }; then
	R[receipt.fallback]="--out $OUT is not a writable directory; the receipt goes to $HOME"
	OUT="$HOME"
	RECEIPT="$OUT/o3-openshell-egress-live-o3-l1-$STAMP.json"
fi
R[mode]="$([ "$MANAGED" = 1 ] && echo managed || echo external)"
command -v python3 >/dev/null || refuse "python3 is needed for the PTY driver and the JSON reads (this receipt is written without it)"
[ -e "$OBSDIR" ] && refuse "$OBSDIR exists; run this on a throwaway host with no Observer state"
WORK="$(mktemp -d "${HOME}/o3-live-XXXXXX")"
chmod 700 "$WORK"
WS="$WORK/ws"
LOG="$WORK/log"
mkdir -p "$OBSDIR" "$WS" "$LOG"
OBSDIR_MADE=1

# ---- preconditions ----------------------------------------------------------
[ "$(id -u)" != 0 ] || refuse "run as a normal user, not root"
[ "$(uname -s)" = Linux ] || refuse "native Linux only"
if grep -qi microsoft /proc/version 2>/dev/null; then refuse "WSL2 is refused by design (row P1)"; fi
command -v openshell >/dev/null || refuse "the openshell CLI is not on PATH (install v0.1.6 from the package yourself; this script never installs it)"
command -v curl >/dev/null || refuse "curl is needed to read the daemon's refusal route"
R[host.kernel]="$(uname -r)"
R[host.docker]="$(docker version --format '{{.Server.Version}}' 2>/dev/null | tr -d '\n' || true)"
R[host.docker]="${R[host.docker]:-absent}"
R[host.openshell_cli]="$( (openshell --version 2>/dev/null || echo unreadable) | head -n 1)"
R[host.gateway_status]="$( (openshell status -o json 2>/dev/null || true) | python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin); print(d.get("gateway",""), d.get("status",""), d.get("version",""), (d.get("authentication") or {}).get("status",""))
except Exception: print("unreadable")' || echo unreadable)"
# The user's gateway config's OCSF export, read the way the driver reads it
# (keys only; the file is never written). External mode: missing is the
# operator's precondition. Managed mode: a fact only (the private gateway's
# own config is judged once it runs), and the user's config must be left
# as it is.
GWCONF="${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateway.toml"
R[host.user_ocsf_export]="$(ocsf_export_of "$GWCONF")"
R[host.user_openshell_config_before]="$(tree_digest "${XDG_CONFIG_HOME:-$HOME/.config}/openshell")"
if [ "$MANAGED" = 1 ]; then
	command -v openshell-gateway >/dev/null || refuse "openshell-gateway is not on PATH (install the OpenShell v0.1.6 package; this script never installs it)"
	command -v systemctl >/dev/null || refuse "systemctl is not on PATH (the managed gateway runs as a systemd user unit)"
	[ -n "${XDG_RUNTIME_DIR:-}" ] || refuse "XDG_RUNTIME_DIR is not set: log in through a systemd session (SSH) or enable lingering"
	R[host.user_manager]="$(systemctl --user is-system-running 2>/dev/null || true)"
	R[host.openshell_gateway]="$( (openshell-gateway --version 2>/dev/null || echo unreadable) | head -n 1)"
	# The private gateway runs under the user manager: it must hold the
	# docker socket's group (or the socket is open to everyone), or the
	# host is refused, not failed (as O2-L1 does).
	if [ -z "${DOCKER_HOST:-}" ] && [ -S /var/run/docker.sock ]; then
		SOCK_GID="$(stat -c %g /var/run/docker.sock)"
		MGR_PID="$(pgrep -u "$(id -u)" -x systemd | head -n 1 || true)"
		[ -n "$MGR_PID" ] || refuse "no systemd user manager runs for this user (log in over SSH, or enable lingering)"
		MGR_GROUPS="$(awk '/^Groups:/{for(i=2;i<=NF;i++)print $i} /^Gid:/{print $2}' "/proc/$MGR_PID/status" 2>/dev/null | tr '\n' ' ')"
		R[host.user_manager_docker_group]="$(printf '%s' "$MGR_GROUPS" | tr ' ' '\n' | grep -qx "$SOCK_GID" && echo yes || echo no)"
		SOCK_OTHER_RW="$([ $((0$(stat -c %a /var/run/docker.sock) & 6)) = 6 ] && echo yes || echo no)"
		if [ "${R[host.user_manager_docker_group]}" != yes ] && [ "$SOCK_OTHER_RW" != yes ]; then
			refuse "the systemd user manager does not hold the docker socket's group: log out of every session (or reboot) so it starts again with it"
		fi
	fi
else
	R[host.ocsf_export]="${R[host.user_ocsf_export]}"
	[ "${R[host.ocsf_export]}" = present ] || refuse "the gateway config ($GWCONF) does not export OCSF events to http://$RECEIVER: add [openshell.gateway.otlp] endpoint = \"http://$RECEIVER\" and [openshell.gateway.otlp.ocsf] enabled = true (this script's header), restart the gateway, and run again"
fi
if command -v ss >/dev/null && [ -n "$(ss -ltnH 'sport = :14317' 2>/dev/null)" ]; then
	refuse "something already listens on port 14317 before the daemon starts; stop it first"
fi

if [ -z "$OBSERVER" ]; then
	command -v go >/dev/null || refuse "no --observer and no go toolchain to build one"
	ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/observer-bin" ./cmd/observer) || refuse "go build failed"
	OBSERVER="$WORK/observer-bin"
fi
OBSERVER="$(readlink -f "$OBSERVER")"
# `observer --version` prints "observer version <v>"; the receipt keeps <v>.
R[observer.version]="$({ "$OBSERVER" --version 2>/dev/null || true; } | awk 'NR == 1 { print $NF }')"
[ -n "${R[observer.version]}" ] || R[observer.version]=unknown
# The in-box probe (finding F-028): OpenShell v0.1.6's default box image
# has no curl, wget or python3, so the agent's network facts come from
# scripts/sandbox/o3probe, built here from this repo static (as observer
# is) and placed in the workspace. Nothing is pulled from anywhere.
if [ -z "$PROBE" ]; then
	command -v go >/dev/null || refuse "no --probe and no go toolchain to build the in-box probe (scripts/sandbox/o3probe)"
	ROOT="${ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
	(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux go build -o "$WORK/o3probe" ./scripts/sandbox/o3probe) || refuse "go build of the in-box probe failed"
	PROBE="$WORK/o3probe"
fi
cp "$PROBE" "$WS/.o3probe" && chmod 755 "$WS/.o3probe" || refuse "could not place the in-box probe in the workspace"
R[probe.sha256]="$(sha256sum "$WS/.o3probe" | cut -c1-16)"

# write_config HOSTS: the daemon and launch config with the internet tier
# and the given TOML host list.
write_config() {
	cat >"$CONFIG" <<EOF
[observer]
db_path = "$OBSDIR/observer.db"

[observer.hooks]
auto_register = false

[terminal.sandbox]
enabled = true
backends = ["openshell"]
egress = "internet"
egress_allow_hosts = [$1]

[components]
add = ["terminals.sandbox.openshell"]
EOF
	# External mode names it; managed mode leaves gateway_mode at its
	# default (managed, decision D2), which is what an install sees.
	if [ "$MANAGED" = 0 ]; then
		printf '\n[terminal.sandbox.openshell]\ngateway_mode = "external"\n' >>"$CONFIG"
	fi
}
LIST='"api.github.com", "*.githubusercontent.com", "*.sslip.io"'
write_config "$LIST"

# ---- the daemon and its loopback OCSF receiver -----------------------------
"$OBSERVER" start >"$LOG/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do
	curl -fsS "$DASH/api/sandbox/refusals?limit=1" >/dev/null 2>&1 && break
	sleep 1
done
for _ in $(seq 1 20); do
	python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1])).get("sink_ready") else 1)' "$MARKER" 2>/dev/null && break
	sleep 1
done
if grep -q "the OCSF receiver is listening" "$LOG/daemon.log" 2>/dev/null; then judge daemon_ocsf_receiver pass; else judge daemon_ocsf_receiver fail "no receiver start line in the daemon log: $( (grep -m 1 'OCSF receiver' "$LOG/daemon.log" || true) | tr -d '\n')"; fi
R[receiver.marker]="$(python3 -I -c 'import json,sys
try:
    m=json.load(open(sys.argv[1])); print("addr=%s sink_ready=%s pid_is_daemon=%s" % (m.get("addr"), m.get("sink_ready"), m.get("pid")==int(sys.argv[2])))
except Exception: print("absent")' "$MARKER" "$DAEMON_PID" 2>/dev/null || echo absent)"
[ "${R[receiver.marker]}" = "addr=$RECEIVER sink_ready=True pid_is_daemon=True" ] && judge receiver_marker_ready pass || judge receiver_marker_ready fail "${R[receiver.marker]}"
if command -v ss >/dev/null; then
	LISTEN="$(ss -ltnH 'sport = :14317' 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ' ')"
	R[receiver.listen]="${LISTEN:-none}"
	if [ "$LISTEN" = "$RECEIVER " ]; then judge receiver_loopback_only pass; else judge receiver_loopback_only fail "listening on: ${LISTEN:-nothing}"; fi
else
	not_run receiver_loopback_only "ss is not installed"
fi
if curl -fsS "$DASH/api/sandbox/refusals?limit=1" >/dev/null 2>&1; then
	judge refusal_route pass
else
	judge refusal_route fail "GET $DASH/api/sandbox/refusals did not answer"
fi

# ---- managed mode: the private gateway and the export Observer wrote --------
if [ "$MANAGED" = 1 ]; then
	# Each sandbox status runs one lifecycle pass (a first start pulls the
	# supervisor and sandbox images, which a slow link stretches past one
	# pass); the row reads available once the private gateway answers.
	PROBE_STATUS=""
	for _ in $(seq 1 10); do
		"$OBSERVER" sandbox status >"$LOG/status.txt" 2>&1 || true
		PROBE_STATUS="$(awk '$1 == "openshell" && NF >= 4 { print $4; exit }' "$LOG/status.txt" 2>/dev/null || true)"
		[ "$PROBE_STATUS" = available ] && break
		sleep 5
	done
	R[managed.probe_status]="${PROBE_STATUS:-not shown}"
	R[managed.unit]="$(gw_unit || true)"
	R[managed.unit]="${R[managed.unit]:-none}"
	if [ "$PROBE_STATUS" = available ] && grep -q "gateway_mode managed" "$LOG/status.txt"; then
		judge managed_gateway_ready pass
	else
		judge managed_gateway_ready fail "status ${PROBE_STATUS:-not shown}: $( (grep -m 1 '^openshell: not available' "$LOG/status.txt" || true) | tr -d '\n')"
	fi
	if [ -n "$(gw_unit)" ] && [ -f "$OBSDIR/sandbox-openshell/gateway/gateway.toml" ]; then
		R[managed.ocsf_export]="$(ocsf_export_of "$OBSDIR/sandbox-openshell/gateway/gateway.toml")"
		[ "${R[managed.ocsf_export]}" = present ] && judge managed_ocsf_export_configured pass || judge managed_ocsf_export_configured fail "the private gateway's config reads ${R[managed.ocsf_export]}"
	else
		not_run managed_ocsf_export_configured "no private gateway config was written (status ${PROBE_STATUS:-not shown})"
	fi
fi

# ---- the agent script inside the workspace -----------------------------------
AGENT="$WS/agent.sh"
HOLD_FILE="$WS/.o3-hold"
cat >"$AGENT" <<'EOS'
#!/bin/sh
# Prints O3 markers, never a body, an address or an environment value. Per
# target: O3:<name>=<http_code>,<connect_code>,<exit>,<resolves>,<policy_denied>
# from the static probe beside this script (.o3probe, finding F-028: the
# default box image has no curl, wget or python3). Then holds for the
# seconds in .o3-hold so the box stays up while its denials are exported.
HOLD=0
DIR="$(dirname "$0")"
HOLD_FILE="$DIR/.o3-hold"
P="$DIR/.o3probe"
if [ -r "$HOLD_FILE" ]; then HOLD="$(head -c 16 "$HOLD_FILE" | tr -cd 0-9)"; fi
echo "O3:client=$( [ -x "$P" ] && echo probe || echo none)"
echo "O3:proxied=$( [ -n "${HTTPS_PROXY:-${https_proxy:-}}" ] && echo yes || echo no)"
BODY="$DIR/.o3-body"
resolves() { "$P" resolve "$1" >/dev/null 2>&1 && echo yes || echo no; }
probe() { # probe NAME URL HOST
	if [ ! -x "$P" ]; then echo "O3:$1=none"; return; fi
	: >"$BODY"
	out="$("$P" fetch -o "$BODY" -m 15 "$2" 2>/dev/null)"
	[ -n "$out" ] || out="000,000,99"
	pd=no
	grep -q policy_denied "$BODY" 2>/dev/null && pd=yes
	echo "O3:$1=$out,$(resolves "$3"),$pd"
}
probe listed https://api.github.com/ api.github.com
probe wildcard https://raw.githubusercontent.com/ raw.githubusercontent.com
probe wildcard2 https://1-1-1-1.sslip.io/ 1-1-1-1.sslip.io
probe apex https://sslip.io/ sslip.io
probe unlisted https://example.com/ example.com
probe provider https://api.anthropic.com/ api.anthropic.com
probe port https://api.github.com:8443/ api.github.com
probe private http://10-0-0-1.sslip.io/ 10-0-0-1.sslip.io
# What the box's own resolver answers for the listed name whose real
# address is private: its class only (rfc1918, public, cgnat, other, or
# none:<why>). OpenShell answers policy names with synthetic placeholder
# addresses and may deny a name; the host's own answer is recorded beside.
echo "O3:private_addr=$(if [ -x "$P" ]; then "$P" resolve 10-0-0-1.sslip.io 2>/dev/null; else echo none:no-probe; fi)"
echo "O3:private_getent=$(getent hosts 10-0-0-1.sslip.io >/dev/null 2>&1 && echo answered || echo none)"
echo "O3:unlisted_name_resolves=$(resolves example.com)"
# The model proxy's own liveness answer, never through any proxy variable.
if [ -x "$P" ]; then
	: >"$BODY"
	code="$("$P" fetch -noproxy -o "$BODY" -m 10 http://127.0.0.1:8820/-/healthz 2>/dev/null | cut -d, -f1)"
	echo "O3:model_proxy=${code:-000},$( [ "$(cat "$BODY" 2>/dev/null)" = '{"status":"ok"}' ] && echo observer || echo other)"
fi
rm -f "$BODY"
echo "O3:ready=1"
read -r _line
sleep "${HOLD:-0}"
exit 42
EOS
chmod 755 "$AGENT"

# ptyrun HOLD OUT: one launch on a PTY; a newline after the ready marker,
# then the agent holds HOLD seconds. The exit code goes to OUT.code.
ptyrun() {
	local hold="$1" out="$2"
	printf '%s\n' "$hold" >"$HOLD_FILE"
	(cd "$WS" && python3 -I - "$OBSERVER" "$AGENT" "$out" <<'PY'
import os, pty, sys, time, select, fcntl, termios, struct
obs, agent, out = sys.argv[1:4]
argv = [obs, "claude", "--claude-path", agent, "--observer-sandbox", "openshell"]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
    os.execv(obs, argv)
open(out + ".pid", "w").write(str(pid))
log = open(out, "wb")
buf = b""; sent = False; deadline = time.time() + 600
while time.time() < deadline:
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
        if not sent and b"O3:ready=1" in buf:
            time.sleep(1)
            os.write(fd, b"\n"); sent = True
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
	rm -f "$HOLD_FILE"
}
marker() {
	[ -f "$1" ] || return 0
	tr -d '\r' <"$1" | sed -n "s/^.*O3:$2=//p" | head -n 1
}
# verdict FACTS: what one probe's facts prove, given whether the box sends
# its traffic through a proxy variable (PROXIED):
#   refused   OpenShell's own refusal, with the name resolving
#   reached   the connection went through: with no proxy variable, any
#             outcome after the TCP connect succeeded (an HTTP status, or
#             curl's 0, 35, 51, 52, 56, 58 or 60) with the name resolving
#             and no policy_denied body (finding OC3-2: a server that
#             resets the TLS handshake for the SNI was still reached);
#             never a refused connect (7) or a name that did not resolve (6)
#   unknown   anything else (DNS failure, a timeout, a TLS error with no
#             CONNECT answer, no client): never judged either way
# scripts/sandbox/o3-verdict-test.sh runs its table.
verdict() {
	local code connect exitc res pd
	IFS=, read -r code connect exitc res pd <<<"$1"
	[ -n "$code" ] && [ "$code" != none ] || { echo unknown; return; }
	if [ "$res" = yes ]; then
		if [ "$connect" = 403 ] || { [ "$code" = 403 ] && [ "$pd" = yes ]; }; then echo refused; return; fi
		if [ "$PROXIED" = no ] && [ "$exitc" = 7 ]; then echo refused; return; fi
	fi
	if [ "$connect" = 200 ]; then echo reached; return; fi
	if [ "$PROXIED" = no ] && [ "$res" = yes ] && [ "$pd" = no ] && [ "$connect" = 000 ]; then
		if [ "$code" != 000 ]; then echo reached; return; fi
		case "$exitc" in 0 | 35 | 51 | 52 | 56 | 58 | 60) echo reached; return ;; esac
	fi
	if [ "$exitc" = 0 ] && [ "$pd" = no ] && [ "$code" != 000 ]; then echo reached; return; fi
	echo unknown
}
# refusal_row HOST: the newest refusal audit row for HOST as "rule key
# backend tier" ("" when there is none).
refusal_row() {
	curl -fsS "$DASH/api/sandbox/refusals?limit=200" 2>/dev/null | python3 -I -c 'import json,sys
host=sys.argv[1]
try:
    rows=json.load(sys.stdin).get("refusals") or []
except Exception:
    rows=[]
for r in rows:
    if r.get("host")==host:
        print(r.get("rule",""), r.get("key",""), r.get("backend",""), r.get("tier","")); break' "$1" || true
}

# ---- run 1: the internet tier through OpenShell's rules ------------------------
ptyrun 40 "$LOG/run1.out" &
RUN1=$!
for _ in $(seq 1 180); do
	grep -q "O3:ready=1" "$LOG/run1.out" 2>/dev/null && break
	kill -0 "$RUN1" 2>/dev/null || break
	sleep 1
done
AGENT1_RAN=0
grep -q "O3:ready=1" "$LOG/run1.out" 2>/dev/null && AGENT1_RAN=1
R[run1.agent_ran]="$([ "$AGENT1_RAN" = 1 ] && echo yes || echo no)"
for k in client proxied listed wildcard wildcard2 apex unlisted provider port private private_addr private_getent unlisted_name_resolves model_proxy; do
	R["run1.$k"]="$(marker "$LOG/run1.out" "$k")"
done
PROXIED="${R[run1.proxied]:-no}"
for k in listed wildcard wildcard2 apex unlisted provider port private; do
	R["run1.$k.verdict"]="$(verdict "${R[run1.$k]}")"
done
# The box id the host helper recorded (while the box runs).
IDFILE=""
for _ in $(seq 1 30); do
	IDFILE="$(find "$RUNS_DIR" -maxdepth 2 -name sandbox-id 2>/dev/null | head -n 1 || true)"
	[ -n "$IDFILE" ] && break
	kill -0 "$RUN1" 2>/dev/null || break
	sleep 1
done
# Wait (while the box holds) for the exported denials to land.
for _ in $(seq 1 30); do
	[ -n "$(refusal_row example.com)" ] && [ -n "$(refusal_row api.anthropic.com)" ] && break
	kill -0 "$RUN1" 2>/dev/null || break
	sleep 1
done
for h in example.com api.anthropic.com sslip.io api.github.com 10-0-0-1.sslip.io; do
	R["run1.refusal_row.$h"]="$(refusal_row "$h")"
done
# The dropped counts the refusal route answers beside the rows (lane OC,
# audit finding O3-W2): a fact, "none" when no run dropped a denial.
R[run1.refusal_dropped]="$(curl -fsS "$DASH/api/sandbox/refusals?limit=200" 2>/dev/null | python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin).get("dropped") or {}
except Exception:
    d={}
print(" ".join("%s=%s" % (k, d[k]) for k in sorted(d)) or "none")' 2>/dev/null || echo unreadable)"
wait "$RUN1" || true
CODE1="$(cat "$LOG/run1.out.code" 2>/dev/null || echo none)"
R[run1.exit_code]="$CODE1"
REFUSAL1="$(refusal_line "$LOG/run1.out")"
R[run1.refusal]="${REFUSAL1:-none}"
# Whether the gateway's own name (the OCSF resource attribute) equals the
# CLI's registered name the run is pinned to: the daemon logs it once per
# run on the run's first event (audit finding O3-V3). Recorded as a fact.
FIRST_EVENT="$( (grep -m 1 'first OCSF event of the run' "$LOG/daemon.log" 2>/dev/null || true) | tr -d '\r')"
gw_field() { printf '%s' "$FIRST_EVENT" | sed -n "s/.* $1=\([^ ]*\).*/\1/p" | head -n 1; }
if [ -n "$FIRST_EVENT" ]; then
	R[run1.gateway_names_match]="$(gw_field gateway_names_match)"
	R[run1.event_gateway]="$(gw_field event_gateway)"
	R[run1.run_gateway]="$(gw_field run_gateway)"
else
	R[run1.gateway_names_match]="not seen: no OCSF event of the run reached the daemon"
fi

[ "$AGENT1_RAN" = 1 ] && judge policy_accepted pass || judge policy_accepted fail "the agent never ran in the box (exit $CODE1): ${REFUSAL1:-no refusal line}"
CONTROLS=0
if [ "$AGENT1_RAN" = 1 ] && [ "${R[run1.client]}" = probe ]; then
	[ "${R[run1.listed.verdict]}" = reached ] && judge listed_host_reachable pass || judge listed_host_reachable fail "api.github.com: ${R[run1.listed]} (${R[run1.listed.verdict]})"
	[ "${R[run1.wildcard.verdict]}" = reached ] && judge wildcard_host_reachable pass || judge wildcard_host_reachable fail "raw.githubusercontent.com: ${R[run1.wildcard]} (${R[run1.wildcard.verdict]})"
	if [ "${R[run1.listed.verdict]}" = reached ] && [ "${R[run1.wildcard.verdict]}" = reached ]; then CONTROLS=1; fi
	# The model proxy: its own liveness answer, never through a proxy.
	[ "${R[run1.model_proxy]}" = "200,observer" ] && judge model_proxy_reachable pass || judge model_proxy_reachable fail "127.0.0.1:8820/-/healthz in the box: ${R[run1.model_proxy]:-no answer}"
else
	WHY1="the agent never ran its probe in the box (exit $CODE1, client ${R[run1.client]:-none}): ${REFUSAL1:-no refusal line}"
	for c in listed_host_reachable wildcard_host_reachable model_proxy_reachable; do not_run "$c" "$WHY1"; done
fi
R[run1.positive_controls]="$([ "$CONTROLS" = 1 ] && echo passed || echo failed)"
# judge_refused NAME KEY: a refusal check, judged only after the positive
# controls passed and only on OpenShell's own refusal.
judge_refused() {
	local name="$1" key="$2" v="${R[run1.$2.verdict]}"
	if [ "$CONTROLS" != 1 ]; then
		not_run "$name" "the positive controls did not pass in this run, so a refusal cannot be told from a broken path (${R[run1.$key]:-no facts})"
	elif [ "$v" = refused ]; then
		judge "$name" pass "${R[run1.$key]}"
	elif [ "$v" = reached ]; then
		judge "$name" fail "reached: ${R[run1.$key]}"
	else
		not_run "$name" "no refusal by OpenShell's proxy was observed (DNS, timeout or TLS failure): ${R[run1.$key]:-no facts}"
	fi
}
# The wildcard's apex: only a name that resolves proves the glob's shape.
if [ "$(cut -d, -f4 <<<"${R[run1.apex]:-}")" = yes ]; then
	judge_refused wildcard_apex_refused apex
	# The other side of the same glob: a name below it is reached.
	if [ "$CONTROLS" = 1 ]; then
		[ "${R[run1.wildcard2.verdict]}" = reached ] && judge wildcard_below_reached pass || judge wildcard_below_reached fail "1-1-1-1.sslip.io: ${R[run1.wildcard2]} (${R[run1.wildcard2.verdict]})"
	else
		not_run wildcard_below_reached "the positive controls did not pass in this run"
	fi
else
	not_run wildcard_apex_refused "sslip.io did not resolve in the box (${R[run1.apex]:-no facts}), so the apex could not be tested"
	not_run wildcard_below_reached "sslip.io did not resolve in the box"
fi
judge_refused unlisted_host_refused unlisted
judge_refused model_host_unreachable provider
judge_refused other_port_refused port
# A listed name whose real address is private (findings F-028 and
# OC2-A3). The box never sees a real address: OpenShell's in-box resolver
# answers a policy name with a synthetic placeholder and may deny one (doc
# 01 section 8.4, the vendor docs), so the real address is the host's
# answer and the box's answer is recorded as its class only. The check
# passes only on OpenShell's own private-address floor: the name must
# have matched the wildcard rule in this run (wildcard_below_reached
# passed, so an allow-list miss is ruled out) and the refusal audit row
# for the name must read rule ssrf-floor. Its outcome names where the
# floor acted: at DNS (the box's resolver gave no answer) or at connect.
R[host.private_name]="$(getent hosts 10-0-0-1.sslip.io 2>/dev/null | awk '{print ($1 == "10.0.0.1") ? "rfc1918" : "other"}' | head -n 1)"
R[host.private_name]="${R[host.private_name]:-none}"
case "${R[run1.private_addr]:-}" in
none:* | "")
	R[run1.private_dns]="openshell_resolver_no_answer"
	PRIV_STAGE=dns
	;;
*)
	R[run1.private_dns]="answered_${R[run1.private_addr]}"
	PRIV_STAGE=connect
	;;
esac
PRIV_ROW="${R[run1.refusal_row.10-0-0-1.sslip.io]:-}"
PRIV_RULE="${PRIV_ROW%% *}"
PRIV_FACTS="box DNS ${R[run1.private_addr]:-no facts}, getent ${R[run1.private_getent]:-unread}, fetch ${R[run1.private]:-none} (${R[run1.private.verdict]:-unknown}), refusal row ${PRIV_ROW:-none}"
if [ "${R[host.private_name]}" != rfc1918 ]; then
	R[run1.private_outcome]="not_tested"
	not_run listed_private_address_refused "10-0-0-1.sslip.io does not resolve to 10.0.0.1 on the host (${R[host.private_name]}), so the name is not a private-address test here"
elif [ "$CONTROLS" != 1 ]; then
	R[run1.private_outcome]="not_tested"
	not_run listed_private_address_refused "the positive controls did not pass in this run ($PRIV_FACTS)"
elif [ "${R[check.wildcard_below_reached]:-}" != pass ]; then
	R[run1.private_outcome]="not_tested"
	not_run listed_private_address_refused "the wildcard rule was not shown to admit a name below sslip.io in this run (wildcard_below_reached ${R[check.wildcard_below_reached]:-not judged}), so a refusal cannot be told from an allow-list miss ($PRIV_FACTS)"
elif [ "${R[run1.private.verdict]:-}" = reached ]; then
	R[run1.private_outcome]="reached"
	judge listed_private_address_refused fail "reached: $PRIV_FACTS"
elif [ "$PRIV_RULE" = ssrf-floor ]; then
	R[run1.private_outcome]="ssrf_floor_at_$PRIV_STAGE"
	judge listed_private_address_refused pass "refused by OpenShell's private-address floor at $PRIV_STAGE: $PRIV_FACTS"
elif [ -z "$PRIV_ROW" ]; then
	R[run1.private_outcome]="no_refusal_row"
	not_run listed_private_address_refused "no refusal audit row for 10-0-0-1.sslip.io, so nothing ties an outcome to its address ($PRIV_FACTS)"
else
	R[run1.private_outcome]="refused_by_$PRIV_RULE"
	judge listed_private_address_refused fail "refused by rule $PRIV_RULE, not the private-address floor: $PRIV_FACTS"
fi
if [ "$AGENT1_RAN" = 1 ]; then
	[ -n "$IDFILE" ] && judge box_id_recorded pass || judge box_id_recorded fail "no sandbox-id file in a run dir while the box ran"
fi
if [ "$AGENT1_RAN" = 1 ] && [ "$CONTROLS" = 1 ]; then
	ROW_EX="${R[run1.refusal_row.example.com]}"
	ROW_PR="${R[run1.refusal_row.api.anthropic.com]}"
	if [ "${R[check.unlisted_host_refused]}" = pass ]; then
		[ "$ROW_EX" = "allow-list-miss terminal.sandbox.egress_allow_hosts openshell internet" ] && judge ocsf_allow_list_miss_row pass || judge ocsf_allow_list_miss_row fail "example.com row: ${ROW_EX:-none} (gateway names match: ${R[run1.gateway_names_match]})"
	else
		not_run ocsf_allow_list_miss_row "the refusal of example.com was not established"
	fi
	if [ "${R[check.model_host_unreachable]}" = pass ]; then
		[ "$ROW_PR" = "provider-host terminal.sandbox.egress openshell internet" ] && judge ocsf_provider_host_row pass || judge ocsf_provider_host_row fail "api.anthropic.com row: ${ROW_PR:-none}"
	else
		not_run ocsf_provider_host_row "the refusal of api.anthropic.com was not established"
	fi
else
	[ "$AGENT1_RAN" = 1 ] || not_run box_id_recorded "the agent never ran in the box"
	for c in ocsf_allow_list_miss_row ocsf_provider_host_row; do
		not_run "$c" "no refusal was established in this run (agent ran: ${R[run1.agent_ran]}, positive controls: ${R[run1.positive_controls]})"
	done
fi

# ---- runs 2 to 4: lists the compiler refuses, before any box -------------------
# refused_run NAME LIST WANT: a launch with LIST must be refused with a line
# containing WANT, and no agent may run.
refused_run() {
	local name="$1" list="$2" want="$3" out="$LOG/$1.out" line
	write_config "$list"
	ptyrun 0 "$out" || true
	line="$(refusal_line "$out")"
	R["$name.exit_code"]="$(cat "$out.code" 2>/dev/null || echo none)"
	R["$name.refusal"]="${line:-none}"
	if grep -q "O3:ready=1" "$out" 2>/dev/null; then
		judge "$name" fail "the agent ran in a box"
	elif printf '%s' "$line" | grep -q "$want"; then
		judge "$name" pass
	else
		judge "$name" fail "no refusal naming '$want': ${line:-none}"
	fi
}
refused_run provider_host_list_refused '"api.github.com", "api.anthropic.com"' "model provider"
refused_run host_alias_list_refused '"api.github.com", "host.openshell.internal"' "host-alias"
refused_run empty_list_refused '' "egress_allow_hosts"
write_config "$LIST"
# Managed mode never touches the user's own OpenShell config.
if [ "$MANAGED" = 1 ]; then
	[ "$(tree_digest "${XDG_CONFIG_HOME:-$HOME/.config}/openshell")" = "${R[host.user_openshell_config_before]}" ] && judge user_openshell_config_untouched pass || judge user_openshell_config_untouched fail "the digest of the user's openshell config dir changed"
fi

# facts_confirmed names only facts whose checks passed after the positive
# controls passed in the same run.
FACTS=""
add_fact() { FACTS="${FACTS:+$FACTS; }$1"; }
[ "${R[check.policy_accepted]:-}" = pass ] && add_fact "OpenShell v0.1.6 accepts the compiled network_policies (endpoints with ports, allowed_ips and enforcement enforce; binaries by path)"
if [ "$CONTROLS" = 1 ]; then
	[ "${R[check.wildcard_apex_refused]:-}" = pass ] && [ "${R[check.wildcard_below_reached]:-}" = pass ] && add_fact "**.<suffix> matches names below the suffix and not the suffix itself"
	[ "${R[check.listed_private_address_refused]:-}" = pass ] && add_fact "OpenShell refuses a name its wildcard rule admits when the name resolves to an RFC 1918 address (its ssrf-floor, here at ${R[run1.private_outcome]#ssrf_floor_at_})"
	[ "${R[check.model_host_unreachable]:-}" = pass ] && add_fact "a model provider's host is refused by OpenShell's proxy on the internet tier"
	[ "${R[check.ocsf_allow_list_miss_row]:-}" = pass ] && add_fact "a denied connection's OCSF event lands one refusal audit row through the loopback receiver"
	if [ "$MANAGED" = 1 ] && [ "${R[check.ocsf_allow_list_miss_row]:-}" = pass ] && [ "${R[check.managed_ocsf_export_configured]:-}" = pass ]; then
		add_fact "the private gateway's OCSF export, written by Observer, reaches the loopback receiver with no operator edit"
	fi
	if [ "$MANAGED" = 1 ] && [ "${R[check.box_id_recorded]:-}" = pass ]; then
		add_fact "the host helper reads the box id through the private gateway's own registry"
	fi
fi
R[facts_confirmed]="${FACTS:-none}"
COMPLETED=1
exit "$FAIL"
