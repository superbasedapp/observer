#!/usr/bin/env bash
# o1b-openshell-live.sh: lane O1B's live check of the OpenShell driver in
# external gateway mode (live register rows O1B-L1 and O1B-L2), and with
# --managed lane O2's live check of the managed local gateway (row O2-L1,
# also run as scripts/sandbox/o2-openshell-managed-live.sh).
#
# Runs unattended on a throwaway native Linux host (Ubuntu 24.04, Docker,
# OpenShell v0.1.6 CLI and gateway, the gateway config from
# _spikes/openshell/README.md step 1 with allow_driver_config and
# enable_bind_mounts under [openshell.drivers.docker]), as a normal user,
# and writes ONE receipt file with no secret in it.
#
# It never installs OpenShell, never edits the gateway's config, never reads
# a key, a token, a certificate or a credential store, and never prints an
# environment value. It starts an Observer daemon over a fresh ~/.observer
# (it refuses when one exists: this script is for a throwaway host; hooks
# auto-registration is off, so no AI tool's config is touched), probes the openshell row, launches one sandboxed run through the
# driver whose "tool" is a script inside the throwaway workspace (named with
# the launcher's own --claude-path flag), reads the box's facts from that
# script's markers, lists the box by its labels while it runs, checks it is
# gone afterwards, then SIGKILLs a second run's host helper and waits for
# the daemon's labelled reaper to remove the box. The receipt is written on
# every exit (a failed precondition or an aborted step included); on exit
# the script deletes any box still listed under this run's install label,
# records what was left, and moves the throwaway ~/.observer into the work
# dir so a re-run starts clean. A check whose precondition never happened
# (the agent never ran in the box, run 2 never got a box) is recorded as
# not_run with the reason, never as a fail of what it checks; a refusal is
# recorded in run1.refusal / run2.refusal (its first line); finished is
# stamped after the cleanup, so it is never earlier than a recorded wait.
#
# With --managed the host needs only what the OpenShell package installs
# (the openshell CLI and openshell-gateway, v0.1.6), Docker with the user in
# the docker group, and a systemd user manager (log in over SSH, or enable
# lingering). The package's own openshell-gateway.service, which its
# installer enables and starts on the same Docker engine, is never used or
# stopped: it is left running, and the run judges that the two gateways
# share the engine (managed_coexists_with_package_gateway, finding F-027).
# The
# script lets Observer start its private gateway, then checks: the unit is
# active, it answers connected and authenticated from a loopback port in
# Observer's block, it listens on loopback only, its telemetry variable is
# false, no key file is left on disk (no key-encryption-key.bin anywhere,
# no PEM key under Observer's state dir), its PKI sits in a tmpfs, the
# user's ~/.config/openshell is unchanged, the private gateway.toml carries
# the OCSF export to the loopback receiver (lane OC; whether events arrive
# is O3-L1's to show), a daemon restart leaves the
# gateway running (the same main PID), the two runs below, and that with
# gateway_mode "external" the daemon stops the idle private gateway and
# removes its RAM dir. It never prints or records an environment value or
# a key.
#
# Usage:
#   scripts/sandbox/o1b-openshell-live.sh [--observer PATH] [--out DIR] [--expect-podman [--podman-launch] | --managed]
#
#   --observer PATH   the observer binary to test, a static build (CGO_ENABLED=0,
#                     as releases are; default: build one)
#   --out DIR         where the receipt goes (default: the current dir)
#   --expect-podman   O1B-L2: the host's gateway runs the Podman driver; only
#                     the probe runs, and it must refuse with driver_untested
#                     and report the podman prerequisite
#   --podman-launch   with --expect-podman, O1B-L2's launch half (tracker
#                     F-033): the binary under test carries lane FU7's P6
#                     lift, so the probe must be available on the Podman
#                     driver; then run 1 launches one box through it (the
#                     same checks as O1B-L1's run 1, the tmpfs home mode
#                     measured inside the box), the run's record is read
#                     back (the gateway's `sandbox get` and Observer's own
#                     plan file, while the box runs), and run 2 checks the
#                     reaper. Without --observer it builds the binary with
#                     the receipt field set to a run marker at link time
#                     (the shipped table refuses Podman until a receipt
#                     path is written in); a binary given with --observer
#                     must be built the same way. Observer's container calls (the runtime
#                     canary, the image digests) go through a `docker` CLI,
#                     so the host needs one that drives the same Podman
#                     engine (podman-docker, or the docker CLI with
#                     DOCKER_HOST at Podman's socket); the receipt says
#                     which. Its receipt is what the P6 lift is merged on
#   --managed         O2-L1: the managed local gateway (gateway_mode left at
#                     its default); see above
#
# Exit 0 when every judged check passed, 1 when one failed or did not run,
# 2 on a precondition the host does not meet (the receipt says which).
# shellcheck disable=SC2015,SC2329
# SC2015: every `COND && judge NAME pass || judge NAME fail` line is safe
# because judge always returns 0. SC2329: cleanup runs from the EXIT trap,
# and write_receipt and json_escape from it.
set -euo pipefail

OBSERVER=""
OUT="$PWD"
EXPECT_PODMAN=0
PODMAN_LAUNCH=0
MANAGED=0
while [ $# -gt 0 ]; do
	case "$1" in
	--managed) MANAGED=1; shift ;;
	--observer) OBSERVER="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	--expect-podman) EXPECT_PODMAN=1; shift ;;
	--podman-launch) PODMAN_LAUNCH=1; shift ;;
	-h | --help) sed -n '2,80p' "$0"; exit 0 ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ROW="O1B-L1"
[ "$EXPECT_PODMAN" = 1 ] && ROW="O1B-L2"
[ "$MANAGED" = 1 ] && ROW="O2-L1"
if [ "$MANAGED" = 1 ] && [ "$EXPECT_PODMAN" = 1 ]; then
	echo "--managed and --expect-podman do not combine" >&2
	exit 2
fi
if [ "$PODMAN_LAUNCH" = 1 ] && [ "$EXPECT_PODMAN" = 0 ]; then
	echo "--podman-launch needs --expect-podman" >&2
	exit 2
fi
PREFIX="o1b-openshell-live"
[ "$MANAGED" = 1 ] && PREFIX="o2-openshell-managed-live"
[ "$PODMAN_LAUNCH" = 1 ] && PREFIX="o1b-openshell-live-podman-launch"
RECEIPT="$OUT/$PREFIX-$(echo "$ROW" | tr '[:upper:]' '[:lower:]')-$STAMP.json"
WORK="$(mktemp -d "${HOME}/o1b-live-XXXXXX")"
OBSDIR="$HOME/.observer"
WS="$WORK/ws"
LOG="$WORK/log"
if [ -e "$OBSDIR" ]; then
	echo "refused: $OBSDIR exists; run this on a throwaway host with no Observer state" >&2
	exit 2
fi
mkdir -p "$OBSDIR" "$WS" "$LOG"
OBSDIR_MADE=1
chmod 700 "$WORK"
INSTALL_ID_FILE="$OBSDIR/sandbox-openshell/install-id"

declare -A R # receipt fields (strings)
R[schema]="observer-o1b-live/2"
R[mode]="$([ "$MANAGED" = 1 ] && echo managed || echo external)"
R[podman_launch]="$([ "$PODMAN_LAUNCH" = 1 ] && echo yes || echo no)"
R[row]="$ROW"
R[started]="$STAMP"
FAIL=0
RECEIPT_WRITTEN=0
# COMPLETED is 1 once every step ran to the end (the receipt's completed
# field); the cleanup stamps finished itself, after its own waits.
COMPLETED=0
EXIT_CODE=""

json_escape() { python3 -I -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
write_receipt() {
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
# not_run NAME REASON records a check that could not be judged (what it
# needed never happened) as not_run with the reason, never as a fail of the
# thing it checks. The run still does not pass: a check did not run.
not_run() {
	R["check.$1"]="not_run"
	R["check.$1.detail"]="$2"
	FAIL=1
}
# refusal_line prints the first line of a launch's refusal from its output
# file ("" when there is none): the driver's or the box's own refusal (for
# example the launch checks inside the box refusing the run), with the
# terminal's colour and cursor codes and carriage returns removed.
refusal_line() {
	[ -f "$1" ] || return 0
	tr -d '\r' <"$1" | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g' |
		grep -m 1 -iE 'refused|sandboxrelayd:|terminal_sandbox:|not available here' | sed 's/^[[:space:]]*//' || true
}
refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	EXIT_CODE=2
	exit 2
}
# install_id prints this run's install id ("" before the driver minted it).
install_id() {
	[ -f "$INSTALL_ID_FILE" ] || return 0
	tr -d '\n' <"$INSTALL_ID_FILE" 2>/dev/null || true
}
# The managed gateway's names for this install (lane O2: name
# observer-<12 hex>, unit observer-openshell-gateway-<12 hex>.service, CLI
# registry in the private RAM dir); "" before the install id exists.
gw_short() { local id; id="$(install_id)"; printf '%s' "${id:0:12}"; }
gw_name() { [ -n "$(gw_short)" ] && printf 'observer-%s' "$(gw_short)"; }
gw_unit() { [ -n "$(gw_short)" ] && printf 'observer-openshell-gateway-%s.service' "$(gw_short)"; }
gw_rtdir() { [ -n "$(gw_short)" ] && printf '%s/observer-openshell-%s' "${XDG_RUNTIME_DIR:-/nonexistent}" "$(gw_short)"; }
gw_pid() { local u; u="$(gw_unit)"; [ -n "$u" ] && systemctl --user show -p MainPID --value "$u" 2>/dev/null | tr -d '\n'; }
# osh runs the openshell CLI against the run's gateway: the user's own in
# external mode, Observer's private one (its name and private registry) in
# managed mode.
osh() {
	if [ "$MANAGED" = 1 ]; then
		[ -n "$(gw_short)" ] || return 1
		XDG_CONFIG_HOME="$(gw_rtdir)/cli" openshell -g "$(gw_name)" "$@"
	else
		openshell "$@"
	fi
}
# list_boxes prints the names of the boxes under this run's install label
# ("" before the driver minted the id).
list_boxes() {
	local id
	id="$(install_id)"
	[ -n "$id" ] || return 0
	osh sandbox list --selector "observer.superbased.install=o${id}o" --names 2>/dev/null | grep '^sbo-' || true
}
# ---- coexistence facts (finding OC2-A2) -------------------------------------
# docker_host_of UNIT prints the DOCKER_HOST a user unit runs with: its own
# Environment property, else the user manager's environment ("" for none).
# Only that one variable is read.
docker_host_of() {
	local v
	v="$(systemctl --user show -p Environment --value "$1" 2>/dev/null | tr ' ' '\n' | sed -n 's/^DOCKER_HOST=//p' | head -n 1 || true)"
	[ -n "$v" ] || v="$(systemctl --user show-environment 2>/dev/null | sed -n 's/^DOCKER_HOST=//p' | head -n 1 || true)"
	printf '%s' "$v"
}
# engine_of SOCKET prints the Docker engine ID answering on a unix socket
# ("" when nothing answers there).
engine_of() {
	[ -n "$1" ] && [ -S "$1" ] || return 0
	docker -H "unix://$1" info --format '{{.ID}}' 2>/dev/null | tr -d '\n' || true
}
# detect_sock DOCKER_HOST prints the socket OpenShell v0.1.6's Docker
# driver connects to when its config sets no socket_path (detect_socket:
# a unix DOCKER_HOST, /var/run/docker.sock, ~/.docker/run/docker.sock,
# $XDG_RUNTIME_DIR/docker.sock, the first that answers), "" for none.
detect_sock() {
	local c
	for c in "$([ "${1#unix://}" != "$1" ] && printf '%s' "${1#unix://}")" /var/run/docker.sock "$HOME/.docker/run/docker.sock" "${XDG_RUNTIME_DIR:-/nonexistent}/docker.sock"; do
		[ -n "$c" ] || continue
		[ -n "$(engine_of "$c")" ] && { printf '%s' "$c"; return 0; }
	done
	return 0
}
# pkg_config prints the config path of the package's openshell-gateway
# user unit: the --config argument of its ExecStart, else the user's
# default ($XDG_CONFIG_HOME/openshell/gateway.toml).
pkg_config() {
	local p
	p="$(systemctl --user show -p ExecStart --value openshell-gateway.service 2>/dev/null | tr ' ;' '\n\n' | sed -n '/^--config$/{n;p;q}; s/^--config=//p' | head -n 1 || true)"
	printf '%s' "${p:-${XDG_CONFIG_HOME:-$HOME/.config}/openshell/gateway.toml}"
}
# toml_docker_key FILE KEY prints [openshell.drivers.docker].KEY from a
# gateway config ("absent" when unset, "unreadable" when it does not
# parse or does not exist).
toml_docker_key() {
	python3 -I - "$1" "$2" <<'PY' || echo unreadable
import sys, tomllib
try:
    with open(sys.argv[1], "rb") as f:
        c = tomllib.load(f)
except Exception:
    print("unreadable"); sys.exit(0)
print(c.get("openshell", {}).get("drivers", {}).get("docker", {}).get(sys.argv[2], "absent"))
PY
}
# priv_sock prints the socket the private gateway's driver uses: the
# DOCKER_HOST its record says the unit was started with, else its unit's.
priv_sock() {
	local dh
	dh="$(python3 -I -c 'import json,sys
try:
    print(json.load(open(sys.argv[1])).get("docker_host", ""))
except Exception:
    print("")' "$OBSDIR/sandbox-openshell/gateway/gateway.json" 2>/dev/null || true)"
	[ -n "$dh" ] || { [ -n "$(gw_unit)" ] && dh="$(docker_host_of "$(gw_unit)")"; }
	detect_sock "$dh"
}
# journal_read UNIT SINCE: the unit's journal since an epoch second, in
# JOURNAL_LINES (lines, journalctl's own "-- " notes removed), with
# JOURNAL_OK=1 only when journalctl succeeded and the unit logged at least
# one line in the window (an unreadable journal is never "no lines").
journal_read() {
	local out
	JOURNAL_OK=0
	JOURNAL_LINES=""
	if out="$(journalctl --user -u "$1" --since "@$2" --no-pager -o cat 2>/dev/null)"; then
		JOURNAL_LINES="$(printf '%s\n' "$out" | grep -v '^-- ' | grep -v '^$' || true)"
		[ -n "$JOURNAL_LINES" ] && JOURNAL_OK=1
	fi
	return 0
}
# coexist_box_facts BOX: while the box exists, the sandbox namespace its
# own containers carry on the private gateway's engine, and every managed
# container's namespace there (name:count).
coexist_box_facts() {
	local s
	s="$(priv_sock)"
	R[coexist.private_socket]="${s:-none answered}"
	if [ -z "$s" ]; then
		R[coexist.box_namespace]="unread: no engine answered on the private gateway's socket"
		return 0
	fi
	R[coexist.box_namespace]="$(docker -H "unix://$s" ps -a --filter "label=openshell.ai/sandbox-name=$1" --format '{{.Label "openshell.ai/sandbox-namespace"}}' 2>/dev/null | sort -u | tr '\n' ' ' | sed 's/ $//' || true)"
	R[coexist.box_namespace]="${R[coexist.box_namespace]:-unread: no container labelled with the box name}"
	R[coexist.engine_namespaces]="$(docker -H "unix://$s" ps -a --filter "label=openshell.ai/managed-by=openshell" --format '{{.Label "openshell.ai/sandbox-namespace"}}' 2>/dev/null | sort | uniq -c | awk '{printf "%s%s:%s", (NR>1?" ":""), $2, $1}' || true)"
}
# coexist_events EVENTS RELEASE_NS reads run 1's container events, one per
# line "<time ns> <action> <role>/ <namespace>", against the release time
# in nanoseconds: the counts per action and role, the namespaces of the
# sandbox and supervisor create events, how many of those creates came
# before the release, how many kills, stops or dies of those roles came
# before it (counted) and after it (the teardown, recorded).
coexist_events() {
	local ev="$1" rel="$2"
	R[coexist.box_events]="$(printf '%s\n' "$ev" | awk 'NF>=2{sub(/\/$/, "", $3); print $2 "/" ($3 == "" ? "none" : $3)}' | sort | uniq -c | awk '{printf "%s%s:%s", (NR>1?" ":""), $2, $1}' || true)"
	R[coexist.box_events]="${R[coexist.box_events]:-none}"
	R[coexist.box_create_namespaces]="$(printf '%s\n' "$ev" | awk '$2=="create" && ($3=="/" || $3=="sandbox/" || $3=="supervisor/") && $4!="" {print $4}' | sort -u | tr '\n' ' ' | sed 's/ $//' || true)"
	R[coexist.box_create_namespaces]="${R[coexist.box_create_namespaces]:-none}"
	R[coexist.box_created_before_release]="$(printf '%s\n' "$ev" | awk -v rel="$rel" '$2=="create" && ($3=="/" || $3=="sandbox/" || $3=="supervisor/") && $1+0 < rel+0' | grep -c . || true)"
	R[coexist.box_stop_events]="$(printf '%s\n' "$ev" | awk -v rel="$rel" '($2=="kill" || $2=="stop" || $2=="die") && ($3=="/" || $3=="sandbox/" || $3=="supervisor/") && $1+0 <= rel+0' | grep -c . || true)"
	R[coexist.box_teardown_events]="$(printf '%s\n' "$ev" | awk -v rel="$rel" '($2=="kill" || $2=="stop" || $2=="die") && ($3=="/" || $3=="sandbox/" || $3=="supervisor/") && $1+0 > rel+0' | grep -c . || true)"
}
# tree_digest prints a digest of a directory tree's names, modes, sizes
# and contents ("absent" when it does not exist); it never prints a
# content.
tree_digest() {
	[ -e "$1" ] || { echo absent; return 0; }
	(cd "$1" && find . -printf '%p %m %s\n' 2>/dev/null | sort && find . -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum 2>/dev/null) | sha256sum | cut -c1-16
}
# cleanup runs on every exit: it deletes the boxes still listed under this
# run's install label and records what was left before and after, stops the
# daemon, moves the throwaway observer dir into the work dir (so a re-run
# is not refused) and writes the receipt once.
cleanup() {
	local rc=$? left after n
	set +e
	[ -n "$EXIT_CODE" ] || EXIT_CODE=$rc
	if [ "$RECEIPT_WRITTEN" = 0 ] && [ "$rc" != 0 ] && [ "$EXIT_CODE" != 2 ] && [ "$COMPLETED" = 0 ]; then
		R[aborted]="the script stopped early (exit $rc); the checks after the last one recorded did not run"
		FAIL=1
	fi
	if [ -n "${INSTALL_ID_FILE:-}" ]; then
		left="$(list_boxes | tr '\n' ' ')"
		R[cleanup.left_boxes]="${left:-none}"
		if [ -n "$left" ]; then
			for n in $left; do osh sandbox delete "$n" >/dev/null 2>&1; done
			after="$(list_boxes | tr '\n' ' ')"
			R[cleanup.after_delete]="${after:-none}"
		else
			R[cleanup.after_delete]="not run: no box of this run was left to delete"
		fi
	fi
	if [ -n "${DAEMON_PID:-}" ]; then
		kill "$DAEMON_PID" 2>/dev/null
		wait "$DAEMON_PID" 2>/dev/null
	fi
	# Managed: stop the private gateway unit in any state but inactive
	# (activating or failed included, audit finding O2-A12), remove its RAM
	# dir (the PKI copy and the env file), unset the sentinel this script
	# put into the user manager, and record it.
	if [ "$MANAGED" = 1 ]; then
		systemctl --user unset-environment O2_LIVE_SENTINEL >/dev/null 2>&1
		if [ -n "$(gw_unit)" ]; then
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
	fi
	# A launch still running (an early abort) is stopped first, so the wait
	# never sits out its own deadline (up to 600 s).
	for n in $(jobs -p); do kill "$n" 2>/dev/null; done
	wait 2>/dev/null
	rm -f "${HOLD_FILE:-}"
	if [ "${OBSDIR_MADE:-0}" = 1 ] && [ -d "$OBSDIR" ]; then
		mv "$OBSDIR" "$WORK/observer-dir" && R[cleanup.observer_dir]="moved to the work dir"
	fi
	# Stamped here, after every wait and the cleanup, so it is the run's true
	# end and never earlier than a wait the receipt records.
	R[finished]="$(date -u +%Y%m%dT%H%M%SZ)"
	R[completed]="$([ "$COMPLETED" = 1 ] && echo yes || echo no)"
	[ "$RECEIPT_WRITTEN" = 1 ] || write_receipt
	if [ "$EXIT_CODE" = 2 ]; then exit 2; fi
	exit "$FAIL"
}
trap cleanup EXIT

# ---- preconditions ----------------------------------------------------------
[ "$(id -u)" != 0 ] || refuse "run as a normal user, not root"
[ "$(uname -s)" = Linux ] || refuse "native Linux only"
if grep -qi microsoft /proc/version 2>/dev/null; then refuse "WSL2 is refused by design (row P1)"; fi
command -v openshell >/dev/null || refuse "the openshell CLI is not on PATH (install v0.1.6 yourself; this script never installs it)"
if [ "$MANAGED" = 1 ]; then
	command -v openshell-gateway >/dev/null || refuse "openshell-gateway is not on PATH (install the OpenShell v0.1.6 package; this script never installs it)"
	command -v systemctl >/dev/null || refuse "systemctl is not on PATH (the managed gateway runs as a systemd user unit)"
	[ -n "${XDG_RUNTIME_DIR:-}" ] || refuse "XDG_RUNTIME_DIR is not set: log in through a systemd session (SSH) or enable lingering"
	R[host.user_manager]="$(systemctl --user is-system-running 2>/dev/null || true)"
	R[host.openshell_gateway]="$( (openshell-gateway --version 2>/dev/null || echo unreadable) | head -n 1)"
	R[host.user_openshell_config_before]="$(tree_digest "$HOME/.config/openshell")"
	R[host.user_openshell_state_kek_before]="$([ -e "$HOME/.local/state/openshell/gateway/credentials/key-encryption-key.bin" ] && echo present || echo absent)"
	# The package installer enables and starts the user's own gateway on the
	# same Docker engine (finding F-027): recorded, never stopped here.
	R[host.package_gateway_before]="$(systemctl --user is-active openshell-gateway.service 2>/dev/null || true)"
	R[host.package_gateway_enabled]="$(systemctl --user is-enabled openshell-gateway.service 2>/dev/null || true)"
	R[coexist.since]="$(date +%s)"
	# The private gateway runs under the user manager: it must hold the
	# docker socket's group (a manager started before the user joined the
	# group keeps its old groups; OB-047), or the host is refused, not
	# failed (audit finding O2-A12).
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
	# A8: a sentinel imported into the user manager's environment must not
	# reach a box (the private gateway inherits the manager's environment).
	systemctl --user set-environment O2_LIVE_SENTINEL=o2-sentinel-0000 || refuse "could not set a sentinel in the user manager's environment"
fi
command -v python3 >/dev/null || refuse "python3 is needed for the PTY driver"
R[host.kernel]="$(uname -r)"
R[host.docker]="$(docker version --format '{{.Server.Version}}' 2>/dev/null | tr -d '\n' || true)"
R[host.docker]="${R[host.docker]:-absent}"
R[host.podman]="$(podman version --format '{{.Version}}' 2>/dev/null | tr -d '\n' || true)"
R[host.podman]="${R[host.podman]:-absent}"
if [ "$PODMAN_LAUNCH" = 1 ]; then
	# Observer's own container calls (the runtime canary, the engine and
	# image reads) run the docker CLI: on this host it must drive the
	# Podman engine the gateway's driver uses. Recorded as a shape, never
	# the DOCKER_HOST value.
	[ "${R[host.podman]}" != absent ] || refuse "--podman-launch needs Podman (podman version answered nothing)"
	command -v docker >/dev/null || refuse "--podman-launch needs a docker CLI that drives the Podman engine (install podman-docker, or the docker CLI with DOCKER_HOST at Podman's socket); Observer's runtime canary and image checks run docker"
	R[podman.docker_cli]="$( (docker --version 2>/dev/null || echo unreadable) | head -n 1 | grep -qi podman && echo podman-docker || echo docker-cli)"
	R[podman.docker_host_set]="$([ -n "${DOCKER_HOST:-}" ] && echo yes || echo no)"
	R[podman.docker_cli_server]="$(docker version --format '{{.Server.Version}}' 2>/dev/null | tr -d '\n' || true)"
	[ -n "${R[podman.docker_cli_server]}" ] || refuse "the docker CLI reaches no engine (start the Podman socket: systemctl --user enable --now podman.socket)"
fi
R[host.docker_group]="$(id -nG | tr ' ' '\n' | grep -qx docker && echo true || echo false)"
# Each precondition pipeline is guarded: a down gateway or a missing tool
# is a fact for the receipt, never an exit without one.
R[host.openshell_cli]="$( (openshell --version 2>/dev/null || echo unreadable) | head -n 1)"
R[host.gateway_status]="$( (openshell status -o json 2>/dev/null || true) | python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin); print(d.get("status",""), d.get("version",""), (d.get("authentication") or {}).get("status",""), d.get("server",""))
except Exception: print("unreadable")' || echo unreadable)"

if [ -z "$OBSERVER" ]; then
	command -v go >/dev/null || refuse "no --observer and no go toolchain to build one"
	ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
	# Static (CGO_ENABLED=0), as releases are: the probe's runtime canary runs
	# this binary inside OpenShell's distroless supervisor image, whose glibc
	# (not the host's) a cgo build would load.
	# The Podman launch half measures the P6 lift, which the shipped table
	# keeps refusing until a receipt path is written in (audit finding
	# FU7-A1): this build sets the receipt field to a run marker at link
	# time, so the binary under test takes the Podman driver. Never ship it.
	LDFLAGS=""
	if [ "$PODMAN_LAUNCH" = 1 ]; then
		LDFLAGS="-X github.com/marmutapp/superbased-observer/internal/sandboxopenshell.podmanLaunchReceipt=o1b-l2-launch-run-$STAMP"
		R[podman.receipt_marker]="o1b-l2-launch-run-$STAMP (set at link time)"
	fi
	(cd "$ROOT" && CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$WORK/observer-bin" ./cmd/observer) || refuse "go build failed"
	OBSERVER="$WORK/observer-bin"
fi
OBSERVER="$(readlink -f "$OBSERVER")"
# `observer --version` prints "observer version <v>"; the receipt keeps <v>.
R[observer.version]="$({ "$OBSERVER" --version 2>/dev/null || true; } | awk 'NR == 1 { print $NF }')"
[ -n "${R[observer.version]}" ] || R[observer.version]=unknown

# ---- a private daemon over a throwaway observer dir ------------------------
CONFIG="$OBSDIR/config.toml"
cat >"$CONFIG" <<EOF
[observer]
db_path = "$OBSDIR/observer.db"

[observer.hooks]
auto_register = false

[terminal.sandbox]
enabled = true
backends = ["openshell"]
egress = "proxy_only"
EOF
# External mode names it; managed mode leaves gateway_mode at its default
# (managed, decision D2), which is what an existing install sees.
if [ "$MANAGED" = 0 ]; then
	printf '\n[terminal.sandbox.openshell]\ngateway_mode = "external"\n' >>"$CONFIG"
fi
printf '\n[components]\nadd = ["terminals.sandbox.openshell"]\n' >>"$CONFIG"
"$OBSERVER" start >"$LOG/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do
	[ -S "$OBSDIR/run/attach.sock" ] || [ -e "$OBSDIR/observer.db" ] && break
	sleep 1
done
sleep 5
# The daemon starts its labelled reaper when it builds the driver with
# openshell listed (audit finding O1B-A4); run 2's reaper check needs it.
if grep -q "the labelled reaper is running" "$LOG/daemon.log" 2>/dev/null; then judge daemon_reaper_running pass; else judge daemon_reaper_running fail "no reaper start line in the daemon log"; fi

# managed_checks judges the private gateway itself (O2-L1); every check
# whose precondition is missing (no unit, no pid, no ss) is not_run.
managed_checks() {
	local unit pid st port addrs bad stray
	unit="$(gw_unit)"
	R[managed.unit]="${unit:-none}"
	if [ -z "$unit" ]; then
		for c in managed_unit_active managed_status_authenticated managed_port_in_block managed_loopback_only managed_telemetry_off managed_custody_disclosed managed_key_custody managed_no_stray_kek_file managed_kek_not_in_unit managed_pki_in_ram user_openshell_config_untouched managed_ocsf_export_configured managed_gateway_started_with_ocsf; do
			not_run "$c" "no install id was minted, so there is no private gateway to check"
		done
		return 0
	fi
	[ "$(systemctl --user is-active "$unit" 2>/dev/null)" = active ] && judge managed_unit_active pass || judge managed_unit_active fail "$(systemctl --user is-active "$unit" 2>&1 | head -n 1)"
	# The unit's restart count and active-enter time before the status call
	# (audit finding OC-V1; managed_gateway_started_with_ocsf compares them).
	local enter_before nr_before
	enter_before="$(systemctl --user show -p ActiveEnterTimestamp --value "$unit" 2>/dev/null || true)"
	nr_before="$(systemctl --user show -p NRestarts --value "$unit" 2>/dev/null || echo unread)"
	st="$( (osh status -o json 2>/dev/null || true) | python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin); print(d.get("gateway",""), d.get("status",""), (d.get("authentication") or {}).get("status",""), d.get("server",""), d.get("version",""))
except Exception: print("unreadable")' || echo unreadable)"
	R[managed.status]="$st"
	# shellcheck disable=SC2086
	set -- $st
	if [ "${1:-}" = "$(gw_name)" ] && [ "${2:-}" = connected ] && [ "${3:-}" = authenticated ]; then judge managed_status_authenticated pass; else judge managed_status_authenticated fail "$st"; fi
	port="${4:-}"
	port="${port##*:}"
	if [[ "${4:-}" == https://127.0.0.1:* ]] && [ "$port" -ge 17700 ] 2>/dev/null && [ "$port" -le 17955 ]; then judge managed_port_in_block pass; else judge managed_port_in_block fail "server ${4:-none}"; fi
	pid="$(gw_pid)"
	R[managed.main_pid_seen]="$([ -n "$pid" ] && [ "$pid" != 0 ] && echo yes || echo no)"
	if [ -z "$pid" ] || [ "$pid" = 0 ]; then
		not_run managed_loopback_only "the unit has no main pid"
		not_run managed_telemetry_off "the unit has no main pid"
	else
		if command -v ss >/dev/null; then
			addrs="$(ss -Hltnup 2>/dev/null | grep "pid=$pid," | awk '{print $5}' | sed 's/:[0-9]*$//' | sort -u | tr '\n' ' ')"
			bad="$(printf '%s' "$addrs" | tr ' ' '\n' | sed '/^$/d' | grep -v -x -e '127\.0\.0\.1' -e '\[::1\]' || true)"
			# Only the class is recorded: a non-loopback address is a host
			# address and never goes into the receipt (audit finding O2-A12).
			if [ -z "$addrs" ]; then R[managed.listen_class]="none"; elif [ -n "$bad" ]; then R[managed.listen_class]="non-loopback"; else R[managed.listen_class]="loopback"; fi
			if [ "${R[managed.listen_class]}" = loopback ]; then judge managed_loopback_only pass; else judge managed_loopback_only fail "listen class ${R[managed.listen_class]}"; fi
		else
			not_run managed_loopback_only "ss is not installed"
		fi
		# The variable's value is compared, never printed or recorded.
		if tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | grep -qx 'OPENSHELL_TELEMETRY_ENABLED=false'; then judge managed_telemetry_off pass; else judge managed_telemetry_off fail "OPENSHELL_TELEMETRY_ENABLED=false is not in the gateway's environment"; fi
	fi
	# Custody: judged from the custody actually in force (audit finding
	# O2-A2, decision OB-050), read from the driver's pin file and from the
	# probe's own disclosure, which must agree.
	local gwdir="$OBSDIR/sandbox-openshell/gateway" custody keyfiles outside badmode
	custody="$(tr -d '\n' <"$gwdir/custody" 2>/dev/null || true)"
	R[managed.custody]="${custody:-none}"
	if [ -n "$custody" ] && grep -q "custody=$custody" "$LOG/status.txt"; then
		judge managed_custody_disclosed pass
	else
		judge managed_custody_disclosed fail "pin ${custody:-none}; the probe does not disclose the same custody"
	fi
	# Key material under the state dir, judged on CONTENT (a PEM private
	# key, or the base64 of a PEM header as the keystore's file store
	# writes it, or the KEK record), never on file names; only paths
	# relative to the state dir are recorded, never a content.
	keyfiles="$(cd "$OBSDIR/sandbox-openshell" 2>/dev/null && { grep -rlIE -e 'PRIVATE KEY' -e 'LS0tLS1CRUdJTi' . 2>/dev/null; find . -type f -name '*.kek' 2>/dev/null; } | sort -u | tr '\n' ' ')"
	R[managed.key_material_files]="$(printf '%s' "$keyfiles" | wc -w | tr -d ' ')"
	case "$custody" in
	keychain)
		if [ -z "${keyfiles// /}" ] && [ ! -d "$gwdir/keys" ]; then judge managed_key_custody pass; else judge managed_key_custody fail "keychain custody, but key material under the state dir: $keyfiles"; fi
		;;
	owner_file)
		# The honest fact: the keys are owner-only files, ONLY under
		# gateway/keys (0700 dir, 0600 files), nowhere else.
		outside="$(printf '%s' "$keyfiles" | tr ' ' '\n' | sed '/^$/d' | grep -v '^\./gateway/keys/' || true)"
		badmode="$(find "$gwdir/keys" -type f ! -perm 0600 2>/dev/null | wc -l | tr -d ' ')"
		if [ -n "${keyfiles// /}" ] && [ -z "$outside" ] && [ "$(stat -c %a "$gwdir/keys" 2>/dev/null)" = 700 ] && [ "$badmode" = 0 ]; then
			judge managed_key_custody pass "owner_file custody: the PKI and the KEK are unencrypted 0600 files under gateway/keys only (disclosed, OSH-21)"
		else
			judge managed_key_custody fail "owner_file custody: key material outside gateway/keys (${outside:-none}) or wrong modes ($badmode files not 0600)"
		fi
		;;
	*)
		not_run managed_key_custody "no custody pin under the state dir, so the custody in force is not known"
		;;
	esac
	# No key-encryption-key.bin anywhere the gateway could leave one (the
	# O0-L2 stray file), checked by name and size.
	stray="$(find "$OBSDIR" -name key-encryption-key.bin 2>/dev/null | sed "s|^$OBSDIR|.observer|" | tr '\n' ' ')"
	if [ "${R[host.user_openshell_state_kek_before]}" = absent ] && [ -e "$HOME/.local/state/openshell/gateway/credentials/key-encryption-key.bin" ]; then
		stray="$stray ~/.local/state/openshell/gateway/credentials/key-encryption-key.bin"
	fi
	[ -z "${stray// /}" ] && judge managed_no_stray_kek_file pass || judge managed_no_stray_kek_file fail "$stray"
	# The KEK is in no transient unit file and no `systemctl show` answer
	# (audit finding O2-A6): the variable's NAME is looked for, never
	# printed with a value.
	local tfile="${XDG_RUNTIME_DIR:-/nonexistent}/systemd/transient/$unit"
	if systemctl --user show -p Environment --value "$unit" 2>/dev/null | tr ' ' '\n' | grep -q '^OBSERVER_OPENSHELL_GATEWAY_KEK='; then
		judge managed_kek_not_in_unit fail "the KEK variable is in the unit's Environment property"
	elif [ -f "$tfile" ] && grep -q 'OBSERVER_OPENSHELL_GATEWAY_KEK=' "$tfile"; then
		judge managed_kek_not_in_unit fail "the KEK variable is in the transient unit file"
	elif ! systemctl --user show -p EnvironmentFiles --value "$unit" 2>/dev/null | grep -q "$(gw_rtdir)/gateway.env"; then
		judge managed_kek_not_in_unit fail "the unit does not read the RAM dir's env file"
	else
		judge managed_kek_not_in_unit pass
	fi
	if [ -z "$(gw_pid)" ] || [ "$(gw_pid)" = 0 ] || [ ! -r "/proc/$(gw_pid)/environ" ]; then
		R[managed.gateway_holds_sentinel]="not read"
	else
		R[managed.gateway_holds_sentinel]="$(tr '\0' '\n' <"/proc/$(gw_pid)/environ" 2>/dev/null | grep -q '^O2_LIVE_SENTINEL=' && echo yes || echo no)"
	fi
	R[managed.supervisor_image_present]="$(docker image inspect --format '{{.Id}}' "ghcr.io/nvidia/openshell/supervisor:$(printf '%s' "${R[managed.status]}" | awk '{print $5}')" >/dev/null 2>&1 && echo yes || echo no)"
	if [ -f "$(gw_rtdir)/tls/ca.key" ] && [ "$(stat -f -c %T "$(gw_rtdir)" 2>/dev/null)" = tmpfs ]; then judge managed_pki_in_ram pass; else judge managed_pki_in_ram fail "the PKI is not in a tmpfs runtime dir"; fi
	[ "$(tree_digest "$HOME/.config/openshell")" = "${R[host.user_openshell_config_before]}" ] && judge user_openshell_config_untouched pass || judge user_openshell_config_untouched fail "the digest of ~/.config/openshell changed"
	# Lane OC: Observer writes the private gateway's OCSF export itself,
	# pointed at the daemon's loopback receiver (read here keys only).
	R[managed.ocsf_export]="$(python3 -I - "$OBSDIR/sandbox-openshell/gateway/gateway.toml" "http://127.0.0.1:14317" <<'PY' || echo unreadable
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
)"
	[ "${R[managed.ocsf_export]}" = present ] && judge managed_ocsf_export_configured pass || judge managed_ocsf_export_configured fail "the private gateway's config reads ${R[managed.ocsf_export]}"
	# Audit findings OC-A5 and OC-V1: the OCSF block's shape is doc-sourced,
	# so the private gateway must be shown to RUN with it, not only to have
	# it written. The unit is Type=simple (active the moment the binary is
	# exec'd, before it parses its config) and Restart=on-failure, so an
	# `active` reading alone can land in one slice of a crash loop. The
	# check passes only when ALL of these hold, each recorded: the export
	# is in the file; the unit entered active after the file was written
	# (Observer writes it and runs openshell-gateway's own config preflight
	# on it only at a start); managed_status_authenticated passed in this
	# run (the gateway answered and authenticated); the unit's NRestarts is
	# 0 and its ActiveEnterTimestamp the same before the status call, at
	# this point and after a settle wait (managed.settle_seconds after it
	# entered active); and the unit is still active after that wait. A
	# condition that was not read is a fail naming it; with the status
	# check not run the fact is not established (not_run), never a pass.
	# Whether events arrive is O3-L1's ocsf_allow_list_miss_row, not this.
	local cfg="$OBSDIR/sandbox-openshell/gateway/gateway.toml" cfg_mtime active_at enter_now enter_after nr_now nr_after nr state_after settle_left why=""
	R[managed.ocsf_block_keys]="$(python3 -I - "$cfg" <<'PY' || echo unreadable
import sys, tomllib
try:
    with open(sys.argv[1], "rb") as f:
        c = tomllib.load(f)
except Exception:
    print("unreadable"); sys.exit(0)
o = c.get("openshell", {}).get("gateway", {}).get("otlp", {})
keys = ["otlp." + k for k in sorted(o) if k != "ocsf"] + ["otlp.ocsf." + k for k in sorted(o.get("ocsf", {}))]
print(",".join(keys) or "none")
PY
)"
	cfg_mtime="$(stat -c %Y "$cfg" 2>/dev/null || echo 0)"
	enter_now="$(systemctl --user show -p ActiveEnterTimestamp --value "$unit" 2>/dev/null || true)"
	active_at="$(date -d "$enter_now" +%s 2>/dev/null || echo 0)"
	[ -n "$enter_now" ] || active_at=0
	nr_now="$(systemctl --user show -p NRestarts --value "$unit" 2>/dev/null || echo unread)"
	R[managed.ocsf_config_written_at]="$cfg_mtime"
	R[managed.unit_active_since]="$active_at"
	R[managed.settle_seconds]=15
	settle_left=$((active_at + 15 - $(date +%s)))
	[ "$active_at" -gt 0 ] && [ "$settle_left" -gt 0 ] && sleep "$settle_left"
	state_after="$(systemctl --user is-active "$unit" 2>/dev/null || true)"
	enter_after="$(systemctl --user show -p ActiveEnterTimestamp --value "$unit" 2>/dev/null || true)"
	nr_after="$(systemctl --user show -p NRestarts --value "$unit" 2>/dev/null || echo unread)"
	R[managed.nrestarts_before_status]="${nr_before:-unread}"
	R[managed.nrestarts_at_check]="${nr_now:-unread}"
	R[managed.nrestarts_after_settle]="${nr_after:-unread}"
	R[managed.active_enter_before_status]="${enter_before:-unread}"
	R[managed.active_enter_at_check]="${enter_now:-unread}"
	R[managed.active_enter_after_settle]="${enter_after:-unread}"
	R[managed.unit_state_after_settle]="${state_after:-unread}"
	R[managed.ocsf_log_lines]="$(journalctl --user -u "$unit" --no-pager -o cat 2>/dev/null | grep -iE 'otlp|ocsf' | head -n 3 | tr '\n' ' ' | cut -c1-400 || true)"
	[ "${R[managed.ocsf_export]}" = present ] || why="$why; the OCSF export is ${R[managed.ocsf_export]} in the file"
	if [ "$cfg_mtime" -le 0 ] || [ "$active_at" -le 0 ]; then
		why="$why; the config's write time or the unit's active-enter time was not read"
	elif [ "$active_at" -lt "$cfg_mtime" ]; then
		why="$why; the unit entered active ($active_at) before the config was written ($cfg_mtime)"
	fi
	[ "${R[check.managed_status_authenticated]:-}" = pass ] || why="$why; managed_status_authenticated is ${R[check.managed_status_authenticated]:-missing}"
	for nr in "${nr_before:-unread}" "${nr_now:-unread}" "${nr_after:-unread}"; do
		if [ "$nr" != 0 ]; then why="$why; NRestarts read $nr (before status ${nr_before:-unread}, at check ${nr_now:-unread}, after settle ${nr_after:-unread})"; break; fi
	done
	if [ -z "${enter_before:-}" ] || [ "${enter_before:-}" != "$enter_now" ] || [ "$enter_now" != "$enter_after" ]; then
		why="$why; ActiveEnterTimestamp changed or was not read (before status ${enter_before:-unread}, at check ${enter_now:-unread}, after settle ${enter_after:-unread})"
	fi
	[ "$state_after" = active ] || why="$why; the unit is ${state_after:-unread} after the settle wait"
	why="${why#; }"
	if [ -z "$why" ]; then
		R[managed.gateway_started_with_ocsf]=yes
		judge managed_gateway_started_with_ocsf pass
	elif [ "${R[check.managed_status_authenticated]:-}" = not_run ] || [ -z "${R[check.managed_status_authenticated]:-}" ]; then
		R[managed.gateway_started_with_ocsf]=not_established
		not_run managed_gateway_started_with_ocsf "not established: $why"
	else
		R[managed.gateway_started_with_ocsf]=no
		judge managed_gateway_started_with_ocsf fail "$why"
	fi
}

# restart_daemon stops the daemon and starts it again over the same config.
restart_daemon() {
	kill "$DAEMON_PID" 2>/dev/null || true
	wait "$DAEMON_PID" 2>/dev/null || true
	"$OBSERVER" start >>"$LOG/daemon.log" 2>&1 &
	DAEMON_PID=$!
	sleep 8
}

# ---- the probe ----------------------------------------------------------------
"$OBSERVER" sandbox status >"$LOG/status.txt" 2>&1 || true
PROBE_LINE="$( (grep -i openshell "$LOG/status.txt" || true) | head -n 3 | tr '\n' ' ')"
R[probe.status_lines]="$PROBE_LINE"
if [ "$EXPECT_PODMAN" = 1 ] && [ "$PODMAN_LAUNCH" = 0 ]; then
	if grep -q driver_untested "$LOG/status.txt" && grep -qi podman "$LOG/status.txt"; then
		judge probe_refuses_podman pass
	else
		judge probe_refuses_podman fail "$PROBE_LINE"
	fi
	COMPLETED=1
	exit "$FAIL"
fi
# ---- the Podman launch half (O1B-L2, tracker F-033) -------------------------
# The gateway must run the Podman driver (gateway info), and the probe must
# take it: a driver_untested refusal means the binary under test does not
# carry lane FU7's P6 lift.
if [ "$PODMAN_LAUNCH" = 1 ]; then
	R[podman.gateway_driver]="$( (openshell gateway info -o json 2>/dev/null || true) | python3 -I -c 'import json,sys
try:
    d=json.load(sys.stdin); print(((d.get("compute_drivers") or [{}])[0]).get("name","") or "unread")
except Exception: print("unread")' || echo unread)"
	[ "${R[podman.gateway_driver]}" = podman ] && judge podman_driver_in_use pass || judge podman_driver_in_use fail "the gateway's compute driver reads ${R[podman.gateway_driver]}"
	if grep -q driver_untested "$LOG/status.txt"; then
		R[podman.probe]="driver_untested: the binary under test does not carry the P6 lift"
	fi
	if grep -q "prerequisite podman" "$LOG/status.txt"; then judge podman_prereq_reported pass; else judge podman_prereq_reported fail "no podman prerequisite line"; fi
fi
# The row is available only when the STATUS column of the openshell row in
# the backend table says exactly "available" (a bare text match would also
# take "not available" on the row's reason line, as the first live
# receipt did).
PROBE_STATUS="$(awk '$1 == "openshell" && NF >= 4 { print $4; exit }' "$LOG/status.txt" 2>/dev/null || true)"
R[probe.status]="${PROBE_STATUS:-not shown}"
if [ "$PROBE_STATUS" = available ]; then
	judge probe_available pass
else
	judge probe_available fail "status ${PROBE_STATUS:-not shown}: $( (grep -m 1 '^openshell: not available' "$LOG/status.txt" || true) | tr -d '\n')"
fi
if [ "$PODMAN_LAUNCH" = 0 ]; then
	if grep -q docker_group "$LOG/status.txt"; then judge prereq_reported pass; else judge prereq_reported fail "no docker_group prerequisite line"; fi
fi

# ---- managed mode: the private gateway's own checks -------------------------
if [ "$MANAGED" = 1 ]; then
	if grep -q "gateway_mode managed" "$LOG/status.txt"; then judge managed_mode_reported pass; else judge managed_mode_reported fail "no gateway_mode managed line in sandbox status"; fi
	managed_checks
fi

# ---- the agent script inside the workspace -----------------------------------
AGENT="$WS/agent.sh"
# HOLD_FILE carries a run's hold to the agent (ptyrun).
HOLD_FILE="$WS/.o1b-hold"
cat >"$AGENT" <<'EOS'
#!/bin/sh
# Prints facts about the box as O1B: markers, then waits for a line, then
# holds for the seconds in .o1b-hold beside it (the workspace is a same-path
# bind; the box gets none of the host launch's environment, so the hold
# cannot ride in a variable).
HOLD=0
RELEASE=0
HOLD_FILE="$(dirname "$0")/.o1b-hold"
if [ -r "$HOLD_FILE" ]; then
	grep -q release "$HOLD_FILE" && RELEASE=1
	HOLD="$(head -c 16 "$HOLD_FILE" | tr -cd 0-9)"
fi
# The launcher sets the box terminal's size once the client attaches, which
# can land just after this script starts (live O2-L1 read 24 80, the PTY
# default, in one of two clean runs). Wait up to 5 s, in 0.1 s steps, for a
# size other than that default and record how many steps it took; the
# check still requires exactly 40 100.
SIZE1="$(stty size 2>/dev/null)"
STEPS=0
while { [ -z "$SIZE1" ] || [ "$SIZE1" = "24 80" ]; } && [ "$STEPS" -lt 50 ]; do
	sleep 0.1 2>/dev/null || sleep 1
	STEPS=$((STEPS + 1))
	SIZE1="$(stty size 2>/dev/null)"
done
echo "O1B:size1=$SIZE1"
echo "O1B:size1_wait_steps=$STEPS"
echo "O1B:uid=$(id -u)"
echo "O1B:home_fs=$(stat -f -c %T "$HOME" 2>/dev/null)"
echo "O1B:home_mode=$(stat -c %a/%u "$HOME" 2>/dev/null)"
echo "O1B:cwd=$(pwd)"
echo "O1B:ws_write=$( (echo x >"$PWD/o1b-written" && echo ok) 2>/dev/null || echo failed)"
echo "O1B:ssh_visible=$( [ -e "$HOME/.ssh" ] && echo yes || echo no)"
echo "O1B:observer_db_visible=$( [ -e "$HOME/.observer/observer.db" ] && echo yes || echo no)"
echo "O1B:config_seeded=$( [ -f "$HOME/.observer/config.toml" ] && echo yes || echo no)"
echo "O1B:sandbox_dir=$( [ -e /sandbox ] && ls -A /sandbox 2>/dev/null | wc -l || echo absent)"
echo "O1B:sandbox_write=$( (: >/sandbox/o1b-probe && rm -f /sandbox/o1b-probe && echo ok) 2>/dev/null || echo failed)"
echo "O1B:sock_link=$(readlink /tmp/.observer-sandbox-net 2>/dev/null)"
echo "O1B:relay_record=$( [ -e /tmp/.observer-sandbox-net/launch.json ] && echo yes || echo no)"
# The dir the relay clients read the record from (the in-box init names it
# in OBSERVER_OPENSHELL_SOCK_DIR), its mode/owner, and the shared
# process_lite variable, which the init removes.
echo "O1B:sock_env=${OBSERVER_OPENSHELL_SOCK_DIR:-}"
echo "O1B:sock_env_dir=$(stat -c %a/%u "${OBSERVER_OPENSHELL_SOCK_DIR:-/nonexistent}" 2>/dev/null)"
echo "O1B:sock_env_record=$( [ -f "${OBSERVER_OPENSHELL_SOCK_DIR:-/nonexistent}/launch.json" ] && echo yes || echo no)"
echo "O1B:shared_sock_env=${OBSERVER_SANDBOX_SOCK_DIR:-unset}"
echo "O1B:docker_sock=$( [ -S /var/run/docker.sock ] && echo visible || echo absent)"
echo "O1B:manager_sentinel=$( [ -n "${O2_LIVE_SENTINEL:-}" ] && echo present || echo absent)"
echo "O1B:ready=1"
read -r _line
echo "O1B:size2=$(stty size 2>/dev/null)"
echo "O1B:hold=${HOLD:-0}"
# A release hold (run 1) waits for a second line, sent once the script has
# listed the box, so a slow host never misses the box (F-023 V9).
if [ "$RELEASE" = 1 ]; then read -r _line2; fi
sleep "${HOLD:-0}"
exit 42
EOS
chmod 755 "$AGENT"

# ptyrun HOLD OUT: runs one launch on a PTY of 40x100, resizes to 50x132 after
# the ready marker, sends a newline, and records the exit code. The agent
# holds HOLD seconds after the newline: the hold rides in .o1b-hold in the
# workspace (a same-path bind the agent reads; the box gets none of the
# launch's host environment), written before the launch and removed after.
# The launch's own output goes to OUT as it arrives (so a waiter can see the
# ready marker while the run holds); the PID of the launch goes to OUT.pid.
ptyrun() {
	local hold="$1" out="$2"
	printf '%s\n' "$hold" >"$HOLD_FILE"
	(cd "$WS" && python3 -I - "$OBSERVER" "$CONFIG" "$AGENT" "$out" <<'PY'
import os, pty, sys, time, select, fcntl, termios, struct, signal
obs, cfg, agent, out = sys.argv[1:5]
argv = [obs, "claude", "--claude-path", agent, "--observer-sandbox", "openshell"]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
    os.execv(obs, argv)
open(out + ".pid", "w").write(str(pid))
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
log = open(out, "wb")
buf = b""; sent = False; released = False; deadline = time.time() + 600
while time.time() < deadline:
    if sent and not released and os.path.exists(out + ".release"):
        time.sleep(0.5)
        os.write(fd, b"\n"); released = True
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
        if not sent and b"O1B:ready=1" in buf:
            time.sleep(1)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 132, 0, 0))
            os.kill(pid, signal.SIGWINCH)
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
code = os.waitstatus_to_exitcode(status)
log.close()
open(out + ".code", "w").write(str(code))
PY
	)
	rm -f "$HOLD_FILE"
}
# marker prints a marker's value from a run's output ("" when the run left
# no output file, so a crashed launch is recorded, not an abort).
marker() {
	[ -f "$1" ] || return 0
	tr -d '\r' <"$1" | sed -n "s/^.*O1B:$2=//p" | head -n 1
}

# ---- managed mode: a daemon restart leaves the private gateway running ------
if [ "$MANAGED" = 1 ]; then
	PID_BEFORE="$(gw_pid)"
	if [ -z "$PID_BEFORE" ] || [ "$PID_BEFORE" = 0 ]; then
		not_run managed_survives_daemon_restart "the private gateway had no main pid before the restart"
	else
		restart_daemon
		PID_AFTER="$(gw_pid)"
		R[managed.restart_same_pid]="$([ "$PID_AFTER" = "$PID_BEFORE" ] && echo yes || echo no)"
		[ "$PID_AFTER" = "$PID_BEFORE" ] && [ "$(systemctl --user is-active "$(gw_unit)" 2>/dev/null)" = active ] && judge managed_survives_daemon_restart pass || judge managed_survives_daemon_restart fail "main pid changed or the unit is not active after the daemon restart"
	fi
fi

# ---- run 1: the box's shape, labels, exit code, gone afterwards --------------
# Run 1 holds until released (F-023 V9): after the ready marker and the
# resize newline the agent waits for a second newline, which ptyrun sends
# only once this script has listed the box (or given up), so the strict
# listing check never races a fast exit on a slow host.
ptyrun release "$LOG/run1.out" &
RUN1=$!
LISTED=""
for _ in $(seq 1 120); do
	LISTED="$(list_boxes)"
	[ -n "$LISTED" ] && break
	kill -0 "$RUN1" 2>/dev/null || break
	sleep 1
done
# Managed mode: the namespace run 1's containers carry, read while they
# exist (finding OC3-1): a box is listed by the gateway before its
# containers are created, so the read waits for the agent's ready marker
# (the agent then holds until the release); up to the release no sandbox
# or supervisor container of the box may be killed, stopped or die
# (finding OC2-A2).
if [ "$MANAGED" = 1 ] && [ -n "$LISTED" ]; then
	R[coexist.box]="$(printf '%s\n' "$LISTED" | head -n 1)"
	for _ in $(seq 1 180); do
		grep -q "O1B:ready=1" "$LOG/run1.out" 2>/dev/null && break
		kill -0 "$RUN1" 2>/dev/null || break
		sleep 1
	done
	R[coexist.box_read_after_ready]="$(grep -q "O1B:ready=1" "$LOG/run1.out" 2>/dev/null && echo yes || echo no)"
	coexist_box_facts "${R[coexist.box]}"
fi
# The Podman launch half reads the run's record back while its box runs:
# the gateway's own `sandbox get` of the listed box, and Observer's plan
# file for the run (its box name, its gateway version and its install
# label must match the listed box and this install).
if [ "$PODMAN_LAUNCH" = 1 ]; then
	if [ -n "$LISTED" ]; then
		for _ in $(seq 1 180); do
			grep -q "O1B:ready=1" "$LOG/run1.out" 2>/dev/null && break
			kill -0 "$RUN1" 2>/dev/null || break
			sleep 1
		done
		PBOX="$(printf '%s\n' "$LISTED" | head -n 1)"
		R[podman.record_box]="$PBOX"
		R[podman.record_gateway_get]="$(osh sandbox get "$PBOX" -o json >"$LOG/podman-get.json" 2>/dev/null && echo read || echo unread)"
		R[podman.record_plan]="$(python3 -I - "$OBSDIR/sandbox-openshell/runs" "$PBOX" "o$(install_id)o" <<'PY' || echo unreadable
import glob, json, os, sys
runs, box, label = sys.argv[1:4]
for p in sorted(glob.glob(os.path.join(runs, "*", "plan.json"))):
    try:
        d = json.load(open(p))
    except Exception:
        continue
    if d.get("name") != box:
        continue
    # The plan file's labels carry Go's field names (Key, Value: the Label
    # type has no json tags); either case is read (audit finding FU7-A2).
    def field(l, name):
        for k, v in l.items():
            if k.lower() == name:
                return v
        return None
    labels = {field(l, "key"): field(l, "value") for l in d.get("labels") or [] if isinstance(l, dict)}
    ok = "observer.superbased.install" in labels and labels["observer.superbased.install"] == label
    print("name=%s gateway_version=%s install_label=%s" % (box, d.get("gateway_version", ""), "match" if ok else "mismatch:" + str(labels.get("observer.superbased.install"))))
    break
else:
    print("no plan names the box")
PY
)"
		if [ "${R[podman.record_gateway_get]}" = read ] && printf '%s' "${R[podman.record_plan]}" | grep -q "install_label=match" && printf '%s' "${R[podman.record_plan]}" | grep -q "gateway_version=0.1.6"; then
			judge podman_run_record_read_back pass
		else
			judge podman_run_record_read_back fail "gateway get ${R[podman.record_gateway_get]}; plan ${R[podman.record_plan]}"
		fi
	else
		not_run podman_run_record_read_back "no box of run 1 was listed, so there was no record to read back"
	fi
fi
R[coexist.window_to]="$(date +%s.%N)"
: >"$LOG/run1.out.release"
R[run1.listed_by_install_label]="$LISTED"
wait "$RUN1" || true
CODE1="$(cat "$LOG/run1.out.code" 2>/dev/null || echo none)"
R[run1.exit_code]="$CODE1"
for k in size1 size1_wait_steps size2 uid home_fs home_mode cwd ws_write ssh_visible observer_db_visible config_seeded sandbox_dir sandbox_write sock_link relay_record sock_env sock_env_dir sock_env_record shared_sock_env docker_sock; do
	R["run1.$k"]="$(marker "$LOG/run1.out" "$k")"
done
# A refusal (the driver's, or the launch checks inside the box) is its own
# field: the first line of its message.
REFUSAL1="$(refusal_line "$LOG/run1.out")"
R[run1.refusal]="${REFUSAL1:-none}"
AGENT1_RAN=0
if grep -q "O1B:ready=1" "$LOG/run1.out" 2>/dev/null; then AGENT1_RAN=1; fi
R[run1.agent_ran]="$([ "$AGENT1_RAN" = 1 ] && echo yes || echo no)"
[ -n "$LISTED" ] && judge dotted_labels_select_the_box pass || judge dotted_labels_select_the_box fail "no box listed under observer.superbased.install"
[ "$CODE1" = 42 ] && judge exact_exit_code pass || judge exact_exit_code fail "exit $CODE1${REFUSAL1:+: $REFUSAL1}"
if [ "$AGENT1_RAN" = 1 ]; then
	[ "${R[run1.size1]}" = "40 100" ] && judge pty_size pass || judge pty_size fail "${R[run1.size1]} after ${R[run1.size1_wait_steps]:-unread} waits of 0.1 s"
	[ "${R[run1.size2]}" = "50 132" ] && judge pty_resize pass || judge pty_resize fail "${R[run1.size2]}"
	[ "${R[run1.uid]}" = "$(id -u)" ] && judge run_as_user pass || judge run_as_user fail "${R[run1.uid]}"
	[ "${R[run1.home_fs]}" = tmpfs ] && [ "${R[run1.home_mode]%%/*}" = 1777 ] && judge tmpfs_home_1777 pass || judge tmpfs_home_1777 fail "${R[run1.home_fs]} ${R[run1.home_mode]}"
	# F-033: the Podman tmpfs mode, measured inside a box the Podman driver
	# made (what probe row P6's lift is grounded on).
	if [ "$PODMAN_LAUNCH" = 1 ]; then
		R[podman.home_fs]="${R[run1.home_fs]}"
		R[podman.home_mode]="${R[run1.home_mode]}"
		[ "${R[run1.home_fs]}" = tmpfs ] && [ "${R[run1.home_mode]%%/*}" = 1777 ] && judge podman_tmpfs_mode_grounded pass || judge podman_tmpfs_mode_grounded fail "home is ${R[run1.home_fs]:-unread} mode ${R[run1.home_mode]:-unread} in the Podman box"
	fi
	[ "${R[run1.cwd]}" = "$WS" ] && [ "${R[run1.ws_write]}" = ok ] && [ -f "$WS/o1b-written" ] && judge workspace_same_path_write pass || judge workspace_same_path_write fail "cwd ${R[run1.cwd]} write ${R[run1.ws_write]}"
	[ "${R[run1.ssh_visible]}" = no ] && judge ssh_hidden pass || judge ssh_hidden fail "${R[run1.ssh_visible]}"
	[ "${R[run1.observer_db_visible]}" = no ] && judge observer_db_hidden pass || judge observer_db_hidden fail "${R[run1.observer_db_visible]}"
	[ "${R[run1.docker_sock]}" = absent ] && judge docker_socket_absent pass || judge docker_socket_absent fail "${R[run1.docker_sock]}"
	if [ "$MANAGED" = 1 ]; then
		R[run1.manager_sentinel]="$(marker "$LOG/run1.out" manager_sentinel)"
		# Only meaningful when the gateway itself held the sentinel (audit
		# finding O2-V5): otherwise the box could not have got it anyway.
		if [ "${R[managed.gateway_holds_sentinel]:-}" != yes ]; then
			not_run user_manager_env_not_in_box "the private gateway's process did not hold the sentinel (${R[managed.gateway_holds_sentinel]:-not read}), so its absence in the box proves nothing"
		elif [ "${R[run1.manager_sentinel]}" = absent ]; then
			judge user_manager_env_not_in_box pass
		else
			judge user_manager_env_not_in_box fail "the user manager's sentinel variable reached the box (${R[run1.manager_sentinel]:-no marker})"
		fi
	fi
	[ "${R[run1.sock_link]}" != "" ] && [ "${R[run1.relay_record]}" = yes ] && judge relay_socket_dir_linked pass || judge relay_socket_dir_linked fail "${R[run1.sock_link]} ${R[run1.relay_record]}"
	# The relay clients read the record from the real dir the init named
	# (review finding V6): the variable names exactly the link's target, that
	# dir is this uid's with mode 0700 and holds the record, and the shared
	# process_lite variable is gone.
	if [ -n "${R[run1.sock_env]}" ] && [ "${R[run1.sock_env]}" = "${R[run1.sock_link]}" ] && [ "${R[run1.sock_env_dir]}" = "700/$(id -u)" ] && [ "${R[run1.sock_env_record]}" = yes ] && [ "${R[run1.shared_sock_env]}" = unset ]; then
		judge relay_record_from_real_dir pass
	else
		judge relay_record_from_real_dir fail "env ${R[run1.sock_env]:-none} link ${R[run1.sock_link]:-none} dir ${R[run1.sock_env_dir]:-unreadable} record ${R[run1.sock_env_record]} shared ${R[run1.shared_sock_env]}"
	fi
	# include_workdir false (the planner never lists OpenShell's /sandbox
	# workdir): /sandbox is absent, or present but neither listable with
	# entries nor writable.
	if [ "${R[run1.sandbox_dir]}" = absent ] || { [ "${R[run1.sandbox_dir]}" = 0 ] && [ "${R[run1.sandbox_write]}" = failed ]; }; then
		judge include_workdir_false pass
	else
		judge include_workdir_false fail "sandbox_dir=${R[run1.sandbox_dir]} sandbox_write=${R[run1.sandbox_write]}"
	fi
else
	# The agent never ran in the box, so the checks that read its markers
	# were not run: said with the reason, never as fails of what they check.
	WHY1="the agent never ran in the box (run 1 exit $CODE1): ${REFUSAL1:-no refusal line in the launch output}"
	for c in pty_size pty_resize run_as_user tmpfs_home_1777 workspace_same_path_write ssh_hidden observer_db_hidden docker_socket_absent relay_socket_dir_linked relay_record_from_real_dir include_workdir_false; do
		not_run "$c" "$WHY1"
	done
	if [ "$PODMAN_LAUNCH" = 1 ]; then not_run podman_tmpfs_mode_grounded "$WHY1"; fi
	if [ "$MANAGED" = 1 ]; then not_run user_manager_env_not_in_box "$WHY1"; fi
fi
if [ -z "$LISTED" ]; then
	not_run box_gone_after_exit "no box of run 1 was listed, so there was no box to show gone"
else
	LEFT=""
	for n in $LISTED; do
		if osh sandbox get "$n" -o json >/dev/null 2>"$LOG/get.err"; then
			LEFT="$LEFT ${n}:present"
		elif ! grep -q "Some requested entity was not found" "$LOG/get.err"; then
			LEFT="$LEFT ${n}:unclear"
		fi
	done
	[ -z "$LEFT" ] && judge box_gone_after_exit pass || judge box_gone_after_exit fail "$LEFT"
fi

# ---- run 2: SIGKILL the host helper, the reaper removes the box --------------
ptyrun 600 "$LOG/run2.out" &
RUN2=$!
for _ in $(seq 1 120); do
	grep -q "O1B:ready=1" "$LOG/run2.out" 2>/dev/null && break
	kill -0 "$RUN2" 2>/dev/null || break
	sleep 1
done
BOX2="$(list_boxes | head -n 1)"
R[run2.box]="${BOX2:-none}"
if [ -z "$BOX2" ]; then
	# No box to kill: nothing is killed and nothing is waited for; the
	# reaper check is not run, with the launch's own end as the reason.
	kill "$RUN2" 2>/dev/null || true
	rm -f "$HOLD_FILE"
	wait "$RUN2" 2>/dev/null || true
	CODE2="$(cat "$LOG/run2.out.code" 2>/dev/null || echo none)"
	REFUSAL2="$(refusal_line "$LOG/run2.out")"
	R[run2.exit_code]="$CODE2"
	R[run2.refusal]="${REFUSAL2:-none}"
	R[run2.reaped_after_s]="not run: run 2 never got a box"
	not_run reaper_removes_killed_run "run 2 never got a box to kill (exit $CODE2): ${REFUSAL2:-no refusal line in the launch output}"
else
	HELPER="$(pgrep -u "$(id -u)" -f 'sandbox-openshell-host' | head -n 1 || true)"
	CLIPID="$(pgrep -u "$(id -u)" -f 'openshell .*sandbox create' | head -n 1 || true)"
	if [ -n "$HELPER" ]; then kill -KILL "$HELPER" 2>/dev/null || true; fi
	if [ -n "$CLIPID" ]; then kill -KILL "$CLIPID" 2>/dev/null || true; fi
	KILLED_AT=$(date +%s)
	GONE=""
	for _ in $(seq 1 240); do
		if ! osh sandbox get "$BOX2" -o json >/dev/null 2>"$LOG/get2.err" && grep -q "Some requested entity was not found" "$LOG/get2.err"; then
			GONE="$(($(date +%s) - KILLED_AT))"
			break
		fi
		sleep 1
	done
	R[run2.waited_s]="$(($(date +%s) - KILLED_AT))"
	kill "$RUN2" 2>/dev/null || true
	rm -f "$HOLD_FILE"
	wait "$RUN2" 2>/dev/null || true
	R[run2.reaped_after_s]="${GONE:-not within 240 s}"
	[ -n "$GONE" ] && judge reaper_removes_killed_run pass || judge reaper_removes_killed_run fail "box $BOX2 was not shown gone within 240 s of the kill"
fi

# ---- managed mode: beside the package's own gateway (finding F-027) --------
# The OpenShell package installer enables and starts the user's own
# openshell-gateway.service on the same Docker engine. Before F-027's fix
# its Docker driver took the private gateway's boxes for its own (both used
# the sandbox namespace "default") and stopped them ("Stopped Docker
# sandbox after control supervisor failure"). Observer now renders
# sandbox_label = <its gateway name>, so each driver lists only its own
# namespace. This judges it only on facts it establishes (finding
# OC2-A2): both gateways' drivers reach the same engine (the engine ID
# behind each one's socket); both journals were read and each unit logged
# in the window (an unreadable journal is not_run, never "0 stopped");
# run 1's own containers carried the private gateway's namespace on that
# engine; and up to the release no sandbox or supervisor container of the
# box was killed, stopped or died (docker events), the package gateway
# stayed active and logged no stopped sandbox, and the private gateway
# logged no control supervisor failure. With the package gateway not
# running at the start coexistence is not shown (not_run).
if [ "$MANAGED" = 1 ]; then
	R[coexist.package_gateway_after]="$(systemctl --user is-active openshell-gateway.service 2>/dev/null || true)"
	R[coexist.private_sandbox_label]="$(toml_docker_key "$OBSDIR/sandbox-openshell/gateway/gateway.toml" sandbox_label)"
	# The engine each driver reaches.
	R[coexist.package_config]="$(pkg_config)"
	PKG_SOCK="$(toml_docker_key "${R[coexist.package_config]}" socket_path)"
	case "$PKG_SOCK" in
	absent | unreadable) PKG_SOCK="$(detect_sock "$(docker_host_of openshell-gateway.service)")" ;;
	esac
	R[coexist.package_socket]="${PKG_SOCK:-none answered}"
	PRIV_SOCK="$(priv_sock)"
	R[coexist.private_socket]="${PRIV_SOCK:-none answered}"
	PKG_ENGINE="$(engine_of "$PKG_SOCK")"
	PRIV_ENGINE="$(engine_of "$PRIV_SOCK")"
	if [ -z "$PKG_ENGINE" ] || [ -z "$PRIV_ENGINE" ]; then
		R[coexist.same_engine]="unknown"
	elif [ "$PKG_ENGINE" = "$PRIV_ENGINE" ]; then
		R[coexist.same_engine]="yes"
	else
		R[coexist.same_engine]="no"
	fi
	# Both journals, read for real.
	journal_read openshell-gateway.service "${R[coexist.since]}"
	PKG_JOK="$JOURNAL_OK"
	R[coexist.package_journal_lines]="$(printf '%s' "$JOURNAL_LINES" | grep -c . || true)"
	R[coexist.package_gateway_stopped_lines]="$(printf '%s\n' "$JOURNAL_LINES" | grep -c 'Stopped Docker sandbox' || true)"
	PRIV_JOK=0
	if [ -n "$(gw_unit)" ]; then
		journal_read "$(gw_unit)" "${R[coexist.since]}"
		PRIV_JOK="$JOURNAL_OK"
		R[coexist.private_journal_lines]="$(printf '%s' "$JOURNAL_LINES" | grep -c . || true)"
		R[coexist.private_supervisor_failure_lines]="$(printf '%s\n' "$JOURNAL_LINES" | grep -ci 'control supervisor failure' || true)"
	fi
	# Run 1's container events from the launch to now (finding OC3-1):
	# when each sandbox or supervisor container was created and in which
	# namespace (the create event carries the container's labels, so this
	# holds even when the box was gone before it could be listed), every
	# kill, stop or die before the release (counted), and the teardown
	# after it (recorded). Staging and identity helpers exit by design, so
	# only the sandbox and supervisor roles count.
	BOX_EVENTS_OK=0
	if [ -n "${R[coexist.box]:-}" ] && [ -n "$PRIV_SOCK" ]; then
		if EV="$(timeout 30 docker -H "unix://$PRIV_SOCK" events --since "${R[coexist.since]}" --until "$(date +%s.%N)" --filter "label=openshell.ai/sandbox-name=${R[coexist.box]}" --filter event=create --filter event=kill --filter event=stop --filter event=die --format '{{.TimeNano}} {{.Action}} {{index .Actor.Attributes "openshell.ai/isolation-role"}}/ {{index .Actor.Attributes "openshell.ai/sandbox-namespace"}}' 2>/dev/null)"; then
			BOX_EVENTS_OK=1
			coexist_events "$EV" "$(printf '%s' "${R[coexist.window_to]}" | tr -d .)"
		else
			R[coexist.box_events]="unreadable"
		fi
	fi
	if [ "${R[host.package_gateway_before]}" != active ]; then
		not_run managed_coexists_with_package_gateway "the package's openshell-gateway.service user unit was not running at the start (${R[host.package_gateway_before]:-unread}), so sharing one Docker engine with it was not shown"
	else
		why=""
		unk=""
		[ "${R[coexist.package_gateway_after]}" = active ] || why="$why; the package gateway is ${R[coexist.package_gateway_after]:-unread} after the runs"
		[ -n "$(gw_name)" ] && [ "${R[coexist.private_sandbox_label]}" = "$(gw_name)" ] || why="$why; the private config's sandbox_label is ${R[coexist.private_sandbox_label]}, not the gateway's own name"
		if [ "$PKG_JOK" = 1 ]; then
			[ "${R[coexist.package_gateway_stopped_lines]}" = 0 ] || why="$why; the package gateway's journal has ${R[coexist.package_gateway_stopped_lines]} 'Stopped Docker sandbox' lines since the run began"
		else
			unk="$unk; the package gateway's journal could not be read, or it logged no line since the run began (journalctl --user -u openshell-gateway.service), so no stop by it is ruled out"
		fi
		if [ "$PRIV_JOK" = 1 ]; then
			[ "${R[coexist.private_supervisor_failure_lines]:-0}" = 0 ] || why="$why; the private gateway's journal has ${R[coexist.private_supervisor_failure_lines]} control supervisor failure lines"
		else
			unk="$unk; the private gateway's journal could not be read, or it logged no line since the run began"
		fi
		case "${R[coexist.same_engine]}" in
		yes) ;;
		no) unk="$unk; the two gateways reach different Docker engines (package socket ${R[coexist.package_socket]}, private socket ${R[coexist.private_socket]}), so sharing one engine was not shown" ;;
		*) unk="$unk; which engine each gateway reaches is unknown (package socket ${R[coexist.package_socket]}, private socket ${R[coexist.private_socket]})" ;;
		esac
		# The namespace run 1's containers carry: read live after the agent
		# was ready, and from their create events; each source that read a
		# value must name the private gateway, and at least one must.
		NS_SEEN=""
		case "${R[coexist.box_namespace]:-unread}" in unread*) ;; *) NS_SEEN="${R[coexist.box_namespace]}" ;; esac
		[ -n "${R[coexist.box_create_namespaces]:-}" ] && [ "${R[coexist.box_create_namespaces]}" != none ] && NS_SEEN="$NS_SEEN ${R[coexist.box_create_namespaces]}"
		NS_SEEN="$(printf '%s\n' $NS_SEEN | sort -u | tr '\n' ' ' | sed 's/ $//')"
		R[coexist.box_namespaces_seen]="${NS_SEEN:-none}"
		if [ -z "$NS_SEEN" ]; then
			unk="$unk; run 1's containers were not read live (${R[coexist.box_namespace]:-no box listed}) and no create event of them was seen (${R[coexist.box_events]:-no box or no engine})"
		elif [ -z "$(gw_name)" ] || [ "$NS_SEEN" != "$(gw_name)" ]; then
			why="$why; run 1's containers carry the namespace $NS_SEEN, not the private gateway's own name"
		fi
		if [ "$BOX_EVENTS_OK" != 1 ]; then
			unk="$unk; docker events for run 1's containers could not be read (${R[coexist.box_events]:-no box or no engine})"
		elif [ "${R[coexist.box_created_before_release]:-0}" = 0 ]; then
			unk="$unk; no sandbox or supervisor container of run 1 was created before the release (${R[coexist.box_events]}), so the window shows nothing about a stop"
		else
			[ "${R[coexist.box_stop_events]}" = 0 ] || why="$why; run 1's sandbox or supervisor containers were killed, stopped or died ${R[coexist.box_stop_events]} time(s) before the release (all events of the run, teardown included: ${R[coexist.box_events]})"
		fi
		why="${why#; }"
		unk="${unk#; }"
		if [ -n "$why" ]; then
			judge managed_coexists_with_package_gateway fail "$why${unk:+; also not shown: $unk}"
		elif [ -n "$unk" ]; then
			not_run managed_coexists_with_package_gateway "$unk"
		else
			judge managed_coexists_with_package_gateway pass
		fi
	fi
fi

# ---- managed mode: not wanted, the idle private gateway stops ---------------
if [ "$MANAGED" = 1 ]; then
	UNIT="$(gw_unit)"
	RT="$(gw_rtdir)"
	if [ -z "$UNIT" ]; then
		not_run managed_stops_when_not_wanted "no private gateway was started"
	else
		kill "$DAEMON_PID" 2>/dev/null || true
		wait "$DAEMON_PID" 2>/dev/null || true
		printf '\n[terminal.sandbox.openshell]\ngateway_mode = "external"\n' >>"$CONFIG"
		"$OBSERVER" start >>"$LOG/daemon.log" 2>&1 &
		DAEMON_PID=$!
		STOPPED=""
		START_WAIT=$(date +%s)
		for _ in $(seq 1 180); do
			if [ "$(systemctl --user is-active "$UNIT" 2>/dev/null)" != active ] && [ ! -e "$RT" ]; then
				STOPPED="$(($(date +%s) - START_WAIT))"
				break
			fi
			sleep 1
		done
		R[managed.stopped_after_s]="${STOPPED:-not within 180 s}"
		[ -n "$STOPPED" ] && judge managed_stops_when_not_wanted pass || judge managed_stops_when_not_wanted fail "the unit is $(systemctl --user is-active "$UNIT" 2>/dev/null); RAM dir $([ -e "$RT" ] && echo present || echo removed)"
	fi
	[ "$(tree_digest "$HOME/.config/openshell")" = "${R[host.user_openshell_config_before]}" ] && judge user_openshell_config_untouched_at_end pass || judge user_openshell_config_untouched_at_end fail "the digest of ~/.config/openshell changed"
fi

# facts_confirmed names only the facts whose checks passed.
FACTS=""
add_fact() { FACTS="${FACTS:+$FACTS; }$1"; }
[ "${R[check.dotted_labels_select_the_box]:-}" = pass ] && add_fact "dotted label keys observer.superbased.run and observer.superbased.install select the box"
[ "${R[check.exact_exit_code]:-}" = pass ] && add_fact "--policy, --driver-config-json, --no-auto-providers, --no-keep and --tty together in one interactive create"
[ "${R[check.include_workdir_false]:-}" = pass ] && add_fact "filesystem_policy.include_workdir false"
[ "${R[check.managed_status_authenticated]:-}" = pass ] && add_fact "a private gateway from generate-certs, OPENSHELL_LOCAL_TLS_DIR and gateway add --local authenticates over mTLS"
[ "${R[check.managed_no_stray_kek_file]:-}" = pass ] && add_fact "key_encryption_key_env leaves no key-encryption-key.bin"
[ "${R[check.managed_kek_not_in_unit]:-}" = pass ] && add_fact "the KEK reaches the unit through the RAM dir's env file only"
if [ "${R[check.managed_key_custody]:-}" = pass ]; then
	case "${R[managed.custody]}" in
	keychain) add_fact "keychain custody: no key material under the state dir" ;;
	owner_file) add_fact "owner_file custody: the PKI and the KEK are unencrypted 0600 files under gateway/keys only" ;;
	esac
fi
[ "${R[check.user_manager_env_not_in_box]:-}" = pass ] && add_fact "a variable imported into the user manager does not reach the box"
[ "${R[check.managed_survives_daemon_restart]:-}" = pass ] && add_fact "the transient user unit survives a daemon restart"
[ "${R[check.managed_ocsf_export_configured]:-}" = pass ] && add_fact "the private gateway.toml Observer writes carries the OCSF export to the loopback receiver (config only; O3-L1 shows events arrive)"
[ "${R[check.managed_gateway_started_with_ocsf]:-}" = pass ] && add_fact "the private gateway authenticated while running with that OCSF block: active since after the file was written, no restarts and the same active-enter time before the status call and after a ${R[managed.settle_seconds]} s settle, still active (block keys ${R[managed.ocsf_block_keys]}; config check only, O3-L1 shows events arrive)"
[ "${R[check.managed_coexists_with_package_gateway]:-}" = pass ] && add_fact "the private gateway and the package's own openshell-gateway.service ran side by side on one Docker engine (the same engine ID behind both drivers' sockets): run 1's containers carried the private namespace ${R[coexist.box_namespaces_seen]} (read live and from their create events), none of its sandbox or supervisor containers was killed, stopped or died between their creation and the release, the package gateway stayed active and its journal (${R[coexist.package_journal_lines]} lines read since the run began) names no stopped sandbox, and the private gateway's journal no control supervisor failure (F-027, OC2-A2)"
R[facts_confirmed]="${FACTS:-none}"
COMPLETED=1
exit "$FAIL"
