#!/usr/bin/env bash
# o4-org-live.sh: lane O4's live check (live register row O4-L1): the org and
# dashboard surfaces of the openshell row, on ONE throwaway amd64 Ubuntu 24.04
# VM that runs both the org (the one-command demo kit, local only) and an
# Observer node enrolled into it as a managed node.
#
# PRECONDITIONS (the operator sets these up; the script never applies them):
#   1. The org: the demo kit built from the MERGED tree on this VM
#      (docs/demo-box.md "Rolling a new build": deploy.sh build, then
#      deploy.sh up), with these values in deploy/demo-box/.env:
#        DEMO_PUBLIC=none      (local only: http://localhost:8443)
#        DEMO_NODES=off        (no simulated nodes; this VM's node is the one)
#        DEMO_TAG=o4-<merged sha, 9 hex>
#        DEMO_ADMIN_EMAIL=     (empty: the kit's local placeholder admin)
#      The public demo (demo.superbased.app) is never used.
#      `deploy.sh up` prints the admin's one-time set-password link on its
#      stdout: never paste `up` output anywhere (a chat, a ticket, a
#      receipt). This script never runs deploy.sh and never echoes its
#      output; it mints its own link inside the org container.
#   2. The node: OpenShell v0.1.6 (CLI and openshell-gateway) installed by its
#      tagged installer; Docker Engine with this user in the docker group
#      (root-equivalent, decision D4); a systemd user manager holding that
#      group (log in over SSH, or enable lingering) and XDG_RUNTIME_DIR set.
#      No ~/.observer (the script refuses an existing one).
#   3. For the external half of the gateway_modes check (--external, the
#      default): your OWN OpenShell gateway running and authenticated
#      (`openshell status` says connected and authenticated) with the
#      gateway-wide bind-mount opt-in from docs/sandbox-openshell.md
#      ("The gateway-wide bind-mount opt-in", the user's own step 1) in its
#      ~/.config/openshell/gateway.toml:
#        [openshell]
#        version = 2
#
#        [openshell.drivers.docker]
#        allow_driver_config = true
#        enable_bind_mounts = true
#      Observer never writes that file (decision D3). Without it pass
#      --no-external and the external half is recorded not_run.
#   4. The node's sandbox posture reaches the org only under the
#      terminal_detail share tier (the sandbox capability rides it; sandbox
#      plan v2 section 8.4), which enrolment does not turn on. The script
#      sets terminal_detail = true in the node's own [org_client.share]
#      before the daemon starts, the raise a managed org's governance would
#      make, and records in the receipt that it did (share.terminal_detail
#      and a note). If that edit cannot be made, the capability checks are
#      not_run with that reason, never a plain fail.
#
# WHAT IT CHECKS (each pass, fail or not_run with the reason; a not_run
# counts as a failed run, never as a pass):
#   node_*      the openshell row, its reason, gateway mode, D4 prerequisite
#               and D3 disclosure as the daemon serves them to the New
#               Terminal picker and the Settings card (GET /api/terminal/
#               sandbox and /api/terminal/sandbox/config on the node's
#               loopback dashboard);
#   org_*       the node's posture push reaches the org: its sandbox
#               capability lists openshell (GET /api/org/sandbox/managed
#               and the node view), and a change made to the managed
#               gateway's config outside Observer shows on the fleet view as
#               sandbox_gateway_config_drift (GET /api/org/fleet/versions),
#               clearing once the file is put back;
#   floor_*     a terminals.isolation floor gateway_modes = [managed_local]
#               (with floor_accepts_beta, since the row is beta) published
#               with observer-org reaches the node; the node in managed mode
#               meets it; switched to external mode it refuses the row with
#               gateway_mode_not_allowed (rule S7g) and the org's view of the
#               node no longer lists openshell (the lint and the node agree);
#               When the org's machine binding for this VM is held by
#               another active member (an earlier run's throwaway member),
#               the org refuses this node's integrity report, so the two
#               drift checks are not_run with that reason (F-030);
#   assistant_* the assistant's tool table lists read_sandbox_managed (GET
#               /api/org/chat/harnesses tool_labels);
#   compat_*    an unknown posture value is ignored, not an error: the
#               compat tests of internal/orgcontract run against this tree
#               when the VM has go and the source, or else read from a
#               result file made elsewhere at the same tree sha
#               (--compat-from); with neither the check is not_run (the
#               live half would need the node's bearer token, which the
#               script never reads, so the receipt carries it as a note).
#
# SECRETS: the admin's one-time password link, the password the script sets
# through it (random, this run only), the session cookie and the enrolment
# token never go on any command line (where /proc/<pid>/cmdline shows them
# to every local user): they move through pipes from shell builtins and
# through 0600 files inside the private (0700) work dir, which are removed
# as soon as they are used and again by the cleanup. curl reads its bodies
# with --data @FILE and `observer enroll` its code with --token-file. None
# is printed or written to the receipt; the receipt names no IP other than
# loopback. ONE receipt is written on every exit, a failed precondition
# included.
#
# PUBLIC DEMO GUARD (a hard refusal, not a convention): the script refuses
# unless the org URL is this VM's loopback AND the kit's .env on this host
# sets DEMO_PUBLIC=none. The .env check is a quiet grep whose output never
# leaves a pipe, so no value from that file is printed or recorded; only
# "none" or "not none" is decided.
#
# Usage:
#   scripts/sandbox/o4-org-live.sh [--observer PATH] [--out DIR] [--org-url URL]
#       [--org-container NAME] [--admin-email EMAIL] [--kit-env PATH]
#       [--wait SECONDS] [--no-external] [--compat-from FILE] [--tree-sha SHA]
#
#   --observer PATH        the node binary (CGO_ENABLED=0 static build of the
#                          merged tree; default: build one)
#   --out DIR              where the receipt goes (default: the current dir)
#   --org-url URL          the org's local URL (default http://localhost:8443)
#   --org-container NAME   the org container (default sbo-demo-org-1)
#   --admin-email EMAIL    the dashboard admin (default admin@example.com)
#   --kit-env PATH         the demo kit's .env (default
#                          deploy/demo-box/.env of this tree)
#   --wait SECONDS         how long each wait for a push lasts (default 900)
#   --no-external          skip the external half of the floor check
#   --compat-from FILE     the compat tests' result, made on a host with go
#                          at the SAME tree sha, from the repo root:
#                            { echo "tree $(git rev-parse HEAD)"
#                              go test -count=1 -v -run "$RUN" \
#                                ./internal/orgcontract/; } >compat.txt 2>&1
#                          with RUN set to the four tests COMPAT_TESTS
#                          names in this script, joined by |:
#                            TestUnknownPostureValueIsIgnoredNotAnError
#                            TestOlderNodeSendsNoGatewayPosture
#                            TestSandboxGatewayPostureKeptByThisServer
#                            TestSandboxPostureCompatBothDirections
#                          The check passes only when the file's tree line
#                          matches this run's tree sha, each of the four
#                          tests reports PASS, the package reports ok and
#                          nothing reports FAIL. Used only when this VM
#                          cannot run the tests itself.
#   --tree-sha SHA         this run's tree sha (default: `git rev-parse
#                          HEAD` of this tree, else the 9-hex sha of the
#                          org image's o4-<sha> tag)
#
# Exit 0 when every check passed, 1 when one failed or did not run, 2 on a
# precondition the host does not meet (the receipt says which).
# shellcheck disable=SC2015,SC2329
# SC2015: every `COND && judge NAME pass || judge NAME fail` is safe because
# judge always returns 0. SC2329: cleanup runs from the EXIT trap.
set -euo pipefail

OBSERVER=""
OUT="$PWD"
ORG_URL="http://localhost:8443"
ORGC="sbo-demo-org-1"
ADMIN_EMAIL="admin@example.com"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KIT_ENV="$ROOT/deploy/demo-box/.env"
WAIT=900
EXTERNAL=1
COMPAT_FROM=""
TREE_SHA=""
while [ $# -gt 0 ]; do
	case "$1" in
	--observer) OBSERVER="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	--org-url) ORG_URL="${2%/}"; shift 2 ;;
	--org-container) ORGC="$2"; shift 2 ;;
	--admin-email) ADMIN_EMAIL="$2"; shift 2 ;;
	--kit-env) KIT_ENV="$2"; shift 2 ;;
	--wait) WAIT="$2"; shift 2 ;;
	--no-external) EXTERNAL=0; shift ;;
	--compat-from) COMPAT_FROM="$2"; shift 2 ;;
	--tree-sha) TREE_SHA="$2"; shift 2 ;;
	-h | --help) sed -n '2,127p' "$0"; exit 0 ;;
	*) echo "unknown argument $1" >&2; exit 2 ;;
	esac
done

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RECEIPT="$OUT/o4-org-live-o4-l1-$STAMP.json"
OBSDIR="$HOME/.observer"
if [ -e "$OBSDIR" ]; then
	echo "refused: $OBSDIR exists; run this on a throwaway host with no Observer state" >&2
	exit 2
fi
WORK="$(mktemp -d "${HOME}/o4-live-XXXXXX")"
chmod 700 "$WORK"
LOG="$WORK/log"
SEC="$WORK/secrets"
JAR="$SEC/jar"
mkdir -p "$LOG" "$OBSDIR"
(umask 077 && mkdir "$SEC")
OBSDIR_MADE=1
CONFIG="$OBSDIR/config.toml"
DASH="http://127.0.0.1:8081"
GWCFG="$OBSDIR/sandbox-openshell/gateway/gateway.toml"
GWCFG_SAVED=""

declare -A R # receipt fields (strings)
R[schema]="observer-o4-live/1"
R[row]="O4-L1"
R[started]="$STAMP"
R[org_url]="$ORG_URL"
FAIL=0
RECEIPT_WRITTEN=0
COMPLETED=0
EXIT_CODE=""
FLOOR_PUBLISHED=0
DAEMON_PID=""
NODE_UID=""

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

# secret_file NAME creates an empty 0600 file in the private secrets dir and
# prints its path. Fill it with printf (a shell builtin, so the value never
# reaches an argv) and remove it once used.
secret_file() {
	local f="$SEC/$1"
	(umask 077 && : >"$f")
	printf '%s' "$f"
}

# kit_is_local succeeds only when the kit's .env sets DEMO_PUBLIC=none (its
# last DEMO_PUBLIC line, quoted or not). Every grep is quiet or feeds the
# next one, so no value from the file is printed, logged or recorded.
kit_is_local() {
	[ -f "$KIT_ENV" ] && [ -r "$KIT_ENV" ] || return 1
	grep -E '^[[:space:]]*(export[[:space:]]+)?DEMO_PUBLIC=' "$KIT_ENV" 2>/dev/null |
		tail -n 1 |
		grep -Eq '^[[:space:]]*(export[[:space:]]+)?DEMO_PUBLIC=("none"|'"'"'none'"'"'|none)[[:space:]]*(#.*)?$'
}

# org_cli runs observer-org inside the org container (the kit's own way,
# docs/demo-box.md "Who can sign in").
org_cli() { docker exec -i "$ORGC" observer-org --config /etc/observer-org/config.toml "$@"; }

# node_get PATH fetches one route of the node's loopback dashboard.
node_get() { curl -fsS --max-time 20 "$DASH$1"; }

# org_get PATH fetches one org route under the admin session.
org_get() { curl -fsS --max-time 20 -b "$JAR" "$ORG_URL$1"; }

# jq_py EXPR reads JSON on stdin with a python expression over d; prints the
# result, or "unreadable".
jq_py() {
	python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    print("unreadable"); sys.exit(0)
expr = sys.argv[1]
try:
    v = eval(expr, {"d": d, "any": any, "len": len, "str": str})
except Exception as e:
    print("unreadable"); sys.exit(0)
print(v if isinstance(v, str) else json.dumps(v))
' "$1"
}

# openshell_row prints the node's openshell backend row as JSON ("{}" when
# absent).
openshell_row() {
	node_get /api/terminal/sandbox 2>/dev/null | jq_py 'next((b for b in d.get("backends", []) if b.get("id") == "openshell"), {})' || echo "{}"
}

# wait_for SECONDS CMD...: polls CMD every 15 s until it succeeds.
wait_for() {
	local limit="$1" i=0
	shift
	until "$@"; do
		i=$((i + 15))
		[ "$i" -lt "$limit" ] || return 1
		sleep 15
	done
}

start_daemon() {
	"$OBSERVER" start >>"$LOG/daemon.log" 2>&1 &
	DAEMON_PID=$!
	wait_for 120 node_get /api/terminal/sandbox >/dev/null 2>&1 || true
	sleep 5
}
stop_daemon() {
	[ -n "$DAEMON_PID" ] || return 0
	kill "$DAEMON_PID" 2>/dev/null || true
	wait "$DAEMON_PID" 2>/dev/null || true
	DAEMON_PID=""
}

cleanup() {
	local rc=$? n
	set +e
	[ -n "$EXIT_CODE" ] || EXIT_CODE=$rc
	if [ "$RECEIPT_WRITTEN" = 0 ] && [ "$rc" != 0 ] && [ "$EXIT_CODE" != 2 ] && [ "$COMPLETED" = 0 ]; then
		R[aborted]="the script stopped early (exit $rc); the checks after the last one recorded did not run"
		FAIL=1
	fi
	# Put the managed gateway's config back if the drift check changed it.
	if [ -n "$GWCFG_SAVED" ] && [ -f "$GWCFG_SAVED" ]; then
		cp -p "$GWCFG_SAVED" "$GWCFG" && R[cleanup.gateway_config]="restored"
	fi
	# Withdraw the floor this run published (an empty body sets no floor).
	if [ "$FLOOR_PUBLISHED" = 1 ]; then
		if printf '{}' | org_cli policy-resource publish --family terminals.isolation --file /dev/stdin --description "o4-live: withdraw" >/dev/null 2>&1; then
			R[cleanup.floor]="withdrawn (an empty terminals.isolation body published)"
		else
			R[cleanup.floor]="could not be withdrawn; the throwaway org keeps it"
		fi
	fi
	stop_daemon
	# The managed gateway's unit, if this run started one.
	if [ -f "$OBSDIR/sandbox-openshell/install-id" ]; then
		n="observer-openshell-gateway-$(head -c 12 "$OBSDIR/sandbox-openshell/install-id").service"
		if [ "$(systemctl --user is-active "$n" 2>/dev/null)" = active ]; then
			systemctl --user stop "$n" >/dev/null 2>&1
			systemctl --user reset-failed "$n" >/dev/null 2>&1
			R[cleanup.gateway_unit]="stopped by the cleanup"
		fi
	fi
	for n in $(jobs -p); do kill "$n" 2>/dev/null; done
	wait 2>/dev/null
	rm -rf "$SEC"
	if [ "${OBSDIR_MADE:-0}" = 1 ] && [ -d "$OBSDIR" ]; then
		mv "$OBSDIR" "$WORK/observer-dir" && R[cleanup.observer_dir]="moved to the work dir"
	fi
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
for c in curl python3 docker openshell openshell-gateway systemctl; do
	command -v "$c" >/dev/null || refuse "$c is not on PATH (see the preconditions; this script installs nothing)"
done
[ -n "${XDG_RUNTIME_DIR:-}" ] || refuse "XDG_RUNTIME_DIR is not set: log in through a systemd session (SSH) or enable lingering"
case "$ORG_URL" in
http://localhost:* | http://127.0.0.1:* | https://localhost:* | https://127.0.0.1:*) ;;
*) refuse "the org URL must be this VM's loopback (DEMO_PUBLIC=none); the public demo is never used" ;;
esac
kit_is_local || refuse "the kit's .env ($KIT_ENV) does not set DEMO_PUBLIC=none, or cannot be read: this script runs only against a local-only kit, never a public one (pass --kit-env if the kit lives elsewhere)"
R[org.kit_public]="none (checked in the kit's .env; no value read into the receipt)"
docker inspect "$ORGC" >/dev/null 2>&1 || refuse "no org container $ORGC (bring the kit up first: deploy.sh build, deploy.sh up)"
curl -fsS --max-time 10 -o /dev/null "$ORG_URL/readyz" || refuse "$ORG_URL/readyz does not answer"
R[host.kernel]="$(uname -r)"
R[host.docker]="$(docker version --format '{{.Server.Version}}' 2>/dev/null | tr -d '\n' || echo unreadable)"
R[host.docker_group]="$(id -nG | tr ' ' '\n' | grep -qx docker && echo true || echo false)"
R[host.openshell_cli]="$( (openshell --version 2>/dev/null || echo unreadable) | head -n 1)"
R[host.openshell_gateway]="$( (openshell-gateway --version 2>/dev/null || echo unreadable) | head -n 1)"
R[org.image]="$(docker inspect --format '{{.Config.Image}}' "$ORGC" 2>/dev/null || echo unreadable)"
if [ "$EXTERNAL" = 1 ]; then
	R[host.user_gateway_status]="$( (openshell status -o json 2>/dev/null || true) | jq_py '" ".join([str(d.get("status","")), str((d.get("authentication") or {}).get("status",""))])')"
fi

if [ -z "$OBSERVER" ]; then
	command -v go >/dev/null || refuse "no --observer and no go toolchain to build one"
	(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/observer-bin" ./cmd/observer) || refuse "go build failed"
	OBSERVER="$WORK/observer-bin"
fi
OBSERVER="$(readlink -f "$OBSERVER")"
# `observer --version` prints "observer version <v>"; the receipt keeps <v>.
R[observer.version]="$({ "$OBSERVER" --version 2>/dev/null || true; } | awk 'NR == 1 { print $NF }')"
[ -n "${R[observer.version]}" ] || R[observer.version]=unknown

# ---- the admin session (never recorded) --------------------------------------
LINK="$(org_cli users set-password-link "$ADMIN_EMAIL" 2>/dev/null | grep -o 'token=[A-Za-z0-9_.~-]*' | head -n 1 | cut -d= -f2 || true)"
[ -n "$LINK" ] || refuse "could not mint a one-time password link for $ADMIN_EMAIL (is it the kit's admin?)"
# The one-time token reaches python on stdin (printf is a builtin); python
# makes the password and writes both request bodies straight into 0600
# files, so neither secret ever sits on an argv or in a shell variable.
SETPW_BODY="$(secret_file set-password.json)"
LOGIN_BODY="$(secret_file login.json)"
printf '%s' "$LINK" | python3 -I -c '
import json, secrets, sys
token = sys.stdin.read().strip()
password = secrets.token_urlsafe(24)
with open(sys.argv[1], "w") as f:
    json.dump({"token": token, "password": password}, f)
with open(sys.argv[2], "w") as f:
    json.dump({"email": sys.argv[3], "password": password}, f)
' "$SETPW_BODY" "$LOGIN_BODY" "$ADMIN_EMAIL" || refuse "could not write the sign-in request bodies"
unset LINK
(umask 077 && : >"$JAR")
curl -fsS --max-time 20 -o /dev/null -H 'Content-Type: application/json' --data-binary "@$SETPW_BODY" "$ORG_URL/api/org/local-login/set-password" || refuse "setting the admin password through the one-time link failed"
rm -f "$SETPW_BODY"
curl -fsS --max-time 20 -o /dev/null -c "$JAR" -H 'Content-Type: application/json' --data-binary "@$LOGIN_BODY" "$ORG_URL/api/org/local-login" || refuse "the admin sign-in failed"
rm -f "$LOGIN_BODY"
chmod 600 "$JAR"
R[org.admin_session]="established (nothing about it recorded)"

# ---- the node: a managed enrolment --------------------------------------------
NODE_EMAIL="o4-node-$STAMP@demo.example.com"
OUTU="$(org_cli users create "$NODE_EMAIL" --name o4node 2>&1 || true)"
NODE_UID="$(printf '%s\n' "$OUTU" | sed -n 's/.*(user_id \([^)]*\)).*/\1/p' | head -n 1)"
[ -n "$NODE_UID" ] || refuse "could not create the node's member"
R[node.member]="created (user id recorded as node.subject)"
R[node.subject]="$NODE_UID"
TOKEN="$(org_cli new-enrolment-token --user-id "$NODE_UID" --managed --ttl-days 1 2>/dev/null | sed -n 's/^token: *//p')"
[ -n "$TOKEN" ] || refuse "could not mint a managed enrolment token"
TOKEN_FILE="$(secret_file enrol-token)"
printf '%s\n' "$TOKEN" >"$TOKEN_FILE"
unset TOKEN
cat >"$CONFIG" <<EOF
[observer]
db_path = "$OBSDIR/observer.db"

[observer.hooks]
auto_register = false

[terminal.sandbox]
enabled = true
backends = ["bwrap", "openshell"]
egress = "proxy_only"

[components]
add = ["terminals.sandbox.openshell"]
EOF
if "$OBSERVER" enroll --config "$CONFIG" --wire-clients=false --accept-governance --token-file "$TOKEN_FILE" "$ORG_URL" >"$LOG/enroll.txt" 2>&1; then
	rm -f "$TOKEN_FILE"
	R[node.enrolled]="managed, against $ORG_URL"
else
	rm -f "$TOKEN_FILE"
	R[node.enroll_output]="$(head -n 3 "$LOG/enroll.txt" | tr '\n' ' ' | cut -c1-300)"
	refuse "the managed enrolment failed"
fi

# The org's machine binding for this machine (F-030). The binding key is the
# org-salted machine identity the node derives only once it is enrolled, so
# the script reads the binding the enrolment's own managed-bind step
# answered, from both sides: the node prints a collision notice, and the org
# writes a managed_node_collision audit row for this run's member. The org
# writes that row only when ANOTHER ACTIVE member holds the machine (a
# deactivated holder is reassigned, not a collision). When that is so, the
# org refuses this node's integrity report (409), so the drift checks that
# ride it are recorded not_run with that reason, never fail. The script
# never deactivates the other member itself.
binding_collides() {
	grep -q "already bound to another managed node" "$LOG/enroll.txt" 2>/dev/null && return 0
	org_get "/api/org/audit?limit=200" 2>/dev/null |
		python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
uid = sys.argv[1]
hit = any(e.get("action") == "managed_node_collision" and e.get("actor_user_id") == uid for e in d.get("entries") or [])
sys.exit(0 if hit else 1)
' "$NODE_UID"
}
BINDING_HELD=0
if binding_collides; then
	BINDING_HELD=1
	R[org.machine_binding]="held by another active member of the org (managed_node_collision for this run's member); the org refuses this node's integrity report"
else
	R[org.machine_binding]="this run's member (no collision in the enrol output or the org audit)"
fi

# The sandbox capability rides the terminal_detail share tier (sandbox plan
# v2 section 8.4), which enrolment leaves off. Turn it on in the node's own
# [org_client.share] (the table enrolment wrote with full_content), the raise
# a managed org's governance would make, before the daemon starts.
# enable_terminal_detail prints already, set, or why it could not.
enable_terminal_detail() {
	python3 -I - "$CONFIG" <<'PY'
import os, re, shutil, sys
p = sys.argv[1]
try:
    import tomllib
except ImportError:
    print("python3 has no tomllib (3.11 or newer is needed to check the edit)")
    sys.exit(3)

def value(text):
    d = tomllib.loads(text)
    return ((d.get("org_client") or {}).get("share") or {}).get("terminal_detail")

src = open(p, encoding="utf-8").read()
try:
    if value(src) is True:
        print("already")
        sys.exit(0)
except tomllib.TOMLDecodeError:
    print("the node config does not parse as TOML")
    sys.exit(4)
lines = src.splitlines(keepends=True)
header = re.compile(r"^\s*\[\s*org_client\s*\.\s*share\s*\]\s*(#.*)?$")
any_header = re.compile(r"^\s*\[")
key = re.compile(r"^\s*terminal_detail\s*=")
start = next((i for i, l in enumerate(lines) if header.match(l.rstrip("\r\n"))), None)
if start is None:
    print("the node config has no [org_client.share] table header")
    sys.exit(4)
end = next((j for j in range(start + 1, len(lines)) if any_header.match(lines[j])), len(lines))
for j in range(start + 1, end):
    if key.match(lines[j]):
        lines[j] = "terminal_detail = true\n"
        break
else:
    lines.insert(start + 1, "terminal_detail = true\n")
out = "".join(lines)
try:
    ok = value(out) is True
except tomllib.TOMLDecodeError:
    ok = False
if not ok:
    print("the edited config did not read back as terminal_detail = true")
    sys.exit(5)
tmp = p + ".o4tmp"
with open(tmp, "w", encoding="utf-8") as f:
    f.write(out)
shutil.copymode(p, tmp)
os.replace(tmp, p)
print("set")
PY
}
TD_ON=0
TD_OUT="$(enable_terminal_detail 2>&1 || true)"
case "$TD_OUT" in
already)
	TD_ON=1
	R[share.terminal_detail_before]="on"
	R[share.terminal_detail]="on (already on; not changed)"
	;;
set)
	TD_ON=1
	R[share.terminal_detail_before]="off"
	R[share.terminal_detail]="on (set by this script)"
	R[note.terminal_detail]="the script set terminal_detail = true in the node's own [org_client.share] before the daemon started, the raise a managed org's governance would make: the sandbox capability rides that share tier (sandbox plan v2 section 8.4), which enrolment leaves off"
	;;
*)
	R[share.terminal_detail_before]="unknown"
	R[share.terminal_detail]="off: $(printf '%s' "$TD_OUT" | head -n 1 | cut -c1-200)"
	;;
esac
start_daemon

# ---- node surfaces: the picker and the Settings card read these ----------------
ROW="$(openshell_row)"
printf '%s' "$ROW" >"$LOG/openshell-row.json"
R[node.row.available]="$(printf '%s' "$ROW" | jq_py 'str(d.get("available", False))')"
R[node.row.verdict]="$(printf '%s' "$ROW" | jq_py 'd.get("verdict", "")')"
R[node.row.reason]="$(printf '%s' "$ROW" | jq_py 'd.get("reason", "")' | cut -c1-300)"
R[node.row.gateway_mode]="$(printf '%s' "$ROW" | jq_py 'd.get("gateway_mode", "")')"
if [ "$(printf '%s' "$ROW" | jq_py 'd.get("id", "")')" = openshell ]; then
	if [ "${R[node.row.available]}" = True ] || [ -n "${R[node.row.reason]}" ]; then judge node_row_and_reason_served pass; else judge node_row_and_reason_served fail "the row is unavailable with no reason"; fi
else
	judge node_row_and_reason_served fail "no openshell row in GET /api/terminal/sandbox"
fi
[ "${R[node.row.gateway_mode]}" = managed_local ] && judge node_gateway_mode_served pass || judge node_gateway_mode_served fail "gateway_mode ${R[node.row.gateway_mode]:-absent}"
PREREQ="$(printf '%s' "$ROW" | jq_py 'd.get("prerequisite", "")')"
case "$PREREQ" in
*"root-equivalent"*"Podman 5"*) judge node_d4_prerequisite_served pass ;;
*) judge node_d4_prerequisite_served fail "prerequisite: ${PREREQ:-absent}" ;;
esac
D3="$(printf '%s' "$ROW" | jq_py 'next((x.get("text","") for x in d.get("disclosures", []) if x.get("id") == "gateway_wide_bind_mounts"), "")')"
case "$D3" in
*"never read or written"*) judge node_d3_disclosure_served pass ;;
*) judge node_d3_disclosure_served fail "disclosure: ${D3:-absent}" ;;
esac
SETTINGS="$(node_get /api/terminal/sandbox/config 2>/dev/null | jq_py 'str("openshell" in d.get("sandbox", {}) and "seccomp" in d.get("sandbox", {}))' || echo unreadable)"
[ "$SETTINGS" = True ] && judge node_settings_card_keys_served pass || judge node_settings_card_keys_served fail "GET /api/terminal/sandbox/config: openshell and seccomp present = $SETTINGS"

# ---- org: the posture push ------------------------------------------------------
fleet_has_openshell() { org_get "/api/org/sandbox/managed/nodes/$NODE_UID" 2>/dev/null | jq_py 'str("openshell" in (d.get("backends") or []))' | grep -qx True; }
if [ "${R[node.row.available]}" = True ]; then
	if wait_for "$WAIT" fleet_has_openshell; then
		judge org_capability_lists_openshell pass
		R[org.fleet_backends]="$(org_get /api/org/sandbox/managed 2>/dev/null | jq_py 'd.get("fleet_backends", [])')"
	elif [ "$TD_ON" != 1 ]; then
		# Without the terminal_detail tier the node sends no sandbox
		# capability at all, so its absence proves nothing about the row.
		not_run org_capability_lists_openshell "terminal_detail is off in the node's [org_client.share] (${R[share.terminal_detail]}), so the node sends no sandbox capability; the node view never listed openshell within ${WAIT}s"
	else
		judge org_capability_lists_openshell fail "the node view never listed openshell within ${WAIT}s, with terminal_detail on"
	fi
else
	not_run org_capability_lists_openshell "the node's openshell row is not available (${R[node.row.verdict]}), so it never reports it"
fi

# The drift posture: change the managed gateway's config outside Observer,
# then put it back.
drift_shown() { org_get /api/org/fleet/versions 2>/dev/null | grep -q '"sandbox_gateway_config_drift"'; }
if [ "$BINDING_HELD" = 1 ]; then
	BOUND_WHY="this machine is bound to another active member of the org (org.machine_binding), so the org refuses this node's integrity report (409) and the drift label cannot reach the fleet view; deactivate the earlier throwaway member (observer-org users deactivate) and run again"
	not_run org_fleet_shows_gateway_drift "$BOUND_WHY"
	not_run org_fleet_drift_clears "$BOUND_WHY"
elif [ -f "$GWCFG" ]; then
	GWCFG_SAVED="$WORK/gateway.toml.saved"
	cp -p "$GWCFG" "$GWCFG_SAVED"
	printf '\n# o4-live: a change made outside Observer\n' >>"$GWCFG"
	if wait_for "$WAIT" drift_shown; then judge org_fleet_shows_gateway_drift pass; else judge org_fleet_shows_gateway_drift fail "sandbox_gateway_config_drift did not reach /api/org/fleet/versions within ${WAIT}s"; fi
	cp -p "$GWCFG_SAVED" "$GWCFG"
	GWCFG_SAVED=""
	drift_gone() { ! drift_shown; }
	if [ "${R[check.org_fleet_shows_gateway_drift]}" != pass ]; then
		not_run org_fleet_drift_clears "the drift never showed"
	elif wait_for "$WAIT" drift_gone; then
		judge org_fleet_drift_clears pass
	else
		judge org_fleet_drift_clears fail "the label stayed after the config was put back (a standing label may be held for its known window)"
	fi
else
	not_run org_fleet_shows_gateway_drift "no managed gateway config at $GWCFG: the private gateway never started (node row: ${R[node.row.verdict]:-available})"
	not_run org_fleet_drift_clears "no managed gateway config"
fi

# ---- the gateway_modes floor ------------------------------------------------------
if printf '%s' '{"gateway_modes":["managed_local"],"floor_accepts_beta":true}' |
	org_cli policy-resource publish --family terminals.isolation --file /dev/stdin --description "o4-live: gateway_modes" >"$LOG/publish.txt" 2>&1; then
	FLOOR_PUBLISHED=1
	R[floor.published]="gateway_modes = [managed_local], floor_accepts_beta = true"
else
	R[floor.publish_output]="$(head -n 3 "$LOG/publish.txt" | tr '\n' ' ' | cut -c1-300)"
fi
floor_on_node() { node_get /api/terminal/sandbox 2>/dev/null | jq_py 'str(any(f.get("key") == "gateway_modes" for f in ((d.get("org") or {}).get("floors") or [])))' | grep -qx True; }
if [ "$FLOOR_PUBLISHED" = 1 ] && wait_for "$WAIT" floor_on_node; then
	judge floor_reaches_node pass
	# The positive verdict: the row is available with no refusal verdict under
	# the floor. Any refusal (S7g or another rule: a probe refusal, the beta
	# drop, the private gateway down) is not evidence that the floor is met.
	ROW="$(openshell_row)"
	printf '%s' "$ROW" >"$LOG/openshell-row-floor.json"
	A="$(printf '%s' "$ROW" | jq_py 'str(d.get("available", False))')"
	V="$(printf '%s' "$ROW" | jq_py 'd.get("verdict", "")')"
	MODE="$(printf '%s' "$ROW" | jq_py 'd.get("gateway_mode", "")')"
	R[floor.managed.available]="$A"
	R[floor.managed.verdict]="$V"
	if [ "$A" = True ] && [ -z "$V" ] && [ "$MODE" = managed_local ]; then
		judge floor_managed_node_meets pass
	else
		judge floor_managed_node_meets fail "available ${A:-absent}, verdict ${V:-none}, gateway_mode ${MODE:-absent}: the floor is met only by an available managed_local row with no refusal verdict"
	fi
else
	judge floor_reaches_node fail "$([ "$FLOOR_PUBLISHED" = 1 ] && echo "the floor did not reach the node within ${WAIT}s" || echo "publishing the floor failed")"
	not_run floor_managed_node_meets "the floor never reached the node"
fi
if [ "$EXTERNAL" = 0 ]; then
	not_run floor_external_node_refused "--no-external: the user's own gateway is not set up"
	not_run floor_org_agrees_unmet "--no-external"
elif [ "${R[check.floor_reaches_node]}" != pass ]; then
	not_run floor_external_node_refused "the floor never reached the node"
	not_run floor_org_agrees_unmet "the floor never reached the node"
else
	# The before-state: the org must list openshell for this node now, while
	# the node meets the floor, or the after-state proves no transition.
	ORG_BEFORE=False
	if [ "${R[check.org_capability_lists_openshell]:-}" = pass ] && fleet_has_openshell; then ORG_BEFORE=True; fi
	R[floor.org_before_lists_openshell]="$ORG_BEFORE"
	stop_daemon
	printf '\n[terminal.sandbox.openshell]\ngateway_mode = "external"\n' >>"$CONFIG"
	start_daemon
	ROW="$(openshell_row)"
	printf '%s' "$ROW" >"$LOG/openshell-row-external.json"
	V="$(printf '%s' "$ROW" | jq_py 'd.get("verdict", "")')"
	RULE="$(printf '%s' "$ROW" | jq_py 'd.get("rule", "")')"
	R[floor.external.verdict]="$V"
	R[floor.external.rule]="$RULE"
	R[floor.external.reason]="$(printf '%s' "$ROW" | jq_py 'd.get("reason", "")' | cut -c1-300)"
	if [ "$V" = gateway_mode_not_allowed ] && [ "$RULE" = S7g ]; then
		judge floor_external_node_refused pass
	else
		judge floor_external_node_refused fail "verdict ${V:-none} rule ${RULE:-none} (a probe refusal before S7g means the user's own gateway is not up)"
	fi
	no_openshell() { org_get "/api/org/sandbox/managed/nodes/$NODE_UID" 2>/dev/null | jq_py 'str("openshell" in (d.get("backends") or []))' | grep -qx False; }
	if [ "$ORG_BEFORE" != True ]; then
		not_run floor_org_agrees_unmet "the org's view of the node did not list openshell before the switch to external mode (org_capability_lists_openshell: ${R[check.org_capability_lists_openshell]:-absent}), so a later absence would prove no change"
	elif [ "${R[check.floor_external_node_refused]}" != pass ]; then
		not_run floor_org_agrees_unmet "the node did not refuse the row with S7g, so the org has no floor refusal to agree with"
	elif wait_for "$WAIT" no_openshell; then
		judge floor_org_agrees_unmet pass
	else
		judge floor_org_agrees_unmet fail "the org's view of the node still lists openshell ${WAIT}s after the switch to external mode"
	fi
fi

# ---- the assistant ------------------------------------------------------------------
HARN="$(org_get /api/org/chat/harnesses 2>"$LOG/harnesses.err" || true)"
if [ -z "$HARN" ]; then
	not_run assistant_lists_sandbox_managed "GET /api/org/chat/harnesses answered nothing (the assistant may be off in this kit): $(head -c 200 "$LOG/harnesses.err" | tr '\n' ' ')"
else
	# tool_labels is a LIST of objects ({"id", "tier", "key", "label", ...},
	# chat.ToolLabels), so the row is found by its id field.
	HAS="$(printf '%s' "$HARN" | jq_py 'str(isinstance(d.get("tool_labels"), list) and any(isinstance(t, dict) and t.get("id") == "read_sandbox_managed" for t in d["tool_labels"]))')"
	[ "$HAS" = True ] && judge assistant_lists_sandbox_managed pass || judge assistant_lists_sandbox_managed fail "tool_labels has no read_sandbox_managed ($HAS)"
fi

# ---- compat: an unknown enum value is ignored ---------------------------------------
COMPAT_TESTS=(TestUnknownPostureValueIsIgnoredNotAnError TestOlderNodeSendsNoGatewayPosture TestSandboxGatewayPostureKeptByThisServer TestSandboxPostureCompatBothDirections)
COMPAT_RUN="$(IFS='|'; printf '%s' "${COMPAT_TESTS[*]}")"
COMPAT_PKG="github.com/marmutapp/superbased-observer/internal/orgcontract"

# tree_sha sets TREE (this run's tree sha) and TREE_SHA_SOURCE: --tree-sha,
# else git in this tree, else the org image's o4-<sha> tag (the kit is
# built from the merged tree, precondition 1); nothing when none is known.
TREE=""
TREE_SHA_SOURCE=""
tree_sha() {
	local s tag
	if [ -n "$TREE_SHA" ]; then
		TREE="$TREE_SHA" TREE_SHA_SOURCE="--tree-sha"
		return
	fi
	if command -v git >/dev/null && s="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" && [ -n "$s" ]; then
		TREE="$s" TREE_SHA_SOURCE="git rev-parse HEAD"
		return
	fi
	tag="${R[org.image]##*:}"
	if printf '%s' "$tag" | grep -Eqx 'o4-[0-9a-f]{9,40}'; then
		TREE="${tag#o4-}" TREE_SHA_SOURCE="the org image tag"
	fi
}

# sha_match A B: both are 9 to 40 hex digits and one is a prefix of the
# other (a 9-hex image tag against a full sha).
sha_match() {
	local a b
	a="$(printf '%s' "$1" | tr 'A-F' 'a-f')"
	b="$(printf '%s' "$2" | tr 'A-F' 'a-f')"
	printf '%s\n%s\n' "$a" "$b" | grep -Eqvx '[0-9a-f]{9,40}' && return 1
	case "$a" in "$b"*) return 0 ;; esac
	case "$b" in "$a"*) return 0 ;; esac
	return 1
}

# compat_from_verdict FILE TREE prints pass, fail: WHY or not_run: WHY for a
# result file made by the recipe in the header (--compat-from).
compat_from_verdict() {
	local file="$1" tree="$2" got t
	[ -f "$file" ] && [ -r "$file" ] || { printf 'not_run: the --compat-from file cannot be read'; return; }
	got="$(sed -n '1s/^tree[[:space:]]\{1,\}\([0-9a-fA-F]\{9,40\}\)[[:space:]]*$/\1/p' "$file")"
	[ -n "$got" ] || { printf 'not_run: the --compat-from file has no "tree <sha>" first line'; return; }
	[ -n "$tree" ] || { printf 'not_run: this run cannot name its own tree sha (pass --tree-sha)'; return; }
	sha_match "$got" "$tree" || { printf 'not_run: the --compat-from result is for tree %s, this run is tree %s' "$got" "$tree"; return; }
	if grep -Eq '^(--- )?FAIL' "$file"; then
		printf 'fail: the --compat-from result reports FAIL at tree %s: %s' "$got" "$(grep -E '^(--- )?FAIL' "$file" | head -n 3 | tr '\n' ' ' | cut -c1-200)"
		return
	fi
	for t in "${COMPAT_TESTS[@]}"; do
		grep -Eq "^[[:space:]]*--- PASS: $t \(" "$file" || { printf 'not_run: the --compat-from result has no PASS for %s (run with -v and the four tests)' "$t"; return; }
	done
	if ! grep -E "^ok[[:space:]]+$COMPAT_PKG([[:space:]]|$)" "$file" | grep -vq 'no tests to run'; then
		printf 'not_run: the --compat-from result has no ok line for %s' "$COMPAT_PKG"
		return
	fi
	printf 'pass'
}

if command -v go >/dev/null && [ -d "$ROOT/internal/orgcontract" ]; then
	if (cd "$ROOT" && go test -count=1 -run "$COMPAT_RUN" ./internal/orgcontract/) >"$LOG/compat.txt" 2>&1; then
		judge compat_unknown_enum_ignored pass
	else
		judge compat_unknown_enum_ignored fail "$(tail -n 3 "$LOG/compat.txt" | tr '\n' ' ' | cut -c1-300)"
	fi
elif [ -n "$COMPAT_FROM" ]; then
	tree_sha
	R[compat.tree_sha]="${TREE:-unknown}"
	R[compat.tree_sha_source]="${TREE_SHA_SOURCE:-none}"
	R[compat.from]="a result file made elsewhere (--compat-from)"
	V="$(compat_from_verdict "$COMPAT_FROM" "$TREE")"
	case "$V" in
	pass) judge compat_unknown_enum_ignored pass "from the --compat-from result at tree $TREE" ;;
	fail:*) judge compat_unknown_enum_ignored fail "${V#fail: }" ;;
	*) not_run compat_unknown_enum_ignored "${V#not_run: }" ;;
	esac
else
	not_run compat_unknown_enum_ignored "no go toolchain or source tree on this VM, and no --compat-from result"
fi
# The live half of the older-value round trip would post a crafted report,
# which needs the node's bearer token; the script never reads one, so it is
# a note, not a check (the unit half above, and the org decoding the node's
# real report in org_fleet_shows_gateway_drift, cover the two directions).
R[note.compat_live]="not run by design: posting a crafted report needs the node's bearer token, which this script never reads"

COMPLETED=1
