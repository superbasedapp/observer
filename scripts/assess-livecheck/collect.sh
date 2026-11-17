#!/usr/bin/env bash
# Security assessments live check: checks and collection.
#
# Operator-attended kit for docs/security-assessments-live-check.md (plan:
# docs/plans/security-assessments-depth-plan-2026-11-14.md section 8, steps C to H).
# It drives a deliberately vulnerable fixture (testdata/secassess) against a
# THROWAWAY node (scripts/assess-livecheck/preflight.sh) and never touches the
# real node or any real tool config. Receipts are data for the live register:
# they hold counts, ports, exit codes and words, never home paths, user names,
# tokens or environment values.
#
# Usage: collect.sh <command> [args]
#   confine [--wait]    C. RUN INSIDE a sandboxed agent terminal (same settings as the
#                       assessment: Claude Code, `!` shell mode; a plain shell is not
#                       sandbox-launchable): loopback canary, node dashboard, a loopback
#                       server, the external network. Writes the in-box server's port to
#                       confine.port and a JSON receipt to confine.receipt.json (both in
#                       the current folder) and prints the receipt.
#   host-checks [--port P | --wait-for FILE [--timeout S]]
#                       C. HOST side while `confine` waits: nothing listens on the in-box
#                       port, nothing on the target ports, the canary saw nothing.
#                       --wait-for polls confine's port file, so no hand-made poller.
#   after-run           D/E. HOST side AFTER the run's terminal was stopped and closed:
#                       no leftover server, nothing listening on the target ports, canary
#                       silent, git state. While the terminal is open the box's own
#                       processes are still there; the check says so and does not judge.
#   negative [core|tier]   F. the refusal rules, driven through the throwaway dashboard.
#                       The launch controls are data in negative-controls.json; no control
#                       can start a terminal (a tripwire digest stops a body that gets past
#                       its rule).
#   score <run dir> [<earlier run dir>]
#                       D. the fixture score (the plan's TestLiveScore, W2.2). The file's own
#                       schema picks what is scored: a pen test or red team, a threat model, or a
#                       retest. A retest is scored against the run it replayed (its findings carry
#                       that run's ids): name that run's folder as the second argument, or leave it
#                       out when exactly one other run folder in the same project holds a pen test
#                       that names the retest's findings.
#   record <name>       H. write a results skeleton to fill in.
#
# Environment (all optional): ASSESS_LIVE_ROOT, DASH_PORT, PROXY_PORT, CANARY_PORT,
# TARGET_PORT (same defaults as preflight.sh), REPO_ROOT, NEG_UNROUTED_TOOL, NEG_TOOL
# (the agent the controls name; default claude-code, else the plan's first allowed agent),
# NEG_CONTROLS (the controls file), CONFINE_HOLD_SECONDS (how long `confine --wait` holds
# when there is no terminal to press Enter in; default 30), CONFINE_PORT_FILE, RECEIPT.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd)}
REAL_HOME=$(getent passwd "$(id -un)" | cut -d: -f6)
ROOT=${ASSESS_LIVE_ROOT:-$REAL_HOME/sbo-scratch/assess-live}
DASH_PORT=${DASH_PORT:-18081}
PROXY_PORT=${PROXY_PORT:-18820}
CANARY_PORT=${CANARY_PORT:-18999}
TARGET_PORT=${TARGET_PORT:-3000}
CONSOLE_PORT=$((TARGET_PORT + 1))
PROJECT="$ROOT/projects/notesapp"
DASH="http://127.0.0.1:$DASH_PORT"
# The launch controls of `negative core`, as data (see the file's own note).
CONTROLS=${NEG_CONTROLS:-$SCRIPT_DIR/negative-controls.json}

PASS=0 FAIL=0
say() { printf '%s\n' "$*"; }
die() {
	printf 'collect: %s\n' "$*" >&2
	exit 1
}
verdict() { # verdict LEVEL text
	case "$1" in
	PASS) PASS=$((PASS + 1)) ;;
	FAIL) FAIL=$((FAIL + 1)) ;;
	esac
	printf '%-5s %s\n' "$1" "$2"
}
port_free() { [ -z "$(ss -ltnH sport = ":$1" 2>/dev/null)" ]; }
stamp() { date -u +%Y%m%dT%H%M%SZ; }

# receipt_dir: where host-side receipts go (the scratch root's receipts folder when it exists).
receipt_dir() {
	if [ -d "$ROOT/receipts" ]; then
		printf '%s' "$ROOT/receipts"
	else
		printf '%s' "$PWD"
	fi
}

# emit_json <file> <name=value>...: a flat JSON object of strings, built with python3
# so every value is escaped. Values are words and numbers only (see the header).
emit_json() {
	local out=$1
	shift
	python3 - "$out" "$@" <<'PY'
import json, sys
out, items = sys.argv[1], sys.argv[2:]
doc = {}
for item in items:
    k, _, v = item.partition("=")
    doc[k] = v
text = json.dumps(doc, indent=2, sort_keys=True)
print(text)
if out != "-":
    try:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    except OSError as err:
        print("(the receipt could not be written to " + out + ": " + err.strerror + "; copy it from above)", file=sys.stderr)
PY
}

# fixture_argv <argv0> <argv1>: succeeds when the two words are the fixture server's own start,
# a python interpreter and server.py (a bare name, ./server.py or a path ending in /server.py).
# Nothing else counts: the box's own processes (observer sandbox-host, bwrap, the agent) carry
# the whole task text in their arguments, and the task names server.py, so matching the whole
# command line (pgrep -f) reported them as a leftover server (live run, 2026-11-15).
fixture_argv() {
	local a=${1##*/} b=${2##*/}
	case "$a" in python | python[0-9]*) ;; *) return 1 ;; esac
	[ "$b" = server.py ]
}

# fixture_pids prints the pid of every process on this host that runs the fixture server.
fixture_pids() {
	local d a0 a1
	for d in /proc/[0-9]*; do
		a0="" a1=""
		{ IFS= read -r -d '' a0 && IFS= read -r -d '' a1; } 2>/dev/null <"$d/cmdline" || true
		[ -n "$a1" ] && fixture_argv "$a0" "$a1" && printf '%s\n' "${d#/proc/}"
	done
	return 0
}

# valid_port succeeds for a whole number from 1 to 65535.
valid_port() {
	case "${1:-}" in '' | *[!0-9]*) return 1 ;; esac
	[ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# ---------------------------------------------------------------- confine

cmd_confine() {
	local wait=0
	[ "${1:-}" = "--wait" ] && wait=1
	command -v curl >/dev/null 2>&1 || die "curl is not available in this terminal"
	command -v python3 >/dev/null 2>&1 || die "python3 is not available in this terminal"
	say "Confinement proof, run inside a sandboxed agent terminal (plan section 8, C)"
	say "canary port $CANARY_PORT, dashboard port $DASH_PORT, proxy port $PROXY_PORT"
	say

	local canary_rc dash_rc proxy_rc ext_direct_rc ext_env_code loop_rc srv_port srv_pid srv_dir
	curl -sS -m 3 -o /dev/null "http://127.0.0.1:$CANARY_PORT/" 2>/dev/null
	canary_rc=$?
	curl -sS -m 3 -o /dev/null "http://127.0.0.1:$DASH_PORT/" 2>/dev/null
	dash_rc=$?
	curl -sS -m 3 -o /dev/null "http://127.0.0.1:$PROXY_PORT/" 2>/dev/null
	proxy_rc=$?
	if [ "$canary_rc" -ne 0 ]; then
		verdict PASS "the host canary is unreachable from the box (curl exit $canary_rc)"
	else
		verdict FAIL "the host canary ANSWERED: the box can reach the host loopback"
	fi
	if [ "$dash_rc" -ne 0 ]; then
		verdict PASS "the node dashboard port is unreachable from the box (curl exit $dash_rc)"
	else
		verdict FAIL "the node dashboard port ANSWERED from inside the box"
	fi
	say "INFO  the proxy port from inside the box: curl exit $proxy_rc (the in-box launcher or relay may serve it; recorded, not judged)"

	# A server started inside the box must work for the box.
	srv_port=$((20000 + RANDOM % 9000))
	srv_dir=$(mktemp -d)
	python3 -m http.server "$srv_port" --bind 127.0.0.1 --directory "$srv_dir" >/dev/null 2>&1 &
	srv_pid=$!
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		curl -sS -m 1 -o /dev/null "http://127.0.0.1:$srv_port/" 2>/dev/null && break
		sleep 0.3
	done
	curl -sS -m 3 -o /dev/null "http://127.0.0.1:$srv_port/" 2>/dev/null
	loop_rc=$?
	if [ "$loop_rc" -eq 0 ]; then
		verdict PASS "a server started in the box answers inside the box (port $srv_port)"
	else
		verdict FAIL "a server started in the box does not answer inside the box (curl exit $loop_rc)"
	fi
	say
	# The port goes to a file as well as the screen: the host side (host-checks --wait-for) polls
	# it, so no hand-made poller is needed. "<port> <epoch seconds>", removed when the server is
	# stopped, so a file that is there names a server that is up.
	local portfile=${CONFINE_PORT_FILE:-confine.port} hold
	printf '%s %s\n' "$srv_port" "$(date +%s)" >"$portfile" 2>/dev/null || portfile=""
	CONFINE_PF=$portfile
	trap '[ -n "${CONFINE_PF:-}" ] && rm -f "$CONFINE_PF"' EXIT
	say "Now, on the HOST, in a shell: $0 host-checks --port $srv_port"
	[ -n "$portfile" ] && say "  or, with no port to copy: host-checks --wait-for <this folder>/$portfile"
	if [ "$wait" -eq 1 ]; then
		hold=${CONFINE_HOLD_SECONDS:-30}
		say "Press Enter here when the host side is done (a terminal with no keyboard to read, such as Claude Code's ! mode, waits ${hold} s instead)."
		read -r _ 2>/dev/null </dev/tty || sleep "$hold"
	else
		hold=${CONFINE_HOLD_SECONDS:-20}
		say "(waiting ${hold} s; use --wait to hold until you press Enter)"
		sleep "$hold"
	fi
	[ -n "$portfile" ] && rm -f "$portfile"
	kill "$srv_pid" 2>/dev/null
	wait "$srv_pid" 2>/dev/null
	rm -rf "$srv_dir"

	curl -sS -m 5 --noproxy '*' -o /dev/null "https://example.com/" 2>/dev/null
	ext_direct_rc=$?
	ext_env_code=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "https://example.com/" 2>/dev/null || true)
	if [ "$ext_direct_rc" -ne 0 ]; then
		verdict PASS "a direct request to an external host fails (curl exit $ext_direct_rc)"
	else
		verdict FAIL "a direct request to an external host SUCCEEDED from the box"
	fi
	say "INFO  an external request through the box's own proxy settings answered '${ext_env_code:-none}' (recorded, not judged: proxy_only should refuse non-model hosts)"

	local observer_path observer_kind=no py_path py_version proxy_vars=""
	observer_path=$(command -v observer 2>/dev/null || true)
	case "$observer_path" in
	"") ;;
	/mnt/*) observer_kind=yes-windows-interop ;;
	*) observer_kind=yes-linux ;;
	esac
	py_path=$(readlink -f "$(command -v python3)" 2>/dev/null || true)
	py_version=$(python3 --version 2>&1)
	for v in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
		[ -n "${!v:-}" ] && proxy_vars="$proxy_vars $v"
	done
	say "INFO  observer on the box's PATH: $observer_kind (the plan's self-check depends on a Linux binary there)"
	say "INFO  python3 in the box: $py_version at ${py_path:-unknown}"
	say
	printf 'result: %d pass, %d fail\n' "$PASS" "$FAIL"
	# The receipt is a file in the current folder too (the live workspace: the host reads it from there).
	emit_json "${RECEIPT:-confine.receipt.json}" \
		"step=confine" "when=$(stamp)" \
		"canary_curl_exit=$canary_rc" "dashboard_curl_exit=$dash_rc" "proxy_port_curl_exit=$proxy_rc" \
		"loopback_server_curl_exit=$loop_rc" "loopback_server_port=$srv_port" \
		"external_direct_curl_exit=$ext_direct_rc" "external_via_env_http_code=${ext_env_code:-none}" \
		"observer_on_path=$observer_kind" \
		"python3_version=$py_version" "python3_dir=$(dirname "${py_path:-/unknown}")" \
		"proxy_variables_set=${proxy_vars# }" "pass=$PASS" "fail=$FAIL"
	[ "$FAIL" -eq 0 ]
}

# ------------------------------------------------------------ host checks

canary_hits() {
	local log="$ROOT/canary.log" n=0
	[ -f "$log" ] && n=$(grep -c '"GET ' "$log" || true)
	printf '%s' "${n:-0}"
}

# wait_for_port <file> <seconds>: polls confine's port file ("<port> <epoch seconds>", written while the
# in-box server is up) and prints the port once the file names a live-looking one: a valid port and a
# stamp at most CONFINE_MAX_AGE (120) seconds old, so a file a killed run left behind is not believed.
# Returns 1, printing nothing, when the time runs out.
wait_for_port() {
	local f=$1 limit=$2 end now port stamp max=${CONFINE_MAX_AGE:-120}
	end=$(($(date +%s) + limit))
	while :; do
		now=$(date +%s)
		port="" stamp=""
		if [ -s "$f" ]; then
			read -r port stamp 2>/dev/null <"$f" || true
			case "$stamp" in '' | *[!0-9]*) stamp="" ;; esac
			if valid_port "$port" && [ -n "$stamp" ] && [ "$stamp" -le $((now + 5)) ] && [ $((now - stamp)) -le "$max" ]; then
				printf '%s' "$port"
				return 0
			fi
		fi
		[ "$now" -ge "$end" ] && return 1
		sleep 0.5
	done
}

host_side() { # host_side <label> [--port P | --wait-for FILE [--timeout S]]
	local label=$1 port="" waitfile="" timeout=300
	shift
	while [ $# -gt 0 ]; do
		[ $# -ge 2 ] || die "$label: $1 needs a value"
		case "$1" in
		--port) port=$2 ;;
		--wait-for) waitfile=$2 ;;
		--timeout) timeout=$2 ;;
		*) die "$label: unknown argument $1" ;;
		esac
		shift 2
	done
	command -v ss >/dev/null 2>&1 || die "ss is required"
	[ -z "$port" ] || [ -z "$waitfile" ] || die "$label: give --port or --wait-for, not both"
	if [ -n "$port" ] && ! valid_port "$port"; then die "$label: --port needs a port number"; fi
	case "$timeout" in '' | *[!0-9]*) die "$label: --timeout needs a number of seconds" ;; esac
	if [ -n "$waitfile" ]; then
		say "waiting up to ${timeout} s for $waitfile (run confine in the box now; the file appears once its server is up)"
		if port=$(wait_for_port "$waitfile" "$timeout") && [ -n "$port" ]; then
			say "the in-box server is on port $port (read from the port file)"
		else
			port=""
			verdict FAIL "no fresh port file at $waitfile within ${timeout} s: the in-box check did not run, or its server was already down (see the doc, C)"
		fi
	fi
	local p
	for p in "$TARGET_PORT" "$CONSOLE_PORT"; do
		if port_free "$p"; then
			verdict PASS "nothing listens on host port $p (the fixture's port)"
		else
			verdict FAIL "something listens on host port $p"
		fi
	done
	if [ -n "$port" ]; then
		if port_free "$port"; then
			verdict PASS "ss on the host shows nothing on the in-box server's port $port"
		else
			verdict FAIL "ss on the host shows a listener on $port: the in-box server is visible from the host"
		fi
		curl -sS -m 3 -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null
		if [ $? -ne 0 ]; then
			verdict PASS "curl from the host to 127.0.0.1:$port fails"
		else
			verdict FAIL "curl from the host to 127.0.0.1:$port ANSWERED"
		fi
	fi
	local hits
	hits=$(canary_hits)
	if [ "$hits" -eq 0 ]; then
		verdict PASS "the canary saw no request"
	else
		verdict FAIL "the canary saw $hits request(s): the box reached the host loopback"
	fi
	if [ "$label" = after-run ]; then
		local pids left box
		pids=$(fixture_pids | tr '\n' ' ')
		left=$(printf '%s' "$pids" | wc -w | tr -d ' ')
		if [ "$left" -eq 0 ]; then
			verdict PASS "no process on the host runs the fixture server (a python interpreter with server.py)"
		else
			verdict FAIL "$left process(es) run the fixture server (python ... server.py) on the host: pid ${pids% }"
		fi
		# after-run is for after Stop and close. While the assessment terminal is open its box is
		# still there, and the box's own processes carry the task text, which names server.py.
		box=$(pgrep -x bwrap 2>/dev/null | wc -l | tr -d ' ')
		if [ "$box" -gt 0 ]; then
			say "INFO  $box bwrap process(es) still run: if the assessment terminal is still open, Stop and close it first; this check is for after the run (the line above judges the fixture's own start command, never the box)"
		fi
		if [ -d "$PROJECT/.git" ]; then
			local changed
			changed=$(git -C "$PROJECT" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
			say "INFO  git status of the fixture project: $changed changed path(s) (the run folder is under .observer/ and carries a .gitignore; anything else is a finding to look at)"
		fi
	fi
	say
	printf 'result: %d pass, %d fail\n' "$PASS" "$FAIL"
	emit_json "$(receipt_dir)/$label-$(stamp).json" \
		"step=$label" "when=$(stamp)" "target_port=$TARGET_PORT" "console_port=$CONSOLE_PORT" \
		"inbox_port=${port:-none}" "canary_hits=$hits" "pass=$PASS" "fail=$FAIL" >/dev/null
	[ "$FAIL" -eq 0 ]
}

# --------------------------------------------------------------- negative

urlenc() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# expect_refusal <label> <rule> <code> <status> <body>: judge one answer. A want_rule of "" is a
# body the rules accepted and the tripwire digest stopped (code plan_changed): nothing started.
expect_refusal() {
	local label=$1 want_rule=$2 want_code=$3 status=$4 body=$5 rule code
	rule=$(printf '%s' "$body" | jq -r '.rule // empty' 2>/dev/null)
	code=$(printf '%s' "$body" | jq -r '.code // empty' 2>/dev/null)
	if [ "$rule" = "$want_rule" ] && [ "$code" = "$want_code" ]; then
		if [ -n "$want_rule" ]; then
			verdict PASS "$label: refused by $want_rule ($want_code), HTTP $status"
		else
			verdict PASS "$label: accepted, stopped by the tripwire digest ($want_code), HTTP $status"
		fi
	else
		verdict FAIL "$label: want ${want_rule:-no rule}/$want_code, got '${rule:-none}'/'${code:-none}' (HTTP $status)"
		if [ -z "$code" ]; then
			# A plain-text refusal (HTTP 400: an agent id that is not launchable, a body that does not decode).
			say "      the answer: $(printf '%s' "$body" | head -c 160 | tr '\n' ' ')"
		fi
		if [ "$status" = 200 ] && printf '%s' "$body" | jq -e '.token' >/dev/null 2>&1; then
			say "      A TERMINAL STARTED: stop it from the Terminals page; the refusal rule did not fire"
		elif [ "$code" = plan_changed ]; then
			say "      the body got past every rule and only the tripwire digest stopped it; nothing started"
		fi
	fi
}

# tripwire_digest <digest>: the plan's prompt digest with its first character changed. A launch
# body carrying it can never start a terminal: the digest is checked after every eligibility rule
# and before anything is claimed, so a body that passes its rule is stopped there (409 plan_changed).
tripwire_digest() {
	local d=$1 first=0
	[ "${d:0:1}" = 0 ] && first=1
	printf '%s%s' "$first" "${d:1}"
}

# render_body <control id> <values json>: the launch body of one control in negative-controls.json:
# the file's base with every @name filled from the values, the control's set laid over it.
render_body() {
	jq -c --arg id "$1" --argjson v "$2" '
		def fill: if type == "string" and startswith("@") then ($v[.[1:]] // error("no value for " + .)) else . end;
		(.base | map_values(fill)) + (.controls[] | select(.id == $id) | .set | map_values(fill))
	' "$CONTROLS"
}

plan_get() { # plan_get <jar> <target>  -> body on stdout
	curl -sS -m 10 -c "$1" -b "$1" "$DASH/api/security/assessments/plan?kind=pentest_local&project=$HASH&target=$(urlenc "$2")"
}

launch_post() { # launch_post <jar> <json> -> "<status>\n<body>"
	local jar=$1 body=$2 token
	token=$(awk '$6 == "sb_remote_confirm" {print $7}' "$jar" | tail -n 1)
	curl -sS -m 15 -c "$jar" -b "$jar" -H 'Content-Type: application/json' -H "X-Observer-Confirm: $token" \
		-w '\n%{http_code}' -d "$body" "$DASH/api/security/assessments/launch"
}

cmd_negative() {
	local set=${1:-core}
	command -v jq >/dev/null 2>&1 || die "jq is required for negative"
	curl -sS -m 5 -o /dev/null "$DASH/api/security/status" || die "the throwaway dashboard does not answer at $DASH"
	HASH=$(curl -sS -m 10 "$DASH/api/security/status" | jq -r '[.projects[] | select(.name == "notesapp")][0].project_root_hash // empty')
	[ -n "$HASH" ] || die "the throwaway node does not know the fixture project yet (run one session in it, see the doc, B)"
	local jar target body plan run_id digest tool values
	jar=$(mktemp)
	target="http://localhost:$TARGET_PORT/"
	say "Negative controls ($set), plan section 8, F; project hash ${HASH:0:12}..."
	case "$set" in
	core)
		body=$(plan_get "$jar" "http://example.com:$TARGET_PORT/")
		expect_refusal "E3 non-loopback target" E3 target_required 200 "$body"
		body=$(plan_get "$jar" "http://localhost/")
		expect_refusal "E3 target without a port" E3 target_required 200 "$body"
		body=$(plan_get "$jar" "http://127.0.0.1:$PROXY_PORT/")
		expect_refusal "E5 the proxy port as target" E5 target_reserved_port 200 "$body"

		plan=$(plan_get "$jar" "$target")
		if [ "$(printf '%s' "$plan" | jq -r '.ok // false')" != true ]; then
			die "the plan does not accept the fixture target, so no launch body can be built: $(printf '%s' "$plan" | jq -r '[.rule, .code, .reason] | map(select(. != null and . != "")) | join(" / ")'). Is the throwaway node's tier proxy_only, a backend available and an agent signed in? (doc, B)"
		fi
		run_id=$(printf '%s' "$plan" | jq -r '.run_id // empty')
		digest=$(printf '%s' "$plan" | jq -r '.prompt_sha256 // empty')
		[ -n "$run_id" ] || die "the plan gave no run id"
		[ -n "$digest" ] || die "the plan gave no prompt digest, so no launch body can be built (the task could not be written)"
		# The agent is the plan's own answer, never a name written in this script (the id is
		# claude-code, not claude): a plan that offers none means no launch can happen here.
		tool=${NEG_TOOL:-$(printf '%s' "$plan" | jq -r '.allowed_tools // [] | if index("claude-code") then "claude-code" else (.[0] // empty) end')}
		[ -n "$tool" ] || die "the plan lists no agent the box can run (allowed_tools is empty): check the Adapters page and allowed_tools in the throwaway config (doc, B)"
		values=$(jq -nc --arg h "$HASH" --arg r "$run_id" --arg t "$tool" --arg g "$target" --arg d "$(tripwire_digest "$digest")" --arg n "${NEG_UNROUTED_TOOL:-}" \
			'{project_root_hash: $h, run_id: $r, tool: $t, target: $g, tripwire_digest: $d} + (if $n != "" then {needs: $n} else {} end)')
		say "controls name the agent '$tool' and carry a tripwire digest: a body that gets past its rule is stopped by the digest and nothing starts"
		local cid want_rule want_code needs hint label out status resp lbody
		while IFS='|' read -r cid want_rule want_code needs hint label; do
			if [ -n "$needs" ] && [ -z "${!needs:-}" ]; then
				say "SKIP  $label: set $needs to ${hint:-a value} (doc, F)"
				continue
			fi
			if ! lbody=$(render_body "$cid" "$values"); then
				verdict FAIL "$label: the launch body could not be built from $CONTROLS"
				continue
			fi
			out=$(launch_post "$jar" "$lbody")
			status=$(printf '%s' "$out" | tail -n 1)
			resp=$(printf '%s' "$out" | sed '$d')
			expect_refusal "$label" "$want_rule" "$want_code" "$status" "$resp"
		done < <(jq -r '.controls[] | [.id, .rule, .code, (.needs // ""), (.skip_hint // ""), .label] | join("|")' "$CONTROLS")
		;;
	tier)
		say "This set expects the throwaway config to say [terminal.sandbox] egress = \"internet\" and the throwaway node restarted (preflight.sh daemon stop, then start)."
		body=$(plan_get "$jar" "$target")
		expect_refusal "E8 the internet tier without the tier tick" E8 tier_not_confined 200 "$body"
		say "NOTE  E5 for the gateway port (proxy port + 1) cannot be run here: under proxy_only there is no gateway, and under internet E8 stops the run first (the dialog reads 'This cannot start here') unless the section 13.9 tier tick is offered, which needs relax_*, max_network_tier = internet and egress_allow_hosts that this kit does not set. Covered by unit tests: TestEligibleGatewayPort and TestSecurityAssessTierRelaxation (doc, F)."
		;;
	*) die "negative takes core or tier" ;;
	esac
	rm -f "$jar"
	say
	printf 'result: %d pass, %d fail\n' "$PASS" "$FAIL"
	emit_json "$(receipt_dir)/negative-$set-$(stamp).json" "step=negative-$set" "when=$(stamp)" "pass=$PASS" "fail=$FAIL" >/dev/null
	[ "$FAIL" -eq 0 ]
}

# ------------------------------------------------------------ score, record

cmd_score() {
	local run=${1:-} earlier=${2:-}
	[ -n "$run" ] || die "score takes a run directory (<project>/.observer/assessments/<run id>) and, for a retest, optionally the folder of the run it replayed"
	[ -d "$run" ] || die "$run is not a directory"
	[ -f "$run/assessment.json" ] || die "$run has no assessment.json (a pen test, a red team run, a retest and a threat model write one; a run of another kind has nothing to score)"
	if [ -n "$earlier" ]; then
		[ -d "$earlier" ] || die "$earlier is not a directory (the folder of the run the retest replayed)"
		[ -f "$earlier/assessment.json" ] || die "$earlier has no assessment.json (the run a retest replayed is a pen test or red team run)"
		earlier=$(cd "$earlier" && pwd)
	fi
	if ! grep -rqs 'func TestLiveScore' "$REPO_ROOT/internal/secassess" 2>/dev/null; then
		say "The scorer is not in this checkout (TestLiveScore, plan W2): keep the run directory for later."
		say "Copy it somewhere safe first; it holds assessment.json, report.md and probes.jsonl."
		return 3
	fi
	# An absolute path: the test runs from the package directory. -count=1: a score is never a cached result.
	# OBSERVER_SECASSESS_LIVE_OF is read only for a retest (empty: look beside the retest's own folder).
	run=$(cd "$run" && pwd)
	( cd "$REPO_ROOT" && OBSERVER_SECASSESS_LIVE_RUN="$run" OBSERVER_SECASSESS_LIVE_OF="$earlier" go test -count=1 ./internal/secassess -run TestLiveScore -v )
}

cmd_record() {
	local name=${1:-}
	[ -n "$name" ] || die "record takes a name, for example pentest-claude-2026-11-14"
	local out="$ROOT/results/$name.json"
	mkdir -p "$ROOT/results"
	[ ! -e "$out" ] || die "$out already exists"
	cat >"$out" <<EOF
{
  "kind": "pentest_local | threat_model | red_team_local",
  "date": "$(date -u +%Y-%m-%d)",
  "node_build": "",
  "agent": "",
  "model": "",
  "prompt_version": "",
  "tier": "proxy_only",
  "backend": "bwrap",
  "wall_time_seconds": null,
  "cost_usd": null,
  "tokens": null,
  "requests_logged": null,
  "recall": null,
  "precision": null,
  "logged_rate": null,
  "coverage_rows": null,
  "validator_counts": {"refused": null, "downgraded": null, "warned": null},
  "boundary_audit": "",
  "r179_asks": null,
  "start_success": null,
  "surprises": "",
  "scrubbed_of_home_paths_and_user_names": false
}
EOF
	say "wrote $out (fill it in; scrub home paths and user names before it leaves the scratch root)"
}

# Sourced (scripts/assess-livecheck/test-kit.sh does that), nothing is dispatched.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
	return 0
fi

case "${1:-}" in
confine) shift && cmd_confine "$@" ;;
host-checks) shift && host_side host-checks "$@" ;;
after-run) shift && host_side after-run "$@" ;;
negative) shift && cmd_negative "$@" ;;
score) shift && cmd_score "$@" ;;
record) shift && cmd_record "$@" ;;
*)
	sed -n '2,/^set -uo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//' >&2
	exit 2
	;;
esac
