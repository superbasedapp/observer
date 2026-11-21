#!/usr/bin/env bash
# n4-refusal-audit-floor-live.sh - OpenShell build lane N4 live check N4-L1
# on the org test rig (D-775): with the terminals.isolation floor
# require_refusal_audit published, a managed node refuses a launch whose
# tier the backend does not audit, naming the floor, and still launches one
# whose tier it audits; a host-local destination refused in that run lands
# a row in the node's refusal audit (GET /api/sandbox/refusals).
#
# The floor is judged per launch tier (audit finding N4-A1): bwrap audits
# internet (the egress gateway reports each refusal), proxy_only and none
# (no way out but the model proxy), never host (the shared host network
# starts no gateway). The network tier is node-wide
# ([terminal.sandbox].egress, set in Terminals, Settings, Sandbox).
#
# The refusing case is picked from the node's own probe once the floor is
# published (F-015 R4, audit finding N4-R4), so the check runs on any
# audited backend, not only bwrap:
#   1. a row the probe already drops by the floor on --audited-tier
#      (verdict refusal_audit_required; for example process_lite or the MXC
#      AppContainer row when they are enabled), so no tier switch is needed;
#   2. else, when the audited row offers the host tier (bwrap only), the
#      audited row on host, asking you to switch the tier and restart;
#   3. else none: on macOS (seatbelt and apple-container audit every tier
#      they offer) no row on this machine is refused by this floor alone, so
#      the refusing half is recorded as not applicable (the receipt says so)
#      and selection tests carry it (TestRefusalAuditFloorPerBackend).
# --refused and --refused-tier override the pick.
#
# The refusal row is matched by run id (F-015 R4): the script lists the
# node's terminal runs before and after the audited launch, takes the run
# that is new, and reads GET /api/sandbox/refusals?run_id=<run>; the row's
# backend and tier must then be the audited row and tier. --run-id names
# the run when several are launched at once.
#
# Operator-attended. Run it on the managed node of the org test rig,
# against that node's own running daemon (`observer start`). It never reads
# a key or a config file; it reads only the node's loopback dashboard
# routes GET /api/terminal/sandbox, GET /api/terminal/sandbox/config (of
# which it keeps only the saved tier), GET /api/terminal/runs (run ids
# only) and GET /api/sandbox/refusals,
# and asks you to publish the floor from the org dashboard (web2), to set
# the tier and to launch the terminals.
#
# Usage:
#   scripts/sandbox/n4-refusal-audit-floor-live.sh [--dashboard http://127.0.0.1:8081] \
#       [--audited bwrap] [--audited-tier internet] [--refused ROW] \
#       [--refused-tier TIER] [--run-id RUN] [--receipt FILE]
#
# --audited names a row that runs on this node (bwrap on Linux or WSL2,
# seatbelt on macOS, mxc-process on Windows) and --audited-tier a tier
# that runs Observer's egress gateway for it (internet), so a refusal can
# be made and recorded. --refused and --refused-tier name a launch the floor
# must refuse; by default the script picks one as above.
#
# The audit records at most one row per run and host per minute, and drops
# a refusal when its report queue is full (lane N1's limiter); the probe
# below makes one refusal, so neither bound applies.
#
# Prerequisites:
#   - the node is enrolled in the rig's org as a managed node, accepts the
#     terminals.isolation family, and has preauthorized enforcement;
#   - [terminal.sandbox] enabled = true and both rows in its backends list;
#   - curl and jq on PATH (and curl inside the sandboxed terminal).

set -euo pipefail

dashboard="http://127.0.0.1:8081"
audited="bwrap"
audited_tier="internet"
refused=""
refused_tier=""
run_id=""
receipt=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dashboard) dashboard="$2"; shift 2 ;;
	--audited) audited="$2"; shift 2 ;;
	--audited-tier) audited_tier="$2"; shift 2 ;;
	--refused) refused="$2"; shift 2 ;;
	--refused-tier) refused_tier="$2"; shift 2 ;;
	--run-id) run_id="$2"; shift 2 ;;
	--receipt) receipt="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
if [ -z "$receipt" ]; then
	receipt="n4-refusal-audit-floor-$(date -u +%Y%m%dT%H%M%SZ).json"
fi
for tool in curl jq; do
	command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
route="$dashboard/api/terminal/sandbox"
verdict="refusal_audit_required"
# A link-local destination the egress gateway always refuses (rule
# link-local-unicast); no request leaves the machine.
probe_host="169.254.169.254"

probe() { curl -fsS "$route"; }
tier_now() { curl -fsS "$route/config" | jq -r '.sandbox.egress // empty'; }
row() { jq -c --arg id "$1" '(.backends // [])[] | select(.id == $id) | {id, available, verdict, rule, reason, egress}'; }
run_ids() { curl -fsS "$dashboard/api/terminal/runs?limit=500" | jq -c '[(.runs // [])[] | .run_id]'; }
floor_listed() { jq -r '[(.org.floors // [])[] | select(.key == "require_refusal_audit")] | length'; }
ask() {
	printf '%s\n' "$1"
	read -r -p "Type yes when done, or no if it did not work: " a
	[ "$a" = "yes" ]
}
set_tier() {
	[ "$(tier_now)" = "$1" ] && return 0
	while [ "$(tier_now)" != "$1" ]; do
		echo "Set the sandbox network tier to '$1' (Terminals, Settings, Sandbox, Network tier) and save."
		read -r -p "Press Enter when saved. " _
	done
	# A saved tier takes effect at the next daemon start.
	echo "Restart the daemon so the tier takes effect: scripts/restart-daemon.sh"
	echo "(route OFF, stop, relaunch, route ON; docs/daemon-restart-runbook.md)."
	read -r -p "Press Enter when the daemon is back. " _
	until probe >/dev/null 2>&1; do sleep 2; done
}

steps='[]'
record() {
	steps=$(jq -c --arg step "$1" --arg ok "$2" --argjson detail "${3:-null}" '. + [{step: $step, ok: ($ok == "true"), detail: $detail}]' <<<"$steps")
	echo "$1: $2"
}

# Step 1: on the auditing tier, before the floor, the audited row probes
# available and nothing names the floor.
probe >/dev/null || { echo "GET $route failed: is the daemon running?" >&2; exit 2; }
set_tier "$audited_tier"
before=$(probe)
a0=$(row "$audited" <<<"$before")
ok=false
if [ "$(jq -r '.available' <<<"${a0:-null}")" = "true" ] && [ "$(floor_listed <<<"$before")" = "0" ]; then
	ok=true
fi
record "before-floor-audited-row-available" "$ok" "$(jq -nc --argjson a "${a0:-null}" --arg tier "$audited_tier" '{tier: $tier, audited: $a}')"
if [ "$ok" != true ]; then
	echo "$audited must probe available on $audited_tier, with no refusal audit floor published, before the floor is published" >&2
fi

# Step 2: publish the floor.
echo
echo "In the org dashboard (web2): Policy, Node features, Isolation floors."
echo "Turn on 'Require refusal audit'. If $audited is beta on this host, also turn on"
echo "'Beta backends may meet the floors'. Publish, then wait until this node"
echo "shows the floor (Terminals, Settings, Sandbox isolation)."
read -r -p "Press Enter when published. " _
after=""
for _ in $(seq 1 30); do
	after=$(probe)
	[ "$(floor_listed <<<"$after")" != "0" ] && break
	sleep 10
done
listed=$(floor_listed <<<"$after")
record "floor-reached-the-node" "$([ "$listed" != "0" ] && echo true || echo false)" "$(jq -c '[(.org.floors // [])[]]' <<<"$after")"

# Step 3: on the auditing tier the audited row stays available.
a1=$(row "$audited" <<<"$after")
record "audited-row-available-under-the-floor" "$([ "$(jq -r '.available' <<<"${a1:-null}")" = "true" ] && echo true || echo false)" "$(jq -nc --argjson a "${a1:-null}" --arg tier "$audited_tier" '{tier: $tier, audited: $a}')"

# Step 4: the auditing launch runs, and a refusal it causes lands in the
# node's refusal audit for that run, matched by run id.
runs_before=$(run_ids)
if ask "Launch: observer claude --observer-sandbox $audited   (any mapped tool works). It must start sandboxed by $audited. In that sandboxed terminal run:
    curl -sS -m 10 http://$probe_host/
It must print a JSON body with \"error\": \"egress_refused\" (the egress gateway's 403). Then exit the tool."; then
	record "audited-launch-runs" true
else
	record "audited-launch-runs" false
fi
if [ -z "$run_id" ]; then
	new_runs=$(jq -c --argjson before "$runs_before" '[.[] | select(. as $r | $before | index($r) | not)]' <<<"$(run_ids)")
	case "$(jq 'length' <<<"$new_runs")" in
	1) run_id=$(jq -r '.[0]' <<<"$new_runs") ;;
	0) echo "No new terminal run was recorded since the launch." >&2 ;;
	*)
		echo "Several terminal runs started during the launch: $new_runs" >&2
		read -r -p "Type the run id of the $audited launch: " run_id
		;;
	esac
fi
record "audited-run-identified" "$([ -n "$run_id" ] && echo true || echo false)" "$(jq -nc --arg run "$run_id" '{run_id: $run}')"
landed='null'
if [ -n "$run_id" ]; then
	for _ in $(seq 1 12); do
		landed=$(curl -fsS -G "$dashboard/api/sandbox/refusals" --data-urlencode "run_id=$run_id" --data-urlencode "limit=50" |
			jq -c --arg host "$probe_host" --arg run "$run_id" \
				'[(.refusals // [])[] | select(.run_id == $run and .host == $host)] | first // null')
		[ "$landed" != "null" ] && break
		sleep 5
	done
fi
record "audited-run-refusal-landed" "$([ "$landed" != "null" ] && echo true || echo false)" "$landed"
# The row's backend and tier are stamped by the daemon from the run record,
# never by the box: they prove the run was the audited row on the audited
# tier.
ok=false
if [ "$landed" != "null" ] && [ "$(jq -r '.backend' <<<"$landed")" = "$audited" ] && [ "$(jq -r '.tier' <<<"$landed")" = "$audited_tier" ]; then
	ok=true
fi
record "audited-run-refusal-backend-and-tier" "$ok" "$(jq -nc --argjson r "$landed" --arg b "$audited" --arg tier "$audited_tier" '{want: {backend: $b, tier: $tier}, got: (if $r == null then null else {backend: $r.backend, tier: $r.tier} end)}')"

# Pick the refusing case (unless named): a row already dropped by the floor
# on the audited tier, else the audited row on host when it offers host,
# else none on this machine.
refused_case="named"
if [ -z "$refused" ]; then
	refused=$(jq -r --arg v "$verdict" --arg a "$audited" '[(.backends // [])[] | select(.verdict == $v and .id != $a) | .id] | first // empty' <<<"$after")
	if [ -n "$refused" ]; then
		refused_case="dropped_on_the_audited_tier"
		[ -n "$refused_tier" ] || refused_tier="$audited_tier"
	elif jq -e '(.egress // []) | index("host")' <<<"${a1:-null}" >/dev/null; then
		refused="$audited"
		refused_case="audited_row_on_host"
		[ -n "$refused_tier" ] || refused_tier="host"
	else
		refused_case="not_applicable"
	fi
elif [ -z "$refused_tier" ]; then
	r0=$(row "$refused" <<<"$after")
	if jq -e '(.egress // []) | index("host")' <<<"${r0:-null}" >/dev/null; then
		refused_tier="host"
	else
		refused_tier="$audited_tier"
	fi
fi
record "refused-case-picked" true "$(jq -nc --arg c "$refused_case" --arg r "$refused" --arg tier "$refused_tier" '{case: $c, refused: (if $r == "" then null else $r end), tier: (if $tier == "" then null else $tier end)}')"

# Step 5: on the refusing tier the refused launch is dropped by S7e,
# naming the floor and the tier, and the launch itself is refused.
if [ "$refused_case" != "not_applicable" ]; then
	set_tier "$refused_tier"
	onref=$(probe)
	r1=$(row "$refused" <<<"$onref")
	ok=false
	if [ "$(jq -r '.verdict' <<<"${r1:-null}")" = "$verdict" ] && jq -e '.reason | contains("require_refusal_audit")' <<<"${r1:-null}" >/dev/null; then
		ok=true
	fi
	record "refused-row-dropped-naming-the-floor" "$ok" "$(jq -nc --argjson r "${r1:-null}" --arg tier "$refused_tier" '{tier: $tier, refused: $r}')"
	if ask "Launch: observer claude --observer-sandbox $refused   It must be refused, and the message must name 'Require refusal audit'."; then
		record "refused-launch-refused" true
	else
		record "refused-launch-refused" false
	fi
else
	echo "No row on this machine is refused by require_refusal_audit alone; the refusing half is not applicable here (selection tests cover it)."
fi

# Step 6: withdraw, and the floor no longer drops the refused row (it may
# still be unavailable for another reason, for example a row that does not
# offer the tier: only the floor's verdict must be gone).
echo
echo "In the org dashboard, turn 'Require refusal audit' off again and publish."
read -r -p "Press Enter when published. " _
back=""
for _ in $(seq 1 30); do
	back=$(probe)
	[ "$(floor_listed <<<"$back")" = "0" ] && break
	sleep 10
done
record "withdrawn-floor-gone" "$([ "$(floor_listed <<<"$back")" = "0" ] && echo true || echo false)"
if [ "$refused_case" != "not_applicable" ]; then
	r2=$(row "$refused" <<<"$back")
	record "withdrawn-refused-row-not-dropped-by-the-floor" "$([ -n "$r2" ] && [ "$(jq -r '.verdict // ""' <<<"$r2")" != "$verdict" ] && echo true || echo false)" "${r2:-null}"
fi
echo "Set the sandbox network tier back to what this node used before the check."

jq -n --arg id "N4-L1" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg audited "$audited" --arg audited_tier "$audited_tier" \
	--arg refused "$refused" --arg refused_tier "$refused_tier" --arg refused_case "$refused_case" --arg run "$run_id" --argjson steps "$steps" \
	'{id: $id, at: $at, audited: $audited, audited_tier: $audited_tier, run_id: $run,
	refused: (if $refused == "" then null else $refused end), refused_tier: (if $refused_tier == "" then null else $refused_tier end),
	refused_case: $refused_case, steps: $steps,
	passed: ([$steps[] | .ok] | all)}' >"$receipt"
echo
echo "receipt: $receipt"
jq -r 'if .passed then "N4-L1 passed" else "N4-L1 FAILED: see the steps" end' "$receipt"
