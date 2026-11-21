#!/usr/bin/env bash
# n4-link-loss-live.sh - OpenShell build lane FU5 live check N4-L3 (tracker
# F-012, audit finding N4-A4): what a sandboxed run does when its relay link
# to the daemon is lost mid-run.
#
#   half A (no floor): the run keeps its network while the daemon is down;
#     the refusals it could not report are counted with the run
#     (GET /api/sandbox/refusals link_lost) once the daemon is back;
#   half B (require_refusal_audit published): once the run finds the link
#     lost, every new request is answered 503 naming the floor until the
#     daemon is back, and the refused requests are counted (egress_closed).
#     A connection opened before keeps running until it closes.
#
# Operator-attended, on Linux or WSL2 with bwrap. The run is a CLI launch
# (observer claude --observer-sandbox bwrap) in your own terminal, so it
# outlives the daemon stop. It reads only the loopback dashboard routes
# GET /api/terminal/runs (run ids) and GET /api/sandbox/refusals; it never
# reads a key or a config file. Stop and start the daemon the safe way:
# scripts/restart-daemon.sh, or route OFF, stop, start, route ON
# (docs/daemon-restart-runbook.md); the tool's own model calls fail while
# the daemon is down, which is expected.
#
# Usage:
#   scripts/sandbox/n4-link-loss-live.sh [--dashboard http://127.0.0.1:8081] \
#       [--half a|b|both] [--receipt FILE]
#
# Prerequisites: [terminal.sandbox] enabled = true, egress = "internet",
# egress_allow_hosts = ["registry.npmjs.org"]; curl and jq. Half B needs a
# managed node of the org test rig with the floor published (the N4-L1
# setup); half A needs no org.

set -euo pipefail

dashboard="http://127.0.0.1:8081"
half="both"
receipt=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dashboard) dashboard="$2"; shift 2 ;;
	--half) half="$2"; shift 2 ;;
	--receipt) receipt="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
case "$half" in a | b | both) ;; *) echo "--half must be a, b or both" >&2; exit 2 ;; esac
[ -n "$receipt" ] || receipt="n4-link-loss-$(date -u +%Y%m%dT%H%M%SZ).json"
for tool in curl jq; do
	command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
refusals="$dashboard/api/sandbox/refusals"
steps='[]'
record() {
	steps=$(jq -c --arg step "$1" --arg ok "$2" --argjson detail "${3:-null}" '. + [{step: $step, ok: ($ok == "true"), detail: $detail}]' <<<"$steps")
	echo "$1: $2"
}
ask() {
	printf '%s\n' "$1"
	read -r -p "Type yes if it did, no if it did not: " a
	[ "$a" = "yes" ]
}
up() { curl -fsS "$refusals?limit=1" >/dev/null 2>&1; }
run_ids() { curl -fsS "$dashboard/api/terminal/runs?limit=500" | jq -c '[(.runs // [])[] | .run_id]'; }
wait_up() { until up; do sleep 2; done; }

# one HALF NAME: a launch, an outage with two refusals and one allowed
# request inside it, then the counts once the daemon is back.
one() {
	local name="$1" floor="$2" before run new
	up || { echo "the daemon must be running before half $name" >&2; exit 1; }
	before=$(run_ids)
	echo
	echo "== half $name"
	read -r -p "In another terminal launch: observer claude --observer-sandbox bwrap   then press Enter. " _
	new=$(jq -c --argjson b "$before" '[.[] | select(. as $r | $b | index($r) | not)]' <<<"$(run_ids)")
	run=$(jq -r 'if length == 1 then .[0] else "" end' <<<"$new")
	if [ -z "$run" ]; then
		read -r -p "Type the run id of that launch (new runs: $new): " run
	fi
	record "$name: run identified" "$([ -n "$run" ] && echo true || echo false)" "$(jq -nc --arg r "$run" '{run_id: $r}')"
	echo "Now stop the daemon (route OFF first). Leave the sandboxed tool running."
	read -r -p "Press Enter when the daemon is stopped. " _
	if up; then
		record "$name: daemon stopped" false
	else
		record "$name: daemon stopped" true
	fi
	if [ "$floor" = "yes" ]; then
		ask "Inside the tool, through its shell, run in this order:
    curl -sS -m 10 -x \"\$HTTPS_PROXY\" http://lost-b.invalid/ ; echo
    curl -sS -m 10 -x \"\$HTTPS_PROXY\" http://lost-c.invalid/ ; echo
    curl -sS -m 10 -o /dev/null -w '%{http_code}\\n' https://registry.npmjs.org/
The third must fail: curl reports 'CONNECT tunnel failed, response 503' (add -v to see the reason naming \"Require refusal audit\"). Did it?" &&
			record "$name: new connections refused while the link is down" true || record "$name: new connections refused while the link is down" false
	else
		ask "Inside the tool, through its shell, run in this order:
    curl -sS -m 10 -x \"\$HTTPS_PROXY\" http://lost-b.invalid/ ; echo
    curl -sS -m 10 -x \"\$HTTPS_PROXY\" http://lost-c.invalid/ ; echo
    curl -sS -m 10 -o /dev/null -w '%{http_code}\\n' https://registry.npmjs.org/
The first two print the JSON 403; the third must print 200 (no floor: the network stays open). Did it?" &&
			record "$name: egress open while the link is down" true || record "$name: egress open while the link is down" false
	fi
	echo "Start the daemon again (route ON after)."
	read -r -p "Press Enter when it is up. " _
	wait_up
	# The helper retries every 2 s; give the counts time to land.
	local page="null"
	for _ in $(seq 1 15); do
		page=$(curl -fsS -G "$refusals" --data-urlencode "run_id=$run" --data-urlencode "limit=50")
		if [ "$floor" = "yes" ]; then
			[ "$(jq -r --arg r "$run" '.egress_closed[$r] // 0' <<<"$page")" -ge 1 ] && break
		else
			[ "$(jq -r --arg r "$run" '.link_lost[$r] // 0' <<<"$page")" -ge 1 ] && break
		fi
		sleep 2
	done
	local lost closed retried
	lost=$(jq -r --arg r "$run" '.link_lost[$r] // 0' <<<"$page")
	closed=$(jq -r --arg r "$run" '.egress_closed[$r] // 0' <<<"$page")
	retried=$(jq -r '[(.refusals // [])[] | select(.host == "lost-c.invalid")] | length' <<<"$page")
	local detail
	detail=$(jq -nc --argjson l "$lost" --argjson c "$closed" --argjson r "$retried" '{link_lost: $l, egress_closed: $c, retried_row: $r}')
	if [ "$floor" = "yes" ]; then
		record "$name: refused requests counted with the run" "$([ "$closed" -ge 1 ] && echo true || echo false)" "$detail"
	else
		record "$name: lost refusals counted with the run" "$([ "$lost" -ge 1 ] && [ "$retried" -ge 1 ] && echo true || echo false)" "$detail"
	fi
	ask "Inside the tool run: curl -sS -m 10 -o /dev/null -w '%{http_code}\\n' https://registry.npmjs.org/   It must print 200 (new connections are allowed again). Did it?" &&
		record "$name: open after the link is back" true || record "$name: open after the link is back" false
	echo "Exit the tool."
}

if [ "$half" != "b" ]; then
	echo "Half A: make sure 'Require refusal audit' is NOT published for this node."
	read -r -p "Press Enter when ready. " _
	one A no
fi
if [ "$half" != "a" ]; then
	echo "Half B: publish 'Require refusal audit' from the org dashboard and wait until this node lists it."
	read -r -p "Press Enter when it is listed. " _
	one B yes
	echo "Withdraw the floor again if this node should not keep it."
fi

jq -n --arg id "N4-L3" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg half "$half" --argjson steps "$steps" \
	'{id: $id, at: $at, half: $half, steps: $steps, passed: ([$steps[] | .ok] | all)}' >"$receipt"
echo
echo "receipt: $receipt"
jq -r 'if .passed then "N4-L3 passed" else "N4-L3 FAILED: see the steps" end' "$receipt"
