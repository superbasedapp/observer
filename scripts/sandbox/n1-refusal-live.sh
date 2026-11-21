#!/usr/bin/env bash
# n1-refusal-live.sh - OpenShell build lane N1 live checks N1-L1 (native
# Linux) and N1-L2 (WSL2): a host the sandbox egress gateway refuses lands
# a row in the refusal audit on bwrap and on oci-runc, and again after the
# oci-runc run is re-adopted.
#
# Operator-attended. Run it on your own machine against your own running
# daemon (`observer start`). It never reads a key, a token or a config file;
# it only reads the owner-local route GET /api/sandbox/refusals on the
# loopback dashboard, and asks you to launch the runs from the dashboard.
#
# Usage:
#   scripts/sandbox/n1-refusal-live.sh [--dashboard http://127.0.0.1:8081] \
#       [--machine linux|wsl2] [--receipt FILE]
#
# Prerequisites:
#   - the daemon is running with [terminal.sandbox] enabled = true,
#     egress = "internet" and egress_allow_hosts = ["registry.npmjs.org"];
#   - for the oci-runc rows, the terminals.sandbox.oci driver is active and
#     Docker or Podman runs; for the re-adoption row, terminals.sandbox.oci
#     re-adoption is on (docs/sandboxed-terminals.md, "Re-adopting local
#     containers and checkpoints") on an engine mode that keeps a
#     container (rootful Docker with live-restore, or Podman with conmon);
#     the run must be a DASHBOARD launch (a CLI launch is reaped by design,
#     row cli-run);
#   - curl and jq on PATH.
#
# Each step asks you to start a sandboxed terminal and, inside it, run:
#   curl -sS -x "$HTTPS_PROXY" http://refused-n1.invalid/ ; echo
# The gateway must answer a JSON body with "error":"egress_refused" (a plain
# http request on port 80 is judged by the host list and refused as
# allow-list-miss, and curl prints the body). An https URL would go through
# a CONNECT tunnel, and curl does not print a proxy's refusal body for a
# CONNECT: it says "CONNECT tunnel failed, response 403" instead, which is
# also a pass (tracker F-009, audit finding N1-A6; add -v to see the 403).
# The script then reads the route and checks for a row for that host.

set -euo pipefail

dashboard="http://127.0.0.1:8081"
machine="linux"
receipt=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dashboard) dashboard="$2"; shift 2 ;;
	--machine) machine="$2"; shift 2 ;;
	--receipt) receipt="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
case "$machine" in
linux) id="N1-L1" ;;
wsl2) id="N1-L2" ;;
*) echo "--machine must be linux or wsl2" >&2; exit 2 ;;
esac
if [ -z "$receipt" ]; then
	receipt="n1-refusal-live-${machine}-$(date -u +%Y%m%dT%H%M%SZ).json"
fi
for tool in curl jq; do
	command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
host="refused-n1.invalid"
route="$dashboard/api/sandbox/refusals"

# The route must answer before anything else (an inactive terminals.sandbox
# component answers 404 component_not_installed).
if ! curl -fsS "$route?limit=1" >/dev/null; then
	echo "GET $route failed: is the daemon running with the sandbox module active?" >&2
	exit 1
fi

results="[]"

# step NAME PROMPT: wait for the operator, then look for a new row for $host
# newer than the highest id seen before the step.
step() {
	local name="$1" prompt="$2" before after row status
	before=$(curl -fsS "$route?limit=1" | jq '.refusals[0].id // 0')
	echo
	echo "== $name"
	echo "$prompt"
	echo "Inside the box run:  curl -sS -x \"\$HTTPS_PROXY\" http://$host/ ; echo"
	echo "It must print a JSON body with \"error\":\"egress_refused\" (plain http, so curl shows the body;"
	echo "an https URL only shows \"CONNECT tunnel failed, response 403\", which also passes)."
	read -r -p "Press Enter once it has printed the body (or type skip): " answer
	if [ "$answer" = "skip" ]; then
		results=$(jq -c --arg n "$name" '. + [{step: $n, status: "skipped"}]' <<<"$results")
		return
	fi
	sleep 2
	after=$(curl -fsS "$route?limit=50")
	row=$(jq -c --arg h "$host" --argjson b "$before" '[.refusals[] | select(.host == $h and .id > $b)][0] // null' <<<"$after")
	if [ "$row" = "null" ]; then
		status="failed"
		echo "FAIL: no new row for $host"
	else
		status="passed"
		echo "PASS: $row"
	fi
	results=$(jq -c --arg n "$name" --arg s "$status" --argjson r "$row" '. + [{step: $n, status: $s, row: $r}]' <<<"$results")
}

step "bwrap" "Launch a sandboxed terminal on the bwrap row (Linux backend) from the dashboard."
step "oci-runc" "Launch a sandboxed terminal on the oci-runc row (container backend) from the dashboard. Keep it running."
step "oci-runc re-adopted" "Restart the daemon (route OFF first, docs/daemon-restart-runbook.md). Then run \`observer sandbox runs\`: it must list the oci-runc run as offered (when it does not, it names the re-adoption row that ended the run, and the daemon log has a 're-adoption decision' line for it: record both). Then run \`observer sandbox readopt <run>\` for that run in your own terminal."

echo
echo "Rows for $host now on the route:"
curl -fsS "$route?limit=50" | jq --arg h "$host" '[.refusals[] | select(.host == $h)]'

overall=$(jq -r 'if all(.[]; .status == "passed") then "passed" else "failed" end' <<<"$results")
jq -n --arg id "$id" --arg machine "$machine" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	--arg status "$overall" --argjson steps "$results" \
	'{id: $id, machine: $machine, at: $at, status: $status, steps: $steps}' >"$receipt"
echo
echo "$id: $overall. Receipt written to $receipt"
[ "$overall" = "passed" ]
