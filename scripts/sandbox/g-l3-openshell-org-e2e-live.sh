#!/usr/bin/env bash
# g-l3-openshell-org-e2e-live.sh: live check G-L3 of the org-hosted
# OpenShell gateway: one managed developer node end to end through the
# front, then held and resume (lane G5 writes it, lane G4 owns the check;
# docs/plans/openshell/build/g1-design.md sections 3.2, 3.6, 3.7, 5.3 and
# 11.6). Operator-attended.
#
# Machines: the sandbox VM running the bundle, a dev org server with its
# front, and the operator's Linux laptop and WSL2 laptop as managed
# developer nodes of one member. Run it on the developer node named by
# --machine, from a build that carries lanes G2 to G4; run it once per
# machine. The resume half needs both laptops: start it on the Linux
# laptop and finish it on the WSL2 one (its steps say which).
#
# Auto steps run on this node: whether this build has the org-shell verbs
# (a missing verb records not_run, naming lane G4), and whether the
# node's managed sandbox body carries the org gateway field (read with the
# node's own CLI). Every other step prints what to do and records the
# operator's judgment. It reads no key, token or config file.
#
# Usage:
#   scripts/sandbox/g-l3-openshell-org-e2e-live.sh --machine linux|wsl2
#       [--out DIR] [--only IDS] [--yes]
#       [--answers FILE]   (op steps answered from FILE, g-l-steps.sh)
#
# Receipt: g-l3-openshell-org-e2e-<machine>-<UTC stamp>.json
set -uo pipefail

# shellcheck source=scripts/sandbox/g-l-steps.sh
. "$(cd "$(dirname "$0")" && pwd)/g-l-steps.sh"
# The machine names the receipt, so it is read before anything else.
MACHINE=""
ARGS=("$@")
for ((i = 0; i < ${#ARGS[@]}; i++)); do
	[ "${ARGS[$i]}" = --machine ] && MACHINE="${ARGS[$((i + 1))]:-}"
done
case "$MACHINE" in linux | wsl2) ;; *) MACHINE="" ;; esac
st_init G-L3 "observer-g-l3-live/1" "g-l3-openshell-org-e2e-${MACHINE:-unknown}"
trap 'st_finish $?' EXIT

while [ $# -gt 0 ]; do
	if st_common_args "$1"; then
		shift
		continue
	fi
	case "$1" in
	--out) OUT="$2"; shift ;;
	--only) ONLY="$2"; shift ;;
	--answers) ANSWERS="$2"; shift ;;
	--machine) shift ;;
	*) st_refuse "unknown argument $1" ;;
	esac
	shift
done
case "$MACHINE" in linux | wsl2) ;; *) st_refuse "--machine must be linux or wsl2" ;; esac
R[machine]="$MACHINE"
if grep -qi microsoft /proc/version 2>/dev/null; then R[host_kind]=wsl2; else R[host_kind]=linux; fi
[ "${R[host_kind]}" = "$MACHINE" ] || st_refuse "--machine $MACHINE but this host is ${R[host_kind]}"
[ -d "$OUT" ] && [ -w "$OUT" ] || OUT="$HOME"
command -v observer >/dev/null || st_refuse "observer is not on PATH"

STEPS=$(
	cat <<'EOF'
L3-00 | auto | this node's build has the org-shell verbs (lane G4) | have observer sandbox org-shell && echo "observer sandbox org-shell present"
L3-01 | op | the node is enrolled managed and holds the verified org gateway field; the picker offers "OpenShell (org-hosted)" | observer sandbox status --all --json (the openshell-org row's verdict); observer sandbox org-shell status; the New Terminal picker
L3-02 | op | device approval: login prints a verification URL and code; the dashboard page shows this node, the front, tiers, quotas and the org_compute disclosure; approving it lands the grant | observer sandbox org-shell login
L3-03 | op | a member who has NOT opted in to the laptop relay is refused at launch (laptop_relay_not_opted_in) | observer claude --observer-sandbox openshell-org (opt-in off)
L3-04 | op | after opting in, a launch creates the RECORDED spec through the front (the org image digest; no binds; the labels; resources.limits cpu and memory, which the docker driver sets on the box container) | observer sandbox org-shell opt-in; observer <script agent> --observer-sandbox openshell-org (with no source flag it prints "workspace source clone-local"; --observer-sandbox-source clone-local says the same explicitly); docker inspect of the box container on the sandbox host (HostConfig.NanoCpus, HostConfig.Memory)
L3-05 | op | the upload arrives in the box (clone-local) and the relay says ready before the agent starts | the launch log
L3-06 | op | a script agent's model turn lands as an api_turns row on the run's rsbx- session | the dashboard Sessions page, session rsbx-<run>-*
L3-07 | op | a hook fires in the box and is captured on this node: launch from a workspace that commits a project-scope hook (.claude/settings.json, a PreToolUse command `observer hook claude-code pre-tool`); every tool call runs (FX4: the payload's transcript_path in the box's agent home is no longer refused path_outside_run) and the hook's action lands. With no project hook no hook runs in the box (the box home gets no user-scope registration; capture is the proxy and the transcript pull) | the session's Actions tab; the relay log has no path_outside_run
L3-08 | op | the diff and the bundle come back to this node and are NOT applied to the working tree | git status in the workspace; the run's return dir
L3-09 | op | teardown deletes the box; both ledgers settle (the node's hosted ledger and the org's box ledger) | the node's ~/.observer/sandbox-hosted/ledger.json (the run's reservation settled; there is no ledger verb) and the dashboard's hosted panel; observer-org openshell boxes; the web2 OpenShell page
L3-10 | op | one real tool turn (claude-code or codex) completes the same way | observer claude --observer-sandbox openshell-org
L3-11 | op | HELD (Linux laptop): unplug the network mid-run; within about 120 s (QuietAfter: 4 x the front's 30 s re-check after its last decide) the org's box ledger shows the run held (H2) | the web2 OpenShell page, Held sessions
L3-12 | op | RESUME (WSL2 laptop, the same member): the held run is listed; resume it; the workspace edits and the agent's session are there, and a ResumeNative tool continues its own session | observer sandbox org-shell resume <run>
L3-13 | op | an explicit hold and a resume from the same node work the same way; the launching terminal says the box is held and names the run id `org-shell held` lists (FX4, F-P6-4, F-P6-5); the resumed agent stream outlives 60 s with no keystroke (FX4, F-P6-3) | observer sandbox org-shell hold <run>; then resume <run>
EOF
)

echo "G-L3 on $MACHINE ($(uname -n)). Each op step asks for p, f or s and a note."
st_run "$STEPS"
R[completed]=1
[ "$FAIL" = 0 ] && exit 0
exit 1
