#!/usr/bin/env bash
# g-l6-openshell-org-clone-live.sh: live check G-L6 of the org-hosted
# OpenShell gateway: the box-side clone-remote with a read-only,
# repository-scoped org git provider (lane G5 writes it, lane G4 owns the
# check; docs/plans/openshell/build/g1-design.md sections 4.3, 7.8 and
# 11.6). Operator-attended.
#
# Machines: the sandbox VM running the bundle, the org server with its
# front, and one managed developer node; a private test repository (and a
# second private repository on the same git host) the org's provider can
# read. Run it on the developer node, from a build that carries lanes G2
# to G4.
#
# The laptop-never-holds-the-credential half is checked with a SENTINEL:
# before the run, the operator gives the org's provider row (on the org
# side, never on this node) a recognisable non-secret marker in a field
# the provider carries along with its credential (for example its
# description or a dummy second credential named SENTINEL), and passes the
# same marker here with --sentinel. The auto steps then confirm this node
# never saw it: not under ~/.observer, not in any process's command line,
# and no git clone process of the repository ran here. The marker is not
# a secret and is the only value this script compares; it reads no key,
# token or config file.
#
# Usage:
#   scripts/sandbox/g-l6-openshell-org-clone-live.sh --sentinel MARKER
#       --repository URL [--out DIR] [--only IDS] [--yes]
#       [--answers FILE]   (op steps answered from FILE, g-l-steps.sh)
#
# Receipt: g-l6-openshell-org-clone-<UTC stamp>.json
# shellcheck disable=SC2016
set -uo pipefail

# shellcheck source=scripts/sandbox/g-l-steps.sh
. "$(cd "$(dirname "$0")" && pwd)/g-l-steps.sh"
st_init G-L6 "observer-g-l6-live/1" g-l6-openshell-org-clone
trap 'st_finish $?' EXIT

SENTINEL=""
REPO=""
while [ $# -gt 0 ]; do
	if st_common_args "$1"; then
		shift
		continue
	fi
	case "$1" in
	--out) OUT="$2"; shift ;;
	--only) ONLY="$2"; shift ;;
	--answers) ANSWERS="$2"; shift ;;
	--sentinel) SENTINEL="$2"; shift ;;
	--repository) REPO="$2"; shift ;;
	*) st_refuse "unknown argument $1" ;;
	esac
	shift
done
case "$SENTINEL" in '' | *[!A-Za-z0-9_-]*) st_refuse "--sentinel must be letters, digits, dash or underscore" ;; esac
[ "${#SENTINEL}" -ge 12 ] || st_refuse "--sentinel must be at least 12 characters"
[ -n "$REPO" ] || st_refuse "--repository is required (the private test repository's URL)"
[ -d "$OUT" ] && [ -w "$OUT" ] || OUT="$HOME"
command -v observer >/dev/null || st_refuse "observer is not on PATH"
R[repository]="$REPO"
R[sentinel_length]="${#SENTINEL}"
export SENTINEL REPO

STEPS=$(
	cat <<'EOF'
L6-00 | auto | this node's build has the org-shell verbs (lane G4) | have observer sandbox org-shell && echo "observer sandbox org-shell present"
L6-01 | op | a member NOT on the repository row's allowed_teams or allowed_members asks for it and is refused at mint (clone_repository_not_allowed) | a clone-remote launch as that member: observer <tool> --observer-sandbox openshell-org --observer-sandbox-source clone-remote --observer-sandbox-remote <url>, or through the node dashboard: POST /api/terminal/launch {"tool":"<tool>","project_root":"<dir>","sandbox":true,"backend":"openshell-org","workspace_source":"clone-remote","workspace_remote":"<url>"}
L6-02 | op | an allowed member's clone-remote run: the clone is made in the box (its first exec), not on this node | the same CLI or dashboard launch as L6-01 as an allowed member; the launch log; the box's workspace
L6-03 | auto | no git clone process of the repository ran on this node during the run (process list now; run it while the clone step is live too) | ! ps -eo comm= -o args= | grep -F -- "$REPO" | awk '$1 ~ /^git/' | grep -q . && echo "no local git process names the repository"
L6-04 | auto | this node never held the org credential: the sentinel is not under ~/.observer | ! grep -rIl -F -- "$SENTINEL" "$HOME/.observer" 2>/dev/null | grep -q . && echo "sentinel absent under ~/.observer"
L6-05 | auto | the sentinel is not in any process's command line | ! ps -eo args | grep -v -e g-l6-openshell-org-clone-live -e grep | grep -qF -- "$SENTINEL" && echo "sentinel absent from process arguments"
L6-06 | op | the provider is detached before the agent starts (GetSandboxProviderStatus through the org's admin view), and the provider instance exists in the member's workspace only between clone_requested and provider_deleted | the web2 OpenShell page's run detail; observer-org openshell boxes
L6-07 | not_built | no exec other than the clone is admitted while the provider is attached | the front logs no decide and the org audits only create and delete decisions (lane G3), so nothing in this build shows each admitted exec
L6-08 | op | a second private repository on the same git host is not readable from the box afterwards | git ls-remote <second repo> inside the box (as the agent)
L6-09 | op | the diff and the bundle still come back, as v1 does | the run's return dir on this node
L6-10 | op | a clone held open past clone_deadline_seconds (lower it to 60 s for this step) is detached and reaped by the worker (G1-R12) | Settings, clone_deadline_seconds = 60; a repository large enough or a stalled clone
EOF
)

echo "G-L6 on $(uname -n) for $REPO. Each op step asks for p, f or s and a note."
st_run "$STEPS"
R[completed]=1
[ "$FAIL" = 0 ] && exit 0
exit 1
