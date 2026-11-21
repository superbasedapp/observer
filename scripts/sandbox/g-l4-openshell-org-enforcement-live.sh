#!/usr/bin/env bash
# g-l4-openshell-org-enforcement-live.sh: live check G-L4 of the org-hosted
# OpenShell gateway: enforcement and tenancy (lane G5 writes it, lane G3
# owns the check; docs/plans/openshell/build/g1-design.md sections 3.6,
# 4.6, 7.2 to 7.8 and 11.6). Operator-attended.
#
# Machines: the sandbox VM running the bundle (deploy/observer-openshell),
# the org server with its front (deploy/observer-org production compose or
# the dev override), and two managed developer nodes of two members. Run
# it on the org host (the host the front container runs on, with docker),
# from a checkout of the build that carries lanes G2 to G4.
#
# Steps marked auto run here (the front container's environment NAMES and
# mounts, never values; the sandbox namespace's container count on the
# sandbox VM through --sandbox-docker, a DOCKER_HOST URL the operator
# already uses, and that the ORG host can reach: an ssh:// URL needs an ssh
# trust from the org host to the sandbox VM that the sandbox host bundle's
# topology does not set up, so either give the org host that trust or run
# L4-22a and L4-23 on the sandbox VM itself with --only and a local
# DOCKER_HOST (G-L4 phase 5 notes); every other step prints what to do and records the
# operator's judgment. A step whose verb is not built yet records not_run.
# --only ID[,ID...] runs a subset (a re-run of one step).
#
# It reads no key, token or config file: the front checks read container
# metadata names, and every refusal the design names (rpc_not_allowed,
# run_held, run_not_yours, return_withheld, return_not_taken,
# teardown_needs_collect, hold_unavailable, collect_failed_admin_only,
# drain_blocked, delete_unstoppable, quota_boxes) is read by the operator
# from the CLI or dashboard answer it names.
#
# Usage:
#   scripts/sandbox/g-l4-openshell-org-enforcement-live.sh --sandbox-label
#       LABEL [--front-container NAME] [--sandbox-docker URL] [--out DIR]
#       [--only IDS] [--yes] [--answers FILE] (op steps answered from FILE,
#       g-l-steps.sh)
#
# LABEL is the gateway's Docker sandbox namespace (observer-org-<gateway
# id>, the rendered gateway.toml's sandbox_label). Receipt:
#   g-l4-openshell-org-enforcement-<UTC stamp>.json
# shellcheck disable=SC2016
set -uo pipefail

# shellcheck source=scripts/sandbox/g-l-steps.sh
. "$(cd "$(dirname "$0")" && pwd)/g-l-steps.sh"
st_init G-L4 "observer-g-l4-live/1" g-l4-openshell-org-enforcement
trap 'st_finish $?' EXIT

LABEL=""
FRONT=""
SANDBOX_DOCKER=""
while [ $# -gt 0 ]; do
	if st_common_args "$1"; then
		shift
		continue
	fi
	case "$1" in
	--out) OUT="$2"; shift ;;
	--only) ONLY="$2"; shift ;;
	--answers) ANSWERS="$2"; shift ;;
	--sandbox-label) LABEL="$2"; shift ;;
	--front-container) FRONT="$2"; shift ;;
	--sandbox-docker) SANDBOX_DOCKER="$2"; shift ;;
	*) st_refuse "unknown argument $1" ;;
	esac
	shift
done
case "$LABEL" in observer-org-[a-z0-9-]*) ;; *) st_refuse "--sandbox-label must be the rendered sandbox_label (observer-org-<gateway id>)" ;; esac
[ -d "$OUT" ] && [ -w "$OUT" ] || OUT="$HOME"
command -v docker >/dev/null || st_refuse "docker is not on PATH (run on the org host)"
if [ -z "$FRONT" ]; then
	FRONT="$(docker ps -q --filter label=com.docker.compose.service=openshell-front | head -n1)"
fi
R[sandbox_label]="$LABEL"
R[front_container]="${FRONT:-none found}"
export LABEL FRONT SANDBOX_DOCKER

# count_all / count_running: step-body snippets that set n to the number
# of containers (all, or running) under the gateway's sandbox namespace ON
# THE SANDBOX VM. They need --sandbox-docker (the org host's own Docker
# would answer 0 and pass vacuously, audit G5-A12), and they capture
# docker's output and exit status apart, so a docker error fails the step
# with its message instead of counting as 0 (fix round 2, G5-R2).
count_snippet() {
	printf '%s' '[ -n "$SANDBOX_DOCKER" ] || { echo "needs --sandbox-docker (the sandbox VM'"'"'s DOCKER_HOST)"; exit 1; }; out=$(DOCKER_HOST="$SANDBOX_DOCKER" docker ps '"$1"' --filter "label=openshell.ai/sandbox-namespace=$LABEL" 2>&1); rc=$?; [ "$rc" = 0 ] || { echo "docker ps failed (exit $rc): $out"; exit 1; }; n=$(printf "%s\n" "$out" | grep -c .)'
}
count_all="$(count_snippet -aq)"
count_running="$(count_snippet -q)"
# count_org_running counts the running containers under the namespace that
# carry an org box name (openshellorg.BoxName: "obs" and 16 more), so
# L4-22a proves an org box existed before the drain: an unledgered
# container under the label (an admin's own) no longer passes it (G-L4
# phase 5 notes).
count_org_running='[ -n "$SANDBOX_DOCKER" ] || { echo "needs --sandbox-docker (the sandbox VM'"'"'s DOCKER_HOST)"; exit 1; }; out=$(DOCKER_HOST="$SANDBOX_DOCKER" docker ps --filter "label=openshell.ai/sandbox-namespace=$LABEL" --format "{{.Label \"openshell.ai/sandbox-name\"}}" 2>&1); rc=$?; [ "$rc" = 0 ] || { echo "docker ps failed (exit $rc): $out"; exit 1; }; n=$(printf "%s\n" "$out" | grep -cE "^obs[a-z2-7]{16}$")'
# The front's environment variable NAMES (never values): the org server's
# DSN names (OBSERVER_CONTROL_STORE_DSN, OBSERVER_DATA_STORE_DSN,
# OBSERVER_POSTGRES_URL) and any DSN, database URL, Postgres or issuer-key
# shaped name (audit G5-A12).
front_env_names='[ -n "$FRONT" ] || { echo "no openshell-front container"; exit 1; }; n=$(docker inspect --format "{{range .Config.Env}}{{println .}}{{end}}" "$FRONT" | cut -d= -f1 | grep -E "^OBSERVER_(CONTROL_STORE_DSN|DATA_STORE_DSN|POSTGRES_URL)$|DSN|DATABASE_URL|POSTGRES|PGPASSWORD|ISSUER_KEY" | tr "\n" " "); [ -z "$n" ] && echo "no DSN, database or issuer-key variable names" || { echo "found: $n"; exit 1; }'
# The front's mounts: no store, and no mount SOURCE (a file, or a
# directory such as a whole secrets dir) holding an issuer key. The front
# image is distroless, so the check reads the host side of each mount; run
# it as root so every source is readable (an unreadable one fails).
front_mounts='[ -n "$FRONT" ] || { echo "no openshell-front container"; exit 1; }; m=$(docker inspect --format "{{range .Mounts}}{{.Destination}} {{end}}" "$FRONT"); case "$m" in *.db\ *|*sqlite*) echo "a store is mounted: $m"; exit 1 ;; esac; for src in $(docker inspect --format "{{range .Mounts}}{{.Source}} {{end}}" "$FRONT"); do [ -r "$src" ] || { echo "cannot read mount source $src (run as root)"; exit 1; }; hit=$(find "$src" -maxdepth 3 -name "openshell-idp*" 2>/dev/null | head -n1); [ -z "$hit" ] || { echo "mount source $src holds an issuer key ($hit)"; exit 1; }; done; echo "mounts: $m; no issuer key under any mount source"'

STEPS=$(
	cat <<EOF
# Network and audience (design 2.4, 5.2)
L4-01 | op | from a host OUTSIDE the front CIDRs, a TCP connection to the gateway port is refused (the firewall rule of the bundle) | nc -vz -w 5 <gateway address> <gateway port>
L4-02 | op | a run token presented straight at the gateway is refused (audience openshell-front:<id>; G-L1 front_audience_refused is the same fact on a throwaway issuer) | the G-L1 receipt's front_audience_refused (no verb hands a run token out of the node in this build)
# The front's least authority (G1-R2, G1-R11)
L4-03 | auto | the front container holds no DSN or issuer-key variable (names only) | $front_env_names
L4-04 | auto | the front container mounts no issuer key and no store | $front_mounts
L4-05 | op | a front process started with a DSN variable, a readable SQLite path or a readable issuer key refuses to start; a healthy front never opened a store | observer-org serve --role openshell-front (with each mistake, one at a time)
L4-06 | op | an internal decide without a valid run token is refused; no internal call returns an admin token | observer-org doctor openshell, the internal decide route on internal_listen
L4-07 | op | with every front stopped, the detective check still reaps a box created with a drifted spec through a front-held member token | stop the openshell-front service; observer-org doctor openshell; observer-org openshell boxes
L4-08 | not_built | a member token issued to the front expires 60 s after issue; a second decide for the same run from the same replica inside 30 s returns no new token, a second replica gets its own (G1-R15) | the front keeps no log of member token issues (lane G3 built none); G-L1 measured the member token's 60 s life on its throwaway issuer
# Through the front (design 7.6)
L4-09 | not_built | a create with an altered image, policy or resources creates the RECORDED spec (spec_replaced shown) | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-10 | not_built | an F7 RPC (ExposeService, ForwardTcp, CreateSshSession, AttachSandboxProvider) and another member's box name are refused | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-11 | not_built | a second Start frame on one exec stream closes it (rpc_not_allowed) | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-12 | op | a revocation closes a live stream within 30 s, and ends a live box within two sync intervals | observer-org openshell revoke <member>, then watch the live run
L4-13 | op | an admin widening a live box's policy with the gateway's own tools is reaped as spec_drift (its recorded network policy restored, then collected, then deleted) | openshell policy set on the box; observer-org openshell boxes
L4-14 | op | a box created around the front is reaped | openshell sandbox create with an admin token on the VM; observer-org openshell boxes
L4-15 | op | quota refusals: max_concurrent_per_member, max_boxes_per_member (quota_boxes), daily minutes | launch past each quota
# Clone bracket (G1-R3)
L4-16 | op | while the repository provider is attached a non-TTY exec is refused; after the clone the provider is detached by the front (GetSandboxProviderStatus) | a clone-remote run; G-L6 carries the full clone row
# Held bounds and drain (design 3.6, 7.4)
L4-17 | op | a held box has no process and answers run_held through the front | observer sandbox org-shell hold <run>; any exec through the front
L4-18 | op | holds beyond max_held_per_member or max_boxes_per_member are refused | observer sandbox org-shell hold <run> past the quota
L4-19 | op | a held box past a lowered max_hold_hours is collected and deleted by the reaper | lower max_hold_hours in Settings; wait one sync interval
L4-20 | op | discard deletes at once | observer sandbox org-shell discard <run>
L4-21 | op | with return_to_node = false the node receives no diff or bundle and the collect lands in the org's object store, readable only with read:content and an audit row | flip return_to_node; end a run; read the collect as an admin
L4-22a | auto | before the drain, at least one running ORG box (an obs box name) is under the namespace label on the sandbox VM (else L4-23's zero would measure nothing; an unledgered container does not count) | $count_org_running; [ "\$n" -ge 1 ] && echo "\$n org boxes running under $LABEL" || { echo "no running org box under the namespace label (\$n)"; exit 1; }
L4-22 | op | drain with live and held boxes collects every unreturned run before deleting | observer-org openshell drain
L4-23 | auto | after the drain no container is left under the gateway's sandbox namespace | $count_all; [ "\$n" = 0 ] && echo "0 containers under $LABEL" || { echo "\$n containers left under $LABEL"; exit 1; }
L4-24 | op | a restart with the feature off and the drain not finished drains once | stop the org server mid-drain; set [openshell].enabled = false; start it
L4-25 | op | the JWKS-404 window for the sync token (the issuer off while the sync runs) | disable the feature on one api replica only; watch the sync
L4-26 | op | a laptop-offline hold followed by a resume from the second member's node is refused (run_not_yours) | observer sandbox org-shell resume <run> on member B's node
# Failed collect and fetch (round 6)
L4-27 | op | a held box whose workspace git config sets an fsmonitor command, and one whose bundle exceeds the size cap, each end in collect_failed with its reason | git config core.fsmonitor in the box before the hold
L4-28 | op | those boxes stay counted against the quota, survive expiry and a plain drain (drain_blocked), refuse a member discard (collect_failed_admin_only), and are deleted only by an admin discard without collect (audited), drain --force, or the reaper's delete_unstoppable | observer-org openshell drain; drain --force; the admin discard
L4-29 | op | with return_to_node = true a member fetches their own collect from their other managed node (audited, returned_at set); another member's fetch is refused; with false the fetch is refused | observer sandbox org-shell fetch <run>
L4-30 | op | after a cross-node resume the first node's run token is refused (active_run_id) | resume on node 2, then any call from node 1
# Server-side return rules (round 7) and teardown (round 8)
L4-31 | not_built | under return_to_node = false a node that mints return is refused (return_withheld), a teardown of the unreturned box is refused (teardown_needs_collect), and a guest --diff or --bundle exec through the front is refused | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-32 | not_built | a DeleteSandbox through the front with an attach or create token is refused (rpc_not_allowed) | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-33 | not_built | a teardown token from the first node used after a cross-node resume is refused (run_not_yours); a teardown token used after the box was held is refused (run_held) | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-34 | op | a logout under return_to_node = false holds the live box (or collects it, then deletes it, with holding off) and leaves the held boxes held, never deleting uncollected (G1-R40) | observer sandbox org-shell logout
L4-35 | op | an admin revoke of a member with an unreturned held box collects it, then deletes it | observer-org openshell revoke <member>
L4-36 | op | an ended report with hold = true over the held quota gets hold_unavailable and the box is collected, then deleted | end a run with hold_on_end on, over the quota
L4-37 | not_built | an ended report forging returned = true under false, or under true without a return token, is refused (return_withheld, return_not_taken) and the box is still collected before any delete | no verb hands a run token or a tampered request out of the node in this build (a node debug client is not built); record it from code review or a later lane
L4-38 | op | a default run's normal end (return, teardown, then ended) completes without run_unknown | one ordinary run
L4-39 | not_built | a collect_failed box whose re-stop the gateway does not confirm (simulated) is deleted after three reaper passes with a delete_unstoppable audit row and a doctor ERROR | the worker has no simulation switch for an unconfirmed re-stop (lane G3 built none); its unit tests cover the delete_unstoppable path
L4-40 | op | a fetch from a revoked grant is refused, and a collect made under false stays unfetchable after the org flips to true | revoke the grant; fetch; flip return_to_node
EOF
)

echo "G-L4 on $(uname -n): sandbox namespace $LABEL, front container ${FRONT:-none found}."
echo "Each op step asks for p, f or s and a note; --only re-runs chosen steps."
st_run "$STEPS"
R[completed]=1
[ "$FAIL" = 0 ] && exit 0
exit 1
