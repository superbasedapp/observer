#!/usr/bin/env bash
# g-l1-openshell-org-idp-live.sh: live check G-L1 of the org-hosted
# OpenShell gateway (lane G5; docs/plans/openshell/build/g1-design.md
# sections 5.2, 7.1, 7.2 and 11.6). G-L1 and G-L2 gate wave 2: lanes G3
# and G4 start after their receipts, or after the orchestrator records
# which written fallback applies (design 11.1 "Gate").
#
# Machine: the throwaway OVHcloud Public Cloud instance (x86_64, Ubuntu
# 24.04) with Docker (the user in the docker group), OpenShell 0.1.6
# installed (openshell-gateway on PATH; its own package gateway may keep
# running, this run never touches it), python3, openssl, and Go 1.25.13 or
# later to build the probe (or --probe PATH to a probe built elsewhere).
# Setup note from the live run (fix round 3): on a fresh host, after the
# user is added to the docker group, run `sudo systemctl restart user@1000`
# (the user's uid) before the package gateway's user service runs, or that
# service does not see the new group.
#
# It starts a throwaway issuer and one gateway process with the bundle's
# own gateway.toml on 127.0.0.1 (scripts/sandbox/g-l-lib.sh says exactly
# what), then measures, as G-L1's row asks:
#   - which signing algorithm the gateway accepts from a non-IdP issuer
#     (EdDSA, else ES256, else RS256), and the discovery shape it needs;
#   - the roles claim ("roles") and scope enforcement ("scope");
#   - workspace membership keyed on the token's sub: member A cannot list,
#     read or exec in member B's workspace;
#   - a workspace-user token cannot UpdateConfig (its own box's policy, or
#     a global setting) or approve drafts on a live box;
#   - an admin create carrying a driver_config bind of /etc is not applied
#     (driver_config_not_applied: refused, or accepted with the gateway's
#     openshell.ai/caller-driver-config-used=false label on its sandbox-role
#     container (helper-role containers carry none), no such bind in
#     docker inspect and the bind target absent in the box);
#   - GetGatewayInfo is admin-only; which soundness facts the admin API
#     reports (fact.api.*) and which only the rendered config shows
#     (fact.deploy_class);
#   - with the bundle's config a request carrying only the edge-style JWT
#     headers is refused, and a token with the front's audience
#     (openshell-front:<id>) is refused;
#   - how long a token is accepted after the JWKS answers 404, drops the
#     key, or serves no key (measured with jwks_ttl_secs = --jwks-ttl,
#     default 20, so the run takes minutes; the receipt records the TTL so
#     the windows scale to the bundle's 300), whether the gateway starts
#     while the issuer answers 404, and the expiry leeway.
#
# Each check is judged pass, fail or not_run in the receipt; the facts the
# orchestrator chooses a fallback from are under verdict.*:
#   verdict.alg         EdDSA | ES256 | RS256 | none
#   verdict.discovery   minimal | extended | failed
#   verdict.membership  sub | none (the front is then the only tenancy layer)
#
# It is operator-attended: it prints what it will create and asks first
# (--yes skips the question). It reads no key, token or config file of the
# operator's and writes one receipt with no secret in it:
#   g-l1-openshell-org-idp-<UTC stamp>.json
#
# Usage:
#   scripts/sandbox/g-l1-openshell-org-idp-live.sh [--yes] [--out DIR]
#       [--probe PATH] [--box-image REPO@sha256:...] [--jwks-ttl SECONDS]
#       [--keep-work]
#
# Exit 0 when every check passed, 1 when one failed, 2 on a precondition
# the host does not meet (the receipt says which).
# shellcheck disable=SC2015,SC2016,SC2317
set -uo pipefail

# shellcheck source=scripts/sandbox/g-l-lib.sh
. "$(cd "$(dirname "$0")" && pwd)/g-l-lib.sh"
gl_init G-L1 "observer-g-l1-live/1" g-l1-openshell-org-idp
trap 'gl_cleanup $?' EXIT

while [ $# -gt 0 ]; do
	if gl_common_args "$1"; then
		shift
		continue
	fi
	case "$1" in
	--out) OUT="$2"; shift ;;
	--probe) PROBE="$2"; shift ;;
	--box-image) BOX_IMAGE="$2"; shift ;;
	--jwks-ttl) JWKS_TTL="$2"; shift ;;
	*) refuse "unknown argument $1" ;;
	esac
	shift
done
case "$JWKS_TTL" in '' | *[!0-9]*) refuse "--jwks-ttl must be a number" ;; esac
[ "$JWKS_TTL" -ge 15 ] && [ "$JWKS_TTL" -le 300 ] || refuse "--jwks-ttl must be 15 to 300"

gl_preconditions
cat <<EOF
G-L1 will, on this host, as $(id -un):
  - make a work dir under $HOME (throwaway keys, tokens, PKI, a sqlite db);
  - run a throwaway issuer and one openshell-gateway on 127.0.0.1 only;
  - pull ${BOX_IMAGE:-$GL_DEFAULT_BOX_TAG} and the OpenShell 0.1.6 supervisor
    and sandbox images by digest if absent;
  - create two OpenShell workspaces and two boxes, then delete them;
  - remove every container under its own sandbox namespace label on exit.
It takes about 10 minutes (the JWKS windows run with jwks_ttl_secs = $JWKS_TTL).
EOF
confirm "Proceed with G-L1?"

gl_make_work g-l1
gl_build_probe
gl_box_image
gl_start_issuer
gl_render_config
gl_prepare_gateway
gl_start_gateway

AUD="openshell:$GW_ID"
WS_A="obs-$(rand_hex 6)"
WS_B="obs-$(rand_hex 6)"
BOX_A="gla$(rand_hex 4)"
BOX_B="glb$(rand_hex 4)"
SUB_A="member:g-live-a-$(rand_hex 3)"
SUB_B="member:g-live-b-$(rand_hex 3)"
USER_SCOPE="sandbox:read sandbox:write"

# 1. Algorithms (audit G5-A3). An admin token per algorithm; whoami is
# authentication only. An algorithm counts as accepted only when the
# gateway answers its token AND refuses the same token with one signature
# byte flipped; and a token signed by ed-2, a key the JWKS does not
# publish, must be refused. Without that the gateway could be skipping
# signature checks and every verdict below would be void. The subject the
# gateway reports is judged on its own (subject_is_sub, fix round 2,
# G5-R3): a rewritten subject fails that one check and the run goes on.
ADMIN_SUB=svc:g-live-admin
probe_algs() {
	first_alg=none
	local pair kid alg out c cf
	for pair in ed-1:EdDSA es-1:ES256 rs-1:RS256; do
		kid="${pair%%:*}"
		alg="${pair#*:}"
		mint "admin-$kid" "$kid" "$ADMIN_SUB" "$AUD" '["openshell-admin"]' "openshell:all"
		python3 -I "$GL_ISSUER" tamper "$WORK/tok/admin-$kid" "$WORK/tok/forged-$kid" || refuse "tamper failed"
		out="$(p "admin-$kid" call -rpc whoami)"
		c="$(printf '%s' "$out" | jget code)"
		cf="$(code "forged-$kid" call -rpc whoami)"
		if [ "$c" = OK ] && denied "$cf"; then
			fact "alg.$alg" "accepted (flipped-signature twin $cf)"
			if [ "$first_alg" = none ]; then
				first_alg="$alg"
				ADMIN="admin-$kid"
			fi
		elif [ "$c" = OK ]; then
			fact "alg.$alg" "unverified: OK, but the flipped-signature twin answered $cf"
			forged_bad=1
		else
			fact "alg.$alg" "refused:$c $(printf '%s' "$out" | jget message)"
		fi
	done
}
forged_bad=0
GL_JWKS_BASE=normal
probe_algs
if [ "$first_alg" = none ] && [ "$forged_bad" = 0 ]; then
	# Audit G5-A17: a gateway that rejects the whole mixed JWKS for one key
	# type would read "none"; retry each type alone before concluding.
	for pair in ed:EdDSA es:ES256 rs:RS256; do
		issuer_state "${R[fact.discovery_shape]}" "only-${pair%%:*}"
		sleep 2
		mint "single-${pair%%:*}" "${pair%%:*}-1" "$ADMIN_SUB" "$AUD" '["openshell-admin"]' "openshell:all"
		fact "alg_single.${pair#*:}" "$(code "single-${pair%%:*}" call -rpc whoami)"
		if [ "${R[fact.alg_single.${pair#*:}]}" = OK ] && [ "$first_alg" = none ]; then
			GL_JWKS_BASE="only-${pair%%:*}"
			probe_algs
			R[verdict.alg_note]="accepted only with a single-type JWKS ($GL_JWKS_BASE); the mixed set was refused"
			break
		fi
	done
	issuer_state "${R[fact.discovery_shape]}" "$GL_JWKS_BASE"
fi
mint unpublished ed-2 "$ADMIN_SUB" "$AUD" '["openshell-admin"]' "openshell:all"
c_unpub="$(code unpublished call -rpc whoami)"
fact forged "unpublished key (ed-2): $c_unpub"
if [ "$first_alg" != none ] && [ "$forged_bad" = 0 ] && denied "$c_unpub"; then
	judge forged_refused pass "an unpublished key's token ($c_unpub) and every accepted algorithm's flipped-signature twin are refused"
else
	judge forged_refused fail "unpublished key $c_unpub; see fact.alg.* (an OK with a forged twin accepted, or no algorithm accepted)"
	R[verdict.alg]="$([ "$first_alg" = none ] && echo none || echo unverified)"
	judge alg_accepted fail "no algorithm passes with its forged twins refused"
	refuse "the gateway's token checks could not be verified (nothing after this is meaningful)"
fi
R[verdict.alg]="$first_alg"
judge alg_accepted pass "first accepted: $first_alg (EdDSA ${R[fact.alg.EdDSA]%% *}, ES256 ${R[fact.alg.ES256]%% *}, RS256 ${R[fact.alg.RS256]%% *})"
ADMIN_KID="${ADMIN#admin-}"
out="$(p "$ADMIN" call -rpc whoami)"
ADMIN_SUBJECT="$(printf '%s' "$out" | jget subject)"
fact whoami.admin "subject=$ADMIN_SUBJECT roles=$(printf '%s' "$out" | jget roles) scopes=$(printf '%s' "$out" | jget scopes) provider=$(printf '%s' "$out" | jget identity_provider)"

# 2. Members A and B: their subjects as the gateway reports them.
mint user-a "$ADMIN_KID" "$SUB_A" "$AUD" '["openshell-user"]' "$USER_SCOPE"
mint user-b "$ADMIN_KID" "$SUB_B" "$AUD" '["openshell-user"]' "$USER_SCOPE"
out="$(p user-a call -rpc whoami)"
PRINCIPAL_A="$(printf '%s' "$out" | jget subject)"
REPORTED_A="$PRINCIPAL_A"
fact whoami.member "subject=$PRINCIPAL_A roles=$(printf '%s' "$out" | jget roles) scopes=$(printf '%s' "$out" | jget scopes)"
PRINCIPAL_B="$(p user-b call -rpc whoami | jget subject)"
[ -n "$PRINCIPAL_A" ] || PRINCIPAL_A="$SUB_A"
[ -n "$PRINCIPAL_B" ] || PRINCIPAL_B="$SUB_B"
# Fix round 2 (G5-R3): the subject check stands alone. The admin and the
# member token must each come back as the sub they were minted with; a
# rewritten subject fails only this check (membership below then keys on
# the subject the gateway reports, which the sync would have to use).
if [ "$ADMIN_SUBJECT" = "$ADMIN_SUB" ] && [ "$REPORTED_A" = "$SUB_A" ]; then
	fact subject_is_sub true
	judge subject_is_sub pass "the gateway reports each token's own sub ($ADMIN_SUB, $SUB_A)"
else
	fact subject_is_sub false
	fact subject_reported "admin sub $ADMIN_SUB -> ${ADMIN_SUBJECT:-(empty)}; member sub $SUB_A -> ${REPORTED_A:-(empty)}"
	judge subject_is_sub fail "the gateway rewrites the subject (${R[fact.subject_reported]})"
fi

ws_ok=1
for pair in "$WS_A:$PRINCIPAL_A" "$WS_B:$PRINCIPAL_B"; do
	ws="${pair%%:*}"
	who="${pair#*:}"
	c="$(code "$ADMIN" call -rpc create-workspace -name "$ws")"
	[ "$c" = OK ] && MADE_WORKSPACES+=("$ws") || ws_ok=0
	c2="$(code "$ADMIN" call -rpc add-member -workspace "$ws" -member "$who")"
	[ "$c2" = OK ] || ws_ok=0
	fact "workspace.$ws" "create=$c add_member=$c2"
done
[ "$ws_ok" = 1 ] && judge workspaces_made pass "two workspaces, one Workspace User each, keyed on the reported subject" ||
	judge workspaces_made fail "see fact.workspace.*"

# 3. Each member creates a box in their own workspace.
boxes_ok=1
for trip in "user-a:$WS_A:$BOX_A" "user-b:$WS_B:$BOX_B"; do
	IFS=: read -r who ws box <<<"$trip"
	out="$(PROBE_TIMEOUT=120s p "$who" call -rpc create -workspace "$ws" -name "$box" -image "$BOX_IMAGE" -run-label "$GW_ID" -command '["sleep","infinity"]')"
	c="$(printf '%s' "$out" | jget code)"
	if [ "$c" = OK ]; then
		MADE_BOXES+=("$ws/$box")
		w="$(PROBE_TIMEOUT=660s p "$who" wait -workspace "$ws" -name "$box" -phase READY -for 600s)"
		[ "$(printf '%s' "$w" | jget reached)" = true ] || boxes_ok=0
		fact "box.$box" "create=OK ready=$(printf '%s' "$w" | jget reached) after $(printf '%s' "$w" | jget elapsed_s)s phase=$(printf '%s' "$w" | jget phase) $(printf '%s' "$w" | jget condition)"
	else
		boxes_ok=0
		fact "box.$box" "create=$c $(printf '%s' "$out" | jget message)"
	fi
done
[ "$boxes_ok" = 1 ] && judge member_boxes pass "each member created a box in their own workspace" ||
	judge member_boxes fail "see fact.box.*"
# Audit G5-A2: the namespace label every container check and the cleanup
# filter on was never seen live; it must select this run's running boxes.
ns_running="$(running_in containers_in_namespace)"
run_running="$(running_in containers_by_run)"
fact container_labels "running under openshell.ai/sandbox-namespace=$GW_NAME: $ns_running; under observer.superbased.glive=$GW_ID: $run_running"
if [ "$boxes_ok" = 1 ] && [ "$ns_running" -ge 1 ]; then
	judge namespace_label pass "$ns_running running container(s) under the namespace label"
else
	judge namespace_label fail "the namespace label selects $ns_running running container(s) (run label: $run_running); the label key or value is wrong or no box runs"
fi

# 4. Membership keyed on sub: A against B's workspace and box.
c_list_own="$(code user-a call -rpc list -workspace "$WS_A")"
own="$(p user-a exec -workspace "$WS_A" -name "$BOX_A" -cmd 'echo reached')"
exec_own_ok=0
[ "$(printf '%s' "$own" | jget code)" = OK ] && [ "$(printf '%s' "$own" | jget exit)" = 0 ] &&
	[ "$(printf '%s' "$own" | jget stdout | tr -d '\n')" = reached ] && exec_own_ok=1
fact exec_own "code=$(printf '%s' "$own" | jget code) exit=$(printf '%s' "$own" | jget exit)"
[ "$exec_own_ok" = 1 ] && judge exec_own pass "member A execs in their own box (the positive control)" ||
	judge exec_own fail "member A cannot exec in their own box: every refusal below would be vacuous (${R[fact.exec_own]})"
c_list_b="$(code user-a call -rpc list -workspace "$WS_B")"
c_get_b="$(code user-a call -rpc get -workspace "$WS_B" -name "$BOX_B")"
out="$(p user-a exec -workspace "$WS_B" -name "$BOX_B" -cmd 'echo reached')"
c_exec_b="$(printf '%s' "$out" | jget code)"
all_out="$(p user-a call -rpc list-all)"
fact membership "list_own=$c_list_own list_b=$c_list_b get_b=$c_get_b exec_b=$c_exec_b list_all=$(printf '%s' "$all_out" | jget code) $(printf '%s' "$all_out" | jget sandboxes)"
if [ "$ws_ok" != 1 ] || [ "$boxes_ok" != 1 ] || [ "$exec_own_ok" != 1 ]; then
	# Audit G5-A4: without both workspaces, both boxes and the positive
	# control, a refusal of B's box measures nothing.
	R[verdict.membership]=unmeasured
	judge membership_by_sub fail "not measured: workspaces_made=$ws_ok member_boxes=$boxes_ok exec_own=$exec_own_ok"
elif [ "$c_list_own" = OK ] && tenant_refused "$c_list_b" && tenant_refused "$c_get_b" && tenant_refused "$c_exec_b"; then
	R[verdict.membership]=sub
	judge membership_by_sub pass "A lists its own workspace; B's list, get and exec are refused"
else
	R[verdict.membership]=none
	judge membership_by_sub fail "see fact.membership"
fi
case "$(printf '%s' "$all_out" | jget sandboxes)" in *"$WS_B/"*) judge list_all_scoped fail "A's all-workspaces list shows B's box" ;; *) judge list_all_scoped pass "A's all-workspaces list shows no box of B ($(printf '%s' "$all_out" | jget code))" ;; esac

# 5. The roles claim path and scope enforcement.
mint a-wrongpath "$ADMIN_KID" "$SUB_A" "$AUD" '["openshell-user"]' "$USER_SCOPE" realm_access.roles
mint a-noroles "$ADMIN_KID" "$SUB_A" "$AUD" - "$USER_SCOPE"
c_wp="$(code a-wrongpath call -rpc list -workspace "$WS_A")"
c_nr="$(code a-noroles call -rpc list -workspace "$WS_A")"
fact roles_claim "roles=$c_list_own realm_access.roles=$c_wp none=$c_nr"
[ "$c_list_own" = OK ] && denied "$c_wp" && denied "$c_nr" &&
	judge roles_claim pass "only the configured roles claim grants access" ||
	judge roles_claim fail "see fact.roles_claim"
mint a-readonly "$ADMIN_KID" "$SUB_A" "$AUD" '["openshell-user"]' "sandbox:read"
mint a-noscope "$ADMIN_KID" "$SUB_A" "$AUD" '["openshell-user"]' -
c_ro_list="$(code a-readonly call -rpc list -workspace "$WS_A")"
c_ro_create="$(code a-readonly call -rpc create -workspace "$WS_A" -name "glr$(rand_hex 4)" -image "$BOX_IMAGE" -run-label "$GW_ID" -command '["sleep","infinity"]')"
c_ns_list="$(code a-noscope call -rpc list -workspace "$WS_A")"
fact scopes "read_only.list=$c_ro_list read_only.create=$c_ro_create no_scope.list=$c_ns_list"
[ "$c_ro_list" = OK ] && denied "$c_ro_create" && denied "$c_ns_list" &&
	judge scope_enforced pass "sandbox:read lists but cannot create; no scope claim is refused" ||
	judge scope_enforced fail "see fact.scopes"

# 6. A workspace user cannot widen a live box or change gateway config.
c_up="$(code user-a call -rpc update-policy -workspace "$WS_A" -name "$BOX_A")"
c_set="$(code user-a call -rpc update-setting)"
c_apr="$(code user-a call -rpc approve-drafts -workspace "$WS_A" -name "$BOX_A")"
fact user_config "update_policy=$c_up update_setting=$c_set approve_drafts=$c_apr"
denied "$c_up" && denied "$c_set" && judge user_no_update_config pass "own box policy and a global setting both refused" ||
	judge user_no_update_config fail "see fact.user_config"
denied "$c_apr" && judge user_no_approve_drafts pass "refused ($c_apr)" || judge user_no_approve_drafts fail "answered $c_apr"

# 7. GetGatewayInfo is admin-only; what the admin API reports.
c_info_user="$(code user-a call -rpc gatewayinfo)"
info="$(p "$ADMIN" call -rpc gatewayinfo)"
c_info_admin="$(printf '%s' "$info" | jget code)"
denied "$c_info_user" && [ "$c_info_admin" = OK ] &&
	judge gatewayinfo_admin_only pass "member $c_info_user, admin OK" ||
	judge gatewayinfo_admin_only fail "member $c_info_user, admin $c_info_admin"
fact api.gateway_version "$(printf '%s' "$info" | jget gateway_version)"
fact api.compute_drivers "$(printf '%s' "$info" | jget compute_drivers)"
fact api.extensions "$(printf '%s' "$info" | jget extensions)"
cfg="$(p "$ADMIN" call -rpc gatewayconfig)"
fact api.gateway_settings "$(printf '%s' "$cfg" | jget code) $(printf '%s' "$cfg" | jget settings)"
gp="$(p "$ADMIN" call -rpc global-policies)"
fact api.global_policy_revisions "$(printf '%s' "$gp" | jget code) $(printf '%s' "$gp" | jget revisions)"
# driver_config_not_applied (fix round 3; was driver_config_refused). The
# live run on 0.1.6 found the gateway ACCEPTS an admin create carrying a
# driver_config and IGNORES it: the box's containers carry
# openshell.ai/caller-driver-config-used=false, docker inspect shows no
# bind, and the bind target is absent in the box. So the check passes on
# either path, and records which one:
#   refused   a denial code (PermissionDenied, FailedPrecondition) or a
#             message naming the disabled setting (fix round 2, G5-R1: a
#             parser error over a misshapen binds document proves nothing);
#   ignored   OK, and all three of: at least one container of the box
#             under the namespace label with openshell.ai/isolation-role
#             =sandbox carries the label =false, no container carries =true
#             or lacks the label other than a helper-role one (supervisor,
#             staging, identity: 0.1.6 never labels those; fix round 4),
#             none has a bind or mount of /etc or onto /host-etc, and
#             /host-etc is absent in the box (an admin exec).
# Anything else fails. fact.driver_config_refused is kept as an alias.
DC_BOX="gld$(rand_hex 4)"
dc="$(p "$ADMIN" call -rpc create -workspace "$WS_A" -name "$DC_BOX" -image "$BOX_IMAGE" -run-label "$GW_ID" -command '["sleep","infinity"]' -driver-config '{"binds":[{"source":"/etc","target":"/host-etc"}]}')"
c_dc="$(printf '%s' "$dc" | jget code)"
msg_dc="$(printf '%s' "$dc" | jget message)"
fact driver_config.code "$c_dc"
fact driver_config.message "$msg_dc"
m_dc="$(printf '%s' "$msg_dc" | tr '[:upper:]' '[:lower:]')"
dc_named=0
case "$m_dc" in *allow_driver_config* | *"not allowed"* | *disabled*) dc_named=1 ;; esac
dc_path=""
if [ "$c_dc" = OK ]; then
	MADE_BOXES+=("$WS_A/$DC_BOX")
	dcw="$(PROBE_TIMEOUT=360s p "$ADMIN" wait -workspace "$WS_A" -name "$DC_BOX" -phase READY -for 300s)"
	fact driver_config.ready "reached=$(jget reached <<<"$dcw") after $(jget elapsed_s <<<"$dcw")s"
	dc_n=0 dc_false=0 dc_label_ok=1 dc_bind_ok=1 dc_labels="" dc_binds="" dc_sel="sandbox-name=$DC_BOX"
	dc_cids="$(docker ps -aq --filter "label=openshell.ai/sandbox-namespace=$GW_NAME" --filter "label=openshell.ai/sandbox-name=$DC_BOX" 2>/dev/null)"
	dc_id="$(printf '%s' "$dc" | jget id)"
	if [ -z "$dc_cids" ] && [ -n "$dc_id" ]; then
		dc_sel="sandbox-id=$dc_id"
		dc_cids="$(docker ps -aq --filter "label=openshell.ai/sandbox-namespace=$GW_NAME" --filter "label=openshell.ai/sandbox-id=$dc_id" 2>/dev/null)"
	fi
	for cid in $dc_cids; do
		dc_n=$((dc_n + 1))
		used="$(docker inspect -f '{{index .Config.Labels "openshell.ai/caller-driver-config-used"}}' "$cid" 2>/dev/null)"
		binds="$(docker inspect -f '{{json .HostConfig.Binds}}' "$cid" 2>/dev/null)"
		mounts="$(docker inspect -f '{{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' "$cid" 2>/dev/null)"
		role="$(docker inspect -f '{{index .Config.Labels "openshell.ai/isolation-role"}}' "$cid" 2>/dev/null)"
		dc_labels+="$cid(role=${role:-absent})=${used:-absent} "
		dc_binds+="$cid binds=$binds mounts=[${mounts% }] "
		# Fix round 4: 0.1.6 labels only the sandbox-role container
		# (openshell.ai/isolation-role=sandbox); a helper-role container
		# (supervisor, staging, identity) never carries the label and is
		# skipped when it has none. Any =true fails; a sandbox-role (or
		# unlabelled-role) container must carry =false.
		case "$used:$role" in
		true:*) dc_label_ok=0 ;;
		false:sandbox) dc_false=$((dc_false + 1)) ;;
		false:*) ;;
		:supervisor | :staging | :identity) ;;
		*) dc_label_ok=0 ;;
		esac
		case "$binds $mounts" in *host-etc* | *'"/etc:'* | *' /etc:'* | '/etc:'*) dc_bind_ok=0 ;; esac
	done
	# At least one sandbox-role container must carry =false.
	[ "$dc_false" -ge 1 ] || dc_label_ok=0
	fact driver_config.containers "$dc_n (namespace label and $dc_sel), $dc_false sandbox-role labelled =false"
	fact driver_config.label "${dc_labels% }"
	fact driver_config.binds "${dc_binds% }"
	dc_in="$(PROBE_TIMEOUT=90s p "$ADMIN" exec -workspace "$WS_A" -name "$DC_BOX" -cmd 'if [ -e /host-etc ]; then echo present; else echo absent; fi')"
	dc_target="$(printf '%s' "$dc_in" | jget stdout | tr -d '\n')"
	fact driver_config.target_in_box "code=$(printf '%s' "$dc_in" | jget code) /host-etc ${dc_target:-unknown}"
	if [ "$dc_label_ok" = 1 ] && [ "$dc_bind_ok" = 1 ] && [ "$dc_target" = absent ]; then
		dc_path=ignored
		judge driver_config_not_applied pass "accepted (OK) and ignored: caller-driver-config-used=false on $dc_false sandbox-role container(s) of $dc_n, no /etc bind in docker inspect, /host-etc absent in the box"
	else
		dc_path="accepted, applied or unproven"
		judge driver_config_not_applied fail "accepted (OK) and not proven ignored: label_ok=$dc_label_ok bind_ok=$dc_bind_ok target_in_box=${dc_target:-unknown} containers=$dc_n sandbox_role_false=$dc_false (fact.driver_config.*)"
	fi
	fact driver_config.delete "$(PROBE_TIMEOUT=60s code "$ADMIN" call -rpc delete -workspace "$WS_A" -name "$DC_BOX")"
elif [ "$c_dc" = PermissionDenied ] || [ "$c_dc" = FailedPrecondition ] || [ "$dc_named" = 1 ]; then
	dc_path=refused
	judge driver_config_not_applied pass "refused: an admin create with a driver_config bind answered $c_dc: $msg_dc"
else
	dc_path="unproven"
	judge driver_config_not_applied fail "answered $c_dc without a denial code or a message naming the disabled setting ($msg_dc); not proof the setting is off"
fi
fact driver_config.path "$dc_path"
fact driver_config_refused "alias of check.driver_config_not_applied (renamed in fix round 3): ${R[check.driver_config_not_applied]} via $dc_path"
fact deploy_class "not reported by the admin API and not measured here: the OIDC block, the roles and scope claims, mtls_auth, allow_unauthenticated_users, the websocket tunnel, loopback service http, enable_bind_mounts (except driver_config_not_applied above), the telemetry environment and the image digests; the rendered config (sha256 ${R[gateway_toml_sha256]}) and the bundle's preflight.sh carry them. The firewall rule is G-L4's (L4-01)"
measured soundness_facts "the admin API's answers are under fact.api.*, the rest under fact.deploy_class"

# 8. Edge headers only, and the front's audience.
out="$(pe "$ADMIN" call -rpc whoami)"
c_edge="$(printf '%s' "$out" | jget code)"
denied "$c_edge" && judge edge_jwt_refused pass "a valid admin token sent only as cf-access-jwt-assertion and CF_Authorization answered $c_edge" ||
	judge edge_jwt_refused fail "answered $c_edge"
mint front-aud "$ADMIN_KID" "$SUB_A" "openshell-front:$GW_ID" '["openshell-user"]' "$USER_SCOPE"
c_front="$(code front-aud call -rpc list -workspace "$WS_A")"
denied "$c_front" && judge front_audience_refused pass "a run-token-shaped audience answered $c_front" ||
	judge front_audience_refused fail "answered $c_front"

# 9. Expiry leeway.
mint exp30 "$ADMIN_KID" "$SUB_A" "$AUD" '["openshell-user"]' "$USER_SCOPE" roles -3630
mint exp90 "$ADMIN_KID" "$SUB_A" "$AUD" '["openshell-user"]' "$USER_SCOPE" roles -3690
c30="$(code exp30 call -rpc list -workspace "$WS_A")"
c90="$(code exp90 call -rpc list -workspace "$WS_A")"
fact exp_leeway "expired 30s ago: $c30; expired 90s ago: $c90"
denied "$c90" && judge expired_refused pass "a token expired 90 s ago is refused (30 s ago: $c30)" ||
	judge expired_refused fail "a token expired 90 s ago answered $c90"

# 10. The JWKS windows. accepted_for TOKEN SECONDS: how long whoami keeps
# answering OK, polling every 5 s ("whole" when it never stopped).
accepted_for() {
	local start=$SECONDS c
	while [ $((SECONDS - start)) -lt "$2" ]; do
		c="$(PROBE_TIMEOUT=10s code "$1" call -rpc whoami)"
		[ "$c" = OK ] || {
			echo "refused_after_$((SECONDS - start))s:$c"
			return 0
		}
		sleep 5
	done
	echo "whole_window_$2s"
}
W=$((3 * JWKS_TTL + 30))
case "${R[fact.alg.EdDSA]}" in accepted*) eddsa_ok=1 ;; *) eddsa_ok=0 ;; esac
if [ "$eddsa_ok" != 1 ] || [ "$GL_JWKS_BASE" != normal ]; then
	for w in jwks_404_window jwks_drop_window jwks_empty_window; do
		not_run "$w" "the windows rotate the two Ed25519 keys inside the mixed JWKS: EdDSA ${R[fact.alg.EdDSA]%% *}, JWKS base $GL_JWKS_BASE"
	done
	R[completed]=1
	[ "$FAIL" = 0 ] && exit 0
	exit 1
fi
mint jw-ed1 ed-1 svc:g-live-jwks "$AUD" '["openshell-admin"]' "openshell:all"
mint jw-ed2 ed-2 svc:g-live-jwks "$AUD" '["openshell-admin"]' "openshell:all"
c="$(code jw-ed1 call -rpc whoami)"
[ "$c" = OK ] || fact jwks.note "the ed-1 token was not accepted before the windows ($c); the windows read the cached key of whatever algorithm the gateway took"

issuer_state "${R[fact.discovery_shape]}" 404
fact jwks.404.cached_key "$(accepted_for jw-ed1 "$W")"
fact jwks.404.uncached_kid "$(code jw-ed2 call -rpc whoami)"
gw_stop
gw_start
if gw_wait_healthy 45; then fact gateway_start_with_issuer_404 started; else fact gateway_start_with_issuer_404 "failed: $(tail -n 2 "$LOG/gateway.log" | tr '\n' ' ' | head -c 300)"; fi
gw_stop
issuer_state "${R[fact.discovery_shape]}" normal
gw_start
gw_wait_healthy 60 || refuse "the gateway did not come back after the 404 window"
measured jwks_404_window "${R[fact.jwks.404.cached_key]}; uncached kid ${R[fact.jwks.404.uncached_kid]}; restart ${R[fact.gateway_start_with_issuer_404]}"

c="$(code jw-ed1 call -rpc whoami)"
issuer_state "${R[fact.discovery_shape]}" drop
fact jwks.drop.removed_key "$(accepted_for jw-ed1 "$W")"
fact jwks.drop.new_key "$(code jw-ed2 call -rpc whoami)"
measured jwks_drop_window "removed key ${R[fact.jwks.drop.removed_key]}; new key ${R[fact.jwks.drop.new_key]} (ed-1 accepted before: $c)"

issuer_state "${R[fact.discovery_shape]}" normal
sleep $((JWKS_TTL + 5))
c="$(code jw-ed1 call -rpc whoami)"
issuer_state "${R[fact.discovery_shape]}" empty
fact jwks.empty.cached_key "$(accepted_for jw-ed1 $((4 * JWKS_TTL + 60)))"
measured jwks_empty_window "${R[fact.jwks.empty.cached_key]} (ed-1 accepted before: $c)"
issuer_state "${R[fact.discovery_shape]}" normal
R[issuer_jwks_fetches]="$(grep -c 'jwks.json' "$LOG/issuer-requests.log" 2>/dev/null)"

R[completed]=1
[ "$FAIL" = 0 ] && exit 0
exit 1
