#!/usr/bin/env bash
# g-l2-openshell-org-transport-live.sh: live check G-L2 of the org-hosted
# OpenShell gateway (lane G5; docs/plans/openshell/build/g1-design.md
# sections 3.3, 3.6 and 11.6). G-L1 and G-L2 gate wave 2.
#
# Machine: the same throwaway OVHcloud instance as G-L1, with the same
# prerequisites (Docker, OpenShell 0.1.6's openshell-gateway, python3,
# openssl, and Go 1.25.13 or later or --probe PATH; the G-L1 header's
# setup note applies: `sudo systemctl restart user@1000` after the user
# joins the docker group, before the package gateway's user service runs).
# It sets up the same
# throwaway issuer and bundle-config gateway on 127.0.0.1
# (scripts/sandbox/g-l-lib.sh), makes one workspace with one member, and
# that member's box (its main command `sleep infinity`, TTY off), then
# measures through the probe (scripts/sandbox/g-l2, the tagged SDK's
# generated client):
#
#   the relay transport (design 3.3)
#     relay_tty_false_accepted  ExecSandboxInteractive with tty = false
#     relay_tty_false_64m       64 MiB through it, echoed byte-exact
#     relay_tty_false_upsha_64m 64 MiB up, the box's sha256 equal
#                               (every transfer is paced, fix round 3:
#                               0.1.6 ends an exec whose stdin buffer
#                               fills, "process stdin buffer is full;
#                               terminating exec", exit 74; the probe keeps
#                               at most --window bytes ahead of what the
#                               box consumed, in --chunk frames: echo
#                               counts the echoed bytes, upsha counts the
#                               box's one-'A'-per-64-KiB acks; fact.relay.*
#                               records chunk, window, mechanism, waits
#                               and the largest in-flight amount)
#     raw_tty_64m, raw_tty_upsha_64m
#                               the fallback: the same over a TTY the box
#                               switched to raw mode before READY
#     resize                    80x24 at start, a Resize to 132x50 seen
#     exit_codes                0 1 7 42 127 255 exact, interactive (TTY
#                               off and on) and ExecSandbox; SIGTERM recorded
#     cut_tty_false, cut_tty    what happens to the in-box process when
#                               the client stream is cut (fact.cut.*)
#   the held facts (design 3.6)
#     held_stop_no_process      StopSandbox: STOPPED, and no container of
#                               the box running for a 30 s window
#     held_no_network           no running container, so no process that
#                               could make a network attempt (method in
#                               the detail)
#     held_suspend_unsupported  SuspendSandbox is refused as unsupported:
#                               Unimplemented, or FailedPrecondition whose
#                               message says the compute driver does not
#                               support suspend (what 0.1.6's Docker driver
#                               answers); code and message recorded
#     held_start_keeps_layer    a file written to the box home before the
#                               stop is there after StartSandbox (/tmp
#                               recorded as a fact)
#     held_start_same_policy    the stored policy's digest and version are
#                               the same after the start
#
# verdict.relay is tty_false, raw_tty or none: the orchestrator's choice
# between design 3.3's shape and its fallback (none stops the build before
# wave 2).
#
# It is operator-attended: it prints what it will create and asks first
# (--yes skips the question). It reads no key, token or config file of the
# operator's and writes one receipt with no secret in it:
#   g-l2-openshell-org-transport-<UTC stamp>.json
#
# Usage:
#   scripts/sandbox/g-l2-openshell-org-transport-live.sh [--yes] [--out DIR]
#       [--probe PATH] [--box-image REPO@sha256:...] [--mib N]
#       [--chunk BYTES] [--window BYTES] [--keep-work]
#
# --mib sets the transfer size (default 64); --chunk the stdin frame size
# (default 32768) and --window the most bytes in flight (default 262144). Exit 0 when every check
# passed, 1 when one failed, 2 on a precondition the host does not meet.
#
# --bundle-shape ADDR (audit G5-A10) runs the BUNDLE's own shape instead of
# the host binary: it copies deploy/observer-openshell into the work dir,
# writes its .env (the gateway image by digest from .env.example, the bind
# ADDR:<free port>, ADDR being one private address of this VM, the front
# CIDR ADDR/32), runs `sudo ./keygen.sh`, `sudo ./firewall.sh install`
# and `./preflight.sh --dev` (the throwaway issuer is http on 127.0.0.1),
# brings the gateway up with `docker compose up -d`, records every
# listening socket (`sudo ss -ltnp`: fact.listeners.all_ports, and the
# gateway's own sockets selected by the compose gateway container's pid,
# fact.listeners.gateway_*, to see whether
# --health-port 0 and --metrics-port 0 open anything outside the firewall),
# and takes one box to READY through the private address (its supervisor
# dialling back to ADDR past the firewall). It skips the transport and
# held checks, and on exit takes the compose project down, removes the
# firewall table and deletes the copy. It needs sudo and asks first.
# shellcheck disable=SC2015,SC2016,SC2317,SC2329
set -uo pipefail

# shellcheck source=scripts/sandbox/g-l-lib.sh
. "$(cd "$(dirname "$0")" && pwd)/g-l-lib.sh"
gl_init G-L2 "observer-g-l2-live/1" g-l2-openshell-org-transport
trap 'gl_cleanup $?' EXIT

MIB=64
CHUNK=32768
WINDOW=262144
BUNDLE_ADDR=""
while [ $# -gt 0 ]; do
	if gl_common_args "$1"; then
		shift
		continue
	fi
	case "$1" in
	--out) OUT="$2"; shift ;;
	--probe) PROBE="$2"; shift ;;
	--box-image) BOX_IMAGE="$2"; shift ;;
	--mib) MIB="$2"; shift ;;
	--chunk) CHUNK="$2"; shift ;;
	--window) WINDOW="$2"; shift ;;
	--bundle-shape) BUNDLE_ADDR="$2"; shift ;;
	*) refuse "unknown argument $1" ;;
	esac
	shift
done
case "$MIB" in '' | *[!0-9]*) refuse "--mib must be a number" ;; esac
[ "$MIB" -ge 1 ] && [ "$MIB" -le 256 ] || refuse "--mib must be 1 to 256"
BYTES=$((MIB * 1024 * 1024))
R[transfer_bytes]="$BYTES"
case "$CHUNK$WINDOW" in *[!0-9]*) refuse "--chunk and --window must be numbers" ;; esac
[ -n "$CHUNK" ] && [ -n "$WINDOW" ] || refuse "--chunk and --window must be numbers"
[ "$CHUNK" -ge 1 ] && [ "$CHUNK" -le 1048576 ] || refuse "--chunk must be 1 to 1048576"
[ "$WINDOW" -ge 131072 ] && [ "$WINDOW" -ge "$CHUNK" ] && [ "$WINDOW" -le 67108864 ] ||
	refuse "--window must be at least 131072 (two upsha acks) and --chunk, and at most 67108864"
R[transfer_chunk]="$CHUNK"
R[transfer_window]="$WINDOW"

if [ -n "$BUNDLE_ADDR" ]; then
	case "$BUNDLE_ADDR" in
	*[!0-9.]* | "" | 0.0.0.0 | 127.*) refuse "--bundle-shape needs one private IPv4 address of this VM (not loopback, not 0.0.0.0)" ;;
	esac
	ip -4 -o addr show 2>/dev/null | grep -q " $BUNDLE_ADDR/" || refuse "--bundle-shape $BUNDLE_ADDR is not an address of this host"
	R[mode]=bundle-shape
else
	R[mode]=host-binary
fi
gl_preconditions
if [ -n "$BUNDLE_ADDR" ]; then
	echo "BUNDLE SHAPE ($BUNDLE_ADDR): with sudo, keygen.sh writes the bundle copy's secrets,"
	echo "firewall.sh installs the nftables table inet observer_openshell (removed on exit), and"
	echo "docker compose runs the gateway image on the host network bound to $BUNDLE_ADDR."
	echo "Only the box-to-READY half runs."
fi
if [ -n "$BUNDLE_ADDR" ]; then
	BANNER_GATEWAY="run a throwaway issuer on 127.0.0.1 and the bundle's gateway (compose) on $BUNDLE_ADDR"
	BANNER_BOX="create one OpenShell workspace and one box, take it to READY
    through $BUNDLE_ADDR (no transfer, no stop or start), then delete both"
else
	BANNER_GATEWAY="run a throwaway issuer and one openshell-gateway on 127.0.0.1 only"
	BANNER_BOX="create one OpenShell workspace and one box, push ${MIB} MiB through it
    four times (paced: ${CHUNK}-byte frames, at most ${WINDOW} bytes in flight),
    stop and start it, then delete both"
fi
cat <<EOF
G-L2 will, on this host, as $(id -un):
  - make a work dir under $HOME (throwaway keys, tokens, PKI, a sqlite db);
  - $BANNER_GATEWAY;
  - pull ${BOX_IMAGE:-$GL_DEFAULT_BOX_TAG} and the OpenShell 0.1.6 supervisor
    and sandbox images by digest if absent;
  - $BANNER_BOX;
  - remove every container under its own sandbox namespace label on exit.
EOF
confirm "Proceed with G-L2?"

gl_make_work g-l2
gl_build_probe
gl_box_image
gl_start_issuer
gl_render_config
# gl_bundle_up: the bundle's own shape (--bundle-shape, audit G5-A10).
BUNDLE_DIR=""
BUNDLE_PROJECT=""
gl_bundle_up() {
	BUNDLE_DIR="$WORK/bundle"
	BUNDLE_PROJECT="gl2bundle-$GW_ID"
	mkdir -p "$BUNDLE_DIR"
	local f img
	for f in .env.example .gitignore Dockerfile.openshell-box README.md docker-compose.yaml firewall.sh gateway.toml.tmpl keygen.sh preflight.sh render-gateway-toml.py; do
		cp "$GL_ROOT/deploy/observer-openshell/$f" "$BUNDLE_DIR/" || refuse "cannot copy the bundle's $f"
	done
	img="$(sed -n 's/^# OPENSHELL_GATEWAY_IMAGE=//p' "$GL_ROOT/deploy/observer-openshell/.env.example" | head -n1)"
	case "$img" in *@sha256:*) ;; *) refuse "the bundle's .env.example names no gateway image digest" ;; esac
	GW_HOST="$BUNDLE_ADDR"
	GW_PORT="$(free_port)"
	R[gateway_addr]="$GW_HOST:$GW_PORT"
	R[gateway_image]="$img"
	{
		echo "OPENSHELL_GATEWAY_IMAGE=$img"
		echo "OPENSHELL_SUPERVISOR_IMAGE=$GL_SUPERVISOR_IMAGE"
		echo "OPENSHELL_SANDBOX_RUNTIME_IMAGE=$GL_SANDBOX_RUNTIME_IMAGE"
		echo "OPENSHELL_BOX_IMAGE=$BOX_IMAGE"
		echo "OBSERVER_ORG_ISSUER=$ISSUER_URL"
		echo "OBSERVER_OPENSHELL_GATEWAY_ID=$GW_ID"
		# A front CIDR that matches no real source (lane GF1, OB-096 item 9):
		# the 2026-11-03 run admitted $BUNDLE_ADDR/32 here, which also
		# admits the box supervisors' dial-back, so it could not show that
		# firewall.sh's lo rule alone carries it. With 127.0.0.2/32, box_ready
		# passes only if the supervisors (host networking) reach the gateway
		# over lo; the probe on this host does too.
		echo "OBSERVER_OPENSHELL_FRONT_CIDRS=127.0.0.2/32"
		echo "OPENSHELL_GATEWAY_BIND=$BUNDLE_ADDR:$GW_PORT"
		echo "OPENSHELL_TELEMETRY_ENABLED=false"
		echo "OPENSHELL_OIDC_JWKS_TTL_SECS=$JWKS_TTL"
		echo "DOCKER_GID=$(stat -c %g /var/run/docker.sock)"
	} >"$BUNDLE_DIR/.env"
	issuer_state g2 normal
	fact discovery_shape g2
	(cd "$BUNDLE_DIR" && sudo ./keygen.sh) >"$LOG/bundle-keygen.log" 2>&1 || refuse "the bundle's keygen.sh failed (see $LOG/bundle-keygen.log)"
	# Fix round 2 (G5-R6): the flag is set BEFORE the install, so a refused
	# or interrupted install is still removed by the cleanup.
	R[bundle_firewall]="install attempted"
	(cd "$BUNDLE_DIR" && sudo ./firewall.sh install) >"$LOG/bundle-firewall.log" 2>&1 || refuse "the bundle's firewall.sh install failed"
	R[bundle_firewall]="installed"
	if (cd "$BUNDLE_DIR" && ./preflight.sh --dev) >"$LOG/bundle-preflight.log" 2>&1; then
		judge bundle_preflight pass "preflight.sh --dev (the dev issuer only): $(tail -n 1 "$LOG/bundle-preflight.log")"
	else
		judge bundle_preflight fail "$(grep -E 'refused' "$LOG/bundle-preflight.log" | tr '\n' ' ' | head -c 400)"
	fi
	sudo install -m 644 "$BUNDLE_DIR/secrets/tls/ca.crt" "$WORK/bundle-ca.crt" || refuse "no CA from keygen.sh"
	CA="$WORK/bundle-ca.crt"
	(cd "$BUNDLE_DIR" && docker compose -p "$BUNDLE_PROJECT" up -d) >"$LOG/bundle-compose.log" 2>&1 || refuse "docker compose up failed (see $LOG/bundle-compose.log)"
	GL_BUNDLE_UP=1
	if gw_wait_healthy 120; then
		judge gateway_started pass "the bundle's compose gateway answers on $GW_HOST:$GW_PORT"
	else
		(cd "$BUNDLE_DIR" && docker compose -p "$BUNDLE_PROJECT" logs --tail 20) >"$LOG/bundle-gateway.log" 2>&1
		judge gateway_started fail "$(tail -n 5 "$LOG/bundle-gateway.log" | tr '\n' ' ' | head -c 500)"
		refuse "the bundle-shape gateway did not answer"
	fi
	# Fix round 3: the gateway's sockets are the ones whose owner is the
	# compose gateway container's process (pid=), not every line naming
	# openshell (the package gateway on this host would match too).
	local i=0 line cid pid
	R[fact.listeners.all_ports]="$(sudo ss -ltnpH 2>/dev/null | awk '{print $4}' | sort -u | tr '\n' ' ')"
	cid="$(cd "$BUNDLE_DIR" && docker compose -p "$BUNDLE_PROJECT" ps -q gateway 2>/dev/null | head -n1)"
	pid="$( [ -n "$cid" ] && docker inspect -f '{{.State.Pid}}' "$cid" 2>/dev/null)"
	R[fact.listeners.gateway_container]="${cid:-none}"
	R[fact.listeners.gateway_pid]="${pid:-none}"
	if [ -n "$pid" ] && [ "$pid" != 0 ]; then
		while IFS= read -r line; do
			i=$((i + 1))
			R["fact.listeners.gateway_$i"]="$(printf '%s' "$line" | awk '{print $4}')"
		done < <(sudo ss -ltnpH 2>/dev/null | grep -E "pid=${pid}[,)]")
	fi
	R[fact.listeners.gateway_count]="$i"
}
gl_extra_cleanup() {
	[ -n "$BUNDLE_DIR" ] && [ -d "$BUNDLE_DIR" ] || return 0
	(cd "$BUNDLE_DIR" && docker compose -p "$BUNDLE_PROJECT" down) >/dev/null 2>&1
	GL_BUNDLE_UP=0
	# Always remove (idempotent: "no table" when none was installed).
	if (cd "$BUNDLE_DIR" && sudo ./firewall.sh remove) >"$LOG/bundle-firewall-remove.log" 2>&1; then
		R[bundle_firewall]="${R[bundle_firewall]:-not installed}; remove ran: $(tail -n 1 "$LOG/bundle-firewall-remove.log")"
	else
		R[bundle_firewall]="${R[bundle_firewall]:-not installed}; remove FAILED: $(tail -n 1 "$LOG/bundle-firewall-remove.log") (sudo nft delete table inet observer_openshell)"
	fi
	sudo rm -rf -- "$BUNDLE_DIR" && R[bundle_dir]="removed (its secrets, data and state with it)"
	return 0
}

if [ -n "$BUNDLE_ADDR" ]; then
	gl_bundle_up
else
	gl_prepare_gateway
	gl_start_gateway
fi

AUD="openshell:$GW_ID"
WS="obs-$(rand_hex 6)"
BOX="glt$(rand_hex 4)"
SUB="member:g-live-t-$(rand_hex 3)"
# The admin and member tokens use the first algorithm the gateway takes.
ADMIN_KID=""
for kid in ed-1 es-1 rs-1; do
	mint "admin-$kid" "$kid" svc:g-live-admin "$AUD" '["openshell-admin"]' "openshell:all"
	if [ "$(code "admin-$kid" call -rpc whoami)" = OK ]; then
		ADMIN_KID="$kid"
		break
	fi
done
[ -n "$ADMIN_KID" ] || refuse "the gateway accepts no token from the throwaway issuer (run G-L1 for the details)"
R[token_kid]="$ADMIN_KID"
ADMIN="admin-$ADMIN_KID"
mint member "$ADMIN_KID" "$SUB" "$AUD" '["openshell-user"]' "sandbox:read sandbox:write"
PRINCIPAL="$(p member call -rpc whoami | jget subject)"
[ -n "$PRINCIPAL" ] || PRINCIPAL="$SUB"
[ "$(code "$ADMIN" call -rpc create-workspace -name "$WS")" = OK ] || refuse "create-workspace failed"
MADE_WORKSPACES+=("$WS")
[ "$(code "$ADMIN" call -rpc add-member -workspace "$WS" -member "$PRINCIPAL")" = OK ] || refuse "add-member failed"

# The box carries an explicit minimal policy (fix round 2, merge note 1:
# the shape a live 0.1.6 box reported), so held_start_same_policy compares
# a real stored digest. Should the gateway refuse it, the refusal is
# recorded and the box is created without one (that check is then not_run).
out="$(PROBE_TIMEOUT=120s p member call -rpc create -workspace "$WS" -name "$BOX" -image "$BOX_IMAGE" -run-label "$GW_ID" -policy minimal -command '["sleep","infinity"]')"
if [ "$(printf '%s' "$out" | jget code)" = OK ]; then
	fact box_policy "minimal (explicit) digest $(printf '%s' "$out" | jget policy_sha)"
else
	fact box_policy "the minimal policy was refused: $(printf '%s' "$out" | jget code) $(printf '%s' "$out" | jget message); created without a policy"
	out="$(PROBE_TIMEOUT=120s p member call -rpc create -workspace "$WS" -name "$BOX" -image "$BOX_IMAGE" -run-label "$GW_ID" -command '["sleep","infinity"]')"
fi
[ "$(printf '%s' "$out" | jget code)" = OK ] || refuse "the member's create failed: $(printf '%s' "$out" | jget code) $(printf '%s' "$out" | jget message)"
MADE_BOXES+=("$WS/$BOX")
w="$(PROBE_TIMEOUT=660s p member wait -workspace "$WS" -name "$BOX" -phase READY -for 600s)"
if [ "$(printf '%s' "$w" | jget reached)" = true ]; then
	judge box_ready pass "READY after $(printf '%s' "$w" | jget elapsed_s)s"
else
	judge box_ready fail "phase $(printf '%s' "$w" | jget phase) $(printf '%s' "$w" | jget condition)"
	refuse "the box never became ready"
fi
if [ -n "$BUNDLE_ADDR" ]; then
	ns="$(running_in containers_in_namespace)"
	fact container_labels "running under the namespace label: $ns; under the run label: $(running_in containers_by_run)"
	if [ "$ns" -ge 1 ]; then
		judge namespace_label pass "$ns running container(s) under the namespace label"
	else
		judge namespace_label fail "the namespace label selects no running container of a READY box"
	fi
	measured listeners "${R[fact.listeners.gateway_count]} listener(s) of the gateway container's pid ${R[fact.listeners.gateway_pid]}: see fact.listeners.*"
	R[completed]=1
	[ "$FAIL" = 0 ] && exit 0
	exit 1
fi

# B: the member's view of one box.
B=(-workspace "$WS" -name "$BOX")
ex() { PROBE_TIMEOUT="${2:-60s}" p member exec "${B[@]}" -cmd "$1"; }

tools="$(ex 'for c in sh head sha256sum stty sleep kill cat dd; do command -v "$c" >/dev/null 2>&1 || printf "%s " "$c"; done; echo')"
missing="$(printf '%s' "$tools" | jget stdout | tr -d '\n')"
fact box_tools_missing "${missing:-none}"
fact box_home "$(ex 'printf %s "$HOME"' | jget stdout)"

# itx ARGS...: one interactive probe as the member.
itx() { PROBE_TIMEOUT="${ITX_TIMEOUT:-120s}" p member interactive "${B[@]}" -chunk "$CHUNK" -window "$WINDOW" "$@"; }
summ() { printf 'code=%s accepted=%s match=%s exit=%s recv=%s %s' "$(jget code <<<"$1")" "$(jget accepted <<<"$1")" "$(jget match <<<"$1")" "$(jget exit <<<"$1")" "$(jget recv_len <<<"$1")" "$(jget message <<<"$1")"; }
# flow NAME RESULT: the pacing of one transfer (fix round 3).
flow() {
	fact "relay.$1.flow" "chunk=$(jget chunk <<<"$2") window=$(jget window <<<"$2") waits=$(jget flow_waits <<<"$2") max_in_flight=$(jget max_in_flight <<<"$2") acks=$(jget acks <<<"$2") send_error=$(jget send_error <<<"$2")"
}
fact relay.flow.chunk "$CHUNK"
fact relay.flow.window "$WINDOW"
fact relay.flow.mechanism "the probe never sends more than window bytes beyond the box's consumption; echo: consumption = bytes echoed back; upsha: the box writes one A per 65536 bytes it read (dd bs=65536 count=1 iflag=fullblock), consumption = acks x 65536; a sender with no new credit for 120 s stops with send_error"

# 1. TTY off on the interactive RPC.
small="$(itx -mode echo -bytes 4096)"
fact relay.tty_false_small "$(summ "$small")"
if [ "$(jget accepted <<<"$small")" = true ] && [ "$(jget match <<<"$small")" = true ]; then
	judge relay_tty_false_accepted pass "4 KiB echoed byte-exact with tty = false"
	big="$(ITX_TIMEOUT=1800s itx -mode echo -bytes "$BYTES")"
	fact relay.tty_false_echo "$(summ "$big")"
	flow tty_false_echo "$big"
	[ "$(jget match <<<"$big")" = true ] && [ "$(jget exit <<<"$big")" = 7 ] &&
		judge relay_tty_false_64m pass "$MIB MiB echoed byte-exact, exit 7 (paced)" ||
		judge relay_tty_false_64m fail "${R[fact.relay.tty_false_echo]}"
	up="$(ITX_TIMEOUT=1800s itx -mode upsha -bytes "$BYTES")"
	fact relay.tty_false_upsha "$(summ "$up") reported=$(jget reported_sha <<<"$up")"
	flow tty_false_upsha "$up"
	[ "$(jget match <<<"$up")" = true ] && judge relay_tty_false_upsha_64m pass "the box's sha256 of $MIB MiB equals the sent one (paced)" ||
		judge relay_tty_false_upsha_64m fail "${R[fact.relay.tty_false_upsha]}"
else
	judge relay_tty_false_accepted fail "${R[fact.relay.tty_false_small]}"
	not_run relay_tty_false_64m "tty = false was not accepted"
	not_run relay_tty_false_upsha_64m "tty = false was not accepted"
fi

# 2. The raw-TTY fallback.
rbig="$(ITX_TIMEOUT=1800s itx -mode echo -tty -raw -bytes "$BYTES")"
fact relay.raw_tty_echo "$(summ "$rbig") extra=$(jget extra <<<"$rbig")"
flow raw_tty_echo "$rbig"
[ "$(jget match <<<"$rbig")" = true ] && judge raw_tty_64m pass "$MIB MiB echoed byte-exact through a raw TTY" ||
	judge raw_tty_64m fail "${R[fact.relay.raw_tty_echo]}"
rup="$(ITX_TIMEOUT=1800s itx -mode upsha -tty -raw -bytes "$BYTES")"
fact relay.raw_tty_upsha "$(summ "$rup") reported=$(jget reported_sha <<<"$rup")"
flow raw_tty_upsha "$rup"
[ "$(jget match <<<"$rup")" = true ] && judge raw_tty_upsha_64m pass "the box's sha256 equals the sent one through a raw TTY" ||
	judge raw_tty_upsha_64m fail "${R[fact.relay.raw_tty_upsha]}"

if [ "${R[check.relay_tty_false_64m]:-}" = pass ] && [ "${R[check.relay_tty_false_upsha_64m]:-}" = pass ]; then
	R[verdict.relay]=tty_false
elif [ "${R[check.raw_tty_64m]}" = pass ] && [ "${R[check.raw_tty_upsha_64m]}" = pass ]; then
	R[verdict.relay]=raw_tty
else
	R[verdict.relay]=none
fi

# 3. Resize.
rs="$(itx -mode resize -tty)"
fact resize "before=$(jget before <<<"$rs") after=$(jget after <<<"$rs") exit=$(jget exit <<<"$rs") code=$(jget code <<<"$rs")"
[ "$(jget match <<<"$rs")" = true ] && judge resize pass "24 80 then 50 132" || judge resize fail "${R[fact.resize]}"

# 4. Exit codes.
bad=""
for n in 0 1 7 42 127 255; do
	xi="$(itx -mode exit -code "$n" | jget exit)"
	xt="$(itx -mode exit -tty -code "$n" | jget exit)"
	xe="$(ex "exit $n" | jget exit)"
	fact "exit.$n" "interactive=$xi interactive_tty=$xt exec=$xe"
	[ "$xi" = "$n" ] && [ "$xt" = "$n" ] && [ "$xe" = "$n" ] || bad="$bad $n"
done
fact exit.sigterm "interactive=$(itx -mode exit -code -15 | jget exit) interactive_tty=$(itx -mode exit -tty -code -15 | jget exit) exec=$(ex 'kill -TERM $$; sleep 5' | jget exit)"
[ -z "$bad" ] && judge exit_codes pass "0 1 7 42 127 255 exact on all three paths" || judge exit_codes fail "mismatch for:$bad (see fact.exit.*)"

# 5. A cut client stream: is the in-box process still there 5 s and 35 s
# after the cut? (Recorded; design 3.3 ends the session either way.)
for mode in tty_false tty; do
	tag="c$(rand_hex 3)"
	if [ "$mode" = tty ]; then out="$(itx -mode cut -tty -tag "$tag")"; else out="$(itx -mode cut -tag "$tag")"; fi
	if [ "$(jget ready <<<"$out")" != true ]; then
		not_run "cut_$mode" "the stream never said READY: $(summ "$out")"
		continue
	fi
	probe_pid='p=$(cat /tmp/g-l2-cut-'"$tag"'.pid 2>/dev/null); if [ -z "$p" ]; then echo nopid; elif kill -0 "$p" 2>/dev/null; then echo alive; else echo gone; fi'
	sleep 5
	at5="$(ex "$probe_pid" | jget stdout | tr -d '\n')"
	sleep 30
	at35="$(ex "$probe_pid" | jget stdout | tr -d '\n')"
	fact "cut.$mode" "after_5s=$at5 after_35s=$at35"
	case "$at35" in alive | gone) measured "cut_$mode" "${R[fact.cut.$mode]}" ;; *) judge "cut_$mode" fail "${R[fact.cut.$mode]}" ;; esac
	[ "$at35" = alive ] && ex "kill \$(cat /tmp/g-l2-cut-$tag.pid) 2>/dev/null; true" >/dev/null
done

# 6. Held: write, stop, observe, suspend, start, read back.
MARK="$(rand_hex 16)"
wr="$(ex "printf %s $MARK > \"\$HOME/g-l2-held.txt\" && printf %s $MARK > /tmp/g-l2-held.txt && sync && cat \"\$HOME/g-l2-held.txt\"")"
[ "$(jget stdout <<<"$wr")" = "$MARK" ] || fact held.write "the marker write answered: $(jget code <<<"$wr") exit=$(jget exit <<<"$wr")"
g1="$(p member call -rpc get "${B[@]}")"
pol1="$(jget policy_sha <<<"$g1")"
ver1="$(jget policy_version <<<"$g1")"
pre_ns="$(running_in containers_in_namespace)"
pre_run="$(running_in containers_by_run)"
fact held.before "phase=$(jget phase <<<"$g1") policy_sha=$pol1 policy_version=$ver1 running under the namespace label=$pre_ns under the run label=$pre_run"
# Audit G5-A2: the window below counts running containers under the
# namespace label, which was never seen live. A label that selects nothing
# would read 0 and pass with nothing measured, so before the stop it must
# select at least one running container of this live box.
label_ok=0
if [ "$pre_ns" -ge 1 ]; then
	label_ok=1
	judge namespace_label pass "$pre_ns running container(s) under openshell.ai/sandbox-namespace=$GW_NAME before the stop"
else
	judge namespace_label fail "openshell.ai/sandbox-namespace=$GW_NAME selects $pre_ns running container(s) of a READY box (run label: $pre_run): the label is wrong and every container check is void"
fi

c_stop="$(code member call -rpc stop "${B[@]}")"
ws="$(PROBE_TIMEOUT=200s p member wait "${B[@]}" -phase STOPPED -for 180s)"
fact held.stop "call=$c_stop reached=$(jget reached <<<"$ws") after $(jget elapsed_s <<<"$ws")s phase=$(jget phase <<<"$ws")"
running_seen=0
samples=""
for i in 1 2 3 4 5 6 7; do
	n="$(running_in containers_in_namespace)"
	samples="$samples $n"
	[ "$n" = 0 ] || running_seen=1
	[ "$i" = 7 ] || sleep 5
done
fact held.running_containers_during_window "$samples (of $(containers_in_namespace | wc -l) in the namespace)"
if [ "$label_ok" != 1 ]; then
	judge held_stop_no_process fail "not measured: the namespace label selected no running container before the stop (check namespace_label)"
	judge held_no_network fail "not measured: the namespace label selected no running container before the stop"
elif [ "$c_stop" = OK ] && [ "$(jget reached <<<"$ws")" = true ] && [ "$running_seen" = 0 ]; then
	judge held_stop_no_process pass "STOPPED, and no container of the box ran during a 30 s window"
	judge held_no_network pass "no running container (so no process, and no network attempt) under the box's namespace for 30 s"
else
	judge held_stop_no_process fail "${R[fact.held.stop]}; running samples:$samples"
	judge held_no_network fail "a container of the box was running during the window:$samples"
fi
# held_suspend_unsupported (fix round 3; was held_suspend_unimplemented):
# 0.1.6's Docker driver answers FailedPrecondition "compute driver does not
# support sandbox suspend", which is the same held fact (no suspend) as
# Unimplemented. Any other code, or a FailedPrecondition for another
# reason, fails.
susp="$(p member call -rpc suspend "${B[@]}")"
c_susp="$(jget code <<<"$susp")"
m_susp="$(jget message <<<"$susp")"
fact held.suspend "$c_susp"
fact held.suspend_message "$m_susp"
m_susp_l="$(printf '%s' "$m_susp" | tr '[:upper:]' '[:lower:]')"
susp_unsupported=0
case "$c_susp" in
Unimplemented) susp_unsupported=1 ;;
FailedPrecondition) case "$m_susp_l" in *"does not support"*suspend* | *"not support"*suspend*) susp_unsupported=1 ;; esac ;;
esac
fact held_suspend_unimplemented "alias of check.held_suspend_unsupported (renamed in fix round 3)"
[ "$susp_unsupported" = 1 ] && judge held_suspend_unsupported pass "SuspendSandbox refused as unsupported: $c_susp: $m_susp" ||
	judge held_suspend_unsupported fail "SuspendSandbox answered $c_susp: $m_susp"

c_start="$(code member call -rpc start "${B[@]}")"
wr2="$(PROBE_TIMEOUT=360s p member wait "${B[@]}" -phase READY -for 300s)"
fact held.start "call=$c_start reached=$(jget reached <<<"$wr2") after $(jget elapsed_s <<<"$wr2")s"
home_back="$(ex 'cat "$HOME/g-l2-held.txt" 2>/dev/null' | jget stdout)"
tmp_back="$(ex 'cat /tmp/g-l2-held.txt 2>/dev/null' | jget stdout)"
fact held.tmp_kept "$([ "$tmp_back" = "$MARK" ] && echo yes || echo no)"
[ "$home_back" = "$MARK" ] && judge held_start_keeps_layer pass "the box home's file survived stop and start (/tmp kept: ${R[fact.held.tmp_kept]})" ||
	judge held_start_keeps_layer fail "the box home's file was not there after the start (start ${R[fact.held.start]})"
g2="$(p member call -rpc get "${B[@]}")"
pol2="$(jget policy_sha <<<"$g2")"
ver2="$(jget policy_version <<<"$g2")"
fact held.after "phase=$(jget phase <<<"$g2") policy_sha=$pol2 policy_version=$ver2"
if [ -z "$pol1" ] || [ "$pol1" = none ]; then
	# Audit G5-A8: a stored spec with no policy reads "none" before and
	# after; that comparison measures nothing.
	not_run held_start_same_policy "the box's stored spec carries no policy (before $pol1/v$ver1, after $pol2/v$ver2); create one with a policy to measure it"
elif [ "$pol1" = "$pol2" ] && [ "$ver1" = "$ver2" ]; then
	judge held_start_same_policy pass "same stored policy digest and version after the start"
else
	judge held_start_same_policy fail "before $pol1/v$ver1, after $pol2/v$ver2"
fi
alive="$(ex 'echo up' | jget stdout | tr -d '\n')"
fact held.exec_after_start "$alive"

R[completed]=1
[ "$FAIL" = 0 ] && exit 0
exit 1
