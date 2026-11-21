# shellcheck shell=bash
# g-l-lib.sh: the shared steps of the org-hosted OpenShell gateway's live
# checks (lane G5; docs/plans/openshell/build/g1-design.md section 11.6).
# Sourced by scripts/sandbox/g-l1-openshell-org-idp-live.sh and
# scripts/sandbox/g-l2-openshell-org-transport-live.sh, never run alone.
#
# What it sets up, all on 127.0.0.1 and all under one throwaway work dir:
#   - the throwaway issuer (scripts/sandbox/g-l1/issuer.py, run with
#     python3 -I): EdDSA, ES256 and RS256 keys, a static discovery
#     document and JWKS, no Observer server code;
#   - one OpenShell 0.1.6 gateway process (openshell-gateway from the
#     host's OpenShell package) run with the bundle's own gateway.toml
#     (deploy/observer-openshell/gateway.toml.tmpl, rendered by
#     render-gateway-toml.py with --dev-loopback-issuer), its own PKI
#     from `openshell-gateway generate-certs`, its own sqlite database and
#     its own Docker sandbox namespace (observer-org-<gateway id>), so it
#     never touches the package's own gateway or its boxes (finding F-027);
#   - the probe (scripts/sandbox/g-l2, built here or given with --probe).
#
# It reads no key, token or config file of the operator's, never prints a
# token (tokens live in 0600 files under the work dir and reach the probe
# by file name), and on exit deletes every box and workspace it made, stops
# the gateway and the issuer, removes any container left under its own
# sandbox namespace label, and removes the throwaway keys, tokens and PKI.
# The receipt is written on every exit and holds no secret and no address
# but loopback.

GL_LIB_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GL_ROOT="$(cd "$GL_LIB_HERE/../.." && pwd)"
GL_ISSUER="$GL_LIB_HERE/g-l1/issuer.py"
GL_RENDER="$GL_ROOT/deploy/observer-openshell/render-gateway-toml.py"
GL_PROBE_SRC="$GL_LIB_HERE/g-l2"

# The OpenShell 0.1.6 runtime images by index digest (lane FU7,
# docs/plans/openshell/build/fu7-image-digests.md; ledger row OSH-48).
GL_SUPERVISOR_IMAGE="ghcr.io/nvidia/openshell/supervisor@sha256:ce859a7d77ee515d3fe0b3c7dc61286516f402eb1d25c761d806d9ae5ed96c0b"
GL_SANDBOX_RUNTIME_IMAGE="ghcr.io/nvidia/openshell/sandbox@sha256:1038eb5c1f191fa3c34684fd7041b891c78ec570979d487f36e06e08f91bfb63"
# The driver's default box image (openshell-core image.rs at v0.1.6); the
# scripts resolve its digest on the host unless --box-image names one.
GL_DEFAULT_BOX_TAG="nvcr.io/nvidia/base/ubuntu:24.04"

declare -A R
FAIL=0
RECEIPT=""
RECEIPT_WRITTEN=0
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$PWD"
YES=0
KEEP_WORK=0
PROBE=""
BOX_IMAGE=""
JWKS_TTL=20
WORK=""
LOG=""
ISSUER_PID=""
GATEWAY_PID=""
GW_ID=""
GW_NAME=""
GW_PORT=""
# GW_HOST is the address the gateway listens on and the probe dials:
# 127.0.0.1 for the host-binary gate, the VM's private address in G-L2's
# --bundle-shape mode.
GW_HOST="127.0.0.1"
# GL_JWKS_BASE is the JWKS state the run's tokens verify under: normal (all
# three key types), or one type alone when the gateway refused the mixed
# set (audit G5-A17; G-L1 sets it).
GL_JWKS_BASE=normal
# GL_BUNDLE_UP is 1 while a compose-run gateway (G-L2 --bundle-shape)
# serves; the cleanup then deletes boxes through it as through the host
# binary. A script may define gl_extra_cleanup, which the cleanup calls
# after the gateway stops.
GL_BUNDLE_UP=0
ISSUER_URL=""
CA=""
# Boxes and workspaces made, as "workspace/name" and "name", for cleanup.
MADE_BOXES=()
MADE_WORKSPACES=()

gl_init() {
	R[schema]="$2"
	R[row]="$1"
	R[started]="$STAMP"
	R[completed]=0
	GL_RECEIPT_PREFIX="$3"
}

json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\r'/\\r}"
	s="${s//$'\t'/\\t}"
	s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
	printf '"%s"' "$s"
}

write_receipt() {
	[ -n "$RECEIPT" ] || RECEIPT="$OUT/$GL_RECEIPT_PREFIX-$STAMP.json"
	{ : >"$RECEIPT"; } 2>/dev/null || RECEIPT="$HOME/$(basename "$RECEIPT")"
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

# judge NAME pass|fail|not_run [DETAIL]
judge() {
	R["check.$1"]="$2"
	[ -n "${3:-}" ] && R["check.$1.detail"]="$3"
	[ "$2" = pass ] || FAIL=1
	echo "check $1: $2${3:+ ($3)}"
	return 0
}
not_run() { judge "$1" not_run "$2"; }
# measured NAME DETAIL: a recording, not a pass/fail claim (audit G5-A16):
# the value is in the detail and the fact.* keys; it never fails the run.
measured() {
	R["check.$1"]=measured
	R["check.$1.detail"]="$2"
	echo "check $1: measured ($2)"
	return 0
}
fact() { R["fact.$1"]="$2"; }
refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	exit 2
}

# confirm PROMPT: ask unless --yes was given; refuse on anything but y.
confirm() {
	[ "$YES" = 1 ] && return 0
	local a
	printf '%s [y/N] ' "$1"
	read -r a || a=""
	case "$a" in y | Y | yes) return 0 ;; esac
	refuse "the operator declined: $1"
}

# jget FIELD: one field of the JSON object on stdin ("" when absent; lists
# and objects as JSON).
jget() {
	python3 -I -c '
import json, sys
try:
    d = json.loads(sys.stdin.read() or "{}")
except ValueError:
    d = {}
v = d
for p in sys.argv[1].split("."):
    v = v.get(p, "") if isinstance(v, dict) else ""
print("" if v is None else json.dumps(v) if isinstance(v, (list, dict, bool)) else v)
' "$1"
}

rand_hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }

free_port() {
	python3 -I -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

gl_common_args() {
	case "$1" in
	--yes) YES=1 ;;
	--keep-work) KEEP_WORK=1 ;;
	*) return 1 ;;
	esac
	return 0
}

gl_preconditions() {
	[ "$(uname -s)" = Linux ] || refuse "not Linux"
	grep -qi microsoft /proc/version 2>/dev/null && refuse "WSL2: run on the throwaway OVHcloud VM (Ubuntu 24.04)"
	local c
	for c in openshell-gateway docker python3 openssl od; do
		command -v "$c" >/dev/null || refuse "$c is not on PATH"
	done
	local v
	v="$(openshell-gateway --version 2>/dev/null | head -n1)"
	R[openshell_gateway_version]="$v"
	case "$v" in *0.1.6*) ;; *) refuse "openshell-gateway is not 0.1.6 ($v)" ;; esac
	docker info >/dev/null 2>&1 || refuse "docker info fails (is the user in the docker group?)"
	R[docker_version]="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
	R[openssl_version]="$(openssl version 2>/dev/null)"
	R[host]="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-unknown}"); kernel $(uname -r)"
	[ -d "$OUT" ] && [ -w "$OUT" ] || OUT="$HOME"
}

gl_make_work() {
	WORK="$(mktemp -d "$HOME/$1-XXXXXX")" || refuse "cannot make a work dir"
	chmod 700 "$WORK"
	LOG="$WORK/log"
	mkdir -p "$LOG" "$WORK/tok" "$WORK/xdg-config" "$WORK/xdg-state"
	chmod 700 "$WORK/tok"
	R[work_dir]="$WORK"
}

gl_build_probe() {
	if [ -n "$PROBE" ]; then
		[ -x "$PROBE" ] || refuse "--probe $PROBE is not executable"
	else
		command -v go >/dev/null || refuse "go is not on PATH: build scripts/sandbox/g-l2 elsewhere and pass --probe PATH (OB-069: dl.google.com answered 404 on the VM, copy a Go toolchain in)"
		(cd "$GL_PROBE_SRC" && CGO_ENABLED=0 go build -o "$WORK/g-l2-probe" .) >"$LOG/probe-build.log" 2>&1 ||
			refuse "the probe did not build (see $LOG/probe-build.log)"
		PROBE="$WORK/g-l2-probe"
	fi
	R[probe]="$("$PROBE" -addr 127.0.0.1:1 -ca /nonexistent call -rpc health 2>/dev/null | jget probe)"
}

# gl_box_image: the box image by digest (--box-image, or the driver's
# default base image pulled and read back by its repo digest).
gl_box_image() {
	if [ -n "$BOX_IMAGE" ]; then
		case "$BOX_IMAGE" in *@sha256:*) ;; *) refuse "--box-image must be a digest reference" ;; esac
	else
		docker pull "$GL_DEFAULT_BOX_TAG" >"$LOG/box-pull.log" 2>&1 || refuse "docker pull $GL_DEFAULT_BOX_TAG failed"
		BOX_IMAGE="$(docker image inspect --format '{{index .RepoDigests 0}}' "$GL_DEFAULT_BOX_TAG" 2>/dev/null)"
		case "$BOX_IMAGE" in *@sha256:*) ;; *) refuse "no repo digest for $GL_DEFAULT_BOX_TAG" ;; esac
	fi
	R[box_image]="$BOX_IMAGE"
}

# issuer_state DISCOVERY JWKS: what the throwaway issuer answers from now on.
issuer_state() {
	printf '{"discovery":"%s","jwks":"%s"}\n' "$1" "$2" >"$WORK/issuer.state"
}

gl_start_issuer() {
	python3 -I "$GL_ISSUER" keys "$WORK/keys" >"$LOG/issuer-keys.log" 2>&1 || refuse "the issuer could not make its keys"
	if python3 -I "$GL_ISSUER" selftest "$WORK/keys" >"$LOG/issuer-selftest.log" 2>&1; then
		judge issuer_selftest pass "EdDSA, ES256 and RS256 verify with openssl"
	else
		judge issuer_selftest fail "$(tr '\n' ';' <"$LOG/issuer-selftest.log")"
		refuse "the issuer self-test failed"
	fi
	issuer_state g2 normal
	python3 -I "$GL_ISSUER" serve "$WORK/keys" --state "$WORK/issuer.state" --portfile "$WORK/issuer.port" \
		--log "$LOG/issuer-requests.log" >"$LOG/issuer.log" 2>&1 &
	ISSUER_PID=$!
	local _
	for _ in $(seq 1 50); do
		[ -s "$WORK/issuer.port" ] && break
		sleep 0.2
	done
	[ -s "$WORK/issuer.port" ] || refuse "the issuer did not start"
	ISSUER_URL="http://127.0.0.1:$(cat "$WORK/issuer.port")/sandbox-idp"
	R[issuer]="$ISSUER_URL"
}

gl_render_config() {
	GW_ID="gl-$(rand_hex 4)"
	GW_NAME="observer-org-$GW_ID"
	R[gateway_id]="$GW_ID"
	R[sandbox_label]="$GW_NAME"
	R[jwks_ttl_secs]="$JWKS_TTL"
	local digest
	digest="$(env -i PATH="$PATH" OBSERVER_OPENSHELL_GATEWAY_ID="$GW_ID" OBSERVER_ORG_ISSUER="$ISSUER_URL" \
		OPENSHELL_SUPERVISOR_IMAGE="$GL_SUPERVISOR_IMAGE" OPENSHELL_SANDBOX_RUNTIME_IMAGE="$GL_SANDBOX_RUNTIME_IMAGE" \
		OPENSHELL_BOX_IMAGE="$BOX_IMAGE" OPENSHELL_OIDC_JWKS_TTL_SECS="$JWKS_TTL" \
		python3 -I "$GL_RENDER" --out "$WORK/gateway.toml" --dev-loopback-issuer 2>"$LOG/render.log")" ||
		refuse "the bundle template did not render: $(cat "$LOG/render.log")"
	R[gateway_toml_sha256]="$digest"
}

# gw_env_set: GW_ENV, the gateway's whole environment (run under env -i):
# its own PKI and XDG dirs, telemetry off, DOCKER_HOST passed through. The
# key-encryption key is never on a command line (audit G5-A13): it sits in
# the 0600 file $WORK/kek.env, which a bash wrapper sources and then execs
# the command, so the PID stays the command's own.
# gw_env CMD...: run CMD in that environment.
GW_ENV=()
gw_env_set() {
	GW_ENV=(PATH="$PATH" HOME="$HOME" OPENSHELL_LOCAL_TLS_DIR="$WORK/tls"
		XDG_CONFIG_HOME="$WORK/xdg-config" XDG_STATE_HOME="$WORK/xdg-state"
		OPENSHELL_TELEMETRY_ENABLED=false OPENSHELL_TELEMETRY_ENDPOINT=)
	[ -n "${DOCKER_HOST:-}" ] && GW_ENV+=(DOCKER_HOST="$DOCKER_HOST")
	return 0
}
# shellcheck disable=SC2016
gw_env() { env -i "${GW_ENV[@]}" bash -c 'set -a; . "$0"; set +a; exec "$@"' "$WORK/kek.env" "$@"; }

gl_prepare_gateway() {
	(umask 077 && printf 'OBSERVER_OPENSHELL_ORG_GATEWAY_KEK=%s\n' "$(head -c 32 /dev/urandom | base64 | tr -d '\n')" >"$WORK/kek.env")
	gw_env_set
	gw_env openshell-gateway generate-certs --output-dir "$WORK/tls" --server-san 127.0.0.1 >"$LOG/generate-certs.log" 2>&1 ||
		refuse "openshell-gateway generate-certs failed (see $LOG/generate-certs.log)"
	CA="$WORK/tls/ca.crt"
	[ -s "$CA" ] || refuse "generate-certs wrote no ca.crt"
	if gw_env openshell-gateway config preflight --path "$WORK/gateway.toml" >"$LOG/preflight.log" 2>&1; then
		judge gateway_preflight pass "the rendered bundle config passes openshell-gateway config preflight"
	else
		judge gateway_preflight fail "$(head -c 300 "$LOG/preflight.log" | tr '\n' ' ')"
	fi
	GW_PORT="$(free_port)"
	R[gateway_addr]="$GW_HOST:$GW_PORT"
}

# gw_start: start the gateway; a plain command in the background (never
# the gw_env function, whose $! would be a subshell), and env and the
# wrapper exec, so $! is the gateway itself. gw_wait_healthy SECONDS: 0
# when it answers.
# shellcheck disable=SC2016
gw_start() {
	env -i "${GW_ENV[@]}" bash -c 'set -a; . "$0"; set +a; exec "$@"' "$WORK/kek.env" openshell-gateway --config "$WORK/gateway.toml" --db-url "sqlite:$WORK/gateway.db" --name "$GW_NAME" \
		--bind-address 127.0.0.1 --port "$GW_PORT" --health-port 0 --metrics-port 0 \
		--compute-driver docker --enable-operator-auth false >>"$LOG/gateway.log" 2>&1 &
	GATEWAY_PID=$!
}
gw_stop() {
	[ -n "$GATEWAY_PID" ] || return 0
	kill "$GATEWAY_PID" 2>/dev/null
	local _
	for _ in $(seq 1 30); do
		kill -0 "$GATEWAY_PID" 2>/dev/null || break
		sleep 0.5
	done
	kill -9 "$GATEWAY_PID" 2>/dev/null
	wait "$GATEWAY_PID" 2>/dev/null
	GATEWAY_PID=""
}
gw_wait_healthy() {
	local deadline=$((SECONDS + $1)) out
	while [ "$SECONDS" -lt "$deadline" ]; do
		[ -n "$GATEWAY_PID" ] && ! kill -0 "$GATEWAY_PID" 2>/dev/null && return 1
		out="$("$PROBE" -addr "$GW_HOST:$GW_PORT" -ca "$CA" -timeout 5s call -rpc health 2>/dev/null)"
		[ "$(printf '%s' "$out" | jget code)" = OK ] && return 0
		sleep 1
	done
	return 1
}

# gl_start_gateway: start the gateway once per discovery shape the
# issuer can serve, the org server's own (g2, lane G2's
# openshellidp.Issuer.Discovery) first, then minimal (issuer and jwks_uri)
# and extended (plus authorization and token endpoints), recording which
# start (fact.discovery.<shape>, audit G5-A5); then run it on the first
# that did. Sets fact.discovery_shape (= the shape the rest of the run
# uses) and verdict.discovery.
GL_SHAPES="g2 minimal extended"
gl_start_gateway() {
	local shape first="" before fetched jwks
	for shape in $GL_SHAPES; do
		issuer_state "$shape" normal
		before="$(log_lines "$LOG/issuer-requests.log")"
		gw_start
		if gw_wait_healthy 60; then
			# Fix round 2 (G5-R4): "started" means the gateway fetched THIS
			# shape's document (a 200 on the discovery path during the
			# attempt), not merely that it answered.
			fetched="$(tail -n +"$((before + 1))" "$LOG/issuer-requests.log" 2>/dev/null | grep -c 'openid-configuration 200')"
			jwks="$(tail -n +"$((before + 1))" "$LOG/issuer-requests.log" 2>/dev/null | grep -c 'jwks.json 200')"
			fact "discovery.$shape.fetches" "discovery $fetched, jwks $jwks"
			if [ "$fetched" -ge 1 ]; then
				fact "discovery.$shape" started
				[ -n "$first" ] || first="$shape"
			else
				fact "discovery.$shape" "unmeasured: the gateway answered but fetched no discovery document"
			fi
		else
			fact "discovery.$shape" "failed: $(tail -n 3 "$LOG/gateway.log" | tr '\n' ' ' | head -c 300)"
		fi
		gw_stop
	done
	if [ -z "$first" ]; then
		fact discovery_shape failed
		R[verdict.discovery]=failed
		judge gateway_started fail "no discovery shape started the gateway (fact.discovery.*)"
		refuse "the gateway did not start with the bundle config"
	fi
	issuer_state "$first" normal
	gw_start
	gw_wait_healthy 60 || refuse "the gateway did not come back with the $first discovery shape"
	fact discovery_shape "$first"
	R[verdict.discovery]="$first"
	judge gateway_started pass "started with the $first discovery shape (g2 ${R[fact.discovery.g2]%%:*}, minimal ${R[fact.discovery.minimal]%%:*}, extended ${R[fact.discovery.extended]%%:*})"
}

# log_lines FILE: its line count (0 when it does not exist yet).
log_lines() {
	if [ -f "$1" ]; then wc -l <"$1" | tr -d ' '; else echo 0; fi
}

# mint NAME KID SUB AUD [ROLES_JSON|-] [SCOPE|-] [ROLES_PATH] [EXP_OFFSET]:
# a token file $WORK/tok/NAME; "-" leaves the claim out.
mint() {
	local name="$1" kid="$2" sub="$3" aud="$4" roles="${5:--}" scope="${6:--}" path="${7:-roles}" off="${8:-0}"
	local -a a=(mint "$WORK/keys" --kid "$kid" --issuer "$ISSUER_URL" --sub "$sub" --aud "$aud" --out "$WORK/tok/$name"
		--roles-path "$path" --exp-offset "$off")
	[ "$roles" = - ] || a+=(--roles "$roles")
	[ "$scope" = - ] || a+=(--scope "$scope")
	python3 -I "$GL_ISSUER" "${a[@]}" >/dev/null 2>>"$LOG/mint.log" || refuse "minting $name failed"
}

# p TOKEN VERB ARGS...: the probe as the holder of token file TOKEN ("-"
# for none); prints the probe's JSON.
p() {
	local tok="$1"
	shift
	local -a a=(-addr "$GW_HOST:$GW_PORT" -ca "$CA" -timeout "${PROBE_TIMEOUT:-60s}")
	[ "$tok" = - ] || a+=(-token-file "$WORK/tok/$tok")
	"$PROBE" "${a[@]}" "$@" 2>>"$LOG/probe.log"
}
# pe TOKEN VERB ARGS...: the same with the token sent only as edge headers.
pe() {
	local tok="$1"
	shift
	"$PROBE" -addr "$GW_HOST:$GW_PORT" -ca "$CA" -edge-token-file "$WORK/tok/$tok" "$@" 2>>"$LOG/probe.log"
}
# code TOKEN VERB ARGS...: only the gRPC code of the call.
code() { p "$@" | jget code; }

# denied CODE: 0 when CODE is an authorization or authentication refusal.
denied() { case "$1" in PermissionDenied | Unauthenticated) return 0 ;; esac; return 1; }
# tenant_refused CODE: denied, or NotFound (a gateway may hide another
# workspace's objects rather than refuse them; the receipt keeps the code).
tenant_refused() { case "$1" in PermissionDenied | Unauthenticated | NotFound) return 0 ;; esac; return 1; }

# containers_in_namespace: this run's containers (the driver labels every
# one with its sandbox namespace, openshell-core driver_utils.rs; never
# seen live before the gate run, so every check that reads it first proves
# it selects at least one running container, audit G5-A2).
# containers_by_run: the containers carrying the probe's per-run create
# label (observer.superbased.glive=<gateway id>), when the driver copies
# sandbox labels onto containers. running_in CMD: how many of CMD's
# containers are running.
containers_in_namespace() {
	docker ps -aq --filter "label=openshell.ai/sandbox-namespace=$GW_NAME" 2>/dev/null
}
containers_by_run() {
	docker ps -aq --filter "label=observer.superbased.glive=$GW_ID" 2>/dev/null
}
running_in() {
	local n=0 cid
	for cid in $("$1"); do
		[ "$(docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null)" = true ] && n=$((n + 1))
	done
	echo "$n"
}

gl_cleanup() {
	local rc=$1 b ws n left c
	set +e
	# Every made box counts as not deleted until a probe delete answers OK
	# (no delete runs at all when the gateway never came up).
	local undeleted=${#MADE_BOXES[@]}
	if { [ -n "$GATEWAY_PID" ] || [ "$GL_BUNDLE_UP" = 1 ]; } && [ -s "$WORK/keys/ed-1.pem" ]; then
		issuer_state "${R[fact.discovery_shape]:-g2}" "$GL_JWKS_BASE"
		mint cleanup-admin "${ADMIN_KID:-es-1}" svc:g-live-cleanup "openshell:$GW_ID" '["openshell-admin"]' "openshell:all"
		# Fix round 4: the gateway may still hold the key set it cached
		# during a JWKS window (empty, dropped key, 404), so it refuses the
		# fresh token until that cache expires. Poll whoami with the
		# cleanup token, bounded at the JWKS TTL plus 10 s, before deleting.
		local waited=0 limit=$((${JWKS_TTL:-20} + 10)) wc=""
		while :; do
			wc="$(PROBE_TIMEOUT=10s p cleanup-admin call -rpc whoami | jget code)"
			[ "$wc" = OK ] && break
			[ "$waited" -ge "$limit" ] && break
			sleep 2
			waited=$((waited + 2))
		done
		R[cleanup_auth]="whoami ${wc:-no answer} after ${waited}s (bound ${limit}s)"
		undeleted=0
		for b in "${MADE_BOXES[@]}"; do
			c="$(PROBE_TIMEOUT=30s p cleanup-admin call -rpc delete -workspace "${b%%/*}" -name "${b#*/}" | jget code)"
			# The delete sends allow_missing, so OK covers a box an
			# earlier step already deleted.
			[ "$c" = OK ] || undeleted=$((undeleted + 1))
		done
		R[cleanup_probe_deletes]="${#MADE_BOXES[@]} box(es), $undeleted not deleted by the probe"
		sleep 5
		for ws in "${MADE_WORKSPACES[@]}"; do
			PROBE_TIMEOUT=30s p cleanup-admin call -rpc delete-workspace -name "$ws" >/dev/null
		done
	fi
	gw_stop
	declare -F gl_extra_cleanup >/dev/null && gl_extra_cleanup
	[ -n "$ISSUER_PID" ] && kill "$ISSUER_PID" 2>/dev/null && wait "$ISSUER_PID" 2>/dev/null
	if [ -n "$GW_NAME" ]; then
		left="$( (containers_in_namespace; containers_by_run) | sort -u | wc -l)"
		R[left_containers_before_rm]="$left (namespace label $(containers_in_namespace | wc -l), run label $(containers_by_run | wc -l))"
		n=0
		for b in $( (containers_in_namespace; containers_by_run) | sort -u); do
			docker rm -f "$b" >/dev/null 2>&1 && n=$((n + 1))
		done
		R[removed_containers]="$n"
		R[left_containers]="$( (containers_in_namespace; containers_by_run) | sort -u | wc -l)"
		# Fix round 3: only a box the probe did NOT delete can be a
		# container the labels missed; a deleted box leaves none by design.
		[ "$undeleted" -gt 0 ] && [ "$left" = 0 ] &&
			R[cleanup_note]="$undeleted box(es) the probe did not delete, and neither label selected a container: the cleanup could not see them; check docker ps -a by hand"
	fi
	if [ -n "$WORK" ]; then
		rm -rf -- "$WORK/keys" "$WORK/tok" "$WORK/tls" "$WORK/kek.env" "$WORK/xdg-config" "$WORK/xdg-state"
		R[secrets_removed]="keys, tokens, PKI and key-encryption key removed from the work dir"
		if [ "$KEEP_WORK" = 0 ] && [ "$rc" = 0 ] && [ "$FAIL" = 0 ]; then
			rm -rf -- "$WORK" && R[work_dir]="removed (all checks passed)"
		fi
	fi
	R[exit]="$rc"
	R[result]="$([ "$FAIL" = 0 ] && [ "$rc" = 0 ] && echo pass || echo fail)"
	[ "$RECEIPT_WRITTEN" = 1 ] || write_receipt
}
