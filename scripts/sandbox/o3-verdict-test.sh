#!/usr/bin/env bash
# o3-verdict-test.sh: runs the verdict table of live check O3-L1
# (scripts/sandbox/o3-openshell-egress-live.sh, function verdict) over
# fixed probe facts, one row per outcome. It needs only bash and awk: no
# OpenShell, no Docker, no network. Exit 0 when every row holds.
#
# Facts are "<http_code>,<connect_code>,<exit>,<resolves>,<policy_denied>"
# as the O3-L1 agent prints them.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/o3-openshell-egress-live.sh"
FN="$(awk '/^verdict\(\) \{$/{on=1} on{print} on && /^}$/{exit}' "$SRC")"
[ -n "$FN" ] || {
	echo "verdict() not found in $SRC" >&2
	exit 2
}
eval "$FN"

FAILED=0
# row PROXIED FACTS WANT WHY
row() {
	local got
	# shellcheck disable=SC2034 # read by the eval'd verdict()
	PROXIED="$1"
	got="$(verdict "$2")"
	if [ "$got" = "$3" ]; then
		printf 'ok    %-8s %-22s %s\n' "$1" "$2" "$4"
	else
		printf 'FAIL  %-8s %-22s %s: %s, want %s\n' "$1" "$2" "$4" "$got" "$3"
		FAILED=1
	fi
}

# No proxy variable (OpenShell strips them; the live receipts read
# proxied=no).
row no "000,000,7,yes,no" refused "a refused connect (the broker's EACCES)"
row no "000,000,7,no,no" unknown "a refused connect to a name that did not resolve"
row no "000,000,6,no,no" unknown "a name that did not resolve"
row no "000,000,6,yes,no" unknown "exit 6 is never reached"
row no "403,000,0,yes,yes" refused "OpenShell's policy_denied answer"
row no "301,000,0,yes,no" reached "an HTTP answer"
row no "200,000,56,yes,no" reached "an HTTP answer, then the body broke"
row no "000,000,56,yes,no" reached "the TLS server reset the handshake for the SNI (OC3-2, the live rerun's 1-1-1-1.sslip.io)"
row no "000,000,35,yes,no" reached "a TLS handshake failure after the connect"
row no "000,000,52,yes,no" reached "an empty reply after the connect"
row no "000,000,60,yes,no" reached "a certificate that did not verify"
row no "000,000,51,yes,no" reached "curl's peer certificate name mismatch"
row no "000,000,58,yes,no" reached "curl's client certificate problem"
row no "000,000,56,no,no" unknown "exit 56 with the name not resolving"
row no "000,000,56,yes,yes" unknown "exit 56 with a policy_denied body"
row no "000,000,28,yes,no" unknown "a timeout"
row no "000,000,99,yes,no" unknown "anything else (the probe's unknown, e.g. the broker's ECANCELED)"
row no "000,502,56,yes,no" unknown "a CONNECT answer other than 200 or 403"
row no "none,,,," unknown "no facts"
# Through a proxy variable.
row yes "000,403,56,yes,no" refused "the proxy refused the CONNECT"
row yes "000,200,56,yes,no" reached "the proxy's CONNECT went through"
row yes "000,000,56,yes,no" unknown "no CONNECT answer through a proxy"
row yes "000,000,7,yes,no" unknown "a refused connect to the proxy itself"
row yes "301,000,0,yes,no" reached "an HTTP answer"

[ "$FAILED" = 0 ] && echo "all rows hold" || echo "some rows failed"
exit "$FAILED"
