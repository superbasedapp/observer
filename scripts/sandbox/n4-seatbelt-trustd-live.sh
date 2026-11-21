#!/usr/bin/env bash
# n4-seatbelt-trustd-live.sh - OpenShell build lane FU5 live check N4-L2
# (tracker F-015 R3, audit finding N4-R3) on a Mac with the seatbelt row.
#
# The Seatbelt profile allows the certificate trust service
# (com.apple.trustd.agent) only on a tier that runs Observer's egress
# gateway (internet). trustd runs outside the box and may fetch a
# certificate's OCSP, CRL or issuer URLs for it, which no SBPL network rule
# governs, so on proxy_only and none the service is left out of the profile
# (internal/sandboxsbpl TLSMachServices). This check proves on a real Mac:
#   1. on proxy_only a sandboxed tool still starts and reaches the model
#      proxy, while a certificate check in the box fails (trustd refused);
#   2. on internet the same certificate check succeeds (trustd allowed),
#      and an HTTPS request through the gateway validates.
#
# Operator-attended. It reads only the node's loopback dashboard routes
# GET /api/terminal/sandbox and GET /api/terminal/sandbox/config (the saved
# tier only); it never reads a key or a config file. You set the tier,
# restart the daemon and run the commands it prints inside the box.
#
# Usage:
#   scripts/sandbox/n4-seatbelt-trustd-live.sh [--dashboard http://127.0.0.1:8081] [--receipt FILE]
#
# Prerequisites: macOS, [terminal.sandbox] enabled with seatbelt in its
# backends, curl and jq on PATH.

set -euo pipefail

dashboard="http://127.0.0.1:8081"
receipt=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dashboard) dashboard="$2"; shift 2 ;;
	--receipt) receipt="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
[ -n "$receipt" ] || receipt="n4-seatbelt-trustd-$(date -u +%Y%m%dT%H%M%SZ).json"
for tool in curl jq; do
	command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
[ "$(uname -s)" = "Darwin" ] || { echo "N4-L2 runs on macOS only" >&2; exit 2; }
route="$dashboard/api/terminal/sandbox"
tier_now() { curl -fsS "$route/config" | jq -r '.sandbox.egress // empty'; }
ask() {
	printf '%s\n' "$1"
	read -r -p "Type yes if it did, no if it did not: " a
	[ "$a" = "yes" ]
}
set_tier() {
	while [ "$(tier_now)" != "$1" ]; do
		echo "Set the sandbox network tier to '$1' (Terminals, Settings, Sandbox, Network tier) and save."
		read -r -p "Press Enter when saved. " _
	done
	echo "Restart the daemon so the tier takes effect: scripts/restart-daemon.sh (route OFF first)."
	read -r -p "Press Enter when the daemon is back. " _
	until curl -fsS "$route" >/dev/null 2>&1; do sleep 2; done
}
steps='[]'
record() {
	steps=$(jq -c --arg step "$1" --arg ok "$2" '. + [{step: $step, ok: ($ok == "true")}]' <<<"$steps")
	echo "$1: $2"
}
# A certificate check that needs trustd: security(1) evaluates the system
# trust for a certificate the box can read (the system root bundle's first
# certificate, extracted into the box's own TMPDIR).
check='awk "/BEGIN CERT/{p=1} p{print} /END CERT/{exit}" /etc/ssl/cert.pem >"$TMPDIR/c.pem" && /usr/bin/security verify-cert -c "$TMPDIR/c.pem" -p basic; echo "exit=$?"'

set_tier proxy_only
if ask "Launch: observer claude --observer-sandbox seatbelt
It must start and answer a prompt (the model proxy works on proxy_only). Did it?"; then
	record "proxy_only-tool-starts" true
else
	record "proxy_only-tool-starts" false
fi
if ask "Inside that sandboxed tool run, through its shell (in claude prefix the line with !):
    $check
It must FAIL (a non-zero exit, trustd refused). Did it fail?"; then
	record "proxy_only-trustd-refused" true
else
	record "proxy_only-trustd-refused" false
fi

set_tier internet
if ask "Launch observer claude --observer-sandbox seatbelt again on the internet tier and run, through its shell:
    $check
It must SUCCEED (exit=0). Did it?"; then
	record "internet-trustd-allowed" true
else
	record "internet-trustd-allowed" false
fi
if ask "In the same run, through its shell: curl -sS -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/
(with registry.npmjs.org in egress_allow_hosts, or no host list). It must print 200 with no certificate error. Did it?"; then
	record "internet-https-validates" true
else
	record "internet-https-validates" false
fi
echo "Set the sandbox network tier back to what this Mac used before the check."

jq -n --arg id "N4-L2" --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson steps "$steps" \
	'{id: $id, at: $at, steps: $steps, passed: ([$steps[] | .ok] | all)}' >"$receipt"
echo "receipt: $receipt"
jq -r 'if .passed then "N4-L2 passed" else "N4-L2 FAILED: see the steps" end' "$receipt"
