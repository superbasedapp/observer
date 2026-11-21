#!/usr/bin/env bash
# n5-advisor-live.sh - OpenShell build lane N5 live check N5-L1 (operator
# laptop): the Terminals page offers "Allow this host" on an allow-list miss
# and on nothing else, the owner applies it through the save preview, the
# next run reaches the host, and a write without the dashboard's confirm
# token is refused.
#
# Operator-attended. Run it on your own machine against your own running
# daemon (`observer start`). It never reads a key, a token or a config file;
# it only reads the owner-local routes GET /api/sandbox/refusals and GET
# /api/sandbox/refusals/allow on the loopback dashboard, sends one PUT
# WITHOUT the confirm token (which must be refused), and asks you to
# launch the runs and click the button in the dashboard yourself.
#
# Usage:
#   scripts/sandbox/n5-advisor-live.sh [--dashboard http://127.0.0.1:8081] \
#       [--host example.com] [--machine linux|wsl2] [--receipt FILE]
#
#   --machine names the machine in the receipt (default linux; lane FU10,
#   F-049: it used to be written as "laptop" whatever the machine was).
#
# Prerequisites:
#   - the daemon is running with [terminal.sandbox] enabled = true,
#     egress = "internet" and egress_allow_hosts = ["registry.npmjs.org"]
#     (a list that does not name --host), and no organization pin of the
#     host list (a managed node shows org_pin_refuses instead, which is a
#     pass of a different row: note it in the receipt);
#   - curl and jq on PATH.

set -euo pipefail

dashboard="http://127.0.0.1:8081"
host="example.com"
machine="linux"
receipt=""
while [ $# -gt 0 ]; do
	case "$1" in
	--dashboard) dashboard="$2"; shift 2 ;;
	--host) host="$2"; shift 2 ;;
	--machine) machine="$2"; shift 2 ;;
	--receipt) receipt="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done
case "$machine" in
linux | wsl2) ;;
*) echo "--machine must be linux or wsl2" >&2; exit 2 ;;
esac
if [ -z "$receipt" ]; then
	receipt="n5-advisor-live-$(date -u +%Y%m%dT%H%M%SZ).json"
fi
for tool in curl jq; do
	command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 2; }
done
refusals="$dashboard/api/sandbox/refusals"
offers="$dashboard/api/sandbox/refusals/allow"
if ! curl -fsS "$refusals?limit=1" >/dev/null || ! curl -fsS "$offers?limit=1" >/dev/null; then
	echo "GET $refusals or $offers failed: is the daemon running with the sandbox module active?" >&2
	exit 1
fi

results="[]"
record() {
	results=$(jq -c --arg n "$1" --arg s "$2" --argjson d "$3" '. + [{step: $n, status: $s, detail: $d}]' <<<"$results")
	echo "$2: $1"
}
wait_enter() {
	read -r -p "$1 (Enter to go on, or type skip): " answer
	[ "$answer" != "skip" ]
}
newest_id() { curl -fsS "$refusals?limit=1" | jq '.refusals[0].id // 0'; }
# row_for HOST AFTER_ID: the newest refusal for HOST above AFTER_ID, or null.
row_for() { curl -fsS "$refusals?limit=100" | jq -c --arg h "$1" --argjson b "$2" '[.refusals[] | select((.host | ascii_downcase) == $h and .id > $b)][0] // null'; }
offer_for() { curl -fsS "$offers?limit=100" | jq -c --argjson id "$1" '[.offers[] | select(.refusal_id == $id)][0] // null'; }

# 1. An allow-list miss is offered.
before=$(newest_id)
echo
echo "== 1. allow-list miss"
echo "Launch a sandboxed terminal from the dashboard (bwrap is fine). Inside the box run:"
echo "  curl -sS -x \"\$HTTPS_PROXY\" https://$host/ ; echo"
echo "It must print a JSON body with \"error\":\"egress_refused\" and \"rule\":\"allow-list-miss\"."
miss_id=0
if wait_enter "Once it has printed the body"; then
	sleep 2
	row=$(row_for "$host" "$before")
	if [ "$row" = "null" ]; then
		record "allow-list miss recorded" failed '{"why":"no new row for the host"}'
	else
		miss_id=$(jq '.id' <<<"$row")
		offer=$(offer_for "$miss_id")
		if [ "$(jq -r '.offerable // false' <<<"$offer")" = "true" ]; then
			record "allow-list miss is offered" passed "$(jq -c -n --argjson r "$row" --argjson o "$offer" '{row: $r, offer: $o}')"
		else
			record "allow-list miss is offered" failed "$(jq -c -n --argjson r "$row" --argjson o "$offer" '{row: $r, offer: $o}')"
		fi
	fi
else
	record "allow-list miss is offered" skipped null
fi

# 2. A provider host or a private range is never offered. The gateway checks
# the host list before the provider block, so an unlisted provider host is
# stored as allow-list-miss (audit finding N5-A1): it must still be refused
# with reason provider_host, never offered. The same order means a private
# literal address is stored as literal-ip, not private-range, while a host
# list is set (internal/sandboxnet/hosts.go: a list names hosts, so any
# literal IP is refused before resolution; F-049 checked this is the
# documented class). Neither rule is offerable (sandboxadvise), and the
# step judges only that.
before=$(newest_id)
echo
echo "== 2. refusals that are never offered"
echo "In the same box run both:"
echo "  curl -sS -x \"\$HTTPS_PROXY\" https://10.0.0.1/ ; echo"
echo "  curl -sS -x \"\$HTTPS_PROXY\" https://api.anthropic.com/ ; echo"
echo "(a private address, refused as literal-ip because a host list is set,"
echo "and a model provider host that is not on the host list)."
if wait_enter "Once both have printed a body"; then
	sleep 2
	rows=$(curl -fsS "$refusals?limit=100" | jq -c --argjson b "$before" --arg h "$host" '[.refusals[] | select(.id > $b and (.host | ascii_downcase) != $h)]')
	provider=$(jq -c '[.[] | select((.host | ascii_downcase) == "api.anthropic.com")][0] // null' <<<"$rows")
	if [ "$(jq 'length' <<<"$rows")" = "0" ]; then
		record "non-offerable refusals recorded" failed '{"why":"no new row"}'
	else
		bad=$(curl -fsS "$offers?limit=100" | jq -c --argjson rows "$rows" '[.offers[] | select(.offerable and (.refusal_id as $i | $rows | any(.id == $i)))]')
		if [ "$(jq 'length' <<<"$bad")" = "0" ]; then
			record "non-offerable refusals are not offered" passed "$(jq -c -n --argjson r "$rows" '{rows: $r}')"
		else
			record "non-offerable refusals are not offered" failed "$(jq -c -n --argjson b "$bad" '{offered: $b}')"
		fi
	fi
	if [ "$provider" = "null" ]; then
		record "provider host refusal recorded" failed '{"why":"no new row for api.anthropic.com"}'
	else
		pid=$(jq '.id' <<<"$provider")
		poffer=$(offer_for "$pid")
		# Stored as allow-list-miss: the reason must be provider_host. Stored
		# as provider-host (a host list that already passed it): rule_not_offerable.
		# The offer's explain flag (tracker F-013, the card branches on it)
		# is true exactly for a rule the host list could lift.
		want="provider_host"
		want_explain="true"
		if [ "$(jq -r '.rule' <<<"$provider")" != "allow-list-miss" ]; then
			want="rule_not_offerable"
			want_explain="false"
		fi
		if [ "$(jq -r '.offerable' <<<"$poffer")" = "false" ] && [ "$(jq -r '.reason' <<<"$poffer")" = "$want" ] &&
			[ "$(jq -r '.explain // false' <<<"$poffer")" = "$want_explain" ]; then
			record "provider host is never offered" passed "$(jq -c -n --argjson r "$provider" --argjson o "$poffer" '{row: $r, offer: $o}')"
		else
			record "provider host is never offered" failed "$(jq -c -n --argjson r "$provider" --argjson o "$poffer" --arg w "$want" '{row: $r, offer: $o, want: $w}')"
		fi
	fi
else
	record "non-offerable refusals are not offered" skipped null
	record "provider host is never offered" skipped null
fi

# 3. A write without the confirm token is refused and changes nothing.
if [ "$miss_id" != "0" ]; then
	code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -d "{\"refusal_id\":$miss_id}" "$offers")
	still=$(offer_for "$miss_id")
	if [ "$code" = "403" ] && [ "$(jq -r '.offerable' <<<"$still")" = "true" ]; then
		record "a write without the confirm token is refused" passed "{\"status\":$code}"
	else
		record "a write without the confirm token is refused" failed "{\"status\":$code,\"offer\":$still}"
	fi
fi

# 4. The owner applies it from the dashboard; the offer is then spent.
echo
echo "== 4. apply"
echo "Open the dashboard Terminals page, find $host under Refused connections and click"
echo "\"Allow this host\". Check the preview names only egress_allow_hosts and says the allow"
echo "covers every sandboxed run on this computer, then click Save."
if [ "$miss_id" != "0" ] && wait_enter "Once it is saved"; then
	after=$(offer_for "$miss_id")
	if [ "$(jq -r '.reason' <<<"$after")" = "already_allowed" ]; then
		record "the applied offer is spent" passed "$after"
	else
		record "the applied offer is spent" failed "$after"
	fi
else
	record "the applied offer is spent" skipped null
fi

# 5. A new run reaches the host and records no refusal for it.
before=$(newest_id)
echo
echo "== 5. a new run"
echo "Launch a NEW sandboxed terminal (a run already open keeps its old list). Inside run:"
echo "  curl -sS -o /dev/null -w '%{http_code}\\n' -x \"\$HTTPS_PROXY\" https://$host/"
echo "It must print an HTTP status from $host (200 for example.com), not a refusal."
if wait_enter "Once it has printed the status"; then
	sleep 2
	row=$(row_for "$host" "$before")
	if [ "$row" = "null" ]; then
		record "the next run reaches the host" passed null
	else
		record "the next run reaches the host" failed "$row"
	fi
else
	record "the next run reaches the host" skipped null
fi

overall=$(jq -r 'if all(.[]; .status == "passed") then "passed" else "failed" end' <<<"$results")
jq -n --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg machine "$machine" --arg host "$host" --arg status "$overall" --argjson steps "$results" \
	'{id: "N5-L1", machine: $machine, at: $at, host: $host, status: $status, steps: $steps}' >"$receipt"
echo
echo "N5-L1: $overall. Receipt written to $receipt"
echo "Remove $host from the host allow-list again on the Terminals settings card if you do not want to keep it."
[ "$overall" = "passed" ]
