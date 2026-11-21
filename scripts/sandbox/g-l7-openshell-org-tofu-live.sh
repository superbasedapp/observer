#!/usr/bin/env bash
# g-l7-openshell-org-tofu-live.sh: live check G-L7 of the org-hosted
# OpenShell gateway: the OpenTofu modules with openshell_gateway = true
# (lane G5; docs/plans/openshell/build/g1-design.md sections 2.3 and
# 11.6). No apply in this build.
#
# Machine: the operator's workstation with OpenTofu (tofu) on PATH and
# network access to the provider registry. Optionally, with --plan
# MODULE --var-file FILE, one `tofu plan` in an account the operator
# already uses (their own credentials, from their own environment; this
# script never reads them and never applies).
#
# It copies deploy/modules into a throwaway dir (so nothing is written
# into the checkout) and, for every root module (compact and appliance, on
# Azure and AWS: app, data and bootstrap), runs `tofu init
# -backend=false`, `tofu validate` and `tofu test` (the modules' own
# tests/*.tftest.hcl, mock providers; the openshell_gateway = true runs
# are among them), plus one `tofu fmt -check -recursive` over the tree.
# Each is a check in the receipt. It asks before it starts (--yes skips
# the question) and removes the copy on exit.
#
# Usage:
#   scripts/sandbox/g-l7-openshell-org-tofu-live.sh [--out DIR] [--yes]
#       [--plan compact/azure/app --var-file FILE]
#
# Receipt: g-l7-openshell-org-tofu-<UTC stamp>.json
# shellcheck disable=SC2329
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=scripts/sandbox/g-l-steps.sh
. "$HERE/g-l-steps.sh"
st_init G-L7 "observer-g-l7-live/1" g-l7-openshell-org-tofu
COPY=""
cleanup() {
	local rc=$?
	[ -n "$COPY" ] && rm -rf -- "$COPY"
	st_finish "$rc"
}
trap cleanup EXIT

PLAN_MODULE=""
VAR_FILE=""
while [ $# -gt 0 ]; do
	if st_common_args "$1"; then
		shift
		continue
	fi
	case "$1" in
	--out) OUT="$2"; shift ;;
	--plan) PLAN_MODULE="$2"; shift ;;
	--var-file) VAR_FILE="$2"; shift ;;
	*) st_refuse "unknown argument $1" ;;
	esac
	shift
done
[ -d "$OUT" ] && [ -w "$OUT" ] || OUT="$HOME"
command -v tofu >/dev/null || st_refuse "tofu is not on PATH"
R[tofu_version]="$(tofu version 2>/dev/null | head -n1)"
if [ -n "$PLAN_MODULE" ]; then
	case "$PLAN_MODULE" in compact/azure/* | compact/aws/* | appliance/azure/* | appliance/aws/*) ;; *) st_refuse "--plan names a root module such as compact/azure/app" ;; esac
	[ -f "$VAR_FILE" ] || st_refuse "--plan needs --var-file FILE (the operator's own tfvars, with openshell_gateway = true)"
fi

echo "G-L7 copies deploy/modules into a throwaway dir and runs tofu init (downloads providers), validate, test and fmt -check."
[ -n "$PLAN_MODULE" ] && echo "It then runs ONE tofu plan of $PLAN_MODULE with your credentials and $VAR_FILE. It never applies."
if [ "$YES" != 1 ]; then
	printf 'Proceed? [y/N] '
	read -r a || a=""
	case "$a" in y | Y | yes) ;; *) st_refuse "the operator declined" ;; esac
fi

COPY="$(mktemp -d)"
cp -R "$ROOT/deploy/modules" "$COPY/modules"
M="$COPY/modules"

if out="$(tofu fmt -check -recursive "$M" 2>&1)"; then
	st_judge fmt pass "tofu fmt -check -recursive"
else
	st_judge fmt fail "$(printf '%s' "$out" | tr '\n' ' ' | head -c 300)"
fi

for mod in compact/azure compact/aws appliance/azure appliance/aws; do
	for part in app data bootstrap; do
		d="$M/$mod/$part"
		id="$(printf '%s_%s' "$mod" "$part" | tr '/' '_')"
		[ -d "$d" ] || {
			st_judge "$id" not_run "no module at $mod/$part"
			continue
		}
		if ! out="$(cd "$d" && tofu init -backend=false -input=false 2>&1)"; then
			st_judge "${id}_init" fail "$(printf '%s' "$out" | tail -n 3 | tr '\n' ' ' | head -c 300)"
			continue
		fi
		if out="$(cd "$d" && tofu validate -no-color 2>&1)"; then
			st_judge "${id}_validate" pass "$(printf '%s' "$out" | tail -n 1)"
		else
			st_judge "${id}_validate" fail "$(printf '%s' "$out" | tail -n 3 | tr '\n' ' ' | head -c 300)"
		fi
		if ls "$d"/tests/*.tftest.hcl >/dev/null 2>&1; then
			if out="$(cd "$d" && tofu test -no-color 2>&1)"; then
				st_judge "${id}_test" pass "$(printf '%s' "$out" | tail -n 1)"
			else
				st_judge "${id}_test" fail "$(printf '%s' "$out" | grep -E 'fail|Error' | head -n 3 | tr '\n' ' ' | head -c 300)"
			fi
		else
			st_judge "${id}_test" not_run "no tests/*.tftest.hcl"
		fi
	done
done

if [ -n "$PLAN_MODULE" ]; then
	d="$M/$PLAN_MODULE"
	vf="$(cd "$(dirname "$VAR_FILE")" && pwd)/$(basename "$VAR_FILE")"
	if out="$(cd "$d" && tofu init -backend=false -input=false >/dev/null 2>&1 && tofu plan -no-color -input=false -lock=false -var openshell_gateway=true -var-file="$vf" 2>&1)"; then
		st_judge plan pass "$(printf '%s' "$out" | grep -E '^Plan:' | head -n1)"
	else
		st_judge plan fail "$(printf '%s' "$out" | grep -E 'Error' | head -n 2 | tr '\n' ' ' | head -c 300)"
	fi
else
	R[plan]="not run (no --plan given; optional)"
fi

R[completed]=1
[ "$FAIL" = 0 ] && exit 0
exit 1
