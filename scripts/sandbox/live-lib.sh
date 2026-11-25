# shellcheck shell=bash
# live-lib.sh: helpers shared, word for word, by the openshell row's live
# checks (o1b-openshell-live.sh, which o2-openshell-managed-live.sh runs,
# o3-openshell-egress-live.sh, o4-org-live.sh, o5-adversarial-live.sh and
# o5-wsl2-expected-failure.sh). Sourced by them, never run alone.
#
# Only helpers whose text was identical in every script that had them live
# here. The variants that differ on purpose stay in their scripts:
# json_escape (bash-only in o3 and o5, python3 in o1b and o4), judge and
# write_receipt (each script's receipt path and fields), osh and
# list_boxes.
#
# The functions read the sourcing script's globals when they run: R (the
# receipt fields), FAIL, EXIT_CODE and INSTALL_ID_FILE.

# not_run NAME REASON records a check that could not be judged (what it
# needed never happened) as not_run with the reason, never as a fail of the
# thing it checks. The run still does not pass: a check did not run.
not_run() {
	R["check.$1"]="not_run"
	R["check.$1.detail"]="$2"
	FAIL=1
}
# refuse REASON records a precondition the host does not meet and exits 2;
# the script's EXIT trap writes the receipt.
refuse() {
	R[refused]="$1"
	echo "refused: $1" >&2
	EXIT_CODE=2
	exit 2
}
# install_id prints this run's install id ("" before the driver minted it).
install_id() {
	[ -f "$INSTALL_ID_FILE" ] || return 0
	tr -d '\n' <"$INSTALL_ID_FILE" 2>/dev/null || true
}
# The managed (private) gateway's names for this install (lane O2: name
# observer-<12 hex>, unit observer-openshell-gateway-<12 hex>.service, CLI
# registry in the private RAM dir); "" before the install id exists.
gw_short() { local id; id="$(install_id)"; printf '%s' "${id:0:12}"; }
gw_name() { [ -n "$(gw_short)" ] && printf 'observer-%s' "$(gw_short)"; }
gw_unit() { [ -n "$(gw_short)" ] && printf 'observer-openshell-gateway-%s.service' "$(gw_short)"; }
gw_rtdir() { [ -n "$(gw_short)" ] && printf '%s/observer-openshell-%s' "${XDG_RUNTIME_DIR:-/nonexistent}" "$(gw_short)"; }
# tree_digest prints a digest of a directory tree's names, modes, sizes
# and contents ("absent" when it does not exist); it never prints a
# content.
tree_digest() {
	[ -e "$1" ] || { echo absent; return 0; }
	(cd "$1" && find . -printf '%p %m %s\n' 2>/dev/null | sort && find . -type f -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum 2>/dev/null) | sha256sum | cut -c1-16
}
