#!/usr/bin/env bash
# recipecheck.sh: the guest image recipe's input self-checks (lane SBX-P4;
# added after the first live build on 2026-10-24, findings R1 to R3).
# build.sh runs each and stops on any finding:
#
#   pins <index dir> <name=version...>
#       every pinned package version is in one of the pockets' Packages
#       indexes (one plain-text index per file in <index dir>, named
#       <pocket>_<component>, which build.sh fetches from the snapshot
#       before anything else); a pin found in none is named with the
#       versions each index has (R1: a ca-certificates version the
#       snapshot does not have; R2: a git version only in the security
#       pocket, which was not a source).
#   installed <packages.tsv> <name=version...>
#       the built rootfs holds exactly the pinned versions.
#   busybox <unpacked busybox-static deb>
#       prints the static busybox's path (usr/bin/busybox in the merged
#       /usr package, bin/busybox in an older one) and refuses one that
#       names a program interpreter (R3: the build copied a fixed
#       bin/busybox the package does not ship).
#
# mmdebstrap still verifies every package it installs against the
# archive's signed Release files; these checks only name a bad pin early.
set -uo pipefail
check=${1:-}
[ $# -gt 0 ] && shift
fail=0
bad() {
	echo "recipecheck: $*" >&2
	fail=1
}
case "$check" in
pins)
	idx=${1:?usage: recipecheck.sh pins <index dir> <name=version...>}
	shift
	for pin in "$@"; do
		name=${pin%%=*}
		want=${pin#*=}
		found=0
		have=""
		for f in "$idx"/*; do
			[ -f "$f" ] || continue
			vers=$(awk -v n="$name" 'BEGIN { RS = ""; FS = "\n" } {
				p = ""; v = ""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) p = substr($i, 10)
					if ($i ~ /^Version: /) v = substr($i, 10)
				}
				if (p == n) print v
			}' "$f")
			while IFS= read -r v; do
				[ -n "$v" ] || continue
				have="$have $(basename "$f")=$v"
				[ "$v" = "$want" ] && found=1
			done <<<"$vers"
		done
		[ "$found" = 1 ] || bad "$name=$want is in none of the pockets' indexes (they have:${have:- no $name})"
	done
	;;
installed)
	tsv=${1:?usage: recipecheck.sh installed <packages.tsv> <name=version...>}
	shift
	for pin in "$@"; do
		name=${pin%%=*}
		want=${pin#*=}
		got=$(awk -F '\t' -v n="$name" '$1 == n { print $2 }' "$tsv")
		[ "$got" = "$want" ] || bad "the rootfs holds $name ${got:-(not installed)}, the recipe pins $want"
	done
	;;
busybox)
	root=${1:?usage: recipecheck.sh busybox <unpacked busybox-static deb>}
	for c in usr/bin/busybox bin/busybox; do
		f=$root/$c
		[ -f "$f" ] && [ ! -L "$f" ] || continue
		if ! readelf -h "$f" >/dev/null 2>&1; then
			bad "$c is not an ELF executable"
		elif readelf -l "$f" 2>/dev/null | grep -q 'program interpreter'; then
			bad "$c names a program interpreter: it is not the static busybox"
		else
			echo "$f"
		fi
		exit $fail
	done
	bad "no busybox at usr/bin/busybox or bin/busybox under $root"
	;;
*)
	echo "usage: recipecheck.sh pins|installed|busybox ..." >&2
	exit 2
	;;
esac
exit $fail
