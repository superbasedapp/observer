#!/usr/bin/env bash
# selfcheck-debug.sh: the debug variant's build-time check (R-016).
#
#   selfcheck-debug.sh rootfs ROOTFS_DIR   the debug rootfs holds every hook
#                                          as a regular 0755 file (owned by
#                                          the unshare build's root, like the
#                                          rest of the rootfs)
#   selfcheck-debug.sh init INIT           the debug /init differs from the
#                                          release one only in handing PID 1
#                                          to init-wrapper
#
# build.sh --debug runs both before it packs; any finding fails the build.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=recipe-debug.env
. "$here/recipe-debug.env"
case "${1:-}" in
rootfs)
	root=$2
	rc=0
	for f in init-wrapper debugd remount-root; do
		p="$root$DEBUG_ROOTFS_DIR/$f"
		if [ ! -f "$p" ] || [ -L "$p" ]; then
			echo "selfcheck-debug: $DEBUG_ROOTFS_DIR/$f is missing from the debug rootfs" >&2
			rc=1
			continue
		fi
		mode=$(stat -c %a "$p")
		[ "$mode" = 755 ] || { echo "selfcheck-debug: $DEBUG_ROOTFS_DIR/$f is mode $mode, want 755" >&2; rc=1; }
	done
	exit $rc
	;;
init)
	got=$2
	want=$(sed "s|switch_root /newroot /run/observer-boot/observer-guest|switch_root /newroot $DEBUG_ROOTFS_DIR/init-wrapper /run/observer-boot/observer-guest|" "$here/../init")
	if [ "$want" = "$(cat "$got")" ] && ! cmp -s "$got" "$here/../init"; then
		exit 0
	fi
	echo "selfcheck-debug: the debug /init is not the release /init with PID 1 handed to init-wrapper" >&2
	exit 1
	;;
esac
echo "usage: selfcheck-debug.sh rootfs DIR | init FILE" >&2
exit 2
