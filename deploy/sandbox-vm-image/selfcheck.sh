#!/usr/bin/env bash
# selfcheck.sh: the build-time check of the guest initramfs tree (lane
# SBX-P4, audit finding 4). build.sh runs it before packing and fails the
# build on any finding:
#
#   - /init calls every program through busybox ($B <applet>), the only
#     other program being /sbin/veritysetup, and busybox --list has every
#     applet /init names plus the ones it always needs;
#   - /sbin/veritysetup and the dynamic loader are there;
#   - every module in /etc/observer-modules is a plain ELF .ko (never
#     .ko.zst: busybox insmod cannot load one) and comes after every module
#     its modinfo depends= line names;
#   - every required module (the arguments) is either loaded from the list
#     or recorded in /etc/observer-builtin as built into the kernel.
#
# Usage: selfcheck.sh <initramfs dir> [required module...]
set -uo pipefail
ird=${1:?usage: selfcheck.sh <initramfs dir> [required module...]}
shift
fail=0
bad() {
	echo "selfcheck: $*" >&2
	fail=1
}
norm() { echo "$1" | tr - _; }

# The applets /init always needs.
required_applets="cat mkdir mount umount insmod poweroff switch_root"

init=$ird/init
bb=$ird/bin/busybox
[ -f "$init" ] || bad "there is no /init"
[ -x "$bb" ] || bad "there is no executable /bin/busybox"
[ -x "$ird/sbin/veritysetup" ] || bad "there is no executable /sbin/veritysetup"
[ -e "$ird/lib64/ld-linux-x86-64.so.2" ] || bad "there is no dynamic loader for veritysetup"

if [ -f "$init" ] && [ -x "$bb" ]; then
	have=$("$bb" --list 2>/dev/null)
	used=$(grep -v '^[[:space:]]*#' "$init" | grep -oE '\$B [a-z_]+' | awk '{print $2}')
	for a in $(printf '%s\n' $required_applets $used | sort -u); do
		printf '%s\n' "$have" | grep -qx "$a" || bad "busybox has no applet $a, which /init needs"
	done
	# A command run without $B does not exist in a busybox-only initramfs.
	bare=$(grep -v '^[[:space:]]*#' "$init" | grep -nE '(^|[;|&(]|\$\()[[:space:]]*(cat|mkdir|mount|umount|insmod|modprobe|poweroff|reboot|switch_root|sleep|ls|grep|sed|awk|cp|mv|rm|ln|chmod|tr|head|tail)([[:space:]]|$)')
	[ -z "$bare" ] || bad "/init runs a command without \$B: $bare"
fi

list=$ird/etc/observer-modules
builtin=$ird/etc/observer-builtin
seen=" "
if [ ! -f "$list" ]; then
	bad "there is no /etc/observer-modules"
else
	while IFS= read -r m; do
		[ -n "$m" ] || continue
		f=$ird/lib/modules/$m.ko
		if [ ! -f "$f" ]; then
			bad "the module $m is listed but $m.ko is not in /lib/modules"
			continue
		fi
		if [ "$(head -c4 "$f" | od -An -c | tr -d ' ')" != '177ELF' ]; then
			bad "$m.ko is not a plain ELF module (compressed modules cannot be loaded by busybox insmod)"
		fi
		deps=$(tr '\0' '\n' <"$f" | grep -m1 -a '^depends=' | cut -d= -f2-)
		for d in $(echo "$deps" | tr ',' ' '); do
			case "$seen" in
			*" $(norm "$d") "*) ;;
			*) bad "the module $m is loaded before its dependency $d" ;;
			esac
		done
		seen="$seen$(norm "$m") "
	done <"$list"
fi
for r in "$@"; do
	case "$seen" in
	*" $(norm "$r") "*) continue ;;
	esac
	if [ -f "$builtin" ] && tr - _ <"$builtin" | grep -qx "$(norm "$r")"; then
		continue
	fi
	bad "the required module $r is neither in the initramfs nor built into the kernel"
done
exit $fail
