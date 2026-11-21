#!/usr/bin/env bash
# build.sh: builds Observer's microVM guest image set from recipe.env
# (lane SBX-P4, ledger SBX-BE-4), rootless. Output, under --out:
#
#   build/vmlinuz          the pinned distro kernel, unpacked from its deb
#   build/initrd.img       busybox, veritysetup and its libraries, the
#                          virtio-fs, vsock and dm-verity modules (with
#                          their dependency closure from modules.dep,
#                          decompressed to plain .ko), ./init; checked by
#                          selfcheck.sh before it is packed
#   build/rootfs.img       the read-only ext4 rootfs (mkfs.ext4 -d, no root)
#   build/rootfs.verity    its dm-verity hash tree (veritysetup format)
#   build/root-hash        the verity root hash (64 hex)
#   build/packages.tsv     the rootfs's packages (the SBOM's input)
#   build/kernel.tsv       the kernel package, version and deb sha256
#
# Then `vendorsign sandboxrootfs -build <out>/build ...` writes the
# descriptor, the SBOM and (with the vendor key, at the release step only)
# the signed sandbox.rootfs manifest. Every input is pinned in recipe.env;
# a checksum mismatch stops the build. Nothing here fetches latest.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=
debug=false
while [ $# -gt 0 ]; do
	case "$1" in
	--out) out=$2; shift 2 ;;
	# --debug builds the debug variant (debug/README.md, R-016): the
	# guest-helper kill and guest-root remount hooks for the live checks.
	# Never shipped; vendorsign signs it only with -debug.
	--debug) debug=true; shift ;;
	*) echo "build.sh: unknown argument $1" >&2; exit 2 ;;
	esac
done
[ -n "$out" ] || { echo "build.sh: --out DIR is required" >&2; exit 2; }
# shellcheck source=recipe.env
. "$here/recipe.env"
if [ "$debug" = true ]; then
	# shellcheck source=debug/recipe-debug.env
	. "$here/debug/recipe-debug.env"
fi
for tool in mmdebstrap mkfs.ext4 veritysetup cpio dpkg-deb gzip sha256sum readelf depmod zstd xz curl awk; do
	command -v "$tool" >/dev/null || { echo "build.sh: $tool is required" >&2; exit 2; }
done
mkdir -p "$out/build" "$out/work"
work=$out/work
build=$out/build
rm -f "$build/debug"
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$here" log -1 --format=%ct 2>/dev/null || echo 0)}

fetch() { # fetch FILE SHA256 DEST
	curl -fsSL --proto '=https' --max-filesize $((256 << 20)) -o "$3" "$SNAPSHOT_MIRROR/$1"
	echo "$2  $3" | sha256sum -c --quiet - || { echo "build.sh: $1 does not match its pinned sha256" >&2; exit 1; }
}
# The recipe's pins against the snapshot's own indexes, before anything is
# fetched: each name=version must be in one of the pockets
# (recipecheck.sh pins names a pin found in none, with what each pocket
# has). mmdebstrap still verifies every package against the signed Release.
rm -rf "$work/index"
mkdir -p "$work/index"
for pocket in $POCKETS; do
	for comp in $(echo "$COMPONENTS" | tr ',' ' '); do
		curl -fsSL --proto '=https' --max-filesize $((256 << 20)) "$SNAPSHOT_MIRROR/dists/$pocket/$comp/binary-$ARCH/Packages.xz" | xz -dc >"$work/index/${pocket}_$comp"
	done
done
# shellcheck disable=SC2086
"$here/recipecheck.sh" pins "$work/index" $ROOTFS_PACKAGES "$KERNEL_PKG=$KERNEL_VERSION" "$MODULES_PKG=$MODULES_VERSION" "$BUSYBOX_PKG=$BUSYBOX_VERSION" ||
	{ echo "build.sh: a pinned package version is not in the snapshot's pockets ($POCKETS)" >&2; exit 1; }
fetch "$KERNEL_FILE" "$KERNEL_SHA256" "$work/kernel.deb"
fetch "$MODULES_FILE" "$MODULES_SHA256" "$work/modules.deb"
fetch "$BUSYBOX_FILE" "$BUSYBOX_SHA256" "$work/busybox.deb"
printf '%s\t%s\t%s\n' "$KERNEL_PKG" "$KERNEL_VERSION" "$KERNEL_SHA256" >"$build/kernel.tsv"

# The kernel: unpacked, never compiled.
rm -rf "$work/kernel" "$work/modules" "$work/busybox"
dpkg-deb -x "$work/kernel.deb" "$work/kernel"
dpkg-deb -x "$work/modules.deb" "$work/modules"
dpkg-deb -x "$work/busybox.deb" "$work/busybox"
cp "$work/kernel/boot/vmlinuz-$KERNEL_RELEASE" "$build/vmlinuz"

# The rootfs: one snapshot, every named package pinned by version, from
# every pocket the recipe names. A guest image never carries an agent CLI
# or runtime; the hook refuses one.
rm -rf "$work/rootfs"
sources=()
for pocket in $POCKETS; do
	sources+=("deb $SNAPSHOT_MIRROR $pocket $(echo "$COMPONENTS" | tr ',' ' ')")
done
# shellcheck disable=SC2086
mmdebstrap --mode=unshare --variant=minbase --arch="$ARCH" --components="$COMPONENTS" \
	--include="$(echo $ROOTFS_PACKAGES | tr ' ' ',')" \
	--customize-hook='chroot "$1" dpkg-query -W -f "\${Package}\t\${Version}\t\${Architecture}\n" > "$1/.packages.tsv"' \
	--customize-hook='if chroot "$1" sh -c "command -v node npm claude codex gemini" >/dev/null 2>&1; then echo "an agent CLI or runtime is in the rootfs" >&2; exit 1; fi' \
	--customize-hook='rm -rf "$1/var/cache/apt" "$1/var/lib/apt/lists"; mkdir -p "$1/run" "$1/tmp" "$1/home" "$1/workspace"' \
	--skip=output/dev \
	"$SUITE" "$work/rootfs" "${sources[@]}"
mv "$work/rootfs/.packages.tsv" "$build/packages.tsv"
if [ "$debug" = true ]; then
	# The debug hooks, read-only under dm-verity like the rest of the rootfs.
	mkdir -p "$work/rootfs$DEBUG_ROOTFS_DIR"
	for f in init-wrapper debugd remount-root; do
		install -m 0755 "$here/debug/$f" "$work/rootfs$DEBUG_ROOTFS_DIR/$f"
	done
	"$here/debug/selfcheck-debug.sh" rootfs "$work/rootfs" || { echo "build.sh: the debug rootfs self-check failed" >&2; exit 1; }
fi
# shellcheck disable=SC2086
"$here/recipecheck.sh" installed "$build/packages.tsv" $ROOTFS_PACKAGES ||
	{ echo "build.sh: the rootfs does not hold the pinned versions" >&2; exit 1; }
size_mb=$(( $(du -sm "$work/rootfs" | cut -f1) + 256 ))
rm -f "$build/rootfs.img"
mkfs.ext4 -q -F -d "$work/rootfs" -L observer-vm -E root_owner=0:0 -U clear -T default "$build/rootfs.img" "${size_mb}M"
veritysetup format --salt=$(printf '%064d' 0) "$build/rootfs.img" "$build/rootfs.verity" | awk '/^Root hash:/{print $3}' >"$build/root-hash"
grep -Eq '^[0-9a-f]{64}$' "$build/root-hash" || { echo "build.sh: no verity root hash" >&2; exit 1; }

# The initramfs: busybox, veritysetup and the libraries it links (from the
# rootfs this recipe built), the modules, ./init.
ird=$work/initramfs
rm -rf "$ird"
mkdir -p "$ird/bin" "$ird/sbin" "$ird/etc" "$ird/lib/modules" "$ird/dev" "$ird/proc" "$ird/sys" "$ird/newroot" "$ird/run"
# The static busybox wherever the package ships it (usr/bin/busybox in the
# merged-/usr package), checked static (recipecheck.sh busybox).
bb=$("$here/recipecheck.sh" busybox "$work/busybox") || { echo "build.sh: no static busybox in $BUSYBOX_PKG" >&2; exit 1; }
cp "$bb" "$ird/bin/busybox"
cp "$work/rootfs/usr/sbin/veritysetup" "$ird/sbin/veritysetup"
copylibs() { # the NEEDED closure of $1, resolved inside the rootfs
	readelf -d "$1" | awk '/NEEDED/{gsub(/[\[\]]/,"",$5); print $5}' | while read -r lib; do
		for dir in lib/x86_64-linux-gnu usr/lib/x86_64-linux-gnu lib64; do
			if [ -e "$work/rootfs/$dir/$lib" ] && [ ! -e "$ird/$dir/$lib" ]; then
				mkdir -p "$ird/$dir"
				cp -L "$work/rootfs/$dir/$lib" "$ird/$dir/$lib"
				copylibs "$ird/$dir/$lib"
			fi
		done
	done
}
copylibs "$ird/sbin/veritysetup"
mkdir -p "$ird/lib64"
cp -L "$work/rootfs/lib64/ld-linux-x86-64.so.2" "$ird/lib64/"
# The modules: each named module and its dependency closure from
# modules.dep (depmod over the unpacked tree, no root), in load order
# (dependencies first), decompressed to plain .ko because busybox insmod
# loads no .ko.zst. A module built into the kernel (modules.builtin) is
# recorded, not copied. A named module that is neither stops the build.
moddir=$work/modules/lib/modules/$KERNEL_RELEASE
depmod -b "$work/modules" "$KERNEL_RELEASE"
: >"$ird/etc/observer-modules"
: >"$ird/etc/observer-builtin"
norm() { echo "$1" | tr - _; }
declare -A modpath=() moddeps=() loaded=()
while IFS= read -r line; do
	f=${line%%:*}
	n=$(basename "$f"); n=${n%%.ko*}
	modpath[$(norm "$n")]=$f
	moddeps[$(norm "$n")]=${line#*:}
done <"$moddir/modules.dep"
addmod() { # addmod FILE: its dependencies first, then itself
	local f=$1 n d deps
	n=$(basename "$f"); n=${n%%.ko*}
	[ -z "${loaded[$(norm "$n")]:-}" ] || return 0
	loaded[$(norm "$n")]=1
	deps=${moddeps[$(norm "$n")]:-}
	# modules.dep lists a module's dependencies so that the last is loaded
	# first.
	for d in $(echo $deps | tr ' ' '\n' | tac); do addmod "$d"; done
	case "$f" in
	*.ko.zst) zstd -dq -o "$ird/lib/modules/$n.ko" "$moddir/$f" ;;
	*.ko.xz) xz -dc "$moddir/$f" >"$ird/lib/modules/$n.ko" ;;
	*.ko.gz) gzip -dc "$moddir/$f" >"$ird/lib/modules/$n.ko" ;;
	*.ko) cp "$moddir/$f" "$ird/lib/modules/$n.ko" ;;
	*) echo "build.sh: $f is not a kernel module" >&2; exit 1 ;;
	esac
	echo "$n" >>"$ird/etc/observer-modules"
}
for m in $INITRAMFS_MODULES; do
	k=$(norm "$m")
	if [ -n "${modpath[$k]:-}" ]; then
		addmod "${modpath[$k]}"
	elif grep -Eq "/$m\.ko(\.(zst|xz|gz))?$|/$k\.ko(\.(zst|xz|gz))?$" "$moddir/modules.builtin"; then
		echo "$m" >>"$ird/etc/observer-builtin"
	else
		echo "build.sh: the module $m is neither in $MODULES_PKG nor built into $KERNEL_PKG" >&2
		exit 1
	fi
done
if [ "$debug" = true ]; then
	# The release /init with PID 1 handed to the debug wrapper, nothing else.
	sed "s|switch_root /newroot /run/observer-boot/observer-guest|switch_root /newroot $DEBUG_ROOTFS_DIR/init-wrapper /run/observer-boot/observer-guest|" "$here/init" >"$ird/init"
	"$here/debug/selfcheck-debug.sh" init "$ird/init" || { echo "build.sh: the debug /init self-check failed" >&2; exit 1; }
else
	cp "$here/init" "$ird/init"
fi
chmod 0755 "$ird/init"
# The build-time self-check: every applet and module /init needs is there.
"$here/selfcheck.sh" "$ird" $INITRAMFS_MODULES || { echo "build.sh: the initramfs self-check failed" >&2; exit 1; }
(cd "$ird" && find . -print0 | LC_ALL=C sort -z | cpio --null --create --format=newc --reproducible --quiet | gzip -n -9) >"$build/initrd.img"
sha256sum "$build"/vmlinuz "$build"/initrd.img "$build"/rootfs.img "$build"/rootfs.verity
if [ "$debug" = true ]; then
	echo "debug image set (R-016), never shipped: sign only with vendorsign -debug and a throwaway key" >"$build/debug"
	echo "build.sh: the DEBUG guest image set is in $build (root hash $(cat "$build/root-hash")); sign it with vendorsign sandboxrootfs -debug -key <throwaway key>, never the vendor key"
	exit 0
fi
echo "build.sh: the guest image set is in $build (root hash $(cat "$build/root-hash")); sign it with vendorsign sandboxrootfs"
