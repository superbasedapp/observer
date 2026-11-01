# Observer's microVM guest image set

The recipe for the guest image set the `cloud-hypervisor` sandbox row boots
(sandbox plan v2 sections 12.3 and 13 P4, lane SBX-P4, ledger SBX-BE-4):
a pinned distro kernel, a small initramfs, a read-only ext4 rootfs and its
dm-verity hash tree. It holds no agent CLI and no agent runtime (D-751 Q38);
the agent arrives through the first-start install cache (off by default) or
not at all.

| File | What it is |
|---|---|
| `recipe.env` | Every input, pinned: one dated Ubuntu archive snapshot, the kernel, modules and busybox debs by version and sha256, the rootfs packages by version, the initramfs module list |
| `build.sh` | The rootless build (`mmdebstrap --mode=unshare`, `mkfs.ext4 -d`, `veritysetup format`, a reproducible `cpio`), writing `build/` |
| `init` | The initramfs `/init` (busybox applets only, through `$B`): loads the modules in load order (a module that does not load stops the boot), opens the rootfs under the signed verity root hash from the kernel command line, mounts the run's boot share and hands PID 1 to the verified guest observer's `sandbox-vm-init` |
| `selfcheck.sh` | The build-time check `build.sh` runs before packing: every busybox applet `/init` needs, `veritysetup` and its loader, every module a plain `.ko` after its dependencies, and every required module (`reed_solomon` included) loaded or built in; any finding fails the build |
| `recipecheck.sh` | The input checks `build.sh` runs (added after the first live build, 2026-10-24): every pinned version is in one of the snapshot's pockets (`POCKETS`, the security pocket included) before anything is fetched, the built rootfs holds exactly the pinned versions, and the static busybox is found where the package ships it (`usr/bin/busybox`) and refused when it names a program interpreter |
| `sbom-input.md` | How the SBOM is generated from the build's package list |
| `debug/` | The debug variant (R-016, never shipped): `build.sh --debug` adds the guest-helper kill and guest-root remount hooks for live checks LIN-5 and LIN-8; signed only with `vendorsign -debug` and a throwaway key, imported only with `--debug-set` and `--debug-key`. See `debug/README.md` |

## Build and sign

```
deploy/sandbox-vm-image/build.sh --out /tmp/vmset
go run ./scripts/vendorsign sandboxrootfs -build /tmp/vmset/build \
    -recipe-dir deploy/sandbox-vm-image -version 1.0.0 -min-version 1.0.0 \
    -commit <full commit> -source-date-epoch <epoch> -out /tmp/vmset/out
go run ./scripts/vendorsign sandboxguest -binary amd64=bin/observer-linux-amd64 \
    -version <agent version> -commit <full commit> -out /tmp/vmset/out
```

Without `-key` both verbs write the unsigned descriptor and files and stop
at the signing seam `sandbox_vm_signing_key_missing`: no node accepts an
unsigned set. With the vendor key (`internal/update/vendorkey.go`, release
step only, operator ruling P-126) they write `manifest.json` for
`sandbox.rootfs` and `sandbox.guest_binary`. The output directory is the
layout `observer sandbox content import <dir>` takes.

Hosting (P-126): the set and the guest binary are assets of the public
Observer GitHub release, with a small signed index on superbased.app. An
organization's content mirror does not carry the rootfs set or the guest
binary yet (it carries the container image manifest only). Nothing is
published from this lane. A test signs with a key generated in the test.

## What the guest does at boot

The kernel command line is a fixed table (`sandboxvm.Cmdline`): the serial
console, `ro`, `init=/init`, the verity root hash, the boot share tag, the
run id and the vsock port. `/init` never waits for a network (the VM has no
NIC; a network-online wait costs 120 s). `sandbox-vm-init` becomes PID 1,
checks its own mounts (the shared in-guest check), mounts tmpfs on the
writable paths, listens on AF_VSOCK and serves the run.

## Live check

The image is built and booted only on a host with `/dev/kvm` (P-124): see
`docs/plans/spikes/JSP-5-cloud-hypervisor-2026-10.md` for the owed sequence.
The build runs as root on Ubuntu hosts where
`kernel.apparmor_restrict_unprivileged_userns = 1` blocks
`mmdebstrap --mode=unshare` for users (first live build, 2026-10-24); it
also needs curl, cpio, dpkg-deb, binutils (readelf), kmod, zstd, xz-utils
and awk.
