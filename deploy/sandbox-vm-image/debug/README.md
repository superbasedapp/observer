# The debug image set (never shipped)

A variant of the microVM guest image set for the live checks that need a
root-side hook inside the guest (R-016): LIN-5 (killing the guest helper
ends the run and offers native resume) and LIN-8 (every read-only root
stays read-only, also against guest root's remount attempts). It is built
from the same pinned recipe (`../recipe.env`) plus this directory, and it
is never shipped:

- `vendorsign sandboxrootfs -debug` signs only a build `build.sh --debug`
  made (it writes `build/debug`), only with a throwaway key (it refuses any
  key this tree's agents accept as a vendor key), marks the signed
  descriptor `"debug": true` and writes `debug-key.pub` beside the kinds;
  a debug build is never signed as a release set.
- `observer sandbox content import` refuses a debug set unless both
  `--debug-set` and `--debug-key <debug-key.pub>` are given. With both it
  verifies the set against that key alone (never the vendor keys), takes
  only `sandbox.rootfs` and `sandbox.guest_binary`, and records the key
  owner-only in the content store (`debug-image-set.key`). A release set
  imported later removes it.
- The driver boots a debug set only when both kinds verify under the
  recorded key and the descriptor says debug (`debug_set` otherwise, in
  either direction); `observer sandbox content status` says "DEBUG image
  set (never shipped)".

| File | What it is |
|---|---|
| `recipe-debug.env` | The variant's values, read after `../recipe.env`: the hooks' directory in the rootfs and the trigger directory |
| `init-wrapper` | The debug PID 1 hand-over: the debug `/init` switch_roots here; it starts `debugd` and execs the guest observer's `sandbox-vm-init` with the same arguments (still PID 1) |
| `debugd` | The root-side watcher: waits for the guest's `/tmp` tmpfs, creates `/tmp/observer-debug` (1777) and the root-only `/tmp/.observer-debug-work` with `mkdir` (it refuses to start when either already exists, so a planted directory or link is never chmodded) and runs a fixed hook when a file named after it appears there; a hook's output is written in the work directory and renamed over `<hook>.out`, so a link planted there is replaced, never written through; a trigger's content is never read |
| `remount-root` | LIN-8's hook, run as guest root: tries `mount -o remount,rw` on every read-only mount and a witness write and rename on each; every line must say refused |
| `selfcheck-debug.sh` | The build-time checks: the debug rootfs holds every hook as a 0755 regular file, and the debug `/init` is the release `/init` with PID 1 handed to `init-wrapper` and nothing else |

## Build, sign and import (on the KVM box)

```
deploy/sandbox-vm-image/build.sh --debug --out /tmp/vmdbg
go run ./scripts/vendorsign keygen -out /tmp/vmdbg/key   # a throwaway key; it prints the key file's path
go run ./scripts/vendorsign sandboxrootfs -debug -key <that key file> -manifest-version 1 \
    -build /tmp/vmdbg/build -recipe-dir deploy/sandbox-vm-image \
    -recipe-path deploy/sandbox-vm-image/debug/recipe-debug.env -version 1.0.0 -min-version 1.0.0 \
    -commit <full commit> -source-date-epoch <epoch> -out /tmp/vmdbg/out
go run ./scripts/vendorsign sandboxguest -debug -key <that key file> -manifest-version 1 \
    -binary amd64=bin/observer-linux-amd64 -version <agent version> -commit <full commit> -out /tmp/vmdbg/out
observer sandbox content import --debug-set --debug-key /tmp/vmdbg/out/debug-key.pub /tmp/vmdbg/out
```

Shred the throwaway key after the run (never put it in
`internal/update/vendorkey.go`: `keygen`'s closing advice is for a vendor
key rotation and does not apply here).

## The checks

From a shell in the sandboxed run (the dashboard's plain shell is enough):

- LIN-5: `touch /tmp/observer-debug/kill-guest-helper`. The run must end
  and offer native resume; `/tmp/observer-debug/kill-guest-helper.out` is
  written just before the guest goes down.
- LIN-8: `touch /tmp/observer-debug/remount-root`, then read
  `/tmp/observer-debug/remount-root.out`: every remount, write and rename
  line must say `refused`. A line saying `ALLOWED` is a finding.
