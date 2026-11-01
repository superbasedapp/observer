package sandboxvm

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// virtiofsd.go composes a share's virtiofsd argv (lane SBX-P4 decisions 5
// and 6). A copy's or the boot share's virtiofsd runs unprivileged with
// --sandbox none (P-097: 1.13.2 works that way). A live workspace's
// virtiofsd runs inside a bwrap mount namespace that enforces the git-dir
// execution paths on the HOST: the WorkspaceExecState overlays bound
// read-only, every GitDirExecParents pin (and .git itself) bound onto
// itself, so a rename from the guest, as guest root too, is EBUSY and a
// write is EROFS; nothing the guest does to its own mounts can change
// what virtiofsd serves (guest root can remount anything inside the VM,
// which is why no in-guest overlay protects anything). Only
// /usr/bin/bwrap and /usr/libexec/virtiofsd run there (the AppArmor
// user-namespace profile names those two paths).

// VirtiofsdCache is every share's virtiofsd cache mode. The guest executes
// programs from its shares (the guest observer from the boot share, an
// agent's tools from the workspace), and with --cache=never every file is
// opened direct-I/O, so the 6.8 guest kernel cannot map one to execute it:
// exec gives EFAULT ("switch_root: can't execute
// '/run/observer-boot/observer-guest': Bad address", then a kernel panic).
// --cache=auto executed the same ELF and script (EM live run 2026-10-24,
// em3 b6: never fails both, auto runs both). auto changes no permission:
// the read-only binds and the pins are the host's mounts, which the guest
// cannot reach through any cache, and the confined virtiofsd's mountinfo is
// still read back before and after boot.
const VirtiofsdCache = "auto"

// VirtiofsdArgv is an unconfined share's virtiofsd.
func VirtiofsdArgv(bin, socket, dir string) ([]string, error) {
	for _, p := range []string{bin, socket, dir} {
		if !cleanAbs(p) {
			return nil, fmt.Errorf("sandboxvm: %q is not a clean absolute path", p)
		}
	}
	return []string{bin, "--socket-path=" + socket, "--shared-dir=" + dir, "--sandbox=none", "--cache=" + VirtiofsdCache}, nil
}

// ConfinedShare is a live share's confined virtiofsd.
type ConfinedShare struct {
	Bwrap, Virtiofsd string
	Socket, Dir      string
	// ReadOnlyPaths are bound read-only (the exec-state files and dirs);
	// Pins are bound onto themselves (a mount point: no rename).
	ReadOnlyPaths []string
	Pins          []string
}

// The only programs a confined share runs.
const (
	ConfinedBwrap     = "/usr/bin/bwrap"
	ConfinedVirtiofsd = "/usr/libexec/virtiofsd"
)

// ConfinedVirtiofsdArgv is the bwrap argv around virtiofsd for a live
// share: the host root read-only, /dev and /proc fresh, the share
// read-write, then the pins (parents first) and the read-only paths on
// top, so a read-only path inside a pinned directory stays read-only.
func ConfinedVirtiofsdArgv(c ConfinedShare) ([]string, error) {
	if c.Bwrap != ConfinedBwrap || c.Virtiofsd != ConfinedVirtiofsd {
		return nil, errors.New("sandboxvm: a confined share runs only " + ConfinedBwrap + " and " + ConfinedVirtiofsd)
	}
	for _, p := range append([]string{c.Socket, c.Dir}, append(append([]string(nil), c.ReadOnlyPaths...), c.Pins...)...) {
		if !cleanAbs(p) {
			return nil, fmt.Errorf("sandboxvm: %q is not a clean absolute path", p)
		}
	}
	for _, p := range append(append([]string(nil), c.ReadOnlyPaths...), c.Pins...) {
		if !within(p, c.Dir) {
			return nil, fmt.Errorf("sandboxvm: %s is outside the share %s", p, c.Dir)
		}
	}
	argv := []string{
		c.Bwrap, "--die-with-parent", "--unshare-user", "--unshare-pid", "--unshare-ipc",
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc",
		"--bind", c.Dir, c.Dir, "--bind", dirOf(c.Socket), dirOf(c.Socket),
	}
	pins := append([]string(nil), c.Pins...)
	sort.Slice(pins, func(i, j int) bool {
		return depth(pins[i]) < depth(pins[j]) || depth(pins[i]) == depth(pins[j]) && pins[i] < pins[j]
	})
	for _, p := range pins {
		argv = append(argv, "--bind", p, p)
	}
	ro := append([]string(nil), c.ReadOnlyPaths...)
	sort.Slice(ro, func(i, j int) bool {
		return depth(ro[i]) < depth(ro[j]) || depth(ro[i]) == depth(ro[j]) && ro[i] < ro[j]
	})
	for _, p := range ro {
		argv = append(argv, "--ro-bind", p, p)
	}
	argv = append(argv, "--", c.Virtiofsd, "--socket-path="+c.Socket, "--shared-dir="+c.Dir, "--sandbox=none", "--cache="+VirtiofsdCache)
	return argv, nil
}

func dirOf(p string) string {
	i := strings.LastIndexByte(p, '/')
	if i <= 0 {
		return "/"
	}
	return p[:i]
}

func depth(p string) int { return strings.Count(p, "/") }

// ConfinedReadBack judges the confined virtiofsd's own mount table
// (/proc/<pid>/mountinfo, parsed by the shared guest-mount parser) against
// the plan: every pin is a mount point and every read-only path a
// read-only mount, not covered by a later mount. Anything less refuses the
// live share (source_unsupported, naming why) before the VM boots.
func ConfinedReadBack(c ConfinedShare, shortfalls []string) Verdict {
	if len(shortfalls) > 0 {
		return refuse(VerdictSourceUnsupported, "the confined virtiofsd for the live workspace read back weaker than planned: "+strings.Join(shortfalls, "; ")+"; the VM was not booted")
	}
	return pass()
}

// ConfinedReadBackAfterBoot is ConfinedReadBack repeated while the VM runs,
// from the same timer and event loop as the vm.info read-back (vm.add-fs
// hotplug and the host's own mount changes both exist): any shortfall now
// means the live share is no longer what was planned under a running guest,
// so the run ends with built_below_plan.
func ConfinedReadBackAfterBoot(c ConfinedShare, shortfalls []string) Verdict {
	if len(shortfalls) > 0 {
		return refuse(VerdictBuiltBelowPlan, "the confined virtiofsd for the live workspace read back weaker than planned after boot: "+strings.Join(shortfalls, "; ")+"; the run was ended")
	}
	return pass()
}

// ConfinedExpectations are what ConfinedReadBack checks: the pins and the
// share as mounts, the read-only paths as read-only.
func ConfinedExpectations(c ConfinedShare) (mounts, ro []string) {
	mounts = append(append([]string{c.Dir}, c.Pins...), c.ReadOnlyPaths...)
	return mounts, append([]string(nil), c.ReadOnlyPaths...)
}
