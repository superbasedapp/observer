//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_sweep_linux.go is the microVM orphan sweep (lane
// SBX-P4 decision 6): in the daemon, at the driver's first passing probe
// and at a later refresh, every run state dir under
// <observer dir>/sandbox-vm/runs is judged by sandboxvm.SweepRun: a run
// whose process record a live helper still holds, or that is under a live
// relay record, is never touched; otherwise each recorded process whose
// /proc start time and executable still match is killed (a reused pid is
// spared), and the run's dir goes with its sockets (api.sock and its lock,
// the vsock socket and its <socket>_<port> listeners, the namespace-mode
// virtiofsd's .pid files, never read) and disk copies. Placeholders are
// cleared by the shared ledger sweep at daemon start.

// vmSweepEnv is the sweep's I/O.
type vmSweepEnv struct {
	facts     func(pid int) sandboxvm.ProcFacts
	kill      func(pid int) error
	relayLive func(runID string) bool
	held      func(lockPath string) bool
}

// vmRealSweepEnv is the sweep over this host.
func vmRealSweepEnv(observerDir string) vmSweepEnv {
	_, _ = sandboxrelayd.PruneDeadRuns(observerDir)
	return vmSweepEnv{
		facts: vmProcFacts,
		kill:  func(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) },
		relayLive: func(runID string) bool {
			_, err := sandboxrelayd.ReadRun(observerDir, runID)
			return err == nil
		},
		held: vmLockHeld,
	}
}

// vmLockHeld reports whether a live helper holds the record's lock (the
// lock file missing means no helper ever held it).
func vmLockHeld(p string) bool {
	f, err := os.OpenFile(p, os.O_RDWR|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a fixed name in a run state dir
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		return errors.Is(err, unix.EWOULDBLOCK)
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec // G115: a descriptor number
	return false
}

// vmSweepResult is what one sweep did.
type vmSweepResult struct {
	Killed  []int
	Removed []string
	Spared  []string
}

// vmSweepRuns sweeps every run dir under observerDir.
func vmSweepRuns(observerDir string, env vmSweepEnv) (vmSweepResult, error) {
	var out vmSweepResult
	runs := filepath.Join(vmStateRoot(observerDir), "runs")
	ents, err := os.ReadDir(runs)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	for _, e := range ents {
		if !e.IsDir() || !tokenLikeVM(e.Name()) {
			continue
		}
		dir := filepath.Join(runs, e.Name())
		rec := sandboxvm.ProcRecord{RunID: e.Name()}
		if b, err := os.ReadFile(filepath.Join(dir, sandboxvm.ProcRecordName)); err == nil { //nolint:gosec // G304: a fixed name in a run state dir
			if r, perr := sandboxvm.ParseProcRecord(b); perr == nil && r.RunID == e.Name() {
				rec = r
			}
		}
		d := sandboxvm.SweepRun(sandboxvm.SweepInput{
			Record: rec, Held: env.held(filepath.Join(dir, sandboxvm.ProcRecordName+".lock")),
			RelayLive: env.relayLive(e.Name()), Facts: env.facts,
		})
		for _, pid := range d.Kill {
			if err := env.kill(pid); err == nil {
				out.Killed = append(out.Killed, pid)
			}
		}
		out.Spared = append(out.Spared, d.Spared...)
		if d.RemoveDir {
			if err := os.RemoveAll(dir); err == nil { //nolint:gosec // G703: a run dir under the driver's own state root
				out.Removed = append(out.Removed, e.Name())
			}
			// The run's short VM socket dir, when its state dir was too deep,
			// and its whole host-services socket dir under either parent
			// (relay.sock and launch.json with the box secret; the first
			// live run found it left after a SIGKILL, D8).
			for _, parent := range append([]string{vmShortSocketRoot()}, vmHostSocketParents()...) {
				vmRemoveOwnedRunDir(filepath.Join(parent, e.Name()))
			}
		}
	}
	return out, nil
}

// vmRemoveOwnedRunDir removes a run's socket dir when it is a directory
// (not a link) this user owns.
func vmRemoveOwnedRunDir(dir string) {
	if fi, err := os.Lstat(dir); err == nil && fi.IsDir() && ownedByMe(fi) { //nolint:gosec // G703: a run-id dir under one of this row's own socket parents
		_ = os.RemoveAll(dir) //nolint:gosec // G703: a run-id dir under one of this row's own socket parents
	}
}

// tokenLikeVM accepts a run dir name as a plain token.
func tokenLikeVM(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// vmSweep is the daemon's sweep.
func vmSweep(observerDir string) {
	_, _ = vmSweepRuns(observerDir, vmRealSweepEnv(observerDir))
}
