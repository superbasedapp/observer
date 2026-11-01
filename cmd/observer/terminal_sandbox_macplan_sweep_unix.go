//go:build unix && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// D-MU7: a Seatbelt helper killed with SIGKILL never runs its deferred
// cleanup, so its plan file (~/.observer/sandbox-seatbelt/plans/<run>.json)
// and the run dirs the plan names ($TMPDIR/obsbx/<run> and
// $TMPDIR/obsbx-tmp/<run>) stayed behind for good. The helper now holds an
// exclusive lock on its plan file for its whole life (lockMacPlan); the
// sweep below, run at daemon start and at every fresh Seatbelt probe, takes
// that lock without waiting on every plan older than macPlanSweepGrace: a
// plan whose lock it gets belongs to a run that is not live, and the sweep
// removes the dirs it names, then the plan. A dir is removed only when it
// sits directly under one of Observer's own run roots, is named after the
// run, is a real directory (never a link, which is not followed) and is
// owned by this user.

// macPlanSweepGrace keeps a plan the daemon just wrote, whose helper may not
// have started and locked it yet, out of the sweep.
const macPlanSweepGrace = 2 * time.Minute

// macPlanMaxBytes caps how much of a plan the sweep reads.
const macPlanMaxBytes = 4 << 20

// lockMacPlan takes the helper's lifetime lock on its plan file: an
// exclusive, non-blocking flock on a descriptor opened without following a
// link. The returned release closes the descriptor (the lock goes with it,
// and with the process on any exit).
func lockMacPlan(p string) (func(), error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the helper's own plan path, read and checked before
	if err != nil {
		return nil, fmt.Errorf("lock plan: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		_ = f.Close()
		return nil, fmt.Errorf("lock plan: another helper holds it: %w", err)
	}
	return func() { _ = f.Close() }, nil
}

// macRunDirRoots are the parents a macOS driver puts run dirs under (the
// candidates macDirsFor picks from), resolved: the sweep removes nothing
// outside them.
func macRunDirRoots() []string {
	base := filepath.Clean(os.TempDir())
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	return []string{
		filepath.Join(base, "obsbx"),
		filepath.Join(base, "obsbx-tmp"),
		macShortSocketParentPrefix + strconv.Itoa(os.Getuid()),
	}
}

// sweepStaleMacPlans removes the plans of driver's runs that are not live,
// with the run dirs each names, and reports how many plans it cleared.
func sweepStaleMacPlans(observerDir, driver string, roots []string, now time.Time) (int, error) {
	dir := filepath.Join(macStateDir(observerDir, driver), "plans")
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("sweep %s plans: %w", driver, err)
	}
	n := 0
	for _, e := range entries {
		runID, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !e.Type().IsRegular() || !sandboxrelay.ValidRunID(runID) {
			continue
		}
		if clearStaleMacPlan(filepath.Join(dir, e.Name()), runID, roots, now) {
			n++
		}
	}
	return n, nil
}

// clearStaleMacPlan clears one plan when its run is not live.
func clearStaleMacPlan(path, runID string, roots []string, now time.Time) bool {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a plan name under the driver's own state dir
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || !ownedByMe(fi) || now.Sub(fi.ModTime()) < macPlanSweepGrace {
		return false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		return false // its helper lives
	}
	var plan struct {
		Dirs macRunDirs `json:"dirs"`
	}
	b, rerr := io.ReadAll(io.LimitReader(f, macPlanMaxBytes+1))
	if rerr == nil && len(b) <= macPlanMaxBytes && json.Unmarshal(b, &plan) == nil {
		for _, d := range []string{plan.Dirs.TempDir, plan.Dirs.SocketDir} {
			removeMacRunDir(d, runID, roots)
		}
	}
	_ = os.Remove(path) //nolint:gosec // G703: the plan this sweep just proved stale
	return true
}

// removeMacRunDir removes dir when it is one of runID's run dirs: directly
// under one of roots, named runID, a real directory this user owns, under a
// root that is itself a real directory this user owns. Anything else is
// left alone.
func removeMacRunDir(dir, runID string, roots []string) {
	if dir == "" || !filepath.IsAbs(dir) {
		return
	}
	dir = filepath.Clean(dir)
	if filepath.Base(dir) != runID {
		return
	}
	parent := filepath.Dir(dir)
	inRoots := false
	for _, r := range roots {
		if filepath.Clean(r) == parent {
			inRoots = true
			break
		}
	}
	if !inRoots || !ownedRealDir(parent) || !ownedRealDir(dir) {
		return
	}
	// RemoveAll removes a link inside the tree as a link; it never
	// follows one.
	_ = os.RemoveAll(dir) //nolint:gosec // G703: a proven run dir of a run that is not live
}

// ownedRealDir reports whether p is a directory (not a link) this user owns.
func ownedRealDir(p string) bool {
	fi, err := os.Lstat(p) //nolint:gosec // G703: a metadata read of a candidate run dir
	return err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && ownedByMe(fi)
}

// sweepStaleSeatbeltPlans is the daemon-start and probe-time sweep of the
// Seatbelt plans whose helper is gone (D-MU7); it logs what it cleared.
func sweepStaleSeatbeltPlans(observerDir string, logger *slog.Logger) {
	if observerDir == "" {
		return
	}
	n, err := sweepStaleMacPlans(observerDir, seatbeltDriverName, macRunDirRoots(), time.Now())
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("terminal_sandbox: sweeping the plans of ended Seatbelt runs", "cleared", n, "err", err)
	} else if n > 0 {
		logger.Info("terminal_sandbox: removed the plans and run dirs of ended Seatbelt runs", "runs", n)
	}
}

func init() {
	sandboxDaemonStartHooks = append(sandboxDaemonStartHooks, func(observerDir string) {
		go sweepStaleSeatbeltPlans(observerDir, slog.Default())
	})
}
