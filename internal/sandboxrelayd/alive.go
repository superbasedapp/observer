package sandboxrelayd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// alive.go is a run's liveness lock (plans decision log P-040, lane
// sbx-p2d): the host helper holds an exclusive advisory lock on
// <runs>/<run>.alive for its whole life, and the kernel drops it when the
// helper exits in any way, SIGKILL included. A helper killed that way cannot
// remove its run record, so the daemon's sweep reads the lock: a lock file
// that exists and that nobody holds means the helper is gone, and the run
// ends there and then (its session claims released, its record removed),
// with no daemon restart.
//
// The lock file only ever appears under its final name already locked (it
// is made under a temporary name, locked, then renamed), so a lock the
// daemon can take is never one a starting helper has not taken yet. A run
// with no lock file at all (a helper from before this change, or one that
// could not take it) keeps the earlier rule: it lives while its record does.

// aliveSuffix names a run's lock file.
const aliveSuffix = ".alive"

// alivePath is runID's lock file under observerDir.
func alivePath(observerDir, runID string) string {
	return filepath.Join(RunsDir(observerDir), runID+aliveSuffix)
}

// HoldRun takes runID's liveness lock for the calling process (the host
// helper) and returns its release, which removes the lock file. The lock
// lasts until release or until the process exits. Off unix it is not
// offered (the relay ships only where bwrap runs).
func HoldRun(observerDir, runID string) (func(), error) {
	if !sandboxrelay.ValidRunID(runID) {
		return nil, ErrBadRecord
	}
	return holdAlive(RunsDir(observerDir), runID)
}

// errAliveNotOffered is HoldRun's error on a platform with no liveness lock
// (neither unix nor Windows); a test may skip on it and on nothing else.
var errAliveNotOffered = errors.New("not offered on this platform")

// DropRunLock releases runID's liveness lock that this process holds
// through HoldRun, leaving the lock file in place, so the daemon's sweep
// reads the helper as gone exactly as for a killed helper (a container
// helper that keeps its container through a daemon hangup and waits for
// the next start's offer, LEFT2 audit S4). The release HoldRun returned
// still removes the file. No-op when this process holds no such lock.
func DropRunLock(observerDir, runID string) {
	if !sandboxrelay.ValidRunID(runID) {
		return
	}
	dropAlive(alivePath(observerDir, runID))
}

// RunLive reports whether runID's helper is alive: it holds its liveness
// lock, or, when the run has no lock file, its run record still exists (the
// earlier rule). A lock file nobody holds is a helper that is gone.
func RunLive(observerDir, runID string) bool {
	if !sandboxrelay.ValidRunID(runID) {
		return false
	}
	switch helperOf(observerDir, runID) {
	case helperHeld:
		return true
	case helperGone:
		return false
	}
	_, err := ReadRun(observerDir, runID)
	return err == nil
}

// LiveRunIDs lists the run ids whose helper still holds its liveness lock
// (RunLive is true), for a caller that needs to know whether any other run
// is live, such as the Windows shared-station box-entry cleanup (WINFIX4
// audit finding 3). An unreadable runs directory yields none.
func LiveRunIDs(observerDir string) []string {
	entries, err := os.ReadDir(RunsDir(observerDir))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		id, ok := strings.CutSuffix(e.Name(), aliveSuffix)
		if !ok || !sandboxrelay.ValidRunID(id) {
			continue
		}
		if helperOf(observerDir, id) == helperHeld {
			out = append(out, id)
		}
	}
	return out
}

// helperState is what a run's liveness lock says about its helper.
type helperState int

const (
	// helperUnknown: no lock file (or it cannot be read): the record
	// decides.
	helperUnknown helperState = iota
	// helperHeld: the helper holds the lock.
	helperHeld
	// helperGone: the lock file exists and nobody holds it.
	helperGone
)

// helperOf reads runID's liveness lock.
func helperOf(observerDir, runID string) helperState {
	return probeAlive(alivePath(observerDir, runID))
}

// PruneDeadRuns removes the record and the lock file of every run whose
// helper is gone (its lock file exists and nobody holds it), and reports how
// many runs it removed. The daemon runs it at start and on every sweep, so
// a helper killed with SIGKILL leaves nothing behind for long. A temporary
// lock file (".<run>.alive") that a helper killed between creating and
// renaming it left behind is removed too once nobody holds it and it is
// older than aliveTempMaxAge (it is not counted: it names no run).
func PruneDeadRuns(observerDir string) (int, error) {
	pruned, err := PruneDeadRunRecords(observerDir)
	return len(pruned), err
}

// PruneDeadRunRecords is PruneDeadRuns returning the removed records, each
// read just before its removal (only its RunID when it could not be read),
// so the caller can end what the run left behind: the stored terminal run
// of a launcher killed together with its helper (live check 2026-10-22,
// D7).
func PruneDeadRunRecords(observerDir string) ([]RunRecord, error) {
	dir := RunsDir(observerDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("sandboxrelayd.PruneDeadRuns: %w", err)
	}
	now := time.Now()
	var pruned []RunRecord
	for _, e := range entries {
		if pruneAliveTemp(dir, e, now) {
			continue
		}
		name := e.Name()
		id, ok := strings.CutSuffix(name, aliveSuffix)
		if !ok || !e.Type().IsRegular() || !sandboxrelay.ValidRunID(id) {
			continue
		}
		if helperOf(observerDir, id) != helperGone {
			continue
		}
		rec, rerr := ReadRun(observerDir, id)
		if rerr != nil {
			rec = RunRecord{RunID: id}
		}
		if err := RemoveRun(observerDir, id); err != nil {
			continue
		}
		_ = os.Remove(alivePath(observerDir, id))
		pruned = append(pruned, rec)
	}
	return pruned, nil
}

// aliveTempMaxAge is how old a temporary lock file must be before the sweep
// may remove it: a starting helper holds the name for microseconds (create,
// lock, rename), so one this old that nobody holds was left by a helper
// killed in between, never one still starting.
const aliveTempMaxAge = time.Minute

// pruneAliveTemp removes e when it is a stale temporary lock file (older
// than aliveTempMaxAge, and nobody holds it); it reports whether e is a
// temporary lock file at all (a run id never starts with a dot).
func pruneAliveTemp(dir string, e os.DirEntry, now time.Time) bool {
	rest, ok := strings.CutPrefix(e.Name(), ".")
	if !ok {
		return false
	}
	id, ok := strings.CutSuffix(rest, aliveSuffix)
	if !ok || !sandboxrelay.ValidRunID(id) {
		return false
	}
	if !e.Type().IsRegular() {
		return true
	}
	fi, err := e.Info()
	if err != nil || now.Sub(fi.ModTime()) < aliveTempMaxAge {
		return true
	}
	path := filepath.Join(dir, e.Name())
	if probeAlive(path) == helperGone {
		_ = os.Remove(path) //nolint:gosec // G703: under the 0700 runs dir; the id passed ValidRunID
	}
	return true
}
