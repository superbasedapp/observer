//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_mxc_boxsweep.go removes the box folders of runs that are
// no longer live (Windows 11 Pro run 3 RERUN2, D4): a run whose helper is
// killed with its console window (the operator closing a WIN-8b window,
// STATUS_CONTROL_C_EXIT) never reaches the helper's own cleanup, and its
// observer-sbx-<run> folder stayed in TEMP. The helper writes an owner file
// into every box folder it makes; the daemon's sweep (at the relay's start
// and every mxcBoxSweepEvery) removes a folder only when that file says it
// is this Observer home's and names the folder's own run, and that run's
// helper is gone. A folder is never recognised by its name alone, and a
// folder another Observer home made (an isolated test home shares TEMP) is
// never touched.

// mxcBoxOwnerFile is the owner file's name in a box folder. The box folder
// itself is read-only inside the box (only its tmp, localappdata and config
// subfolders are writable), so a box cannot write or replace it.
const mxcBoxOwnerFile = "observer-sbx.owner"

// mxcBoxOwnerMax bounds the owner file read.
const mxcBoxOwnerMax = 4 << 10

// mxcBoxSweepEvery is how often the daemon sweeps box folders.
const mxcBoxSweepEvery = 10 * time.Minute

// mxcBoxOwner is the owner file's content.
type mxcBoxOwner struct {
	V           int    `json:"v"`
	RunID       string `json:"run_id"`
	ObserverDir string `json:"observer_dir"`
}

// writeMXCBoxOwner writes boxDir's owner file, owner-only and new.
func writeMXCBoxOwner(boxDir, runID, observerDir string) error {
	b, err := json.Marshal(mxcBoxOwner{V: 1, RunID: runID, ObserverDir: filepath.Clean(observerDir)})
	if err != nil {
		return err
	}
	f, err := fsatomic.CreateOwnerOnly(filepath.Join(boxDir, mxcBoxOwnerFile))
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// mxcBoxSweepVerdict is what the sweep decided for one folder.
type mxcBoxSweepVerdict string

const (
	mxcSweepRemove      mxcBoxSweepVerdict = "remove"
	mxcSweepNotABox     mxcBoxSweepVerdict = "not a box folder of Observer's (no valid owner file)"
	mxcSweepOtherHome   mxcBoxSweepVerdict = "another Observer home's box folder"
	mxcSweepLive        mxcBoxSweepVerdict = "its run is live"
	mxcSweepNotAFolder  mxcBoxSweepVerdict = "not a plain folder"
	mxcSweepNameNoMatch mxcBoxSweepVerdict = "the owner file names another run"
)

// mxcJudgeBoxDir decides one candidate folder (dir, under the temp folder,
// named mxcBoxDirPrefix + something). The rows are walked in order; the
// first that refuses wins.
func mxcJudgeBoxDir(dir, observerDir string, live func(runID string) bool) mxcBoxSweepVerdict {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return mxcSweepNotAFolder
	}
	owner, ok := readMXCBoxOwner(filepath.Join(dir, mxcBoxOwnerFile))
	if !ok || owner.V != 1 || !sandboxrelay.ValidRunID(owner.RunID) {
		return mxcSweepNotABox
	}
	if filepath.Base(dir) != mxcBoxDirPrefix+owner.RunID {
		return mxcSweepNameNoMatch
	}
	if !mxcSamePath(owner.ObserverDir, observerDir) {
		return mxcSweepOtherHome
	}
	if live(owner.RunID) {
		return mxcSweepLive
	}
	return mxcSweepRemove
}

// mxcSamePath compares two absolute paths, case-insensitively on Windows.
func mxcSamePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// readMXCBoxOwner reads an owner file: a regular file (never a link), at
// most mxcBoxOwnerMax bytes, holding one owner record.
func readMXCBoxOwner(path string) (mxcBoxOwner, bool) {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > mxcBoxOwnerMax {
		return mxcBoxOwner{}, false
	}
	f, err := os.Open(path) //nolint:gosec // G304: a box folder's owner file, checked to be a regular file just above
	if err != nil {
		return mxcBoxOwner{}, false
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, mxcBoxOwnerMax))
	if err != nil {
		return mxcBoxOwner{}, false
	}
	var o mxcBoxOwner
	if json.Unmarshal(b, &o) != nil {
		return mxcBoxOwner{}, false
	}
	return o, true
}

// mxcSweepStaleBoxDirs removes, under tmp, every box folder whose owner file
// is this Observer home's (observerDir) and whose run is not live. It
// returns the folders removed and the removal errors joined.
func mxcSweepStaleBoxDirs(tmp, observerDir string, live func(runID string) bool) ([]string, error) {
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tmp, err)
	}
	var removed []string
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), mxcBoxDirPrefix) {
			continue
		}
		dir := filepath.Join(tmp, e.Name())
		if mxcJudgeBoxDir(dir, observerDir, live) != mxcSweepRemove {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			errs = append(errs, err)
			continue
		}
		removed = append(removed, dir)
	}
	return removed, errors.Join(errs...)
}

// mxcBoxRunLive is the sweep's liveness rule: the run's helper holds its
// liveness lock, or, with no lock file, its run record still exists.
func mxcBoxRunLive(observerDir string) func(string) bool {
	return func(runID string) bool { return sandboxrelayd.RunLive(observerDir, runID) }
}

// mxcStartBoxSweep sweeps now and every mxcBoxSweepEvery until ctx ends.
func mxcStartBoxSweep(ctx context.Context, observerDir string, logger *slog.Logger) {
	sweep := func() {
		removed, err := mxcSweepStaleBoxDirs(os.TempDir(), observerDir, mxcBoxRunLive(observerDir))
		if len(removed) > 0 {
			logger.Info("sandbox: removed the box folders of runs that are no longer live", "count", len(removed), "folders", strings.Join(removed, ", "))
		}
		if err != nil {
			logger.Warn("sandbox: a stale box folder could not be removed", "err", err)
		}
	}
	sweep()
	go func() {
		t := time.NewTicker(mxcBoxSweepEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sweep()
			}
		}
	}()
}

func init() { sandboxRelayStartHooks = append(sandboxRelayStartHooks, mxcStartBoxSweep) }
