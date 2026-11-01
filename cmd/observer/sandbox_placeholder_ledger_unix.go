//go:build (linux || darwin) && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// sandbox_placeholder_ledger_unix.go is the host helper's record of the
// protected-path placeholders it created (Linux live re-check on the Docker
// sandbox 2026-10-23, N3). The helper removes its placeholders on its own
// exit (startHostServices' undo); a helper killed with SIGKILL cannot, and
// its read-only .git placeholder stayed in a non-git workspace for good,
// where every later launch then saw a .git. The ledger is the proof a later
// sweep needs that Observer made a placeholder: <runs>/<run>.placeholders
// under the observer directory (which no box can reach), held under an
// exclusive lock for the helper's whole life like the run's liveness lock
// (internal/sandboxrelayd alive.go), naming each placeholder with the inode
// the helper made and the body it wrote. The daemon's start sweep clears a
// ledger nobody holds, and with it each named placeholder that is still that
// inode with that body (removePlaceholders' own rule), and only a body
// sandbox.PlaceholderContent gives that path or an empty directory. A real
// .git (a directory git wrote into, a config git replaced) is never removed.
//
// The macOS host helper (terminal_sandbox_macdriver_darwin.go, the Seatbelt
// and Apple container rows) keeps the same ledger in the same format under
// the same rule since lane LEFT-SBX (ledger SBX-MAC-4): a SIGKILLed Apple
// helper used to leave its inert placeholders in the host .git for good.
// Each OS's helper turns what it created into ledger entries
// (sandbox_placeholder_ledger_linux.go, _darwin.go); the sweep and its
// removal rule (removeLedgerPlaceholders) are this one file.

// placeholderLedgerSuffix names a run's ledger under the runs dir.
const placeholderLedgerSuffix = ".placeholders"

// placeholderLedgerVersion is the ledger's format version.
const placeholderLedgerVersion = 1

// placeholderLedgerMaxBytes caps what the sweep reads of one ledger.
const placeholderLedgerMaxBytes = 1 << 20

// placeholderLedgerTempMaxAge is how old a temporary ledger (a helper killed
// between creating and renaming it) must be before the sweep removes it.
const placeholderLedgerTempMaxAge = time.Minute

// placeholderLedgerFile is the ledger's body.
type placeholderLedgerFile struct {
	V       int                      `json:"v"`
	Entries []placeholderLedgerEntry `json:"entries"`
}

// placeholderLedgerEntry is one created placeholder (createdPlaceholder).
type placeholderLedgerEntry struct {
	Path    string `json:"path"`
	Dir     bool   `json:"dir,omitempty"`
	Dev     uint64 `json:"dev"`
	Ino     uint64 `json:"ino"`
	Content []byte `json:"content,omitempty"`
}

// placeholderLedger is a helper's open, locked ledger.
type placeholderLedger struct {
	f    *os.File
	path string
}

// placeholderLedgerPath is runID's ledger under observerDir.
func placeholderLedgerPath(observerDir, runID string) string {
	return filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+placeholderLedgerSuffix)
}

// openPlaceholderLedger creates runID's ledger, locked: made under a
// temporary name, locked, then renamed, so a ledger at its final name is
// never one a starting helper has not locked yet. It returns nil with no
// error when the helper has no observer directory (no relay), so there is
// nowhere outside the box to record.
func openPlaceholderLedger(observerDir, runID string) (*placeholderLedger, error) {
	if observerDir == "" {
		return nil, nil
	}
	if !sandboxrelay.ValidRunID(runID) {
		return nil, fmt.Errorf("placeholder ledger: run id %q", runID)
	}
	dir := sandboxrelayd.RunsDir(observerDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("placeholder ledger: %w", err)
	}
	final := placeholderLedgerPath(observerDir, runID)
	tmp := filepath.Join(dir, "."+runID+placeholderLedgerSuffix)
	_ = os.Remove(tmp)                                                                    //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G703: under the 0700 runs dir; runID passed ValidRunID
	if err != nil {
		return nil, fmt.Errorf("placeholder ledger: %w", err)
	}
	fail := func(err error) (*placeholderLedger, error) {
		_ = f.Close()
		_ = os.Remove(tmp) //nolint:gosec // G703: as above
		return nil, fmt.Errorf("placeholder ledger: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		return fail(err)
	}
	if err := os.Rename(tmp, final); err != nil { //nolint:gosec // G703: as above
		return fail(err)
	}
	return &placeholderLedger{f: f, path: final}, nil
}

// recordEntries writes the entries the helper created into its ledger (a
// nil ledger records nothing).
func (l *placeholderLedger) recordEntries(entries []placeholderLedgerEntry) error {
	if l == nil {
		return nil
	}
	led := placeholderLedgerFile{V: placeholderLedgerVersion, Entries: append([]placeholderLedgerEntry{}, entries...)}
	b, err := json.Marshal(led)
	if err != nil {
		return fmt.Errorf("placeholder ledger: %w", err)
	}
	if err := l.f.Truncate(0); err != nil {
		return fmt.Errorf("placeholder ledger: %w", err)
	}
	if _, err := l.f.WriteAt(b, 0); err != nil {
		return fmt.Errorf("placeholder ledger: %w", err)
	}
	return l.f.Sync()
}

// close removes the ledger and drops its lock: the helper's own exit, after
// it removed its placeholders itself.
func (l *placeholderLedger) close() {
	if l == nil {
		return
	}
	_ = os.Remove(l.path) //nolint:gosec // G703: the ledger this helper created
	_ = l.f.Close()
}

// sweepStalePlaceholders clears the ledger of every helper that is gone (its
// ledger exists and nobody holds the lock) and the placeholders it proves,
// and removes temporary ledgers older than placeholderLedgerTempMaxAge that
// nobody holds (they name nothing: entries are written after the rename).
// It reports how many ledgers it cleared.
func sweepStalePlaceholders(observerDir string, now time.Time) (int, error) {
	dir := sandboxrelayd.RunsDir(observerDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("sweep placeholders: %w", err)
	}
	n := 0
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), placeholderLedgerSuffix)
		if !ok || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if rest, temp := strings.CutPrefix(id, "."); temp {
			if fi, ierr := e.Info(); ierr == nil && sandboxrelay.ValidRunID(rest) && now.Sub(fi.ModTime()) >= placeholderLedgerTempMaxAge {
				_ = clearStaleLedger(path, false)
			}
			continue
		}
		if sandboxrelay.ValidRunID(id) && clearStaleLedger(path, true) {
			n++
		}
	}
	return n, nil
}

// clearStaleLedger takes the ledger's lock without waiting: held means its
// helper lives and the ledger is left alone. Taken, the ledger's proven
// placeholders are removed (when apply) and the ledger with them. A ledger
// that is not this user's private regular file is never read; one that does
// not parse proves nothing and is removed with every placeholder left.
func clearStaleLedger(path string, apply bool) bool {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a ledger name under the 0700 runs dir
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		return false
	}
	if apply {
		b, rerr := io.ReadAll(io.LimitReader(f, placeholderLedgerMaxBytes+1))
		var led placeholderLedgerFile
		if rerr == nil && len(b) <= placeholderLedgerMaxBytes && json.Unmarshal(b, &led) == nil && led.V == placeholderLedgerVersion {
			removeLedgerPlaceholders(provenPlaceholders(led.Entries))
		}
	}
	_ = os.Remove(path) //nolint:gosec // G703: as above
	return true
}

// provenPlaceholders keeps the entries the helper can have made: a clean
// absolute path that is an empty-bodied directory, or a file whose body is
// the one sandbox.PlaceholderContent gives that path (so a ledger can never
// name, say, a source file of the user's to remove).
func provenPlaceholders(entries []placeholderLedgerEntry) []placeholderLedgerEntry {
	var out []placeholderLedgerEntry
	for _, e := range entries {
		if !filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path {
			continue
		}
		if e.Dir && len(e.Content) != 0 {
			continue
		}
		if !e.Dir && !bytes.Equal(e.Content, sandbox.PlaceholderContent(e.Path)) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// removeLedgerPlaceholders removes each proven entry that is still the inode
// the helper made and still holds what it was created with (a file with the
// same bytes, an empty directory), last created first. Anything changed
// since (git writing into a placeholder .git, an atomic replace) is left in
// place. It is the Linux helper's own removal rule (removePlaceholders),
// shared by both helpers' sweeps.
func removeLedgerPlaceholders(entries []placeholderLedgerEntry) {
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		dev, ino, size, ok := placeholderInode(e.Path)
		if !ok || dev != e.Dev || ino != e.Ino {
			continue
		}
		if e.Dir {
			_ = os.Remove(e.Path) //nolint:gosec // G703: a proven placeholder; fails and keeps the dir unless it is empty
			continue
		}
		if size != int64(len(e.Content)) {
			continue
		}
		b, err := os.ReadFile(e.Path) //nolint:gosec // G304: a proven placeholder path
		if err != nil || !bytes.Equal(b, e.Content) {
			continue
		}
		_ = os.Remove(e.Path) //nolint:gosec // G703: as above
	}
}

// placeholderInode is path's device, inode and size, not following a final
// symlink.
func placeholderInode(path string) (dev, ino uint64, size int64, ok bool) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), st.Size, true //nolint:unconvert,gosec // Dev is int32 on darwin, uint64 on linux/amd64; a device number is never negative
}

// sweepStaleSandboxPlaceholders is the daemon-start sweep of the placeholders
// killed helpers left behind (N3); it logs what it cleared.
func sweepStaleSandboxPlaceholders(observerDir string, logger *slog.Logger) {
	if observerDir == "" {
		return
	}
	n, err := sweepStalePlaceholders(observerDir, time.Now())
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn("terminal_sandbox: sweeping the placeholders of killed sandbox helpers", "cleared", n, "err", err)
	} else if n > 0 {
		logger.Info("terminal_sandbox: removed the placeholders of killed sandbox helpers", "runs", n)
	}
}
