//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_returns_sweep.go removes sandboxed runs' managed copies
// that are safe to remove (decision SBXD-2): by age, on the daemon's sandbox
// ticker (`[terminal.sandbox].returned_copy_retention_days`, default 30, 0
// off), and all at once on the person's click ("Remove all copies that are
// safe to remove" on the Changes from sandboxed runs panel). Both walk the
// one removal table a single click walks (removeSandboxCopy ->
// workspace.DecideCopyRemoval, the facts read again for each copy), so
// nothing is removed that a click on that copy would keep: a copy whose
// commits did not come back, that holds uncommitted or unignored files,
// whose run is live, or that could not be compared stays, with its reason.
// The sweep checks one capped batch per pass (the archival invariant: never
// loop until done) and logs every copy it removes;
// workspace_retention_days is not read here and keeps its meaning.

// sandboxCopySweepEvery is how often the age sweep runs (at daemon start,
// then on the first return tick past it); a variable for tests.
var sandboxCopySweepEvery = time.Hour

// The sweep's and the click's bounds.
const (
	// sandboxCopySweepBatch caps the copies one age pass checks (a check
	// hashes the copy's files, up to 4 GiB).
	sandboxCopySweepBatch = 5
	// sandboxCopySweepRecheck is how long a copy the table kept is left
	// before the sweep checks it again.
	sandboxCopySweepRecheck = 24 * time.Hour
	// sandboxCopyBulkMax caps the copies one click checks; past it the
	// panel says how many are left for another click.
	sandboxCopyBulkMax = 50
)

// sandboxCopyRemoveMu serializes the age sweep and the bulk click in this
// process (a single copy's own click is safe beside them: a removal of a
// copy already gone is a refusal, never a second delete).
var sandboxCopyRemoveMu sync.Mutex

// sandboxCopySweepRetention reads returned_copy_retention_days from the
// daemon's config (a variable so tests stand it in); -1 when the config
// does not load (the sweep then does nothing).
var sandboxCopySweepRetention = func(configPath string) int {
	if configPath == "" {
		configPath = daemonConfigPath()
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return -1
	}
	return cfg.Terminal.Sandbox.ReturnedCopyRetentionDays
}

// copySweeper is one observer dir's age sweep state: when it last ran and
// the copies it checked and kept (so a copy that holds work is not hashed
// again on every pass, and never starves the batch).
type copySweeper struct {
	mu   sync.Mutex
	last time.Time
	kept map[string]time.Time
}

// sandboxCopySweepers holds one sweeper per observer dir.
var sandboxCopySweepers sync.Map

// maybeSweepReturnedCopies runs the age sweep when it is due (called from
// the return loop, after each return sweep).
func maybeSweepReturnedCopies(ctx context.Context, observerDir string, now time.Time, logger *slog.Logger) {
	v, _ := sandboxCopySweepers.LoadOrStore(observerDir, &copySweeper{kept: map[string]time.Time{}})
	s := v.(*copySweeper)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.last.IsZero() && now.Sub(s.last) < sandboxCopySweepEvery {
		return
	}
	s.last = now
	_, managedRoot, active := sandboxReturnsEnv("")
	if !active || managedRoot == "" {
		return
	}
	days := sandboxCopySweepRetention("")
	if days <= 0 {
		return
	}
	sweepReturnedCopies(ctx, observerDir, managedRoot, days, now, s.kept, logger)
}

// copySweepOutcome is one checked copy's answer.
type copySweepOutcome struct {
	ID     string `json:"id"`
	Origin string `json:"origin,omitempty"`
	Bytes  int64  `json:"bytes"`
	// Reason says why a kept copy stays ("" for a removed one).
	Reason string `json:"reason,omitempty"`
}

// sweepReturnedCopies is one age pass: the copies older than days whose
// return is not pending or refused, oldest first, at most
// sandboxCopySweepBatch of them, each handed to removeSandboxCopy. kept is
// the sweeper's memory of copies the table kept (updated here).
func sweepReturnedCopies(ctx context.Context, observerDir, managedRoot string, days int, now time.Time, kept map[string]time.Time, logger *slog.Logger) (removed, stayed []copySweepOutcome) {
	if logger == nil {
		logger = slog.Default()
	}
	sandboxCopyRemoveMu.Lock()
	defer sandboxCopyRemoveMu.Unlock()
	cands := readCopySweepCandidates(observerDir, managedRoot)
	for i := range cands {
		cands[i].KeptAt = kept[cands[i].ID]
	}
	policy := workspace.CopySweepPolicy{MinAge: time.Duration(days) * 24 * time.Hour, Recheck: sandboxCopySweepRecheck, Max: sandboxCopySweepBatch}
	check, due := workspace.PlanCopySweep(cands, policy, now)
	for _, id := range check {
		out := removeOneCopy(ctx, observerDir, managedRoot, id)
		if out.Reason == "" {
			delete(kept, id)
			removed = append(removed, out)
			logger.Info("terminal_sandbox: removed a sandboxed run's copy past returned_copy_retention_days (its work came back and nothing in it was left behind)",
				"run", id, "origin", out.Origin, "bytes", out.Bytes, "days", days)
			continue
		}
		kept[id] = now
		stayed = append(stayed, out)
		logger.Info("terminal_sandbox: kept a sandboxed run's copy past returned_copy_retention_days", "run", id, "reason", out.Reason)
	}
	if left := due - len(check); left > 0 {
		logger.Info("terminal_sandbox: more copies are past returned_copy_retention_days; the next pass checks them", "left", left)
	}
	return removed, stayed
}

// removeOneCopy hands one copy to removeSandboxCopy and says what came of
// it (a refusal or an error is a kept copy with its reason).
func removeOneCopy(ctx context.Context, observerDir, managedRoot, id string) copySweepOutcome {
	out := copySweepOutcome{ID: id}
	runDir := filepath.Join(managedRoot, id)
	if meta, ok := readWorkspaceMeta(runDir); ok {
		out.Origin = meta.Origin
	}
	out.Bytes, _ = dirSizeCapped(runDir, sandboxReturnsMaxSize)
	v, err := removeSandboxCopy(ctx, observerDir, managedRoot, id)
	switch {
	case err != nil:
		out.Reason = err.Error()
	case !v.Remove:
		out.Reason = v.Reason
		if out.Reason == "" {
			out.Reason = "the removal rules keep it"
		}
	}
	return out
}

// readCopySweepCandidates lists the managed root's clone copies with what
// the sweep picks on, from host-written files only (no git runs).
func readCopySweepCandidates(observerDir, managedRoot string) []workspace.CopySweepCandidate {
	var out []workspace.CopySweepCandidate
	entries, err := os.ReadDir(managedRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 || !validSandboxWorktreeID(id) {
			continue
		}
		meta, ok := readWorkspaceMeta(filepath.Join(managedRoot, id))
		if !ok || (meta.Source != workspace.SourceCloneLocal && meta.Source != workspace.SourceCloneRemote) {
			continue
		}
		c := workspace.CopySweepCandidate{ID: id, Since: meta.CreatedAt, Return: workspace.CopyReturnUnknown, RunLive: sandboxWorktreeRunLive(observerDir, id)}
		if rec, err := readSandboxLocalReturn(sandboxLocalReturnPath(observerDir, id)); err == nil {
			c.Return = rec.State
			if !rec.EndedAt.IsZero() {
				c.Since = rec.EndedAt
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			// A record that does not read is a return Observer cannot vouch
			// for: left alone.
			c.Return = workspace.CopyReturnRefused
		} else if c.RunLive {
			c.Return = workspace.CopyReturnPending
		}
		out = append(out, c)
	}
	return out
}

// copyBulkResult is the "Remove all copies that are safe to remove" answer.
type copyBulkResult struct {
	Removed []copySweepOutcome `json:"removed"`
	Kept    []copySweepOutcome `json:"kept"`
	// Freed is the bytes the removed copies held.
	Freed int64 `json:"freed_bytes"`
	// Left counts the copies past this click's cap, for another click.
	Left int `json:"left"`
}

// removeSafeSandboxCopies is the click: every clone copy, oldest first, at
// most sandboxCopyBulkMax, each through removeSandboxCopy, the facts read
// again per copy.
func removeSafeSandboxCopies(ctx context.Context, observerDir, managedRoot string) copyBulkResult {
	sandboxCopyRemoveMu.Lock()
	defer sandboxCopyRemoveMu.Unlock()
	cands := readCopySweepCandidates(observerDir, managedRoot)
	sort.SliceStable(cands, func(i, j int) bool {
		if !cands[i].Since.Equal(cands[j].Since) {
			return cands[i].Since.Before(cands[j].Since)
		}
		return cands[i].ID < cands[j].ID
	})
	res := copyBulkResult{Removed: []copySweepOutcome{}, Kept: []copySweepOutcome{}}
	if len(cands) > sandboxCopyBulkMax {
		res.Left = len(cands) - sandboxCopyBulkMax
		cands = cands[:sandboxCopyBulkMax]
	}
	for _, c := range cands {
		out := removeOneCopy(ctx, observerDir, managedRoot, c.ID)
		if out.Reason == "" {
			res.Removed = append(res.Removed, out)
			res.Freed += out.Bytes
			slog.Default().Info("terminal_sandbox: removed a sandboxed run's copy on the person's click (remove all that are safe)", "run", c.ID, "origin", out.Origin, "bytes", out.Bytes)
			continue
		}
		res.Kept = append(res.Kept, out)
	}
	return res
}
