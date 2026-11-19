//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
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
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_localreturn.go is the return step of a bwrap copy run
// (lane RETURNS, audit item L1). Before it, a bwrap clone-local or
// clone-remote run's commits were never returned: the oci-runc and microVM
// host helpers run the return when their box ends
// (terminal_sandbox_oci_run.go ociAfterRun, terminal_sandbox_vm_host_linux.go),
// but bwrap's host helper (runSandboxHost) is shared by every local layer and
// ended with the box, so the copy only stayed under the managed root.
//
// The bwrap return runs the SAME steps (sandboxReturn / sandboxReturnBare:
// the precheck of the box-written copy, the checked fetch, the path and
// symlink checks, the injected scan, the create-only
// refs/observer/sandbox/<run>), chosen per source by one table
// (workspace.LocalReturnFor): live returns nothing (the agent worked in the
// person's own folder), clone-local returns into the source repository,
// clone-remote into the run's host-created bare return repository, and a
// worktree's branch is already in the repository (its own end,
// terminal_sandbox_worktree.go, keeps or removes it).
//
// It runs in the daemon, not in the host helper, the way the worktree
// source's end does: at attach the run's return is recorded (a clone-remote
// copy's cloned commit is read then, before the box runs), and once the run
// is gone (its relay record removed AND its host helper's placeholder ledger
// released, so the placeholders the helper made inside the copy are removed
// before the precheck reads the copy; the OCI order fix D3), a watcher, the
// daemon's ticker or the start sweep runs it. The outcome is kept in the
// record, which the Terminals page lists. The record directory is under the
// observer dir, a tmpfs inside every box, so a box never sees or writes it.

// sandboxLocalReturnDirName holds one record per bwrap copy run (<id>.json).
const sandboxLocalReturnDirName = "sandbox-returns"

// sandboxLocalReturnVersion is the record's version.
const sandboxLocalReturnVersion = 1

// sandboxLocalReturnRecord is one bwrap copy run's return.
type sandboxLocalReturnRecord struct {
	V      int    `json:"v"`
	RunID  string `json:"run_id"`
	Source string `json:"source"`
	// Request is the planned return (nil when none could be planned; the
	// reason is then in Reason and the State is refused).
	Request *workspace.ReturnRequest `json:"request,omitempty"`
	// CopyBase is the commit the copy was at when the box started.
	CopyBase string `json:"copy_base,omitempty"`
	// State is one of the workspace.CopyReturn* states.
	State  string `json:"state"`
	Ref    string `json:"ref,omitempty"`
	Commit string `json:"commit,omitempty"`
	// Commits is how many commits the box made on top of CopyBase (-1 when
	// not counted).
	Commits   int       `json:"commits"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
}

// sandboxLocalReturnPoll is how often a run's watcher checks whether the
// run ended.
var sandboxLocalReturnPoll = 5 * time.Second

// sandboxLocalReturnTick is how often the daemon's ticker looks for an ended
// run whose return has not run (a CLI launch has no watcher of the daemon's).
var sandboxLocalReturnTick = 30 * time.Second

// sandboxLocalReturnClaimStale is how old a claim must be before a sweep
// takes it over (a process that crashed while returning).
const sandboxLocalReturnClaimStale = 10 * time.Minute

// sandboxLocalReturnMu serializes this process's sweeps; claims serialize
// them across processes.
var sandboxLocalReturnMu sync.Mutex

// sandboxLocalReturnLoops starts one ticker per observer dir.
var sandboxLocalReturnLoops sync.Map

func init() {
	sandboxDaemonStartHooks = append(sandboxDaemonStartHooks, func(observerDir string) {
		if _, loaded := sandboxLocalReturnLoops.LoadOrStore(observerDir, true); loaded {
			return
		}
		go sandboxLocalReturnLoop(observerDir)
	})
}

// sandboxLocalReturnLoop sweeps at daemon start and then on every tick, for
// the daemon's life. After each return sweep the age sweep of returned
// copies runs when it is due (SBXD-2, terminal_sandbox_returns_sweep.go):
// the same goroutine, so a copy is never swept while its return runs.
func sandboxLocalReturnLoop(observerDir string) {
	sweepSandboxLocalReturns(context.Background(), observerDir, slog.Default())
	maybeSweepReturnedCopies(context.Background(), observerDir, time.Now().UTC(), slog.Default())
	t := time.NewTicker(sandboxLocalReturnTick)
	defer t.Stop()
	for range t.C {
		sweepSandboxLocalReturns(context.Background(), observerDir, slog.Default())
		maybeSweepReturnedCopies(context.Background(), observerDir, time.Now().UTC(), slog.Default())
	}
}

// sandboxLocalReturnDir is observerDir's record directory.
func sandboxLocalReturnDir(observerDir string) string {
	return filepath.Join(observerDir, sandboxLocalReturnDirName)
}

// sandboxLocalReturnPath is runID's record.
func sandboxLocalReturnPath(observerDir, runID string) string {
	return filepath.Join(sandboxLocalReturnDir(observerDir), runID+".json")
}

// noteLocalReturn records, at attach and before the box starts, the return
// a bwrap copy run gets at its end, and starts its watcher. A run whose
// source returns nothing records nothing.
func (r *sandboxRuntime) noteLocalReturn(run termsvc.SandboxRun) {
	rec, ok := planLocalReturn(r.managedRoot, run, runReturnGit, time.Now().UTC())
	if !ok {
		return
	}
	if err := writeSandboxLocalReturn(r.observerDir, rec); err != nil {
		if r.logger != nil {
			r.logger.Warn("terminal_sandbox: the copy's return could not be recorded; its commits stay in the copy", "run", run.ID, "err", err)
		}
		return
	}
	r.watchLocalReturn(run.ID)
}

// planLocalReturn builds a run's return record from its managed
// workspace's meta.json (host-written, outside the box's bind), per
// workspace.LocalReturnFor; ok is false for a run whose source returns
// nothing.
func planLocalReturn(managedRoot string, run termsvc.SandboxRun, git func(context.Context, workspace.Step) ([]byte, error), now time.Time) (sandboxLocalReturnRecord, bool) {
	if !run.Copy || run.Dir == "" {
		return sandboxLocalReturnRecord{}, false
	}
	meta, ok := readWorkspaceMeta(filepath.Dir(run.Dir))
	if !ok {
		return sandboxLocalReturnRecord{}, false
	}
	rule, ok := workspace.LocalReturnFor(meta.Source)
	if !ok || !rule.Return {
		return sandboxLocalReturnRecord{}, false
	}
	rec := sandboxLocalReturnRecord{V: sandboxLocalReturnVersion, RunID: run.ID, Source: string(meta.Source), State: workspace.CopyReturnPending, Commits: -1, CreatedAt: now}
	refuse := func(why string) (sandboxLocalReturnRecord, bool) {
		rec.State, rec.Reason, rec.Request = workspace.CopyReturnRefused, why, nil
		return rec, true
	}
	req := workspace.ReturnRequest{SourceRepo: run.ProjectRoot, CopyDir: run.Dir, ManagedRoot: managedRoot, RunID: run.ID}
	if rule.Bare {
		repo, err := workspace.ReturnRepoPath(managedRoot, run.ID)
		if err != nil {
			return refuse("the box's commits will not be returned from this copy: " + err.Error())
		}
		req.SourceRepo, req.Bare = repo, true
	}
	plan, err := workspace.PlanReturn(req)
	if err != nil {
		return refuse("the box's commits will not be returned from this copy: " + err.Error())
	}
	// The copy's commit before the box runs: the host made the copy, the box
	// has not written it yet.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := git(ctx, plan.CopyHead())
	if err == nil {
		rec.CopyBase, err = workspace.ParseHead(out)
	}
	if err != nil {
		if rule.Bare {
			return refuse("the box's commits will not be returned from this clone-remote copy: read the clone's HEAD: " + err.Error())
		}
		rec.CopyBase = ""
	}
	if rule.Bare {
		req.BaseCommit = rec.CopyBase
	}
	rec.Request = &req
	return rec, true
}

// watchLocalReturn runs the run's return once the run is gone. A process
// that exits first leaves it to the daemon's ticker or start sweep.
func (r *sandboxRuntime) watchLocalReturn(runID string) {
	observerDir, logger := r.observerDir, r.logger
	go func() {
		t := time.NewTicker(sandboxLocalReturnPoll)
		defer t.Stop()
		for range t.C {
			if !sandboxLocalRunGone(observerDir, runID) {
				continue
			}
			sweepSandboxLocalReturns(context.Background(), observerDir, logger)
			return
		}
	}()
}

// sandboxLocalRunGone reports whether runID's host helper is gone: no relay
// record, and no placeholder ledger it still holds (a ledger nobody holds,
// a killed helper's, is cleared here with the placeholders it proves). An
// unreadable record counts as live: never return on doubt.
func sandboxLocalRunGone(observerDir, runID string) bool {
	if sandboxWorktreeRunLive(observerDir, runID) {
		return false
	}
	if _, err := os.Lstat(sandboxLocalLedgerFile(observerDir, runID)); err == nil {
		return clearRunPlaceholderLedger(observerDir, runID)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false
	}
	return true
}

// sandboxLocalLedgerFile is runID's placeholder ledger (the unix host
// helper's placeholderLedgerPath, which only Linux and macOS builds carry;
// TestSandboxLocalLedgerFileIsTheHelpers pins the two equal there).
func sandboxLocalLedgerFile(observerDir, runID string) string {
	return filepath.Join(sandboxrelayd.RunsDir(observerDir), runID+".placeholders")
}

// sweepSandboxLocalReturns runs the return of every recorded run that is
// pending and gone, and retakes a claim a crashed process left. Each one is
// claimed by renaming its record, so two processes never return one run.
func sweepSandboxLocalReturns(ctx context.Context, observerDir string, logger *slog.Logger) {
	sandboxLocalReturnMu.Lock()
	defer sandboxLocalReturnMu.Unlock()
	dir := sandboxLocalReturnDir(observerDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		var id string
		claimed := false
		switch {
		case strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".returning"):
			id, claimed = strings.TrimSuffix(strings.TrimPrefix(name, "."), ".returning"), true
		case strings.HasSuffix(name, ".json"):
			id = strings.TrimSuffix(name, ".json")
		default:
			continue
		}
		if !validSandboxWorktreeID(id) {
			continue
		}
		path := filepath.Join(dir, name)
		claim := filepath.Join(dir, "."+id+".returning")
		if claimed {
			fi, err := e.Info()
			if err != nil || now.Sub(fi.ModTime()) < sandboxLocalReturnClaimStale {
				continue
			}
			if err := os.Chtimes(claim, now, now); err != nil {
				continue
			}
		} else {
			rec, err := readSandboxLocalReturn(path)
			if err != nil || rec.State != workspace.CopyReturnPending || !sandboxLocalRunGone(observerDir, id) {
				continue
			}
			if err := os.Rename(path, claim); err != nil {
				continue // another process took it
			}
		}
		rec, err := readSandboxLocalReturn(claim)
		if err != nil || rec.RunID != id {
			continue
		}
		rec = runSandboxLocalReturn(ctx, rec, runReturnGit, sandboxLocalReturnScan(), now)
		if err := writeSandboxLocalReturn(observerDir, rec); err == nil {
			_ = os.Remove(claim)
		}
		sandboxLocalReturnLog(logger, rec)
	}
}

// sandboxLocalReturnScan is the bound return scan with the daemon's config
// path (the oci-runc helper's ociReturnScan); nil while no scan is bound.
func sandboxLocalReturnScan() func(context.Context, sandboxReturnScanInput) error {
	scan := sandboxReturnScan
	if scan == nil {
		return nil
	}
	cfgPath := daemonConfigPath()
	return func(ctx context.Context, in sandboxReturnScanInput) error {
		in.ConfigPath = cfgPath
		return scan(ctx, in)
	}
}

// runSandboxLocalReturn runs one recorded return and returns the record with
// its outcome. A record with nothing to return is ended as it is.
func runSandboxLocalReturn(ctx context.Context, rec sandboxLocalReturnRecord, git func(context.Context, workspace.Step) ([]byte, error), scan func(context.Context, sandboxReturnScanInput) error, now time.Time) sandboxLocalReturnRecord {
	rec.EndedAt = now
	if rec.Request == nil {
		if rec.State == workspace.CopyReturnPending {
			rec.State, rec.Reason = workspace.CopyReturnRefused, "no return was planned for this copy"
		}
		return rec
	}
	req := *rec.Request
	var res sandboxReturnResult
	var err error
	if req.Bare {
		res, err = sandboxReturnBare(ctx, req, git, scan)
	} else {
		res, err = sandboxReturn(ctx, req, git, scan)
	}
	rec.Ref, rec.Commit = res.Ref, res.Commit
	switch {
	case err != nil:
		rec.State, rec.Reason = workspace.CopyReturnRefused, "the box's commits were not returned: "+err.Error()
	case res.NothingNew:
		rec.State, rec.Commits = workspace.CopyReturnNothingNew, 0
	default:
		rec.State = workspace.CopyReturnReturned
		rec.Commits = countReturnedCommits(ctx, git, req.SourceRepo, rec.CopyBase, res.Ref)
	}
	return rec
}

// countReturnedCommits counts the commits of ref on top of base in repo (a
// repository Observer trusts: the source, or the host-made return
// repository); -1 when it cannot be read.
func countReturnedCommits(ctx context.Context, git func(context.Context, workspace.Step) ([]byte, error), repo, base, ref string) int {
	if !workspace.ValidSHA(base) || !strings.HasPrefix(ref, workspace.ReturnRefPrefix) {
		return -1
	}
	out, err := git(ctx, workspace.Step{Argv: []string{"git", "-C", repo, "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "rev-list", "--count", base + ".." + ref}, Hardened: true})
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// sandboxLocalReturnLog names a return's outcome in the daemon log.
func sandboxLocalReturnLog(logger *slog.Logger, rec sandboxLocalReturnRecord) {
	if logger == nil {
		logger = slog.Default()
	}
	switch rec.State {
	case workspace.CopyReturnReturned:
		logger.Info("terminal_sandbox: the copy's commits came back", "run", rec.RunID, "ref", rec.Ref, "repo", rec.Request.SourceRepo, "commit", rec.Commit)
	case workspace.CopyReturnNothingNew:
		logger.Info("terminal_sandbox: the box made no new commit in its copy", "run", rec.RunID)
	default:
		logger.Warn("terminal_sandbox: the copy's commits were not returned; the copy is kept", "run", rec.RunID, "reason", rec.Reason)
	}
}

// readSandboxLocalReturn reads one record, no-follow and capped.
func readSandboxLocalReturn(path string) (sandboxLocalReturnRecord, error) {
	b, err := readRegularCapped(path, 1<<20)
	if err != nil {
		return sandboxLocalReturnRecord{}, err
	}
	var rec sandboxLocalReturnRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return sandboxLocalReturnRecord{}, err
	}
	if rec.V != sandboxLocalReturnVersion {
		return sandboxLocalReturnRecord{}, fmt.Errorf("the return record %s is version %d", path, rec.V)
	}
	return rec, nil
}

// readRegularCapped reads a regular file (never through a link) of at most
// limit bytes.
func readRegularCapped(path string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(path) //nolint:gosec // G703: an Observer record or a managed copy's small git file, lstat only (never followed)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Size() > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	f, err := os.Open(path) //nolint:gosec // G304: an Observer record or a managed copy's small git file, lstat-checked regular and capped
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	// The file opened must be the one lstat'd (no link swapped in between).
	if got, err := f.Stat(); err != nil || !os.SameFile(fi, got) {
		return nil, fmt.Errorf("%s changed while it was read", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is over %d bytes", path, limit)
	}
	return b, nil
}

// writeSandboxLocalReturn writes rec whole: a fresh 0600 file renamed over
// the old one.
func writeSandboxLocalReturn(observerDir string, rec sandboxLocalReturnRecord) error {
	if !validSandboxWorktreeID(rec.RunID) {
		return fmt.Errorf("the return record's run id %q is not a clean token", rec.RunID)
	}
	dir := sandboxLocalReturnDir(observerDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return replaceFileAtomic(sandboxLocalReturnPath(observerDir, rec.RunID), b, 0o600)
}
