//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_box_wire.go binds the security module's copy-workspace coverage
// to the sandbox module (security pillar plan 4.8 "Copy workspaces", M7;
// sandbox plan v2 section 6, revision 5; lane sec-box). It is built only
// with both modules (the build tags of terminal_sandbox_return.go plus
// !sbo_omit_security), so a build without either leaves every hook it
// sets nil and the return step, the post-write feed and the quick scan
// exactly as they were.

func init() {
	sandboxReturnScan = securitySandboxReturnScan
	securityCopyWorkspace = func(ctx context.Context, st *store.Store, tree string) secsvc.CopyResolution {
		return securityCopyRuns.resolve(ctx, st, tree)
	}
	securityBoxRunOwns = func(ctx context.Context, root, runID string) bool {
		return securityCopyRuns.owns(ctx, root, runID)
	}
	securityCopySourceRoot = func(root string) string {
		return securityCopyRuns.sourceRoot(context.Background(), root)
	}
}

// sourceRoot is the same place as tree in its copy run's source project,
// "" when no copy run the index holds works on tree (lane LEFT-SEC).
func (x *copyRunIndex) sourceRoot(ctx context.Context, tree string) string {
	runs, _ := x.snapshot(ctx, nil)
	src, ok := secsvc.SourceTreeOf(runs, securityResolvePath(tree))
	if !ok {
		return ""
	}
	return securityResolvePath(src)
}

// securitySandboxReturnScan is the return step's injected scan. It runs
// only while the security module's secret detection is selected: in the
// daemon, while the postwrite loop has published the commit-scan step
// (securityRT.commitScan); in the oci-runc host helper, a process of its
// own that runs the return, while the same loop's component gate would
// start it under the daemon's config (in.ConfigPath, from the helper's
// plan). Otherwise it does nothing and the return is today's. It never
// refuses the return: a finding is recorded before the ref is written, and
// a scan that cannot run is an unknown run.
func securitySandboxReturnScan(ctx context.Context, in sandboxReturnScanInput) error {
	step, done := securityReturnStep(ctx, in.ConfigPath)
	if step == nil {
		return nil
	}
	defer done()
	securityScanReturn(ctx, step, in.Repo, in.Commit, in.Ref, in.RunID)
	return nil
}

// securityReturnStep returns the commit-scan step the return records
// through and the function that releases it: the daemon's published step,
// else one built from configPath, the daemon's resolved config the helper
// was handed (securityReturnStepFromConfig), else nil. A process that was
// not handed an absolute config path records nothing: it never falls back
// to the default config, which could open or create a database the daemon
// never reads (lane sec-box audit finding 4); the commit scan's box-ref
// walk covers the returned ref at its next tick.
func securityReturnStep(ctx context.Context, configPath string) (*securityCommitStep, func()) {
	if s := securityRT.commitScan.Load(); s != nil && s.st != nil {
		return s, func() {}
	}
	if configPath == "" || !filepath.IsAbs(configPath) {
		return nil, nil
	}
	return securityReturnStepFromConfig(ctx, configPath)
}

// securityReturnStepFromConfig builds the commit-scan step in a process
// that is not the daemon (the oci-runc host helper): only when the
// security.postwrite loop would run under configPath's components (the
// loop that publishes the step in the daemon), with the same engine, the
// same switches ([security.secrets].commit_check, security.code) and the
// daemon's database. A config or database that cannot be opened gives
// nil: nothing is recorded here, and the commit scan's box-ref walk
// covers the returned ref at its next tick. A seam for tests.
var securityReturnStepFromConfig = func(ctx context.Context, configPath string) (*securityCommitStep, func()) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil, nil
	}
	snap := componentSnapshotForConfig(cfg)
	if !loopAllowed(snap, "security.postwrite") || !moduleRuleActive(snap, "security.secrets") {
		cleanup()
		return nil, nil
	}
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		cleanup()
		return nil, nil
	}
	identify := securityIdentify(resolved)
	return &securityCommitStep{
		scan:        &secquickscan.CommitScan{Engine: newSecurityQuickScanEngine(identify)},
		st:          store.New(database),
		logger:      newLogger(cfg.Observer.LogLevel),
		code:        moduleRuleActive(snap, "security.code"),
		skipSecrets: !cfg.Security.Secrets.CommitCheck,
	}, cleanup
}

// The run-record index's timing: how often the records are read again,
// and how long a run whose record is gone (the run ended, its helper
// removed it) is still answered for, so a write the post-write feed reads
// a little after the run ended is still placed in its copy.
const (
	copyRunRefresh = 2 * time.Second
	copyRunGrace   = 30 * time.Minute
	// copyRunMax bounds the records one read keeps.
	copyRunMax = 256
)

// copyRunIndex is the daemon's (or the hook's) view of the relay run
// records for securityCopyWorkspace: one owner, read-only over the
// records (internal/sandboxrelayd owns them).
type copyRunIndex struct {
	mu   sync.Mutex
	dir  string
	read time.Time
	runs map[string]*copyRunEntry
	// overflow: the last read found more records than copyRunMax, so the
	// index is incomplete (lane sec-box audit finding 6); a tree no indexed
	// run holds then reads as inside a box, never live.
	overflow bool
	// now, observerDir and warn are seams for tests (nil: time.Now, the
	// observer directory of the daemon's config, and slog's default
	// logger).
	now         func() time.Time
	observerDir func() string
	warn        func(msg string, args ...any)
}

// copyRunEntry is one run's record and what the index learned about it.
type copyRunEntry struct {
	rec  sandboxrelayd.RunRecord
	seen time.Time
	// inBox is resolved once from the run's isolation stack; nil while it
	// could not be resolved (no store, no stored run yet).
	inBox *bool
}

// securityCopyRuns is the process's one copyRunIndex.
var securityCopyRuns = &copyRunIndex{}

// resolve answers for tree from the records
// (secsvc.ResolveCopyWorkspaceIndex: an incomplete index answers a tree no
// indexed run holds as inside a box).
func (x *copyRunIndex) resolve(ctx context.Context, st *store.Store, tree string) secsvc.CopyResolution {
	runs, incomplete := x.snapshot(ctx, st)
	return secsvc.ResolveCopyWorkspaceIndex(runs, incomplete, securityResolvePath(tree))
}

// owns reports whether the records hold run runID and it is root's: its
// host-written project root is root (lane sec-box audit finding 5). A run
// the index does not hold (ended past copyRunGrace, or past copyRunMax)
// is not confirmed.
func (x *copyRunIndex) owns(ctx context.Context, root, runID string) bool {
	if runID == "" || root == "" {
		return false
	}
	_, _ = x.snapshot(ctx, nil)
	x.mu.Lock()
	e, ok := x.runs[runID]
	dir := x.dir
	x.mu.Unlock()
	if !ok || e.rec.RunID != runID || e.rec.ProjectRoot == "" {
		// The index forgets a run copyRunGrace after it ends; a worktree
		// run's own host-written record outlives it while its branch is
		// kept (lane LEFT-SEC, the P-102 residual).
		return worktreeRecordOwns(dir, root, runID)
	}
	return securityResolvePath(e.rec.ProjectRoot) == securityResolvePath(root)
}

// worktreeRecordOwns reports whether the host's worktree run record for
// runID (written by the sandbox module at launch and kept while the run's
// branch is kept, sandboxWorktreeRecordPath) names root's repository as its
// main repository. The record lives in the observer directory, which no
// box can write, so a branch name the box chose is confirmed only by a run
// the host prepared for that repository.
func worktreeRecordOwns(observerDir, root, runID string) bool {
	if observerDir == "" || !validSandboxWorktreeID(runID) {
		return false
	}
	rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(observerDir, runID))
	if err != nil || rec.RunID != runID || rec.MainRoot == "" {
		return false
	}
	return securityResolvePath(rec.MainRoot) == securityResolvePath(root)
}

// snapshot reads the records at most every copyRunRefresh and returns the
// runs known within copyRunGrace, sorted by run id, and whether the last
// read was incomplete (more records than copyRunMax).
func (x *copyRunIndex) snapshot(ctx context.Context, st *store.Store) ([]secsvc.CopyRun, bool) {
	now := time.Now
	if x.now != nil {
		now = x.now
	}
	t := now()
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.runs == nil {
		x.runs = map[string]*copyRunEntry{}
	}
	if x.read.IsZero() || t.Sub(x.read) >= copyRunRefresh || t.Before(x.read) {
		x.read = t
		x.readRecords(t)
	}
	ids := make([]string, 0, len(x.runs))
	for id, e := range x.runs {
		if t.Sub(e.seen) > copyRunGrace {
			delete(x.runs, id)
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]secsvc.CopyRun, 0, len(ids))
	for _, id := range ids {
		e := x.runs[id]
		run := secsvc.CopyRun{
			RunID: id, Copy: e.rec.Delivery == sandboxrelayd.DeliveryCopy,
			WorkspaceDir: securityResolvePath(e.rec.WorkspaceDir),
			ProjectRoot:  securityResolvePath(e.rec.ProjectRoot),
		}
		if run.Copy {
			if e.rec.CopyHostPath != "" {
				run.CopyHostPath = securityResolvePath(e.rec.CopyHostPath)
			}
			run.InBox = x.inBox(ctx, st, e)
		}
		out = append(out, run)
	}
	return out, x.overflow
}

// readRecords reads every run record under the observer directory into
// the index (a record that does not read is skipped; one already known
// keeps its entry and is marked seen).
func (x *copyRunIndex) readRecords(t time.Time) {
	if x.dir == "" {
		if x.observerDir != nil {
			x.dir = x.observerDir()
		} else {
			x.dir = securityDaemonObserverDir()
		}
	}
	if x.dir == "" {
		return
	}
	entries, err := os.ReadDir(sandboxrelayd.RunsDir(x.dir))
	if err != nil {
		return
	}
	n, over := 0, false
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		if n >= copyRunMax {
			over = true
			break
		}
		rec, err := sandboxrelayd.ReadRun(x.dir, strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		n++
		if cur, ok := x.runs[rec.RunID]; ok {
			cur.rec, cur.seen = rec, t
			continue
		}
		x.runs[rec.RunID] = &copyRunEntry{rec: rec, seen: t}
	}
	if over && !x.overflow {
		// One line when the index becomes incomplete, not one per read.
		warn := x.warn
		if warn == nil {
			warn = slog.Default().Warn
		}
		warn("security: more sandbox run records than the copy-workspace index reads; a tree no indexed run holds reads as inside a box (unknown) until the records drop under the cap",
			"cap", copyRunMax, "dir", sandboxrelayd.RunsDir(x.dir))
	}
	x.overflow = over
}

// inBox reports whether a copy run's tree lives only inside its box: not
// when every layer of its recorded isolation stack is a local backend
// (secsvc.TreeOnHost over the sandbox backend rows' location). A run whose
// stack cannot be read yet reads as inside the box (never a stale host
// tree read as the box's) and is asked again next time.
func (x *copyRunIndex) inBox(ctx context.Context, st *store.Store, e *copyRunEntry) bool {
	if e.inBox != nil {
		return *e.inBox
	}
	if st == nil || e.rec.TerminalRunID == "" {
		return true
	}
	stack, ok, err := st.TerminalRunStack(ctx, e.rec.TerminalRunID)
	if err != nil || !ok {
		return true
	}
	v := !secsvc.TreeOnHost(stack, sandboxBackendLocal)
	e.inBox = &v
	return v
}

// sandboxBackendLocal answers a backend id's location from the registry.
func sandboxBackendLocal(id string) (isLocal, ok bool) {
	row, ok := sandboxbackend.Get(id)
	if !ok {
		return false, false
	}
	return row.Iso.Location == sandboxvocab.LocationLocal, true
}

// securityDaemonObserverDir is the observer directory of the daemon's
// config, or in a hook process of the invocation's config (where the
// relay run records live), "" when it cannot be told.
func securityDaemonObserverDir() string {
	path := daemonConfigPath()
	if path == "" {
		// A hook process: the config its invocation was read for.
		path = securityHookConfig()
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return ""
	}
	return sandboxObserverDirFor(cfg)
}

// securityResolvePath is p cleaned, with symlinks resolved when it exists,
// so a record's spelling and the store's (git.Resolve) compare.
func securityResolvePath(p string) string {
	if p == "" {
		return ""
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// The hosted saved diff (lane LEFT-SEC, SECP-18 "the guest staged-diff"):
// a hosted run's teardown saves the box's staged diff home owner-only and
// never applies it (terminal_sandbox_hosted_host.go saveStagedDiff, which
// this lane leaves unchanged); a diff that could not be saved leaves a kept
// diff-error line. The daemon's minute rescan reads each of them once,
// after teardown, through what that lane already writes:
//
//   - a saved <run>.diff is scanned by the commit-scope detectors
//     (secquickscan.Engine.ScanDiff) and recorded as box work of the run
//     (its findings carry the run id, are shown, and gate nothing until the
//     tree or a commit holds them, store.secBlockingWhere);
//   - a diff the guest cut at its cap (sandbox.MaxStagedDiff) is an unknown
//     run, never clean, and so is one that cannot be read;
//   - a kept diff-error line (no diff came home) is an unknown run naming
//     diff_not_saved.
//
// The run's project is the host's attribution: its relay run record (the
// copy-run index keeps it copyRunGrace after the run ends) or its hosted
// teardown record's root; a diff neither names yet is left for a later
// tick. A marker beside the posture records each run handled, so nothing is
// scanned twice.

// hostedReturnsMarkerDir holds one marker per hosted run handled.
const hostedReturnsMarkerDir = "hosted-returns"

// hostedDiffRef is the ref the hosted diff's box run is recorded under.
const hostedDiffRef = "hosted-staged-diff"

// The reasons of the hosted diff's unknown runs.
const (
	hostedDiffTruncated  = "staged_diff_truncated"
	hostedDiffUnreadable = "staged_diff_unreadable"
	hostedDiffNotSaved   = "diff_not_saved"
)

// hostedReturnsMaxPerTick bounds the runs one tick handles.
const hostedReturnsMaxPerTick = 8

func init() {
	securityHostedReturnsTick = func(ctx context.Context, step *securityCommitStep, securityDir string) {
		securityScanHostedReturns(ctx, step, securityDir, securityDaemonObserverDir(), securityCopyRuns.projectOf)
	}
}

// projectOf is the project root the index's record of runID names, "" when
// the index does not hold it.
func (x *copyRunIndex) projectOf(ctx context.Context, runID string) string {
	_, _ = x.snapshot(ctx, nil)
	x.mu.Lock()
	defer x.mu.Unlock()
	if e, ok := x.runs[runID]; ok && e.rec.RunID == runID {
		return e.rec.ProjectRoot
	}
	return ""
}

// securityScanHostedReturns handles the saved diffs and kept diff errors no
// marker names yet, at most hostedReturnsMaxPerTick a tick.
func securityScanHostedReturns(ctx context.Context, step *securityCommitStep, securityDir, observerDir string, projectOf func(context.Context, string) string) {
	if step == nil || step.st == nil || step.scan == nil || step.scan.Engine == nil || securityDir == "" || observerDir == "" {
		return
	}
	roots := map[string]string{}
	for _, rec := range hostedLoadRecords(observerDir) {
		if r := rec.Extra[sandboxremote.ExtraRoot]; r != "" {
			roots[rec.RunID] = r
		}
	}
	rootOf := func(runID string) string {
		if r := projectOf(ctx, runID); r != "" {
			return r
		}
		return roots[runID]
	}
	markers := filepath.Join(securityDir, hostedReturnsMarkerDir)
	done := func(runID string) bool {
		_, err := os.Stat(filepath.Join(markers, runID)) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
		return err == nil
	}
	mark := func(runID string) {
		if os.MkdirAll(markers, 0o700) == nil {
			_ = os.WriteFile(filepath.Join(markers, runID), []byte("1\n"), 0o600) //nolint:gosec // G703: a run-id marker under Observer's own markers dir
		}
	}
	n := 0
	dir := filepath.Join(hostedStateDir(observerDir), "returns")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		runID, ok := strings.CutSuffix(e.Name(), ".diff")
		if !ok || !e.Type().IsRegular() || !hostedRunIDOK(runID) || done(runID) || n >= hostedReturnsMaxPerTick {
			continue
		}
		root := rootOf(runID)
		if root == "" {
			continue // not attributed yet: a later tick
		}
		n++
		// Marked handled only once its record is written (audit F7): a
		// failed write is retried next tick.
		rctx, failed := withRecordFailures(ctx)
		step.recordHostedDiff(rctx, root, runID, filepath.Join(dir, e.Name()))
		if !failed.Load() {
			mark(runID)
		}
	}
	for _, l := range hostedLoadDiffErrors(observerDir) {
		if !hostedRunIDOK(l.RunID) || done(l.RunID) || n >= hostedReturnsMaxPerTick {
			continue
		}
		root := rootOf(l.RunID)
		if root == "" {
			continue
		}
		n++
		rctx, failed := withRecordFailures(ctx)
		step.recordBoxUnknown(rctx, root, secsvc.BoxCommit{RunID: l.RunID, Ref: hostedDiffRef}, hostedDiffNotSaved)
		if !failed.Load() {
			mark(l.RunID)
		}
	}
}

// recordHostedDiff scans one saved diff and records it as the run's box
// work: findings with the run id, or an unknown run when the diff was cut at
// the guest's cap or cannot be read.
func (step *securityCommitStep) recordHostedDiff(ctx context.Context, root, runID, path string) {
	b := hostedBox{RunID: runID, Ref: hostedDiffRef}
	f, err := os.Open(path) //nolint:gosec // G304: <observer>/sandbox-hosted/returns/<run>.diff, a run id checked to one clean token
	if err != nil {
		step.recordBoxUnknown(ctx, root, b.commit(), hostedDiffUnreadable)
		return
	}
	defer func() { _ = f.Close() }()
	diff, err := io.ReadAll(io.LimitReader(f, int64(sandbox.MaxStagedDiff)+1))
	switch {
	case err != nil:
		step.recordBoxUnknown(ctx, root, b.commit(), hostedDiffUnreadable)
		return
	case len(diff) >= sandbox.MaxStagedDiff:
		// The guest stops at its cap and the host saves what came: a diff
		// that long may be cut, so it is never read as clean.
		step.recordBoxUnknown(ctx, root, b.commit(), hostedDiffTruncated)
		return
	}
	res := step.scan.Engine.ScanDiff(ctx, diff, hostedDiffBudget)
	step.recordCommit(secsvc.WithBoxCommit(ctx, b.commit()), root, secposture.ProjectRootHash(root), secquickscan.CommitResult{Result: res})
}

// hostedDiffBudget bounds one saved diff's scan (off the hook path).
const hostedDiffBudget = 30 * time.Second

// hostedBox names a hosted run's diff as box work.
type hostedBox struct{ RunID, Ref string }

func (b hostedBox) commit() secsvc.BoxCommit { return secsvc.BoxCommit{RunID: b.RunID, Ref: b.Ref} }

// hostedRunIDOK reports a run id that is one clean file-name token.
func hostedRunIDOK(id string) bool {
	if id == "" || len(id) > 128 || strings.HasPrefix(id, ".") {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}
