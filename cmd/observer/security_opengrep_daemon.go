//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/powerstate"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_opengrep_daemon.go is the code rules' daemon loop (security
// pillar plan section 5.5, lane SEC-G2 milestone 3), the moduleGates row
// security.scan.opengrep (components_gate.go), started only while the
// component is selected (the opt-in rule of security_optin.go). It never
// runs in a hook and never in the commit gate's quick scan. Each pass:
//
//   - refreshes the rule pack and engine pins every 6 hours (the vendor
//     feed on an individual node, the org mirror on a managed one), only
//     while an engine is installed (plans decision log P-061);
//   - post-write: reads the recorded agent writes (store.PostWritesAfter,
//     from the daemon's start, like security.postwrite) and, debounced per
//     project (opengrep.Debouncer), scans the written files;
//   - commit diff: every 2 minutes reads each active project's HEAD and,
//     when it moved, scans what changed since the previous HEAD
//     (--baseline-commit against their merge base); its findings are
//     recorded like any other, so the commit gate (S-791) sees them at the
//     agent's next commit or push;
//   - the schedule: a full scan of each project active in the last week
//     once per [security.scan.opengrep] schedule_hours, held on battery.
//
// Nothing runs and nothing is fetched while Opengrep is not installed (no
// process starts, no feed request), and
// runs go one at a time: the loop is one goroutine, and every run takes
// the machine's scan lease without waiting (a CLI scan holding it defers
// the work to the next pass).

// Cadence.
const (
	codeLoopTick       = 15 * time.Second
	codeHeadsEvery     = 2 * time.Minute
	codeFeedEvery      = 6 * time.Hour
	codeFeedFirst      = 2 * time.Minute
	codeScheduleFirst  = 10 * time.Minute
	codeActiveWindow   = 7 * 24 * time.Hour
	codeHeadsPerPass   = 20
	codeSchedulePerRun = 10
	codeWritesBatch    = 256
	codeHeadsFile      = "opengrep-heads.json"
)

// startOpengrepDaemon starts the loop when the component is selected.
func startOpengrepDaemon(ctx context.Context, ng *gatedGroup, configPath string, snap componentstate.Snapshot) {
	if !codeScanSelected(snap) {
		return
	}
	// The loop name is a literal so TestEveryDaemonLoopIsClassified can
	// match it against the moduleGates row.
	ng.Go("security.scan.opengrep", func() error {
		l, err := newCodeLoop(ctx, configPath)
		if err != nil {
			slog.Default().Warn("security: code rules loop not started", "err", err)
			return nil
		}
		defer l.close()
		l.run(ctx)
		return nil
	})
}

// codeLoop owns the loop's state: the database handle, the post-write
// cursor and debouncer, the remembered HEADs and the cadence clocks.
type codeLoop struct {
	configPath string
	db         *sql.DB
	st         *store.Store
	cleanup    func()
	cursor     int64
	deb        opengrep.Debouncer
	started    time.Time
	lastFeed   time.Time
	lastHeads  time.Time
	logger     *slog.Logger

	// The seams a test swaps: one scan, the HEAD read, the merge base,
	// the power state and whether the engine is installed.
	scan      func(ctx context.Context, e *codeEnv, t secscan.Target) error
	head      func(ctx context.Context, root string) string
	mergeBase func(ctx context.Context, root, a, b string) string
	power     func() powerstate.State
	installed func(ctx context.Context, e *codeEnv) bool
}

// newCodeLoop opens the database and starts the post-write cursor at the
// newest stored action (writes stored while the daemon was down are not
// scanned; the commit diff and the schedule cover what they commit).
func newCodeLoop(ctx context.Context, configPath string) (*codeLoop, error) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return nil, err
	}
	l := &codeLoop{configPath: configPath, db: database, st: store.New(database), cleanup: cleanup, started: time.Now(), logger: newLogger(cfg.Observer.LogLevel)}
	l.scan, l.head, l.mergeBase, l.power, l.installed = runCodeScanOnce, codeGitHead, codeGitMergeBase, powerstate.Read, codeEngineInstalled
	if l.cursor, err = l.st.MaxActionID(ctx); err != nil {
		cleanup()
		return nil, err
	}
	return l, nil
}

func (l *codeLoop) close() {
	if l.cleanup != nil {
		l.cleanup()
	}
}

// run passes every tick until ctx ends.
func (l *codeLoop) run(ctx context.Context) {
	t := time.NewTicker(codeLoopTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		l.pass(ctx, time.Now())
	}
}

// pass is one pass over the four triggers.
func (l *codeLoop) pass(ctx context.Context, now time.Time) {
	e, err := codeEnvForDash(l.configPath, l.db)
	if err != nil || e == nil {
		return
	}
	oc := e.cfg.Security.Scan.Opengrep
	installed := l.installed(ctx, e)
	l.readWrites(ctx, now, oc.PostWrite && installed)
	if !installed {
		// Plans decision log P-061: with no engine installed nothing is
		// fetched either, whatever feed says.
		return
	}
	if now.Sub(l.started) >= codeFeedFirst && now.Sub(l.lastFeed) >= codeFeedEvery {
		l.lastFeed = now
		if rep := e.refreshCodeContent(ctx); rep.Err != nil {
			l.logger.Warn("security: code rules content refresh failed; the last verified pack and pins stay in use", "source", rep.Source, "err", rep.Err)
		}
	}
	for _, b := range l.deb.Due(now) {
		l.runPostWrite(ctx, e, b, now)
	}
	if oc.CommitDiff && now.Sub(l.lastHeads) >= codeHeadsEvery {
		l.lastHeads = now
		l.checkHeads(ctx, e)
	}
	if oc.ScheduleHours > 0 && now.Sub(l.started) >= codeScheduleFirst {
		l.runSchedule(ctx, e, oc, now)
	}
}

// readWrites drains the stored writes; they are queued only while keep.
func (l *codeLoop) readWrites(ctx context.Context, now time.Time, keep bool) {
	for {
		writes, next, err := l.st.PostWritesAfter(ctx, l.cursor, codeWritesBatch)
		if err != nil {
			l.logger.Warn("security: code rules could not read the post-write feed", "err", err)
			return
		}
		l.cursor = next
		if keep {
			for _, w := range writes {
				l.deb.Add(w.ProjectRoot, w.Path, now)
			}
		}
		if len(writes) < codeWritesBatch {
			return
		}
	}
}

// errCodeScanBusy is a run that did not start: another scan holds the
// machine's lease.
var errCodeScanBusy = errors.New("another Opengrep scan is running")

// runPostWrite scans one project's written files that still exist.
func (l *codeLoop) runPostWrite(ctx context.Context, e *codeEnv, b opengrep.Batch, now time.Time) {
	var paths []string
	for _, p := range b.Paths {
		if fi, err := os.Lstat(filepath.Join(b.Root, filepath.FromSlash(p))); err == nil && fi.Mode().IsRegular() {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 {
		return
	}
	err := l.scan(ctx, e, secscan.Target{ProjectRoot: b.Root, Scope: policy.FindingScopePostWrite, Paths: paths})
	switch {
	case errors.Is(err, errCodeScanBusy):
		l.deb.Requeue(opengrep.Batch{Root: b.Root, Paths: paths}, now)
	case err != nil:
		l.logger.Warn("security: code rules post-write scan failed", "err", err)
	}
	if b.Dropped > 0 {
		l.logger.Debug("security: code rules post-write batch over its cap; the commit diff covers the rest", "dropped", b.Dropped)
	}
}

// codeHeads is the remembered HEAD per project root hash (no path stored).
type codeHeads map[string]string

func (l *codeLoop) headsPath(e *codeEnv) string { return filepath.Join(e.secDir, codeHeadsFile) }

func (l *codeLoop) loadHeads(e *codeEnv) codeHeads {
	out := codeHeads{}
	if b, err := readCappedFile(l.headsPath(e), 64<<10); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

// checkHeads runs the new-HEAD rule over each active project's main
// checkout and scans what changed when HEAD moved.
func (l *codeLoop) checkHeads(ctx context.Context, e *codeEnv) {
	roots, err := l.st.SecActiveProjectRoots(ctx, time.Now().Add(-codeActiveWindow))
	if err != nil {
		return
	}
	heads := l.loadHeads(e)
	changed := false
	n := 0
	for _, root := range roots {
		if ctx.Err() != nil || n >= codeHeadsPerPass {
			break
		}
		if fi, err := os.Stat(filepath.Join(root, ".git")); err != nil || !fi.IsDir() {
			continue // not a main checkout (a linked worktree's commits are not watched here)
		}
		n++
		key := secposture.ProjectRootHash(root)
		prev, cur := heads[key], l.head(ctx, root)
		switch opengrep.HeadRule(prev, cur) {
		case opengrep.HeadRemember:
			heads[key], changed = cur, true
		case opengrep.HeadScan:
			base := l.mergeBase(ctx, root, prev, cur)
			if base == "" || base == cur {
				// No common history (a rewritten branch) or HEAD went back:
				// remember the new HEAD, scan nothing.
				heads[key], changed = cur, true
				continue
			}
			err := l.scan(ctx, e, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeCommit, BaseRev: base, HeadRev: cur})
			if errors.Is(err, errCodeScanBusy) {
				continue // keep the previous HEAD: retried next pass
			}
			if err != nil {
				l.logger.Warn("security: code rules commit diff scan failed", "err", err)
			}
			heads[key], changed = cur, true
		}
	}
	if changed {
		if b, err := json.Marshal(heads); err == nil {
			_ = writeCodeFile(l.headsPath(e), b)
		}
	}
}

// runSchedule runs the due scheduled full scans, held on battery.
func (l *codeLoop) runSchedule(ctx context.Context, e *codeEnv, oc config.SecurityOpengrepConfig, now time.Time) {
	if oc.PauseOnBattery && l.power() != powerstate.AC {
		return
	}
	roots, err := l.st.SecActiveProjectRoots(ctx, now.Add(-codeActiveWindow))
	if err != nil {
		return
	}
	every := time.Duration(oc.ScheduleHours) * time.Hour
	n := 0
	for _, root := range roots {
		if ctx.Err() != nil || n >= codeSchedulePerRun {
			return
		}
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		// The last scheduled run comes from the store, so the schedule
		// survives a daemon restart.
		last, err := l.st.SecLastDriverRun(ctx, secposture.ProjectRootHash(root), opengrep.DriverID, policy.FindingScopeScheduled)
		if err != nil || !opengrep.ScheduleDue(last, every, now) {
			continue
		}
		n++
		err = l.scan(ctx, e, secscan.Target{ProjectRoot: root, Scope: policy.FindingScopeScheduled})
		if errors.Is(err, errCodeScanBusy) {
			return
		}
		if err != nil {
			l.logger.Warn("security: code rules scheduled scan failed", "err", err)
		}
	}
}

// codeEngineInstalled reports whether the driver finds an engine (no
// process starts).
func codeEngineInstalled(ctx context.Context, e *codeEnv) bool {
	d, err := e.inspector()
	return err == nil && d.Probe(ctx).Installed
}

// runCodeScanOnce runs one scan under the machine's lease without waiting,
// and records it through the one findings writer.
func runCodeScanOnce(ctx context.Context, e *codeEnv, t secscan.Target) error {
	// A root that is not rooted on this host is never scanned relative to
	// the working directory (audit row 8).
	if !git.HostRooted(t.ProjectRoot) {
		return fmt.Errorf("security scan: project root %q is not a folder on this host", t.ProjectRoot)
	}
	release, ok, err := dblease.TryAcquire(e.secDir, codeScanLeaseName)
	if err == nil && !ok {
		return errCodeScanBusy
	}
	defer release()
	if checkout, ok := git.FindCheckoutRoot(t.ProjectRoot); ok && checkout != "" {
		t.CheckoutRoot = checkout
	}
	d, cleanup, err := e.driver(0)
	if err != nil {
		return err
	}
	defer cleanup()
	started := time.Now()
	res, scanned, err := d.ScanFiles(ctx, t)
	if err != nil {
		return err
	}
	if e.st == nil {
		return nil
	}
	_, err = recordCodeScan(ctx, e.st, t, res, scanned, started, securityRT.notify)
	return err
}

// codeGitOut runs one read-only git command in dir under the git
// hardening and returns its trimmed output, "" on any failure.
func codeGitOut(ctx context.Context, dir string, args ...string) string {
	r := extrunhost.NewRunner(extrunhost.Options{})
	run := r.Run(ctx, extrun.Request{
		Component: opengrepComponent, Program: extrun.Program{Spec: &opengrep.GitSpec},
		Args: args, Env: extrun.EnvSpec{Set: extrun.GitHardeningEnv(runtime.GOOS)}, Dir: dir,
		Limits: extrun.Limits{Wall: 10 * time.Second, StdoutBytes: 4 << 10, StderrBytes: 4 << 10},
	})
	if run.Outcome != extrun.OutcomeOK {
		return ""
	}
	return strings.TrimSpace(string(run.Stdout))
}

// codeGitHead is the checkout's HEAD commit, "" when it cannot be read.
func codeGitHead(ctx context.Context, root string) string {
	c := codeGitOut(ctx, root, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}")
	if !opengrep.ValidBase(c) {
		return ""
	}
	return c
}

// codeGitMergeBase is the merge base of two commit ids, "" when none.
func codeGitMergeBase(ctx context.Context, root, a, b string) string {
	if !opengrep.ValidBase(a) || !opengrep.ValidBase(b) {
		return ""
	}
	c := codeGitOut(ctx, root, "merge-base", "--end-of-options", a, b)
	if !opengrep.ValidBase(c) {
		return ""
	}
	return c
}
