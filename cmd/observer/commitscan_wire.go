package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/landingscan"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// commitScanLoop is the daemon-lifetime driver for internal/commitscan —
// the same shape as guidanceScanLoop (cmd/observer/guidance.go): open its
// own config+DB, bail out quietly when the surface is disabled, and hand
// a wired Scanner to Run for the rest of the daemon's life.
func commitScanLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	if !cfg.Projects.CommitScan {
		return
	}
	logger := newLogger(cfg.Observer.LogLevel)
	sc := newCommitScannerWithDelivery(store.New(database), cfg.Projects, cfg.Delivery, logger)
	liveCommitScanner.Store(sc)
	defer liveCommitScanner.CompareAndSwap(sc, nil)
	sc.Run(ctx)
}

// liveCommitScanner is the daemon loop's scanner, so the dashboard's
// "Rescan now" (commitRescanFunc) runs through the SAME instance and can
// never scan a root at the same time as a tick (Scanner.ScanNow's in-flight
// guard). Nil when the loop is not running (commit scanning off, or a
// standalone `observer dashboard`).
var liveCommitScanner atomic.Pointer[commitscan.Scanner]

// commitScanRoot is the ONE translation from a stored project root to the
// path the scanner runs git in: a Windows path recorded by a Windows-side
// tool (C:\programsx\repo) becomes /mnt/c/programsx/repo under a WSL
// daemon (internal/platform/pathnorm, the same rule the adapters use). Any
// other value is returned unchanged.
func commitScanRoot(stored string) string {
	return pathnorm.Normalize(stored)
}

// commitRescanOption is the dashapi.Options.CommitRescan value both
// dashboard.New call sites (start.go, dashboard.go) pass: nil when commit
// scanning is off, so the page hides the action instead of offering one
// that can only fail.
func commitRescanOption(cfg config.Config, database *sql.DB) func(ctx context.Context, projectID int64) error {
	if !cfg.Projects.CommitScan || database == nil {
		return nil
	}
	return commitRescanFunc(store.New(database), cfg.Projects, cfg.Delivery, newLogger(cfg.Observer.LogLevel))
}

// commitRescanFunc builds the dashboard's "Rescan now" seam
// (dashapi.Options.CommitRescan): look up the project's root, then scan it
// once through the live daemon scanner, or through a scanner built for
// this call when the loop is not running in this process. The fallback
// scanner carries the real [delivery] section, so its landing step runs
// exactly as the daemon's does. It never runs when [projects].commit_scan
// is off.
func commitRescanFunc(st *store.Store, cfg config.ProjectsConfig, dcfg config.DeliveryConfig, logger *slog.Logger) func(ctx context.Context, projectID int64) error {
	return func(ctx context.Context, projectID int64) error {
		if !cfg.CommitScan {
			return errors.New("commit scanning is turned off ([projects].commit_scan = false)")
		}
		rootPath, err := st.ProjectRootByID(ctx, projectID)
		if err != nil {
			return err
		}
		if rootPath == "" {
			return fmt.Errorf("no project with id %d", projectID)
		}
		sc := liveCommitScanner.Load()
		if sc == nil {
			sc = newCommitScannerWithDelivery(st, cfg, dcfg, logger)
		}
		_, err = sc.ScanNow(ctx, commitscan.Root{ProjectID: projectID, RootPath: commitScanRoot(rootPath)})
		return err
	}
}

// newCommitScanner builds a commitscan.Scanner wired to st and cfg. Shared
// by the daemon loop above and `observer backfill --commits`
// (cmd/observer/backfill.go), so both go through the SAME
// exec/parse/store pipeline — the lines-of-code tracking "one path for
// live and backfill" precedent (internal/store/loc.go's doc comment).
// commitScanExecTimeout bounds ONE git invocation of the commit scanner
// (a page of MaxPerTick commits, or a rev-list for reachability).
const commitScanExecTimeout = 60 * time.Second

func newCommitScanner(st *store.Store, cfg config.ProjectsConfig, logger *slog.Logger) *commitscan.Scanner {
	return newCommitScannerWithDelivery(st, cfg, config.DeliveryConfig{}, logger)
}

// newCommitScannerWithDelivery is newCommitScanner with the [delivery]
// landing step (internal/landingscan) chained after the skills step. The
// daemon loop and the stand-alone "Rescan now" fallback pass the real
// [delivery] section; the backfill (newCommitScanner) passes the zero value
// (local off), so it runs exactly as before.
func newCommitScannerWithDelivery(st *store.Store, cfg config.ProjectsConfig, dcfg config.DeliveryConfig, logger *slog.Logger) *commitscan.Scanner {
	return commitscan.New(commitscan.Options{
		Roots: func(ctx context.Context) ([]commitscan.Root, error) {
			roots, err := st.ActiveProjectRoots(ctx, cfg.ActiveProjectDays)
			if err != nil {
				return nil, err
			}
			out := make([]commitscan.Root, len(roots))
			for i, r := range roots {
				out[i] = commitscan.Root{ProjectID: r.ID, RootPath: commitScanRoot(r.RootPath)}
			}
			return out, nil
		},
		// A commit-log page (`git log --numstat` over up to MaxPerTick
		// commits) needs far more than the dashboard's 3 s request-path
		// bound on a large repository: this repo's full history took 32 s
		// in one call (2026-09-22), and a scan that always times out
		// captures nothing. 60 s per page, on a background worker.
		Scannable: func(root string) bool {
			fi, err := os.Stat(root) //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
			return err == nil && fi.IsDir()
		},
		Exec: func(ctx context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error) {
			return gitview.RunReadOnlyTimeout(ctx, root, maxBytes, commitScanExecTimeout, args...)
		},
		Unavailable: func(err error) bool {
			return errors.Is(err, gitview.ErrGitUnavailable)
		},
		// NotRepo keeps a root that exists but is not inside any
		// repository (a scratch dir, an un-initialised /mnt/c folder)
		// out of the per-tick "scan failed" WARN: logged once at Info
		// and re-probed every NotRepoRecheck (default 30 min), so a
		// later init is still picked up. Classified from git's own
		// failure on the scan's first probe, so it costs no extra exec.
		NotRepo: gitview.IsNotRepoError,
		// NoCommits classifies resolveHeadSHA's `rev-parse --verify
		// --quiet HEAD` first probe as "this ref did not resolve,
		// silently" — resolveHeadSHA then confirms that with its own
		// independent ref-state probe before ever concluding "this
		// repository has no commits yet" (2026-09-22 review findings #6
		// then S8) — see gitview.IsNoCommitsError's doc comment for the
		// structural (exit-code/empty-stderr) classification.
		NoCommits: gitview.IsNoCommitsError,
		// Inspect feeds the failure classification table (exit code,
		// stderr, and whether our own timeout killed the call), so the
		// Projects page names the cause instead of "the scan failed".
		Inspect: func(err error) (commitscan.GitFailure, bool) {
			f, ok := gitview.InspectError(err)
			return commitscan.GitFailure{ExitCode: f.ExitCode, Stderr: f.Stderr, TimedOut: f.TimedOut}, ok
		},
		State: func(ctx context.Context, projectID int64) (commitscan.State, bool, error) {
			ss, ok, err := st.CommitScanState(ctx, projectID)
			return storeScanStateToCommitscan(ss), ok, err
		},
		SetState: func(ctx context.Context, cs commitscan.State) error {
			return st.SetCommitScanState(ctx, commitscanStateToStore(cs))
		},
		Sink:         st.UpsertCommits,
		Reachability: st.MarkCommitsReachability,
		// Review 2026-09-29 finding 8: the repository's configured
		// identity, read through the same read-only envelope; the scanner
		// hashes it (the raw name is never stored).
		LocalAuthorName: commitScanLocalAuthorName,
		// S10-SKILLS: the skills-history git step rides the daemon tick
		// (nil when [projects].skill_history is off; never runs for a
		// root whose commit scan failed, and not for backfill).
		// D-689: the delivery landing step runs after the skills step, on
		// the same successful tick (nil when [delivery].local is off).
		AfterScan: chainAfterScan(
			newSkillScanAfterScan(st, cfg, logger),
			newLandingScanAfterScan(st, dcfg, logger),
			// Security Phase C (S-723): every landed commit's secret scan;
			// a no-op until the security.postwrite loop runs.
			newSecurityCommitAfterScan(st),
		),
		// Security F2 (lane sec-f2a): the AI change record per commit; a
		// no-op until the security.provenance loop runs.
		OnCommit: newProvenanceOnCommit(logger),
		// Box refs are listed only while the provenance loop runs, and a
		// box ref's tip is kept only once its commits were decided (lane
		// SEC-F2B audit finding 4).
		BoxActive:   provenanceRunning,
		OnBoxCommit: newProvenanceOnBoxCommit(logger),
		Interval:    time.Duration(cfg.CommitScanIntervalSeconds) * time.Second,
		LinkWindow:  time.Duration(cfg.CommitLinkWindowDays) * 24 * time.Hour,
		Logger:      logger,
	})
}

// storeScanStateToCommitscan / commitscanStateToStore convert between
// store.ScanState and commitscan.State — two identically-shaped types
// that deliberately live in different packages (internal/commitscan must
// never import internal/store; see imports_test.go).
func storeScanStateToCommitscan(s store.ScanState) commitscan.State {
	return commitscan.State{
		ProjectID:           s.ProjectID,
		LastSHA:             s.LastSHA,
		LastCommittedAt:     s.LastCommittedAt,
		LastScanAt:          s.LastScanAt,
		LastError:           s.LastError,
		ConsecutiveFailures: s.ConsecutiveFailures,
		LocalAuthorHash:     s.LocalAuthorHash,
		LastErrorKind:       commitscan.FailureKind(s.LastErrorKind),
		LastSuccessAt:       s.LastSuccessAt,
		LastHeadSHA:         s.LastHeadSHA,
		HistoryPending:      s.HistoryPending,
		BackfillRev:         s.BackfillRev,
		BackfillSkip:        s.BackfillSkip,
	}
}

func commitscanStateToStore(s commitscan.State) store.ScanState {
	return store.ScanState{
		ProjectID:           s.ProjectID,
		LastSHA:             s.LastSHA,
		LastCommittedAt:     s.LastCommittedAt,
		LastScanAt:          s.LastScanAt,
		LastError:           s.LastError,
		ConsecutiveFailures: s.ConsecutiveFailures,
		LocalAuthorHash:     s.LocalAuthorHash,
		LastErrorKind:       string(s.LastErrorKind),
		LastSuccessAt:       s.LastSuccessAt,
		LastHeadSHA:         s.LastHeadSHA,
		HistoryPending:      s.HistoryPending,
		BackfillRev:         s.BackfillRev,
		BackfillSkip:        s.BackfillSkip,
	}
}

// landingScanExecTimeout bounds one read-only git call of the landing step
// (a diff-tree of one commit, an ancestry check, a page of default-branch
// subjects).
const landingScanExecTimeout = 30 * time.Second

// chainAfterScan runs each non-nil after-scan step in order; nil when every
// step is nil, so a scanner with no steps keeps a nil AfterScan.
func chainAfterScan(steps ...func(context.Context, commitscan.Root, commitscan.Result)) func(context.Context, commitscan.Root, commitscan.Result) {
	var live []func(context.Context, commitscan.Root, commitscan.Result)
	for _, s := range steps {
		if s != nil {
			live = append(live, s)
		}
	}
	if len(live) == 0 {
		return nil
	}
	return func(ctx context.Context, root commitscan.Root, res commitscan.Result) {
		for _, s := range live {
			s(ctx, root, res)
		}
	}
}

// newLandingScanAfterScan builds the commit scanner's delivery landing step
// (internal/landingscan, D-689), or nil when [delivery].local is off. The
// wiring is landingStepOptions (delivery_wire.go), the one copy shared with
// the "Check now" re-evaluation: every git call goes through
// gitview.RunReadOnlyNoLazyFetch, every write through the store's one owner
// of each table.
func newLandingScanAfterScan(st *store.Store, dcfg config.DeliveryConfig, logger *slog.Logger) func(context.Context, commitscan.Root, commitscan.Result) {
	if !dcfg.Local {
		return nil
	}
	step := landingscan.New(landingStepOptions(st, dcfg, logger))
	return func(ctx context.Context, root commitscan.Root, res commitscan.Result) {
		if _, err := step.Run(ctx, landingscan.Target{
			ProjectID: root.ProjectID, RootPath: root.RootPath, HeadSHA: res.HeadSHA,
		}); err != nil && logger != nil {
			logger.Warn("landingscan: step failed", "project_id", root.ProjectID, "error", err)
		}
	}
}

// commitScanLocalAuthorName reads the effective user.name of the repository
// at root (local config over global) through the read-only gitview envelope.
// An unset identity (the config read exits 1) is an error, which the scanner
// treats as unknown.
func commitScanLocalAuthorName(ctx context.Context, root string) (string, error) {
	out, _, err := gitview.RunReadOnlyTimeout(ctx, root, 4096, commitScanExecTimeout, "config", "--get", "user.name")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
