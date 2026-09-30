package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/gitview"
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
	newCommitScanner(store.New(database), cfg.Projects, logger).Run(ctx)
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
	return commitscan.New(commitscan.Options{
		Roots: func(ctx context.Context) ([]commitscan.Root, error) {
			roots, err := st.ActiveProjectRoots(ctx, cfg.ActiveProjectDays)
			if err != nil {
				return nil, err
			}
			out := make([]commitscan.Root, len(roots))
			for i, r := range roots {
				out[i] = commitscan.Root{ProjectID: r.ID, RootPath: r.RootPath}
			}
			return out, nil
		},
		// A commit-log page (`git log --numstat` over up to MaxPerTick
		// commits) needs far more than the dashboard's 3 s request-path
		// bound on a large repository: this repo's full history took 32 s
		// in one call (2026-09-22), and a scan that always times out
		// captures nothing. 60 s per page, on a background worker.
		Scannable: func(root string) bool {
			fi, err := os.Stat(root)
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
		AfterScan:  newSkillScanAfterScan(st, cfg, logger),
		Interval:   time.Duration(cfg.CommitScanIntervalSeconds) * time.Second,
		LinkWindow: time.Duration(cfg.CommitLinkWindowDays) * 24 * time.Hour,
		Logger:     logger,
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
