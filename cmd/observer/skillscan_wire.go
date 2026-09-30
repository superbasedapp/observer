package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitscan"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
	"github.com/marmutapp/superbased-observer/internal/skillscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// skillScanExecTimeout bounds one read-only invocation of the skills
// history step (a reflog page, one ls-tree, one status). Each is small;
// the bound matches the dashboard's snapshot scale more than a log page.
const skillScanExecTimeout = 20 * time.Second

// newSkillScanAfterScan builds the commit scanner's AfterScan callback for
// the skills-history git step (S10-SKILLS), or nil when
// [projects].skill_history is off. Every invocation goes through
// gitview.RunReadOnlyNoLazyFetch (the one read-only envelope, plus
// GIT_NO_LAZY_FETCH=1 so a partial clone never fetches); the pathspecs are
// derived from the guidance discovery table, never from repository
// content; every write goes through the store's one owner
// (internal/store/skillgit.go).
func newSkillScanAfterScan(st *store.Store, cfg config.ProjectsConfig, logger *slog.Logger) func(context.Context, commitscan.Root, commitscan.Result) {
	if !cfg.SkillHistory {
		return nil
	}
	stepper := skillscan.New(skillscan.Options{
		Exec: func(ctx context.Context, root string, maxBytes int, args ...string) ([]byte, bool, error) {
			return gitview.RunReadOnlyNoLazyFetch(ctx, root, maxBytes, skillScanExecTimeout, args...)
		},
		MissingObject: gitview.IsMissingObjectError,
		HasSignal:     st.ProjectHasSkillSignal,
		NewestMove:    st.NewestHeadMove,
		State: func(ctx context.Context, projectID int64) (skillscan.State, bool, error) {
			s, ok, err := st.SkillScanStateFor(ctx, projectID)
			return skillscan.State(s), ok, err
		},
		SetState: func(ctx context.Context, s skillscan.State) error {
			return st.SetSkillScanState(ctx, store.SkillScanState(s))
		},
		InsertMoves: func(ctx context.Context, projectID int64, moves []skillscan.Move) (int, bool, error) {
			rows := make([]store.HeadMoveRow, len(moves))
			for i, m := range moves {
				rows[i] = store.HeadMoveRow(m)
			}
			return st.InsertHeadMoves(ctx, projectID, rows)
		},
		TreeCandidates: st.SkillTreeCandidates,
		TreeKnown:      st.SkillTreeKnown,
		SaveTree: func(ctx context.Context, projectID int64, sha, state string, files []skillscan.TreeFile, at time.Time) error {
			rows := make([]store.SkillTreeFileRow, len(files))
			for i, f := range files {
				rows[i] = store.SkillTreeFileRow(f)
			}
			return st.SaveSkillTree(ctx, projectID, sha, state, rows, at)
		},
		ReplaceWorktree: func(ctx context.Context, projectID int64, entries []skillscan.WorktreeEntry) error {
			rows := make([]store.SkillWorktreeRow, len(entries))
			for i, e := range entries {
				rows[i] = store.SkillWorktreeRow(e)
			}
			return st.ReplaceSkillWorktree(ctx, projectID, rows)
		},
		Pathspecs: skillhistory.Pathspecs(guidance.Rules()),
		Logger:    logger,
	})
	return func(ctx context.Context, root commitscan.Root, res commitscan.Result) {
		if err := stepper.Step(ctx, skillscan.Target{
			ProjectID: root.ProjectID, RootPath: root.RootPath,
			HeadSHA: res.HeadSHA, Subtree: res.Subtree,
		}); err != nil && logger != nil {
			logger.Warn("skillscan: step failed", "project_id", root.ProjectID, "error", err)
		}
	}
}
