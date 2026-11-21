package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/intelligence/compaction"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// WorktreeRootsBackfill is the --worktree-roots report: projects rows that
// earlier builds created for linked worktrees (before F0-14 the admin
// directory `<main>/.git/worktrees`; before lane shr-worktree2 a
// relative-path worktree's own checkout; before the hook root fix of
// 2026-11-07 any folder inside a git working tree a hook ran in: a linked
// worktree, a subdirectory, a worktree since removed) and the project each
// one's rows move to.
type WorktreeRootsBackfill struct {
	Moves   []WorktreeRootMove `json:"moves"`
	Skipped []WorktreeRootSkip `json:"skipped,omitempty"`
	Applied bool               `json:"applied"`
}

// WorktreeRootMove is one old row and its target. Planned is what a dry
// run would move (per table, clashes included); Moved what --apply moved.
type WorktreeRootMove struct {
	FromID   int64  `json:"from_project_id"`
	FromRoot string `json:"from_root"`
	ToID     int64  `json:"to_project_id,omitempty"`
	ToRoot   string `json:"to_root"`
	Sessions int64  `json:"sessions"`
	// FolderGone is set when the old row's folder is no longer on disk and
	// its nearest existing ancestor named the repository.
	FolderGone bool `json:"folder_gone,omitempty"`
	// MarkOnly is set for an old row that holds nothing to move: it is only
	// marked as folded into the repository's project, so the project list
	// stops showing it as an empty project of its own.
	MarkOnly bool              `json:"mark_only,omitempty"`
	Planned  store.ProjectMove `json:"planned,omitempty"`
	Moved    store.ProjectMove `json:"moved"`
}

// WorktreeRootSkip is an old-shaped row left alone, with the reason.
type WorktreeRootSkip struct {
	ID     int64  `json:"project_id"`
	Root   string `json:"root"`
	Reason string `json:"reason"`
}

// worktreeRootsClashRule states what happens when both projects hold a
// row a table keeps unique per project (lane shr-worktree2, PT-39).
const worktreeRootsClashRule = "rule: file_state (one row per file path) and project_commits (one row per commit) keep one row per main project; when the old row and the main project's row clash, the newer one (last seen, last scanned) ends on the main project and the older stays on the old row, which is kept, so nothing is deleted. file_changes, failure_context, compaction_events, process_runs and process_events have no such key and move whole. Tables not listed (patterns, the commit scan cursor, code intelligence, guard and security state) stay on the old row"

// worktreeRootsSecurityNote is what the upgrade does to security state,
// which this backfill does not move (SHR-8, audit finding 2).
const worktreeRootsSecurityNote = "security: state recorded under an old worktree key (`<main>/.git/worktrees`, or a relative-path worktree's own checkout) is no longer read: guard approvals and exceptions given in a worktree are asked for again, and open findings recorded there drop out of the editor feed; this backfill does not move them. The main project's approvals and exceptions now apply in every worktree of it"

// worktreeRootsSeparateGitDirNote names the rows this backfill does not
// cover (SHR-8, audit finding 5).
const worktreeRootsSeparateGitDirNote = "note: a --separate-git-dir clone or a submodule with an absolute gitdir is now its own project instead of being folded into the parent of its git directory; its new sessions land on a new project row, and this backfill does not move its older ones"

// worktreeRootsMovedMark is the name an old row gets once its rows moved
// (store.WorktreeRootMovedMark, which the project list and count match).
func worktreeRootsMovedMark(toID int64) string {
	return store.WorktreeRootMovedMark(toID)
}

// worktreeRootsExtraMovers are the movers of tables whose owning package
// the store cannot import (compaction_events, internal/intelligence/
// compaction).
var worktreeRootsExtraMovers = []store.ProjectTableMover{{
	Table: "compaction_events",
	Move: func(ctx context.Context, tx *sql.Tx, fromID, toID int64) (store.TableMove, error) {
		n, err := compaction.MoveProjectEvents(ctx, tx, fromID, toID)
		return store.TableMove{Moved: n}, err
	},
}}

// worktreeRootsIdentity resolves the main project's identity for its
// projects row (remote, upstream, owners, root commit, fingerprint), so the
// backfill never creates a row with none. The root-commit exec runs here
// (a hand-run CLI), not on the hot path.
var worktreeRootsIdentity = func(ctx context.Context, root string) (string, store.ProjectIdentity) {
	id, err := git.ResolveIdentity(root, git.IdentityOptions{RootCommit: git.DefaultRootCommit})
	if err != nil || !id.IsGit {
		return "", store.ProjectIdentity{}
	}
	return id.Remote, store.ProjectIdentity{
		UpstreamRemote: id.UpstreamRemote, RemoteOwner: id.RemoteOwner, UpstreamOwner: id.UpstreamOwner,
		RootCommitSHA: id.RootCommitSHA, ContentFingerprint: id.ContentFingerprint,
	}
}

// worktreeRootTarget is the main project an old worktree row's rows move
// to: a pre-F0-14 `<main>/.git/worktrees` row (git.LegacyWorktreeRootTarget),
// a row rooted at a linked worktree's own checkout, which builds before
// lane shr-worktree2 gave a relative-path worktree
// (git.CheckoutRootTarget), or a row rooted anywhere inside a git working
// tree that is not its project root, which the hook path filed under the
// raw working directory before the hook root fix (git.ContainingRootTarget;
// gone when the folder is no longer on disk). ok is false for every other
// row; reason, when set, is why an old-shaped row is left.
func worktreeRootTarget(root string) (target string, ok bool, reason string, gone bool) {
	// A stored root that is not rooted on this host (FU-193's "Xcode
	// (project unknown)") is never resolved against the working directory
	// (audit row 8).
	if !git.HostRooted(root) {
		return "", false, "", false
	}
	if t, ok := git.LegacyWorktreeRootTarget(root); ok {
		return t, true, "", false
	}
	if git.IsLegacyWorktreeRoot(root) {
		return "", false, "the main repository is not a git repository on disk", false
	}
	if t, ok := git.CheckoutRootTarget(root); ok {
		return t, true, "", false
	}
	if t, gone, ok := git.ContainingRootTarget(root); ok {
		return t, true, "", gone
	}
	return "", false, "", false
}

// worktreeRootsGoneReason is why a removed folder's row is left when the
// repository that contained it is not a project here: the move never
// creates a project from a folder that no longer exists.
const worktreeRootsGoneReason = "the folder is gone and the repository that contained it is not a project here; not creating one from a removed folder"

// backfillWorktreeRoots plans, and with apply performs, the move of every
// row of an old worktree projects row (worktreeRootTarget) onto the main
// project's row, in every project-keyed table the store moves (sessions,
// actions, api_turns, failure_context, process_runs, process_events,
// compaction_events, file_state,
// file_changes, project_commits), only while the main repository is a git
// repository on disk. Each old row's move is one transaction; the old row
// is kept and marked, never deleted, and on a unique-key clash (file_state
// path, project_commits sha) the newer row ends on the main project and
// the older one stays on the old row. The main row is created with the
// repository's identity, and an old row is left when there is none to
// give it. Without apply it changes nothing: the plan runs the same move
// in a transaction it rolls back.
func backfillWorktreeRoots(ctx context.Context, database *sql.DB, apply bool, out io.Writer) (WorktreeRootsBackfill, error) {
	res := WorktreeRootsBackfill{Applied: apply}
	st := store.New(database)
	rows, err := st.ListProjectRoots(ctx)
	if err != nil {
		return res, fmt.Errorf("backfill worktree-roots: %w", err)
	}
	for _, r := range rows {
		target, ok, reason, gone := worktreeRootTarget(r.RootPath)
		if !ok {
			if reason != "" {
				res.Skipped = append(res.Skipped, WorktreeRootSkip{ID: r.ID, Root: r.RootPath, Reason: reason})
			}
			continue
		}
		toID, err := st.ProjectIDForRoot(ctx, target)
		if err != nil {
			return res, fmt.Errorf("backfill worktree-roots: %w", err)
		}
		if toID == r.ID {
			res.Skipped = append(res.Skipped, WorktreeRootSkip{ID: r.ID, Root: r.RootPath, Reason: "already the main project's row"})
			continue
		}
		if gone && toID == 0 {
			res.Skipped = append(res.Skipped, WorktreeRootSkip{ID: r.ID, Root: r.RootPath, Reason: worktreeRootsGoneReason})
			continue
		}
		plan, err := st.PlanProjectMove(ctx, r.ID, toID, worktreeRootsExtraMovers...)
		if err != nil {
			return res, fmt.Errorf("backfill worktree-roots: %w", err)
		}
		markOnly := worktreeMoveTotal(plan) == 0
		if markOnly && (toID == 0 || store.IsWorktreeRootMovedMark(r.Name)) {
			// Already folded, or an empty row whose repository is not a
			// project here: a project is never created for an empty row.
			res.Skipped = append(res.Skipped, WorktreeRootSkip{ID: r.ID, Root: r.RootPath, Reason: "nothing left to move (already moved)"})
			continue
		}
		remote, ident := worktreeRootsIdentity(ctx, target)
		if toID == 0 && remote == "" && ident == (store.ProjectIdentity{}) {
			res.Skipped = append(res.Skipped, WorktreeRootSkip{ID: r.ID, Root: r.RootPath, Reason: "the main repository has no identity to record (no remote, root commit or manifest); not creating an empty project row"})
			continue
		}
		mv := WorktreeRootMove{FromID: r.ID, FromRoot: r.RootPath, ToID: toID, ToRoot: target, Sessions: r.Sessions, FolderGone: gone, MarkOnly: markOnly, Planned: plan}
		if apply {
			toID, err := st.UpsertProjectWithIdentity(ctx, target, remote, ident)
			if err != nil {
				return res, fmt.Errorf("backfill worktree-roots: %w", err)
			}
			if toID == r.ID {
				res.Skipped = append(res.Skipped, WorktreeRootSkip{ID: r.ID, Root: r.RootPath, Reason: "already the main project's row"})
				continue
			}
			moved, err := st.MoveProjectRows(ctx, r.ID, toID, worktreeRootsMovedMark(toID), worktreeRootsExtraMovers...)
			if err != nil {
				return res, fmt.Errorf("backfill worktree-roots: %w", err)
			}
			mv.ToID, mv.Moved = toID, moved
		}
		res.Moves = append(res.Moves, mv)
	}
	if out != nil {
		printWorktreeRoots(out, res)
	}
	return res, nil
}

// worktreeMoveTotal is how many rows a move touches in all tables.
func worktreeMoveTotal(m store.ProjectMove) int64 {
	var n int64
	for _, t := range m.Tables {
		n += t.Moved + t.KeptOnOld
	}
	return n
}

func printWorktreeRoots(out io.Writer, res WorktreeRootsBackfill) {
	verb := "would move"
	if res.Applied {
		verb = "moved"
	}
	if len(res.Moves) == 0 {
		fmt.Fprintln(out, "worktree-roots: no linked-worktree project rows to move")
	}
	for _, m := range res.Moves {
		if m.MarkOnly {
			markVerb := "would mark"
			if res.Applied {
				markVerb = "marked"
			}
			fmt.Fprintf(out, "worktree-roots: %s project %d (%s) as folded into %s; it holds nothing to move\n", markVerb, m.FromID, m.FromRoot, m.ToRoot)
			continue
		}
		fmt.Fprintf(out, "worktree-roots: %s the rows of project %d (%s) to %s\n", verb, m.FromID, m.FromRoot, m.ToRoot)
		if m.FolderGone {
			fmt.Fprintf(out, "  the folder is gone; its nearest existing parent folder is inside %s\n", m.ToRoot)
		}
		tables := m.Planned.Tables
		if res.Applied {
			tables = m.Moved.Tables
		}
		for _, t := range tables {
			if t.Moved == 0 && t.KeptOnOld == 0 {
				continue
			}
			fmt.Fprintf(out, "  %s: %s %d row(s)", t.Table, verb, t.Moved)
			if t.KeptOnOld > 0 {
				fmt.Fprintf(out, "; %d older row(s) clash with the main project's and stay on project %d (%d of them the main project's own, swapped for a newer one)", t.KeptOnOld, m.FromID, t.Swapped)
			}
			fmt.Fprintln(out)
		}
		if res.Applied {
			fmt.Fprintf(out, "  project %d is kept, marked as moved to project %d\n", m.FromID, m.ToID)
		}
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(out, "worktree-roots: left project %d (%s): %s\n", s.ID, s.Root, s.Reason)
	}
	fmt.Fprintln(out, worktreeRootsClashRule)
	fmt.Fprintln(out, worktreeRootsSecurityNote)
	fmt.Fprintln(out, worktreeRootsSeparateGitDirNote)
	if len(res.Moves) == 0 {
		return
	}
	fmt.Fprintln(out, "org: when this node is enrolled, every moved session is queued for the push's re-send lane and the org then lists it under the main project's hashes; sessions below the enrolment floor were never shared and stay unshared; the org keeps the old project entry it already has (nothing here deletes org rows), with no sessions once the re-sends land")
	if !res.Applied {
		fmt.Fprintln(out, "nothing changed (dry run) - re-run with --apply to move:\n  observer backfill --worktree-roots --apply")
	}
}
