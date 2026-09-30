package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
)

// READ-ONLY seam for the Projects-page Skills tab (S10-SKILLS). It
// assembles internal/skillhistory's Input from tables other files own
// (project_guidance_files: guidance.go; project_commits/_files: commits.go;
// the migration-135 tables: skillsnap.go + skillgit.go; sessions/actions:
// store.go) and writes nothing.

// skillHistoryTimelineCap bounds the commit-timeline rows one read loads.
// Commits touching skill directories are few; the cap is defence in depth.
const skillHistoryTimelineCap = 5000

// skillHistoryHeadMoveCap bounds the reflog rows one read loads.
const skillHistoryHeadMoveCap = 20000

// LoadSkillHistoryInput loads everything skillhistory.Build needs for one
// project and window, except the capability tables and the discovery
// rules, which the caller supplies. prefixes are the literal skill
// directory prefixes (skillhistory.Pathspecs). The commit timeline, trees
// and reflog are loaded WHOLE (not windowed): a version's history starts
// before the window. Sessions and invocations are windowed on
// [since, until).
func (s *Store) LoadSkillHistoryInput(ctx context.Context, projectID int64, rootPath string, since, until time.Time, prefixes []string) (skillhistory.Input, error) {
	var in skillhistory.Input
	var err error
	if in.Inventory, err = s.loadSkillInventory(ctx, rootPath); err != nil {
		return in, err
	}
	if in.Timeline, in.TimelineTruncated, err = s.loadSkillTimeline(ctx, projectID, prefixes); err != nil {
		return in, err
	}
	if in.Ancestry, err = s.loadSameSecondAncestry(ctx, projectID, in.Timeline); err != nil {
		return in, err
	}
	if in.Trees, err = s.loadSkillTrees(ctx, projectID); err != nil {
		return in, err
	}
	if in.HeadMoves, err = s.loadHeadMoves(ctx, projectID); err != nil {
		return in, err
	}
	if in.Worktree, err = s.loadSkillWorktree(ctx, projectID); err != nil {
		return in, err
	}
	st, ok, err := s.SkillScanStateFor(ctx, projectID)
	if err != nil {
		return in, err
	}
	if ok {
		in.Git = skillhistory.GitState{
			Scanned: !st.LastScanAt.IsZero(), LastScanAt: st.LastScanAt, HeadSHA: st.HeadSHA,
			ReflogSince: st.ReflogSince, IgnoreCase: st.IgnoreCase, Shallow: st.Shallow,
			ObjectFormat: st.ObjectFormat, LastError: st.LastError,
		}
		if in.Git.Scanned {
			for _, p := range []struct {
				name    string
				unknown bool
			}{
				{"ignorecase", !st.IgnoreCaseKnown},
				{"shallow", !st.ShallowKnown},
				{"object_format", st.ObjectFormat == ""},
			} {
				if p.unknown {
					in.Git.ProbeUnknown = append(in.Git.ProbeUnknown, p.name)
				}
			}
		}
	}
	if in.Sessions, err = s.loadSkillSessions(ctx, projectID, since, until); err != nil {
		return in, err
	}
	if in.Invocations, err = s.loadSkillInvocations(ctx, projectID, since, until); err != nil {
		return in, err
	}
	if in.Snapshots, err = s.loadSkillSnapshots(ctx, in.Sessions, in.Invocations); err != nil {
		return in, err
	}
	return in, nil
}

func (s *Store) loadSkillInventory(ctx context.Context, rootPath string) ([]skillhistory.InventoryFile, error) {
	root := normalizeGuidanceRoot(strings.TrimSpace(rootPath))
	rows, err := s.db.QueryContext(ctx, `
SELECT scope, rel_path, MAX(name), MAX(present)
  FROM project_guidance_files
 WHERE project_root IN (?, ?) AND kind = 'skill'
 GROUP BY scope, rel_path
 ORDER BY scope, rel_path`, root, GuidanceUserScopeRoot)
	if err != nil {
		return nil, fmt.Errorf("store.loadSkillInventory: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.InventoryFile
	for rows.Next() {
		var f skillhistory.InventoryFile
		var present int
		if err := rows.Scan(&f.Scope, &f.RelPath, &f.Name, &present); err != nil {
			return nil, fmt.Errorf("store.loadSkillInventory: scan: %w", err)
		}
		f.Present = present != 0
		out = append(out, f)
	}
	return out, rows.Err()
}

// loadSkillTimeline loads the commits that touched a skill path, oldest
// first. At the cap it keeps the NEWEST rows (ordered newest first, then
// reversed) and reports truncated; the oldest commit, possibly cut
// mid-file-list, is dropped whole. Within one committer second the
// scanner's insertion order is the tiebreak (its --date-order history
// walk emits children first, so a LOWER id is newer), never the sha; the
// pure layer then orders such groups by ancestry.
func (s *Store) loadSkillTimeline(ctx context.Context, projectID int64, prefixes []string) ([]skillhistory.TimelineCommit, bool, error) {
	pats := likePrefixes(prefixes)
	if len(pats) == 0 {
		return nil, false, nil
	}
	args := []any{projectID}
	for _, p := range pats {
		args = append(args, p)
	}
	args = append(args, skillHistoryTimelineCap)
	//nolint:gosec // G202: likeClause emits a fixed in-package column and "LIKE ?" placeholders; every pattern is bound.
	rows, err := s.db.QueryContext(ctx, `
SELECT c.sha, c.committed_at, c.subject, c.reachable, c.is_merge, c.parents_json, f.rel_path
  FROM project_commits c JOIN project_commit_files f ON f.commit_id = c.id
 WHERE c.project_id = ? AND `+likeClause("f.rel_path", len(pats))+`
 ORDER BY c.committed_at DESC, c.id ASC, f.rel_path
 LIMIT ?`, args...)
	if err != nil {
		return nil, false, fmt.Errorf("store.loadSkillTimeline: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.TimelineCommit
	idx := map[string]int{}
	n := 0
	for rows.Next() {
		var sha, at, subject, parents, rel string
		var reachable, merge int
		if err := rows.Scan(&sha, &at, &subject, &reachable, &merge, &parents, &rel); err != nil {
			return nil, false, fmt.Errorf("store.loadSkillTimeline: scan: %w", err)
		}
		n++
		i, ok := idx[sha]
		if !ok {
			i = len(out)
			idx[sha] = i
			out = append(out, skillhistory.TimelineCommit{
				SHA: sha, CommittedAt: parseCommitTime(at), Subject: subject,
				Reachable: reachable != 0, IsMerge: merge != 0, Parents: parseParents(parents),
			})
		}
		out[i].Files = append(out[i].Files, rel)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("store.loadSkillTimeline: rows: %w", err)
	}
	truncated := n >= skillHistoryTimelineCap
	if truncated && len(out) > 0 {
		out = out[:len(out)-1]
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, truncated, nil
}

// parseParents decodes project_commits.parents_json; a malformed value is
// treated as "no known parents" (ordering then falls back, never fails).
func parseParents(v string) []string {
	var ps []string
	if json.Unmarshal([]byte(v), &ps) != nil {
		return nil
	}
	return ps
}

// loadSameSecondAncestry returns sha -> parents for every recorded commit
// that shares a committer second with two or more timeline commits, so the
// pure layer can order such a group through commits that touched no skill.
func (s *Store) loadSameSecondAncestry(ctx context.Context, projectID int64, timeline []skillhistory.TimelineCommit) (map[string][]string, error) {
	count := map[string]int{}
	for _, c := range timeline {
		count[timestamp(c.CommittedAt)]++
	}
	var tied []string
	for k, n := range count {
		if n > 1 {
			tied = append(tied, k)
		}
	}
	if len(tied) == 0 {
		return nil, nil
	}
	sort.Strings(tied)
	out := map[string][]string{}
	for lo := 0; lo < len(tied); lo += 500 {
		hi := lo + 500
		if hi > len(tied) {
			hi = len(tied)
		}
		args := []any{projectID}
		for _, t := range tied[lo:hi] {
			args = append(args, t) // the scanner's own stored format (timestamp)
		}
		//nolint:gosec // G202: only a ",?" placeholder run is concatenated; every value is bound.
		rows, err := s.db.QueryContext(ctx, `
SELECT sha, parents_json FROM project_commits
 WHERE project_id = ? AND committed_at IN (?`+strings.Repeat(",?", hi-lo-1)+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("store.loadSameSecondAncestry: %w", err)
		}
		for rows.Next() {
			var sha, parents string
			if err := rows.Scan(&sha, &parents); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.loadSameSecondAncestry: scan: %w", err)
			}
			out[sha] = parseParents(parents)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, fmt.Errorf("store.loadSameSecondAncestry: rows: %w", err)
		}
	}
	return out, nil
}

func (s *Store) loadSkillTrees(ctx context.Context, projectID int64) ([]skillhistory.Tree, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT t.sha, t.state, COALESCE(f.rel_path, ''), COALESCE(f.mode, ''), COALESCE(f.blob_oid, '')
  FROM project_skill_trees t
  LEFT JOIN project_skill_tree_files f ON f.project_id = t.project_id AND f.sha = t.sha
 WHERE t.project_id = ?
 ORDER BY t.sha, f.rel_path`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store.loadSkillTrees: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.Tree
	idx := map[string]int{}
	for rows.Next() {
		var sha, state, rel, mode, blob string
		if err := rows.Scan(&sha, &state, &rel, &mode, &blob); err != nil {
			return nil, fmt.Errorf("store.loadSkillTrees: scan: %w", err)
		}
		i, ok := idx[sha]
		if !ok {
			i = len(out)
			idx[sha] = i
			out = append(out, skillhistory.Tree{SHA: sha, State: state, Files: map[string]skillhistory.TreeFile{}})
		}
		if rel != "" {
			out[i].Files[rel] = skillhistory.TreeFile{Mode: mode, BlobOID: blob}
		}
	}
	return out, rows.Err()
}

func (s *Store) loadHeadMoves(ctx context.Context, projectID int64) ([]skillhistory.HeadMove, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT moved_at, sha, kind, seq FROM project_head_moves
 WHERE project_id = ? ORDER BY moved_at DESC, seq DESC LIMIT ?`, projectID, skillHistoryHeadMoveCap)
	if err != nil {
		return nil, fmt.Errorf("store.loadHeadMoves: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.HeadMove
	for rows.Next() {
		var at string
		var m skillhistory.HeadMove
		if err := rows.Scan(&at, &m.SHA, &m.Kind, &m.Seq); err != nil {
			return nil, fmt.Errorf("store.loadHeadMoves: scan: %w", err)
		}
		m.MovedAt = parseSkillTime(at)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) loadSkillWorktree(ctx context.Context, projectID int64) ([]skillhistory.WorktreeEntry, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT rel_path, state FROM project_skill_worktree WHERE project_id = ? ORDER BY rel_path`, projectID)
	if err != nil {
		return nil, fmt.Errorf("store.loadSkillWorktree: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.WorktreeEntry
	for rows.Next() {
		var w skillhistory.WorktreeEntry
		if err := rows.Scan(&w.RelPath, &w.State); err != nil {
			return nil, fmt.Errorf("store.loadSkillWorktree: scan: %w", err)
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// loadSkillSessions loads the project's sessions that STARTED in the
// window, with their lineage. Relation: a claude-code "<parent>:agent:<id>"
// child or a thread_source='subagent' / parent_thread_id link is a
// sub-agent; a forked_from_id link is a user fork.
func (s *Store) loadSkillSessions(ctx context.Context, projectID int64, since, until time.Time) ([]skillhistory.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tool, started_at,
       COALESCE(parent_thread_id, ''), COALESCE(forked_from_id, ''), COALESCE(thread_source, '')
  FROM sessions
 WHERE project_id = ? AND started_at >= ? AND started_at < ?
 ORDER BY started_at, id`, projectID, timestamp(since), timestamp(until))
	if err != nil {
		return nil, fmt.Errorf("store.loadSkillSessions: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.Session
	for rows.Next() {
		var ss skillhistory.Session
		var started, parent, forked, source string
		if err := rows.Scan(&ss.ID, &ss.Tool, &started, &parent, &forked, &source); err != nil {
			return nil, fmt.Errorf("store.loadSkillSessions: scan: %w", err)
		}
		ss.StartedAt = parseCommitTime(started)
		switch {
		case forked != "" && source != "subagent":
			ss.Relation, ss.ParentID = skillhistory.RelationFork, forked
		case parent != "":
			ss.Relation, ss.ParentID = skillhistory.RelationSubagent, parent
		case strings.Contains(ss.ID, ":agent:"):
			ss.Relation = skillhistory.RelationSubagent
			ss.ParentID, _, _ = strings.Cut(ss.ID, ":agent:")
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}

// loadSkillInvocations loads the window's skill_invoke actions. It reuses
// guidanceUsageQuery's `+project_id` planner trick so the selective
// (action_type, ...) index wins over the project index.
func (s *Store) loadSkillInvocations(ctx context.Context, projectID int64, since, until time.Time) ([]skillhistory.Invocation, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT session_id, tool, target, COALESCE(source_event_id, ''), timestamp
  FROM actions
 WHERE action_type = ?
   AND +project_id = ?
   AND timestamp >= ? AND timestamp < ?
   AND target IS NOT NULL AND target <> ''
 ORDER BY timestamp, id`, models.ActionSkillInvoke, projectID, timestamp(since), timestamp(until))
	if err != nil {
		return nil, fmt.Errorf("store.loadSkillInvocations: %w", err)
	}
	defer rows.Close()
	var out []skillhistory.Invocation
	for rows.Next() {
		var inv skillhistory.Invocation
		var at string
		if err := rows.Scan(&inv.SessionID, &inv.Tool, &inv.Name, &inv.ToolUseID, &at); err != nil {
			return nil, fmt.Errorf("store.loadSkillInvocations: scan: %w", err)
		}
		inv.At = parseCommitTime(at)
		out = append(out, inv)
	}
	return out, rows.Err()
}

// loadSkillSnapshots loads the session_start snapshots of the window's
// sessions and the skill_invoke snapshots of the window's invocations
// (joined by tool_use_id, so a sub-agent invocation re-parented to its
// child session still finds its snapshot), with their member sets.
func (s *Store) loadSkillSnapshots(ctx context.Context, sessions []skillhistory.Session, invs []skillhistory.Invocation) ([]skillhistory.Snapshot, error) {
	const cols = `session_id, tool, event, source, tool_use_id, invoked_name, observed_at, set_hash, complete, home_resolved`
	var out []skillhistory.Snapshot
	var outHash []string // set_hash of out[i], attached as members below
	var hashes []string
	seenHash := map[string]bool{}
	scan := func(query string, args []any) error {
		rows, err := s.db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sn skillhistory.Snapshot
			var at, setHash string
			var complete, home int
			if err := rows.Scan(&sn.SessionID, &sn.Tool, &sn.Event, &sn.Source, &sn.ToolUseID,
				&sn.InvokedName, &at, &setHash, &complete, &home); err != nil {
				return err
			}
			sn.ObservedAt = parseSkillTime(at)
			sn.Complete, sn.HomeResolved = complete != 0, home != 0
			out = append(out, sn)
			outHash = append(outHash, setHash)
			if !seenHash[setHash] {
				seenHash[setHash] = true
				hashes = append(hashes, setHash)
			}
		}
		return rows.Err()
	}

	ids := make([]string, 0, len(sessions))
	for _, ss := range sessions {
		ids = append(ids, ss.ID)
	}
	for _, chunk := range chunkStrings(ids, 500) {
		if len(chunk) == 0 {
			continue
		}
		if err := scan(`SELECT `+cols+` FROM session_skill_snapshots
 WHERE event = 'session_start' AND session_id IN (`+placeholders(len(chunk))+`)
 ORDER BY session_id, observed_at`, stringArgs(chunk)); err != nil {
			return nil, fmt.Errorf("store.loadSkillSnapshots: session_start: %w", err)
		}
	}
	var tus []string
	for _, inv := range invs {
		if inv.ToolUseID != "" {
			tus = append(tus, inv.ToolUseID)
		}
	}
	for _, chunk := range chunkStrings(tus, 500) {
		if len(chunk) == 0 {
			continue
		}
		if err := scan(`SELECT `+cols+` FROM session_skill_snapshots
 WHERE event = 'skill_invoke' AND tool_use_id IN (`+placeholders(len(chunk))+`)
 ORDER BY tool_use_id, observed_at`, stringArgs(chunk)); err != nil {
			return nil, fmt.Errorf("store.loadSkillSnapshots: skill_invoke: %w", err)
		}
	}

	members := map[string][]skillhistory.Member{}
	for _, chunk := range chunkStrings(hashes, 500) {
		if len(chunk) == 0 {
			continue
		}
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value is bound.
		rows, err := s.db.QueryContext(ctx, `
SELECT set_hash, scope, rel_path, name, state, blob_oid, blob_oid_lf
  FROM skill_snapshot_members WHERE set_hash IN (`+placeholders(len(chunk))+`)
 ORDER BY set_hash, scope, rel_path`, stringArgs(chunk)...)
		if err != nil {
			return nil, fmt.Errorf("store.loadSkillSnapshots: members: %w", err)
		}
		for rows.Next() {
			var h string
			var m skillhistory.Member
			if err := rows.Scan(&h, &m.Scope, &m.RelPath, &m.Name, &m.State, &m.BlobOID, &m.BlobOIDLF); err != nil {
				rows.Close()
				return nil, fmt.Errorf("store.loadSkillSnapshots: members scan: %w", err)
			}
			members[h] = append(members[h], m)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store.loadSkillSnapshots: members: %w", err)
		}
		rows.Close()
	}
	for i := range out {
		out[i].Members = members[outHash[i]]
	}
	return out, nil
}

func stringArgs(ids []string) []any {
	out := make([]any, len(ids))
	for i, v := range ids {
		out[i] = v
	}
	return out
}
