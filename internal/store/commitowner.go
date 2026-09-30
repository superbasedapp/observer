package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// commitowner.go composes the commit-ownership fold (internal/projectroi.
// Ownership, docs/projects-page.md "Commit ownership") over one project's
// window. It is the ONE composition of "load prompts + AI edits + commits,
// Link them, fold ownership" shared by the node dashboard's session
// "Commits" section and the org-wire composer, so the two can never run a
// different loader set or a different link window over the same commit.
// Every table read stays in the existing owners (projectroi.go for
// actions/file_changes, commits.go for project_commit*); this file adds no
// SQL against those tables.

// OwnershipCaps bounds the three loaders feeding Link. A zero field falls
// back to the loader's own default.
type OwnershipCaps struct {
	Prompts int
	Edits   int
	Commits int
}

// CommitOwnershipResult is one project window's ownership fold.
type CommitOwnershipResult struct {
	// Commits are the window's commit rows (newest first, as
	// LoadProjectCommits orders them), including the scrubbed subject.
	Commits []ProjectCommitRow
	// Ownership is keyed by ProjectCommitRow.ID.
	Ownership map[int64]projectroi.CommitOwnership
	// Linkage is the Link result the ownership was folded from.
	Linkage projectroi.Linkage
	// *Truncated report whether a loader hit its cap; an ownership computed
	// over a truncated input is a best effort, and a caller must say so.
	PromptsTruncated bool
	EditsTruncated   bool
	CommitsTruncated bool
}

// Truncated reports whether any loader hit its cap.
func (r CommitOwnershipResult) Truncated() bool {
	return r.PromptsTruncated || r.EditsTruncated || r.CommitsTruncated
}

// LoadCommitOwnership loads one project's prompts, AI edits and commits in
// [since, until), links them under linkWindow and folds commit ownership.
func (s *Store) LoadCommitOwnership(ctx context.Context, projectID int64, since, until time.Time, linkWindow time.Duration, caps OwnershipCaps) (CommitOwnershipResult, error) {
	var res CommitOwnershipResult
	prompts, pt, err := s.LoadProjectPrompts(ctx, projectID, since, until, caps.Prompts)
	if err != nil {
		return res, fmt.Errorf("store.LoadCommitOwnership: %w", err)
	}
	edits, et, err := s.LoadProjectAIEdits(ctx, projectID, since, until, caps.Edits)
	if err != nil {
		return res, fmt.Errorf("store.LoadCommitOwnership: %w", err)
	}
	commits, rows, ct, err := s.loadCommitsAndRowsForLink(ctx, projectID, since, until, caps.Commits)
	if err != nil {
		return res, fmt.Errorf("store.LoadCommitOwnership: %w", err)
	}
	res.Commits = rows
	res.Linkage = projectroi.Link(prompts, edits, commits, projectroi.Options{LinkWindow: linkWindow})
	res.Ownership = projectroi.Ownership(res.Linkage, commits)
	res.PromptsTruncated, res.EditsTruncated, res.CommitsTruncated = pt, et, ct
	return res, nil
}

// SessionWindow is the project + time span a session's commit ownership is
// computed over.
type SessionWindow struct {
	ProjectID int64
	StartedAt time.Time
	// EndedAt is the session's end, or now for a session still open.
	EndedAt time.Time
}

// LoadSessionWindow resolves a session's project and span. ok=false means
// the session is unknown or belongs to no project.
func (s *Store) LoadSessionWindow(ctx context.Context, sessionID string, now time.Time) (SessionWindow, bool, error) {
	w, exists, err := s.LookupSessionWindow(ctx, sessionID, now)
	if err != nil || !exists || w.ProjectID <= 0 {
		return SessionWindow{}, false, err
	}
	return w, true, nil
}

// LookupSessionWindow is LoadSessionWindow with its two ok=false cases
// told apart, for a caller that must answer them differently (the session
// "Commits" endpoint: an unknown session is a 404, a session with no
// project an honest empty list). exists=false means no such session;
// exists=true with ProjectID == 0 means the session belongs to no project.
func (s *Store) LookupSessionWindow(ctx context.Context, sessionID string, now time.Time) (SessionWindow, bool, error) {
	var pid sql.NullInt64
	var started string
	var ended sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT project_id, started_at, ended_at FROM sessions WHERE id = ?`, sessionID).
		Scan(&pid, &started, &ended)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionWindow{}, false, nil
	}
	if err != nil {
		return SessionWindow{}, false, fmt.Errorf("store.LookupSessionWindow: %w", err)
	}
	if !pid.Valid || pid.Int64 <= 0 {
		return SessionWindow{}, true, nil
	}
	w := SessionWindow{ProjectID: pid.Int64, StartedAt: parseCommitTime(started), EndedAt: now}
	if ended.Valid && ended.String != "" {
		if t := parseCommitTime(ended.String); !t.IsZero() && t.Before(now) {
			w.EndedAt = t
		}
	}
	return w, true, nil
}

// SessionOwnershipSpan is the [since, until) window LoadCommitOwnership
// must cover so every commit this session could have fed - and every OTHER
// session that fed the same commits - is inside it: prompts from one link
// window before the session started (an earlier session can co-contribute
// to a commit this session also reached) through one link window after it
// ended (the last moment one of its prompts can still be carried).
func SessionOwnershipSpan(w SessionWindow, linkWindow time.Duration, now time.Time) (since, until time.Time) {
	if linkWindow <= 0 {
		linkWindow = projectroi.DefaultLinkWindow
	}
	since = w.StartedAt.Add(-linkWindow)
	until = w.EndedAt.Add(linkWindow)
	if until.After(now) {
		until = now.Add(time.Minute)
	}
	return since, until
}
