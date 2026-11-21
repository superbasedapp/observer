package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// FirstRunGlanceFacts is what the local dashboard's first-run "at a
// glance" card reads from the database beyond the spend substrate: the
// project with the most captured sessions, how many sessions started in
// the glance window, and the agent session that is working right now, if
// any. Every field is a plain count or a name already shown elsewhere on
// the dashboard (the Projects and Live pages); nothing here is content.
// Node-local: nothing reads this from the org push seam.
type FirstRunGlanceFacts struct {
	// BusiestProject is the project with the most captured sessions, all
	// time (nil when no session has a project).
	BusiestProject *FirstRunGlanceProject
	// RecentSessions counts sessions started at or after the window start.
	RecentSessions int64
	// ActiveNow is the session with the newest action at or after the live
	// cutoff (nil when nothing is working).
	ActiveNow *FirstRunGlanceActive
}

// FirstRunGlanceProject is one project and its captured session count.
type FirstRunGlanceProject struct {
	Name     string
	Root     string
	Sessions int64
}

// FirstRunGlanceActive is the session with the newest recent action: its
// tool and project root only (never the action or its target).
type FirstRunGlanceActive struct {
	Tool        string
	ProjectRoot string
}

// LoadFirstRunGlance reads the first-run glance facts. since is the glance
// window's start (sessions started at or after it count as recent);
// liveSince is the "working right now" cutoff, compared against
// actions.timestamp (RFC3339 UTC text, so string order is time order and
// idx_actions_timestamp bounds the scan).
func (s *Store) LoadFirstRunGlance(ctx context.Context, since, liveSince time.Time) (FirstRunGlanceFacts, error) {
	var out FirstRunGlanceFacts
	if s == nil || s.db == nil {
		return out, nil
	}
	var p FirstRunGlanceProject
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(p.name, ''), p.root_path, COUNT(s.id) AS n
		FROM sessions s JOIN projects p ON p.id = s.project_id
		GROUP BY p.id
		ORDER BY n DESC, MAX(s.started_at) DESC
		LIMIT 1`).Scan(&p.Name, &p.Root, &p.Sessions)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return out, fmt.Errorf("store.LoadFirstRunGlance: busiest project: %w", err)
	default:
		out.BusiestProject = &p
	}

	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE started_at >= ?`,
		since.UTC().Format(time.RFC3339Nano)).Scan(&out.RecentSessions); err != nil {
		return out, fmt.Errorf("store.LoadFirstRunGlance: recent sessions: %w", err)
	}

	var a FirstRunGlanceActive
	err = s.db.QueryRowContext(ctx, `
		SELECT s.tool, COALESCE(p.root_path, '')
		FROM actions a
		JOIN sessions s ON s.id = a.session_id
		LEFT JOIN projects p ON p.id = s.project_id
		WHERE a.timestamp >= ?
		ORDER BY a.timestamp DESC
		LIMIT 1`, liveSince.UTC().Format(time.RFC3339Nano)).Scan(&a.Tool, &a.ProjectRoot)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return out, fmt.Errorf("store.LoadFirstRunGlance: active now: %w", err)
	default:
		out.ActiveNow = &a
	}
	return out, nil
}
