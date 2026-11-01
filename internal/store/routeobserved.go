package store

import (
	"context"
	"fmt"
	"time"
)

// routeobserved.go is the node half of per-surface traffic truth (surface-
// gap arc Wave 1, findings OBS-1 and OBS-2; docs/audits/surface-settings-
// precedence-gap-review-2026-10-25.md section 3.2). It answers, per capture
// surface, how many sessions ran and how many of them reached this node's
// proxy. The doctor's route.observed check and the dashboard's capture pill
// feed its rows to routeattest.AttestSurfaces; neither reads a settings file
// to decide whether traffic was proxied.

// RouteObservedRow is one (tool, surface, surface_host) session group.
// Both counts are SESSIONS in the window, never API turns: a session with
// many api_turns rows counts once in ProxiedSessions.
type RouteObservedRow struct {
	Tool string
	// Surface is sessions.surface ("" when no adapter stamped it).
	Surface string
	// SurfaceHost is sessions.surface_host ("" when unstamped).
	SurfaceHost string
	// Sessions is the number of the group's sessions that started at or
	// after the window start.
	Sessions int
	// ProxiedSessions is the number of those sessions with at least one
	// api_turns row joined on api_turns.session_id = sessions.id.
	ProxiedSessions int
}

// routeObservedQuery is RouteObservedSince's SQL. The window sits in WHERE
// so idx_sessions_started (migration 001) serves it as a range scan: each
// integrity cycle reads only the window's sessions, never the whole table
// (surface-gap audit finding 7). Its one parameter is the window start.
const routeObservedQuery = `
SELECT COALESCE(s.tool, ''), COALESCE(s.surface, ''), COALESCE(s.surface_host, ''),
       COUNT(*),
       SUM(CASE WHEN EXISTS (SELECT 1 FROM api_turns a WHERE a.session_id = s.id)
                THEN 1 ELSE 0 END)
  FROM sessions s
 WHERE s.started_at >= ?
   AND COALESCE(s.tool, '') != ''
 GROUP BY COALESCE(s.tool, ''), COALESCE(s.surface, ''), COALESCE(s.surface_host, '')
 ORDER BY 1, 2, 3`

// RouteObservedSince returns one row per (tool, surface, surface_host)
// group with at least one session that started at or after since (a zero
// since counts every session), ordered by those three keys. A group whose
// sessions all started before the window is not returned: every reader
// passes the rows through routeattest.WithDeclaredSurfaces, which adds a
// zero-count group for each declared surface of a tool with rows, and a
// zero-session group can never be a bypass or speak for another group.
// Sessions with no tool are skipped. Metadata only: counts, never a row's
// content.
func (s *Store) RouteObservedSince(ctx context.Context, since time.Time) ([]RouteObservedRow, error) {
	start := ""
	if !since.IsZero() {
		start = timestamp(since.UTC())
	}
	rows, err := s.db.QueryContext(ctx, routeObservedQuery, start)
	if err != nil {
		return nil, fmt.Errorf("store.RouteObservedSince: %w", err)
	}
	defer rows.Close()
	var out []RouteObservedRow
	for rows.Next() {
		var r RouteObservedRow
		if err := rows.Scan(&r.Tool, &r.Surface, &r.SurfaceHost, &r.Sessions, &r.ProxiedSessions); err != nil {
			return nil, fmt.Errorf("store.RouteObservedSince: scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.RouteObservedSince: %w", err)
	}
	return out, nil
}
