package store

import (
	"context"
	"database/sql"
	"reflect"
	"strings"
	"testing"
	"time"
)

// seedRouteObserved inserts one session with its surface stamp and n
// api_turns rows.
func seedRouteObserved(t *testing.T, database *sql.DB, id, tool, surface, host string, started time.Time, turns int) {
	t.Helper()
	ts := timestamp(started)
	if _, err := database.Exec(`INSERT INTO projects (root_path, name, created_at) VALUES ('/p', 'p', ?) ON CONFLICT DO NOTHING`, ts); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(
		`INSERT INTO sessions (id, project_id, tool, started_at, surface, surface_host) VALUES (?, 1, ?, ?, NULLIF(?, ''), NULLIF(?, ''))`,
		id, tool, ts, surface, host); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < turns; i++ {
		if _, err := database.Exec(
			`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens) VALUES (?, ?, 'anthropic', 'm', 1, 1)`,
			id, ts); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRouteObservedSince(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	since := now.Add(-24 * time.Hour)
	old := now.Add(-72 * time.Hour)

	type session struct {
		id, tool, surface, host string
		started                 time.Time
		turns                   int
	}
	cases := []struct {
		name     string
		sessions []session
		want     []RouteObservedRow
	}{
		{
			name: "a session with several api_turns counts once",
			sessions: []session{
				{"s1", "claude-code", "cli", "", now, 5},
			},
			want: []RouteObservedRow{{Tool: "claude-code", Surface: "cli", Sessions: 1, ProxiedSessions: 1}},
		},
		{
			name: "mixed: CLI proxied, desktop unproxied",
			sessions: []session{
				{"c1", "claude-code", "cli", "", now, 3},
				{"c2", "claude-code", "cli", "", now, 1},
				{"c3", "claude-code", "cli", "", now, 0},
				{"d1", "claude-code", "desktop", "claude-desktop", now, 0},
				{"d2", "claude-code", "desktop", "claude-desktop", now, 0},
			},
			want: []RouteObservedRow{
				{Tool: "claude-code", Surface: "cli", Sessions: 3, ProxiedSessions: 2},
				{Tool: "claude-code", Surface: "desktop", SurfaceHost: "claude-desktop", Sessions: 2, ProxiedSessions: 0},
			},
		},
		{
			name: "a group seen only before the window is not returned",
			sessions: []session{
				{"o1", "codex", "ide", "vscode", old, 2},
				{"n1", "codex", "cli", "", now, 1},
			},
			want: []RouteObservedRow{
				{Tool: "codex", Surface: "cli", Sessions: 1, ProxiedSessions: 1},
			},
		},
		{
			name: "sessions before the window are not counted in a group that has newer ones",
			sessions: []session{
				{"o1", "codex", "cli", "", old, 2},
				{"o2", "codex", "cli", "", old, 0},
				{"n1", "codex", "cli", "", now, 0},
			},
			want: []RouteObservedRow{
				{Tool: "codex", Surface: "cli", Sessions: 1, ProxiedSessions: 0},
			},
		},
		{
			name: "a session at the window start is inside it",
			sessions: []session{
				{"b1", "codex", "cli", "", since, 1},
			},
			want: []RouteObservedRow{
				{Tool: "codex", Surface: "cli", Sessions: 1, ProxiedSessions: 1},
			},
		},
		{
			name: "only sessions before the window returns no rows",
			sessions: []session{
				{"o1", "codex", "cli", "", old, 1},
				{"o2", "claude-code", "desktop", "claude-desktop", old, 0},
			},
			want: nil,
		},
		{
			name: "an unstamped session is its own group",
			sessions: []session{
				{"u1", "gemini", "", "", now, 0},
			},
			want: []RouteObservedRow{{Tool: "gemini", Sessions: 1}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			for _, sess := range tc.sessions {
				seedRouteObserved(t, database, sess.id, sess.tool, sess.surface, sess.host, sess.started, sess.turns)
			}
			got, err := s.RouteObservedSince(context.Background(), since)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

func TestRouteObservedSinceZeroCountsEverySession(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	seedRouteObserved(t, database, "o1", "codex", "cli", "", time.Now().Add(-400*24*time.Hour), 2)
	got, err := s.RouteObservedSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	want := []RouteObservedRow{{Tool: "codex", Surface: "cli", Sessions: 1, ProxiedSessions: 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

// TestRouteObservedQueryUsesStartedIndex pins finding 7 of the surface-gap
// audit: the window is a WHERE range that idx_sessions_started serves, so an
// integrity cycle does not scan every session the node ever recorded.
func TestRouteObservedQueryUsesStartedIndex(t *testing.T) {
	t.Parallel()
	_, database := newTestStore(t)
	rows, err := database.Query("EXPLAIN QUERY PLAN "+routeObservedQuery, timestamp(time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(plan, "\n")
	if !strings.Contains(joined, "idx_sessions_started") {
		t.Fatalf("query plan does not use idx_sessions_started:\n%s", joined)
	}
}
