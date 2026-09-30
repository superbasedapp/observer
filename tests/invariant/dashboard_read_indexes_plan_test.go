package invariant

import (
	"context"
	"strings"
	"testing"

	agentdb "github.com/marmutapp/superbased-observer/internal/db"
)

// TestDashboardReadIndexesArePicked pins migration 147
// (docs/audits/node-dashboard-performance-audit-2026-09-29.md): each index
// must be the one SQLite's planner actually picks for the query shape it
// exists for, and the stale-read probe must seek its target. Without
// sqlite_stat1 the planner's choice does not depend on row counts, so an
// empty in-memory database reproduces the plan the real 27 GB node gets.
//
// The last row is the regression this migration nearly shipped: a covering
// (action_type, timestamp, ...) variant was preferred for the stale-read
// EXISTS probe over the 4-column seek, turning /api/analysis/headline from
// about a minute into several. The probe must name `target=?` in its seek.
func TestDashboardReadIndexesArePicked(t *testing.T) {
	ctx := context.Background()
	database, err := agentdb.Open(ctx, agentdb.Options{Path: ":memory:"})
	if err != nil {
		t.Fatalf("agentdb.Open: %v", err)
	}
	defer database.Close()

	const since = "2026-01-01T00:00:00Z"
	cases := []struct {
		name  string
		query string
		args  []any
		// want: every substring must appear in the plan text.
		want []string
		// deny: no substring may appear in the plan text.
		deny []string
	}{
		{
			// internal/intelligence/dashboard.handleSessions window filter.
			name: "sessions list activity EXISTS",
			query: `SELECT COUNT(*) FROM sessions s
				 WHERE (s.started_at >= ?
				    OR EXISTS (SELECT 1 FROM actions a2 WHERE a2.session_id = s.id AND a2.timestamp >= ?)
				    OR EXISTS (SELECT 1 FROM api_turns at2 WHERE at2.session_id = s.id AND at2.timestamp >= ?)
				    OR EXISTS (SELECT 1 FROM token_usage tu2 WHERE tu2.session_id = s.id AND tu2.timestamp >= ?))`,
			args: []any{since, since, since, since},
			want: []string{
				"idx_actions_session_ts (session_id=? AND timestamp>?)",
				"idx_api_turns_session_ts (session_id=? AND timestamp>?)",
				"idx_token_usage_session_ts (session_id=? AND timestamp>?)",
			},
		},
		{
			// internal/store.LatestLimitSnapshotForTool.
			name: "latest limit snapshot for a tool",
			query: `SELECT l.id FROM limit_snapshots l
				  JOIN sessions s ON s.id = l.session_id
				 WHERE l.provider = ? AND s.tool = ?
				 ORDER BY l.observed_at DESC, l.id DESC LIMIT 1`,
			args: []any{"anthropic", "claude-code"},
			want: []string{"idx_limit_snapshots_provider_observed (provider=?)"},
			deny: []string{"TEMP B-TREE FOR ORDER BY"},
		},
		{
			// internal/intelligence/dashboard.loadActionExcerpts.
			name: "excerpts by action id",
			query: `SELECT rowid, action_id, excerpt FROM action_excerpts
				 WHERE rowid IN (SELECT id FROM action_excerpts_content WHERE c0 IN (?, ?, ?))`,
			args: []any{int64(1), int64(2), int64(3)},
			want: []string{"idx_action_excerpts_content_c0 (c0=?)"},
		},
		{
			// internal/intelligence/discover.repeatedCommands.
			name: "discover repeated commands",
			query: `SELECT a.target, COALESCE(p.root_path, ''), COUNT(*) AS total_runs,
				       SUM(CASE WHEN a.success THEN 1 ELSE 0 END), SUM(CASE WHEN NOT a.success THEN 1 ELSE 0 END)
				  FROM actions a LEFT JOIN projects p ON p.id = a.project_id
				 WHERE a.action_type = 'run_command' AND a.target != '' AND a.timestamp >= ?
				 GROUP BY a.target, a.project_id HAVING total_runs > 1
				 ORDER BY total_runs DESC LIMIT ?`,
			args: []any{since, 20},
			want: []string{"COVERING INDEX idx_actions_type_target_cover (action_type=?)"},
		},
		{
			// internal/intelligence/discover.staleReads correlated probe.
			name: "discover stale-read probe seeks the target",
			query: `SELECT a.target,
				       SUM(CASE WHEN a.freshness = 'stale' AND EXISTS (
				             SELECT 1 FROM actions a2
				              WHERE a2.session_id = a.session_id AND a2.project_id = a.project_id
				                AND a2.target = a.target AND a2.action_type = 'read_file'
				                AND a2.timestamp < a.timestamp)
				           THEN 1 ELSE 0 END) AS stale_count
				  FROM actions a
				 WHERE a.action_type = 'read_file' AND a.target != '' AND a.timestamp >= ?
				 GROUP BY a.target, a.project_id`,
			args: []any{since},
			want: []string{"target=?"},
			deny: []string{"(action_type=? AND timestamp<?)"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := database.QueryContext(ctx, "EXPLAIN QUERY PLAN "+tc.query, tc.args...)
			if err != nil {
				t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
			}
			defer rows.Close()
			var plan strings.Builder
			for rows.Next() {
				var id, parent, notused int64
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatalf("scan: %v", err)
				}
				plan.WriteString(detail)
				plan.WriteString("\n")
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("rows: %v", err)
			}
			got := plan.String()
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("plan lacks %q:\n%s", w, got)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(got, d) {
					t.Errorf("plan contains %q:\n%s", d, got)
				}
			}
		})
	}
}
