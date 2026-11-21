package diag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestStatusSnapshotMarshalJSONOmitsZeroTimes(t *testing.T) {
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		snap        StatusSnapshot
		wantLast    bool
		wantStarted bool
	}{
		{
			name: "fresh database omits both zero timestamps",
			snap: StatusSnapshot{DBPath: "/tmp/empty.db"},
		},
		{
			name:     "captured activity emits last timestamp",
			snap:     StatusSnapshot{DBPath: "/tmp/active.db", LastActionAt: now},
			wantLast: true,
		},
		{
			name:        "serving dashboard emits process start",
			snap:        StatusSnapshot{DBPath: "/tmp/served.db", StartedAt: now},
			wantStarted: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.snap)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatalf("Unmarshal wire: %v", err)
			}
			if _, ok := fields["db_path"]; !ok {
				t.Fatalf("ordinary embedded fields disappeared: %s", body)
			}
			_, gotLast := fields["last_action_at"]
			if gotLast != tc.wantLast {
				t.Errorf("last_action_at present = %v, want %v: %s", gotLast, tc.wantLast, body)
			}
			_, gotStarted := fields["started_at"]
			if gotStarted != tc.wantStarted {
				t.Errorf("started_at present = %v, want %v: %s", gotStarted, tc.wantStarted, body)
			}
		})
	}
}

func TestSnapshot_EmptyDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	snap, err := Snapshot(context.Background(), d, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.SchemaVersion == 0 {
		t.Errorf("schema version should be > 0 after migration: %d", snap.SchemaVersion)
	}
	if snap.Counts.Actions != 0 || snap.Counts.Sessions != 0 {
		t.Errorf("expected empty counts: %+v", snap.Counts)
	}
	if snap.Counts.CacheEvents != 0 {
		t.Errorf("cache_events empty-DB count: want 0 got %d", snap.Counts.CacheEvents)
	}
	if !snap.LastActionAt.IsZero() {
		t.Errorf("LastActionAt should be zero on empty DB")
	}
	// T-425: the snapshot names its machine, so a remote dashboard can.
	if want, err := os.Hostname(); err == nil && snap.HostName != want {
		t.Errorf("HostName = %q, want %q", snap.HostName, want)
	}
}

func TestSnapshot_PopulatedAndPerToolSummary(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	st := store.New(d)
	now := time.Now().UTC()
	events := []models.ToolEvent{
		{
			SourceFile: "a.jsonl", SourceEventID: "e1",
			SessionID: "s-claude", ProjectRoot: "/r1",
			Timestamp: now.Add(-30 * time.Minute),
			Tool:      models.ToolClaudeCode, ActionType: models.ActionReadFile,
			Target: "x.go", Success: true, RawToolName: "Read",
		},
		{
			SourceFile: "a.jsonl", SourceEventID: "e2",
			SessionID: "s-claude", ProjectRoot: "/r1",
			Timestamp: now.Add(-20 * time.Minute),
			Tool:      models.ToolClaudeCode, ActionType: models.ActionRunCommand,
			Target: "go test", Success: false, RawToolName: "Bash",
			ErrorMessage: "FAIL",
		},
		{
			SourceFile: "b.jsonl", SourceEventID: "e3",
			SessionID: "s-codex", ProjectRoot: "/r2",
			Timestamp: now.Add(-5 * time.Minute),
			Tool:      models.ToolCodex, ActionType: models.ActionReadFile,
			Target: "y.go", Success: true,
		},
	}
	if _, err := st.Ingest(context.Background(), events, nil, store.IngestOptions{
		RecordFailures: true,
	}); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	snap, err := Snapshot(context.Background(), d, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Counts.Sessions != 2 {
		t.Errorf("sessions: %d", snap.Counts.Sessions)
	}
	if snap.Counts.Actions != 3 {
		t.Errorf("actions: %d", snap.Counts.Actions)
	}
	if snap.Counts.FailureContext != 1 {
		t.Errorf("failure_context: %d", snap.Counts.FailureContext)
	}
	// Live badge: only s-codex has activity inside the 15-minute live
	// window (its action is 5m old; s-claude's newest is 20m old).
	if snap.Counts.LiveSessions != 1 {
		t.Errorf("live_sessions: want 1 got %d", snap.Counts.LiveSessions)
	}
	if snap.LastActionTool != models.ToolCodex {
		t.Errorf("last action tool: %s (want codex - most recent)", snap.LastActionTool)
	}
	tools := map[string]bool{}
	for _, ta := range snap.PerToolLastSeen {
		tools[ta.Tool] = true
	}
	if !tools[models.ToolClaudeCode] || !tools[models.ToolCodex] {
		t.Errorf("per-tool missing entries: %+v", snap.PerToolLastSeen)
	}
}

// TestSnapshot_CountsCacheEvents pins the migration-036 surface — a
// fresh-but-populated cache_events table should be counted by the
// snapshot so the sidebar badge has a non-zero number to render.
func TestSnapshot_CountsCacheEvents(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if _, err := d.ExecContext(
		context.Background(), `
		INSERT INTO cache_events (session_id, tier, timestamp, model, kind, tokens_read, tokens_written)
		VALUES (?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?)`,
		"s-1", "tier1", "2026-06-09T12:00:00Z", "claude-opus-4-7", "hit", 1024, 0,
		"s-1", "tier1", "2026-06-09T12:00:30Z", "claude-opus-4-7", "write", 0, 4096,
	); err != nil {
		t.Fatalf("seed cache_events: %v", err)
	}

	snap, err := Snapshot(context.Background(), d, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Counts.CacheEvents != 2 {
		t.Errorf("cache_events count: want 2 got %d", snap.Counts.CacheEvents)
	}
}

// TestSnapshot_CountsGuardAndRouterRows pins the migration-040/041
// surfaces — guard verdicts and router decisions feed the sidebar
// "Security" and "Routing" badges the same way cache_events feeds
// "Cache".
func TestSnapshot_CountsGuardAndRouterRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	if _, err := d.ExecContext(
		context.Background(), `
		INSERT INTO guard_events (ts, rule_id, severity, decision, enforced, chain_prev, chain_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"2026-06-12T10:00:00Z", "R-101", "warn", "flag", 0, "", "deadbeef",
	); err != nil {
		t.Fatalf("seed guard_events: %v", err)
	}
	if _, err := d.ExecContext(
		context.Background(), `
		INSERT INTO router_decisions (ts, mode, channel, original_model, selected_model, turn_kind, policy_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?)`,
		"2026-06-12T10:00:00Z", "advise", "proxy", "claude-opus-4-8", "claude-haiku-4-5", "read_only", "h1",
		"2026-06-12T10:01:00Z", "advise", "proxy", "claude-opus-4-8", "claude-opus-4-8", "code_edit", "h1",
	); err != nil {
		t.Fatalf("seed router_decisions: %v", err)
	}

	snap, err := Snapshot(context.Background(), d, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Counts.GuardEvents != 1 {
		t.Errorf("guard_events count: want 1 got %d", snap.Counts.GuardEvents)
	}
	if snap.Counts.RouterDecisions != 2 {
		t.Errorf("router_decisions count: want 2 got %d", snap.Counts.RouterDecisions)
	}
}

// TestSnapshot_CountsPatternsPlansBenchmarks pins the three table counts
// behind the sidebar "Patterns", "Plans & limits" and "Benchmarks" badges:
// each counts its own table (Patterns used to show the projects count).
func TestSnapshot_CountsPatternsPlansBenchmarks(t *testing.T) {
	cases := []struct {
		name                         string
		patterns, plans, benchmarks  int
		wantPatterns, wantPlans      int
		wantBenchmarks, wantProjects int
	}{
		{name: "empty tables count zero", wantProjects: 1},
		{
			name: "each table counted on its own", patterns: 3, plans: 2, benchmarks: 1,
			wantPatterns: 3, wantPlans: 2, wantBenchmarks: 1, wantProjects: 1,
		},
		{
			name: "patterns are not projects", patterns: 5,
			wantPatterns: 5, wantProjects: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dbPath := filepath.Join(t.TempDir(), "obs.db")
			d, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			// One project for the patterns' foreign key.
			if _, err := store.New(d).Ingest(ctx, []models.ToolEvent{{
				SourceFile: "f", SourceEventID: "e1", SessionID: "s1",
				ProjectRoot: t.TempDir(), Timestamp: time.Now().UTC().Add(-48 * time.Hour),
				Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
				Target: "a.go", Success: true,
			}}, nil, store.IngestOptions{}); err != nil {
				t.Fatal(err)
			}
			var projectID int64
			if err := d.QueryRowContext(ctx, `SELECT id FROM projects LIMIT 1`).Scan(&projectID); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < tc.patterns; i++ {
				if _, err := d.ExecContext(ctx,
					`INSERT INTO project_patterns (project_id, pattern_type, pattern_data) VALUES (?, ?, ?)`,
					projectID, "hot_file", fmt.Sprintf(`{"n":%d}`, i)); err != nil {
					t.Fatalf("seed project_patterns: %v", err)
				}
			}
			for i := 0; i < tc.plans; i++ {
				if _, err := d.ExecContext(ctx,
					`INSERT INTO plan_accounts (id, provider, source, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
					fmt.Sprintf("acct-%d", i), "anthropic", "official", 1, 1); err != nil {
					t.Fatalf("seed plan_accounts: %v", err)
				}
			}
			for i := 0; i < tc.benchmarks; i++ {
				if _, err := d.ExecContext(ctx,
					`INSERT INTO benchmark_runs (run_id, spec_name, spec_hash, spec_json, started_at, status)
					 VALUES (?, ?, ?, ?, ?, ?)`,
					fmt.Sprintf("run-%d", i), "spec", "h", "{}", "2026-11-07T10:00:00Z", "completed"); err != nil {
					t.Fatalf("seed benchmark_runs: %v", err)
				}
			}

			snap, err := Snapshot(ctx, d, dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if snap.QueryErrors != 0 {
				t.Errorf("QueryErrors = %d, want 0", snap.QueryErrors)
			}
			got := [4]int{snap.Counts.ProjectPatterns, snap.Counts.PlanAccounts, snap.Counts.BenchmarkRuns, snap.Counts.Projects}
			want := [4]int{tc.wantPatterns, tc.wantPlans, tc.wantBenchmarks, tc.wantProjects}
			if got != want {
				t.Errorf("patterns/plans/benchmarks/projects = %v, want %v", got, want)
			}
		})
	}
}

// TestSnapshot_ActiveSessionWindows pins the "Live" and "Overview" badges:
// distinct sessions with activity in actions, api_turns or token_usage in
// the last 15 minutes and the last 24 hours, one session counted once
// however many tables and rows it touches.
func TestSnapshot_ActiveSessionWindows(t *testing.T) {
	type activity struct {
		table, session string
		age            time.Duration
	}
	cases := []struct {
		name              string
		rows              []activity
		wantLive, wantDay int
	}{
		{name: "no recent activity", wantLive: 0, wantDay: 0},
		{
			name: "an action five minutes ago is live and day-active",
			rows: []activity{{"actions", "s1", 5 * time.Minute}}, wantLive: 1, wantDay: 1,
		},
		{
			name: "a token row two hours ago is day-active only",
			rows: []activity{{"token_usage", "s1", 2 * time.Hour}}, wantLive: 0, wantDay: 1,
		},
		{
			name: "an api turn thirty hours ago is neither",
			rows: []activity{{"api_turns", "s1", 30 * time.Hour}}, wantLive: 0, wantDay: 0,
		},
		{
			name: "one session across all three tables counts once",
			rows: []activity{
				{"actions", "s1", time.Minute},
				{"api_turns", "s1", 2 * time.Minute},
				{"token_usage", "s1", 3 * time.Hour},
			}, wantLive: 1, wantDay: 1,
		},
		{
			name: "sessions split across the windows",
			rows: []activity{
				{"actions", "s1", 10 * time.Minute},
				{"api_turns", "s2", 20 * time.Minute},
				{"token_usage", "s3", 23 * time.Hour},
				{"actions", "s4", 25 * time.Hour},
			}, wantLive: 1, wantDay: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dbPath := filepath.Join(t.TempDir(), "obs.db")
			d, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			st := store.New(d)
			now := time.Now().UTC()
			root := t.TempDir()
			// Every session exists first, through an action outside both
			// windows (token_usage references sessions).
			seeded := map[string]bool{}
			for _, r := range tc.rows {
				if seeded[r.session] {
					continue
				}
				seeded[r.session] = true
				if _, err := st.Ingest(ctx, []models.ToolEvent{{
					SourceFile: "seed", SourceEventID: "seed-" + r.session, SessionID: r.session,
					ProjectRoot: root, Timestamp: now.Add(-72 * time.Hour),
					Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
					Target: "a.go", Success: true,
				}}, nil, store.IngestOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			for i, r := range tc.rows {
				ts := now.Add(-r.age)
				var err error
				switch r.table {
				case "actions":
					_, err = st.Ingest(ctx, []models.ToolEvent{{
						SourceFile: "f", SourceEventID: fmt.Sprintf("e%d", i), SessionID: r.session,
						ProjectRoot: root, Timestamp: ts,
						Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
						Target: "a.go", Success: true,
					}}, nil, store.IngestOptions{})
				case "api_turns":
					_, err = d.ExecContext(ctx,
						`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens)
						 VALUES (?, ?, 'anthropic', 'claude-opus-4-8', 1, 1)`,
						r.session, ts.Format(time.RFC3339Nano))
				case "token_usage":
					_, err = d.ExecContext(ctx,
						`INSERT INTO token_usage (session_id, timestamp, tool, source, source_file, source_event_id)
						 VALUES (?, ?, 'claude-code', 'jsonl', 'f', ?)`,
						r.session, ts.Format(time.RFC3339Nano), fmt.Sprintf("t%d", i))
				default:
					t.Fatalf("unknown table %q", r.table)
				}
				if err != nil {
					t.Fatalf("seed %s: %v", r.table, err)
				}
			}

			snap, err := Snapshot(ctx, d, dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if snap.QueryErrors != 0 {
				t.Errorf("QueryErrors = %d, want 0", snap.QueryErrors)
			}
			if snap.Counts.LiveSessions != tc.wantLive || snap.Counts.ActiveSessions24h != tc.wantDay {
				t.Errorf("live/24h = %d/%d, want %d/%d",
					snap.Counts.LiveSessions, snap.Counts.ActiveSessions24h, tc.wantLive, tc.wantDay)
			}
		})
	}
}

// TestSnapshot_LeavesOpenIssuesUnset pins that the plain-SQL snapshot never
// fabricates the open-issue count the dashboard stamps: nil, and absent on
// the wire.
func TestSnapshot_LeavesOpenIssuesUnset(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	snap, err := Snapshot(context.Background(), d, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Counts.OpenIssues != nil {
		t.Fatalf("OpenIssues = %+v, want nil (the dashboard stamps it)", snap.Counts.OpenIssues)
	}
	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "open_issues") {
		t.Errorf("open_issues on the wire of an unstamped snapshot: %s", body)
	}
}

func TestFormatStatus_RendersAllFields(t *testing.T) {
	snap := StatusSnapshot{
		DBPath:         "/tmp/x.db",
		DBSizeBytes:    2048,
		SchemaVersion:  1,
		Counts:         SnapshotCounts{Projects: 2, Sessions: 5, Actions: 100},
		LastActionAt:   time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC),
		LastActionTool: "claude-code",
		PerToolLastSeen: []ToolActivity{
			{Tool: "claude-code", LastSeenAt: time.Now(), ActionCount: 80},
		},
		RecentFailures24: 3,
	}
	out := FormatStatus(snap)
	for _, want := range []string{
		"/tmp/x.db", "schema v1", "Projects:", "Failures (24h):   3", "Cache events:", "claude-code",
		"Sessions (24h):", "Patterns:", "Plan accounts:", "Benchmark runs:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestFormatStatus_QueryErrorsWarning pins the CLI-visible half of the
// completeness signal: FormatStatus must stay silent on a healthy
// snapshot (QueryErrors == 0, including the legitimately-empty-DB case)
// and must surface an unmistakable warning the moment any lookup failed,
// so a reader of `observer status` can't mistake a degraded, partially
// fabricated read for a clean one.
func TestFormatStatus_QueryErrorsWarning(t *testing.T) {
	base := StatusSnapshot{
		DBPath:        "/tmp/x.db",
		DBSizeBytes:   2048,
		SchemaVersion: 1,
		Counts:        SnapshotCounts{Projects: 2, Sessions: 5, Actions: 100},
	}

	cases := []struct {
		name        string
		queryErrors int
		wantWarn    bool
		wantSubstr  string
	}{
		{name: "zero query errors on empty DB stays silent", queryErrors: 0, wantWarn: false},
		{name: "zero query errors on populated DB stays silent", queryErrors: 0, wantWarn: false},
		{name: "one query error warns, singular", queryErrors: 1, wantWarn: true, wantSubstr: "1 query failed"},
		{name: "many query errors warn, plural", queryErrors: 14, wantWarn: true, wantSubstr: "14 queries failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			snap := base
			snap.QueryErrors = c.queryErrors
			out := FormatStatus(snap)

			gotWarn := strings.Contains(out, "WARNING")
			if gotWarn != c.wantWarn {
				t.Fatalf("FormatStatus with QueryErrors=%d: WARNING present = %v, want %v\noutput:\n%s",
					c.queryErrors, gotWarn, c.wantWarn, out)
			}
			if c.wantWarn {
				if !strings.Contains(out, c.wantSubstr) {
					t.Errorf("output missing %q:\n%s", c.wantSubstr, out)
				}
				if !strings.Contains(out, "INCOMPLETE") {
					t.Errorf("warning does not tell the reader the counts are INCOMPLETE:\n%s", out)
				}
			}
			// The healthy path must be byte-for-byte what it always was —
			// no noise added for QueryErrors == 0.
			if !c.wantWarn && strings.Contains(out, "INCOMPLETE") {
				t.Errorf("unexpected INCOMPLETE warning on a healthy snapshot:\n%s", out)
			}
		})
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{500, "500 B"},
		{2048, "2.0 KB"},
		{2 * 1024 * 1024, "2.0 MB"},
	}
	for _, c := range cases {
		if got := humanBytes(c.in); got != c.want {
			t.Errorf("humanBytes(%d) = %q want %q", c.in, got, c.want)
		}
	}
}

// dummy import keeper — bytes used in main file but not here
var _ = bytes.Buffer{}

// TestSnapshot_QueryErrors pins the completeness signal StatusSnapshot.
// QueryErrors carries.
//
// Snapshot swallows every per-lookup failure into a zero value on purpose —
// a partial schema must still yield whatever else is readable — but that
// makes a broken read wire-indistinguishable from an empty database. The
// dashboard's /api/status cache refuses to memoize a snapshot whose numbers
// might be fabricated, so this counter has to be right in BOTH directions:
// zero on a healthy database including a completely empty one (an empty table
// is an ANSWER, not a failure), non-zero the moment lookups genuinely cannot
// run.
func TestSnapshot_QueryErrors(t *testing.T) {
	t.Run("empty database is complete, not degraded", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "obs.db")
		d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()

		snap, err := Snapshot(context.Background(), d, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		// Every count is legitimately zero here, and several lookups return
		// sql.ErrNoRows (no advisor digest, no last action). None of that is a
		// failure to read: a fresh install must never look degraded, or its
		// snapshot would never be cacheable.
		if snap.QueryErrors != 0 {
			t.Errorf("QueryErrors = %d on a healthy empty DB, want 0", snap.QueryErrors)
		}
	})

	t.Run("populated database is complete", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "obs.db")
		d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		st := store.New(d)
		if _, err := st.Ingest(context.Background(), []models.ToolEvent{{
			SourceFile: "f", SourceEventID: "e1", SessionID: "s1",
			ProjectRoot: t.TempDir(), Timestamp: time.Now().UTC(),
			Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
			Target: "a.go", Success: true,
		}}, nil, store.IngestOptions{}); err != nil {
			t.Fatal(err)
		}

		snap, err := Snapshot(context.Background(), d, dbPath)
		if err != nil {
			t.Fatal(err)
		}
		if snap.QueryErrors != 0 {
			t.Errorf("QueryErrors = %d on a healthy populated DB, want 0", snap.QueryErrors)
		}
		if snap.Counts.Actions != 1 {
			t.Errorf("Counts.Actions = %d, want 1", snap.Counts.Actions)
		}
	})

	t.Run("unreadable database is degraded, not empty", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "obs.db")
		d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		// Close the handle: every lookup now fails outright. This is the
		// shape that matters — the snapshot still comes back "successfully",
		// with all-zero counts that look exactly like a fresh install.
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}

		snap, err := Snapshot(context.Background(), d, dbPath)
		if err != nil {
			t.Fatalf("Snapshot must stay tolerant and return what it has: %v", err)
		}
		if snap.Counts.Sessions != 0 || snap.Counts.Actions != 0 {
			t.Fatalf("expected the all-zero fabricated counts: %+v", snap.Counts)
		}
		if snap.QueryErrors == 0 {
			t.Fatal("QueryErrors = 0 on a database that answered nothing - a partial " +
				"snapshot is indistinguishable from an empty one, which is exactly what " +
				"this field exists to prevent")
		}
		// Sanity: the counter is a count, not a bool — every table lookup
		// plus the aggregate queries should have registered.
		if snap.QueryErrors < 15 {
			t.Errorf("QueryErrors = %d, want >= 15 (14 table counts + the aggregates)", snap.QueryErrors)
		}
	})

	t.Run("cancelled context is degraded", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "obs.db")
		d, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		snap, err := Snapshot(ctx, d, dbPath)
		if err != nil {
			t.Fatalf("Snapshot must stay tolerant: %v", err)
		}
		if snap.QueryErrors == 0 {
			t.Error("QueryErrors = 0 for a scan under a cancelled context - the zeros " +
				"it returned would be cached as fact")
		}
	})
}

// TestSnapshot_SurfacesIntegrityVerdict is the RES-3 status-surface pin
// (codebase audit 2026-09-16). The background `PRAGMA quick_check` used to
// write one ERROR log line and nothing else, so a corrupt database degraded
// capture silently. Its verdict now reaches the struct `observer status` prints
// and /api/status serves.
//
// Four rows: never probed (ABSENT — a fresh install must not read as damaged,
// and the healthy render must stay silent), probed clean (present, silent), and
// the two non-ok statuses, which must each be rendered LOUDLY and distinctly —
// "error" means the probe could not complete and must not be reported as
// corruption.
func TestSnapshot_SurfacesIntegrityVerdict(t *testing.T) {
	for _, tc := range []struct {
		name        string
		record      *db.IntegrityVerdict
		wantPresent bool
		wantOK      bool
		wantInText  []string
		wantNotText []string
	}{
		{
			name:        "never probed",
			wantPresent: false,
			wantNotText: []string{"DB INTEGRITY"},
		},
		{
			name:        "probed clean",
			record:      &db.IntegrityVerdict{Status: db.IntegrityOK},
			wantPresent: true,
			wantOK:      true,
			wantNotText: []string{"DB INTEGRITY"},
		},
		{
			name:        "corrupt",
			record:      &db.IntegrityVerdict{Status: db.IntegrityCorrupt, Message: "Page 42: btreeInitPage"},
			wantPresent: true,
			wantInText:  []string{"DB INTEGRITY:     CORRUPT", "Page 42: btreeInitPage", "observer doctor db"},
		},
		{
			name:        "probe did not complete",
			record:      &db.IntegrityVerdict{Status: db.IntegrityError, Message: "context deadline exceeded"},
			wantPresent: true,
			wantInText:  []string{"DB INTEGRITY:     UNVERIFIED", "context deadline exceeded"},
			wantNotText: []string{"CORRUPT"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "agent.db")
			database, err := dbtemplate.Open(ctx, db.Options{Path: path})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer func() { _ = database.Close() }()

			if tc.record != nil {
				body, err := json.Marshal(db.IntegrityVerdict{
					CheckedAt: time.Now().UTC(), Status: tc.record.Status, Message: tc.record.Message,
				})
				if err != nil {
					t.Fatalf("marshal verdict: %v", err)
				}
				if _, err := database.ExecContext(ctx,
					`INSERT INTO schema_meta(key, value) VALUES ('integrity_verdict', ?)
					 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(body)); err != nil {
					t.Fatalf("seed verdict: %v", err)
				}
			}

			snap, err := Snapshot(ctx, database, path)
			if err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			if (snap.Integrity != nil) != tc.wantPresent {
				t.Fatalf("Integrity present = %v, want %v", snap.Integrity != nil, tc.wantPresent)
			}
			if snap.QueryErrors != 0 {
				t.Errorf("QueryErrors = %d, want 0 - an absent verdict is a legitimate answer, not a failed lookup", snap.QueryErrors)
			}
			if tc.wantPresent {
				if snap.Integrity.Status != tc.record.Status {
					t.Errorf("status = %q, want %q", snap.Integrity.Status, tc.record.Status)
				}
				if snap.Integrity.OK() != tc.wantOK {
					t.Errorf("OK() = %v, want %v", snap.Integrity.OK(), tc.wantOK)
				}
			}

			out := FormatStatus(snap)
			for _, want := range tc.wantInText {
				if !strings.Contains(out, want) {
					t.Errorf("FormatStatus output missing %q:\n%s", want, out)
				}
			}
			for _, bad := range tc.wantNotText {
				if strings.Contains(out, bad) {
					t.Errorf("FormatStatus output unexpectedly contains %q:\n%s", bad, out)
				}
			}

			// The JSON surface (what the dashboard reads) must carry it too.
			raw, err := json.Marshal(snap)
			if err != nil {
				t.Fatalf("marshal snapshot: %v", err)
			}
			if got := bytes.Contains(raw, []byte(`"integrity"`)); got != tc.wantPresent {
				t.Errorf("JSON carries \"integrity\" = %v, want %v", got, tc.wantPresent)
			}
		})
	}
}

// TestSnapshot_ProjectsLeaveOutFoldedRows: the Projects badge counts what
// the Projects page lists. A row the worktree-roots backfill folded into
// its repository's project, with nothing filed under it since, is left
// out; an empty row that was never folded still counts.
func TestSnapshot_ProjectsLeaveOutFoldedRows(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "obs.db")
	d, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := store.New(d).Ingest(ctx, []models.ToolEvent{{
		SourceFile: "f", SourceEventID: "e1", SessionID: "s1",
		ProjectRoot: t.TempDir(), Timestamp: time.Now().UTC().Add(-48 * time.Hour),
		Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile,
		Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	const at = "2026-11-07T00:00:00Z"
	if _, err := d.ExecContext(ctx, `INSERT INTO projects (root_path, name, created_at) VALUES ('/r/main/.claude/worktrees/x', ?, ?), ('/r/empty', NULL, ?)`,
		store.WorktreeRootMovedMark(1), at, at); err != nil {
		t.Fatal(err)
	}
	snap, err := Snapshot(ctx, d, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if snap.QueryErrors != 0 {
		t.Errorf("QueryErrors = %d, want 0", snap.QueryErrors)
	}
	if snap.Counts.Projects != 2 {
		t.Errorf("Counts.Projects = %d, want 2 (the ingested project and the never-folded empty row)", snap.Counts.Projects)
	}
}
