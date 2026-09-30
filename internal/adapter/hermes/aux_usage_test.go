package hermes

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// buildAuxUsageFixtureDB writes a synthetic state.db in the schema-v30
// shape (hermes v2026.9.24, hermes_state_common.py SCHEMA_SQL): the
// sessions/messages column subset scanStateDB reads, plus the
// session_model_usage table verbatim. All content is synthetic.
//
// Session s-aux carries a main-loop aggregate on sessions AND:
//   - an empty-task main-loop row (must NOT emit: it is the aggregate, split),
//   - a title_generation row on a different model (must emit),
//   - a vision row whose model Hermes could not resolve ('unknown'),
//   - an all-zero compression row (observationally vacant, must skip).
func buildAuxUsageFixtureDB(t *testing.T) string {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(dbPath))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE schema_version (version INTEGER NOT NULL);
		INSERT INTO schema_version VALUES (30);
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY, source TEXT NOT NULL, model TEXT, system_prompt TEXT,
			parent_session_id TEXT, started_at REAL NOT NULL, ended_at REAL, end_reason TEXT,
			message_count INTEGER DEFAULT 0, tool_call_count INTEGER DEFAULT 0,
			input_tokens INTEGER DEFAULT 0, output_tokens INTEGER DEFAULT 0,
			cache_read_tokens INTEGER DEFAULT 0, cache_write_tokens INTEGER DEFAULT 0,
			reasoning_tokens INTEGER DEFAULT 0, cwd TEXT,
			estimated_cost_usd REAL, actual_cost_usd REAL, api_call_count INTEGER DEFAULT 0,
			handoff_state TEXT, handoff_platform TEXT,
			rewind_count INTEGER NOT NULL DEFAULT 0, archived INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL,
			content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT,
			timestamp REAL NOT NULL, token_count INTEGER, finish_reason TEXT,
			reasoning TEXT, reasoning_content TEXT, platform_message_id TEXT,
			active INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE session_model_usage (
			session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
			model TEXT NOT NULL,
			billing_provider TEXT NOT NULL DEFAULT '',
			billing_base_url TEXT NOT NULL DEFAULT '',
			billing_mode TEXT NOT NULL DEFAULT '',
			task TEXT NOT NULL DEFAULT '',
			api_call_count INTEGER NOT NULL DEFAULT 0,
			input_tokens INTEGER NOT NULL DEFAULT 0,
			output_tokens INTEGER NOT NULL DEFAULT 0,
			cache_read_tokens INTEGER NOT NULL DEFAULT 0,
			cache_write_tokens INTEGER NOT NULL DEFAULT 0,
			reasoning_tokens INTEGER NOT NULL DEFAULT 0,
			estimated_cost_usd REAL NOT NULL DEFAULT 0,
			actual_cost_usd REAL NOT NULL DEFAULT 0,
			cost_status TEXT, cost_source TEXT, first_seen REAL, last_seen REAL,
			PRIMARY KEY (session_id, model, billing_provider, billing_base_url, billing_mode, task)
		);
		INSERT INTO sessions (id, source, model, started_at, input_tokens, output_tokens,
			cache_read_tokens, cwd, estimated_cost_usd, api_call_count)
		VALUES ('s-aux', 'cli', 'anthropic/claude-sonnet-4.6', 1790000000, 1200, 300, 5000,
			'/tmp/fixture-project', 0.05, 3);
		INSERT INTO messages (session_id, role, content, timestamp)
		VALUES ('s-aux', 'user', 'synthetic prompt', 1790000001);
		INSERT INTO session_model_usage (session_id, model, billing_provider, task,
			api_call_count, input_tokens, output_tokens, cache_read_tokens, estimated_cost_usd, last_seen)
		VALUES
			('s-aux', 'anthropic/claude-sonnet-4.6', 'openrouter', '', 3, 1200, 300, 5000, 0.05, 1790000050),
			('s-aux', 'google/gemini-3-flash', 'openrouter', 'title_generation', 1, 400, 12, 0, 0.0002, 1790000060),
			('s-aux', 'unknown', '', 'vision', 1, 900, 40, 0, 0, NULL),
			('s-aux', 'google/gemini-3-flash', 'openrouter', 'compression', 0, 0, 0, 0, 0, 1790000070);
	`); err != nil {
		t.Fatalf("fixture setup: %v", err)
	}
	return dbPath
}

func TestScanStateDB_ReadsAuxUsageOnlyForTaskRows(t *testing.T) {
	t.Parallel()
	sessions, _, _, err := scanStateDB(context.Background(), buildAuxUsageFixtureDB(t), 0)
	if err != nil {
		t.Fatalf("scanStateDB: %v", err)
	}
	got := sessions["s-aux"].AuxUsage
	// title_generation + vision + the zero compression row; the task=''
	// main-loop row is excluded at the query.
	if len(got) != 3 {
		t.Fatalf("AuxUsage rows = %d, want 3 (task='' excluded): %+v", len(got), got)
	}
	for _, r := range got {
		if r.Task == "" {
			t.Errorf("main-loop (task='') row leaked into AuxUsage: %+v", r)
		}
	}
}

func TestBuildEvents_AuxUsageRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name          string
		hooked        bool
		wantAggregate bool
	}{
		{name: "unhooked session emits aggregate plus aux rows", hooked: false, wantAggregate: true},
		// The hook path never sees auxiliary calls (they fire
		// post_auxiliary_call, not post_api_request), so aux rows emit
		// even when the aggregate is suppressed for hook coverage.
		{name: "hook-covered session still emits aux rows", hooked: true, wantAggregate: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sessions, messages, _, err := scanStateDB(context.Background(), buildAuxUsageFixtureDB(t), 0)
			if err != nil {
				t.Fatalf("scanStateDB: %v", err)
			}
			check := func(context.Context, string) (bool, error) { return tc.hooked, nil }
			_, tokens, warnings := buildEvents(context.Background(), sessions, messages, "state.db", nil, check)
			if len(warnings) != 0 {
				t.Fatalf("warnings: %v", warnings)
			}
			byID := map[string]models.TokenEvent{}
			for _, ev := range tokens {
				byID[ev.SourceEventID] = ev
			}
			if _, ok := byID["tk:s-aux"]; ok != tc.wantAggregate {
				t.Errorf("aggregate row present = %v, want %v", ok, tc.wantAggregate)
			}
			var title, vision *models.TokenEvent
			for id, ev := range byID {
				ev := ev
				switch {
				case strings.HasPrefix(id, "tk-aux:s-aux:title_generation:"):
					title = &ev
				case strings.HasPrefix(id, "tk-aux:s-aux:vision:"):
					vision = &ev
				case strings.HasPrefix(id, "tk-aux:s-aux:compression:"):
					t.Errorf("all-zero compression row emitted: %+v", ev)
				}
			}
			if title == nil || vision == nil {
				t.Fatalf("aux rows missing: title=%v vision=%v (all: %v)", title != nil, vision != nil, byID)
			}
			if title.Model != "gemini-3-flash" || title.InputTokens != 400 || title.OutputTokens != 12 ||
				title.EstimatedCostUSD != 0.0002 {
				t.Errorf("title_generation row = %+v", *title)
			}
			if title.Timestamp.Unix() != 1790000060 {
				t.Errorf("title_generation timestamp = %v, want last_seen", title.Timestamp)
			}
			if vision.Model != "" {
				t.Errorf("vision model = %q, want empty for Hermes's literal 'unknown'", vision.Model)
			}
			if vision.Timestamp.Unix() != 1790000000 {
				t.Errorf("vision timestamp = %v, want session start when last_seen is NULL", vision.Timestamp)
			}
			if title.Tool != models.ToolHermes || title.Source != models.TokenSourceJSONL {
				t.Errorf("title tool/source = %s/%s", title.Tool, title.Source)
			}
		})
	}
}

// TestAuxTokenEvent_StableAcrossRoutes pins the SourceEventID contract:
// stable for one row, distinct across billing routes of the same task.
func TestAuxTokenEvent_StableAcrossRoutes(t *testing.T) {
	t.Parallel()
	sess := sessionRow{ID: "s1", StartedAt: 1790000000}
	a := auxUsageRow{Model: "m", BillingProvider: "p1", Task: "vision", InputTokens: 1}
	b := a
	b.BillingProvider = "p2"
	ea, _ := auxTokenEvent(sess, a, "state.db")
	ea2, _ := auxTokenEvent(sess, a, "state.db")
	eb, _ := auxTokenEvent(sess, b, "state.db")
	if ea.SourceEventID != ea2.SourceEventID {
		t.Errorf("unstable id: %q vs %q", ea.SourceEventID, ea2.SourceEventID)
	}
	if ea.SourceEventID == eb.SourceEventID {
		t.Errorf("two routes collided on %q", ea.SourceEventID)
	}
}
