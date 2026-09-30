package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestInsertTokenEvents_GenTimingUpsert pins agent migration 136's upsert
// rule (S10-SPEED): the first stamped duration is final at a given parser
// version, an empty re-emit never clears it, and only a strictly newer
// gen_timing_v replaces it. A row that never carried timing stays NULL.
func TestInsertTokenEvents_GenTimingUpsert(t *testing.T) {
	st, db := newTestStore(t)
	ctx := context.Background()
	ts := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	ev := func(id string, genMs int64, v int) models.TokenEvent {
		e := models.TokenEvent{
			SourceFile: "f", SourceEventID: id, SessionID: "s-gen", ProjectRoot: t.TempDir(), Timestamp: ts,
			Tool: models.ToolClaudeCode, Model: "m", OutputTokens: 500,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		}
		if genMs > 0 {
			e.GenMs, e.GenBasis, e.GenTimingV = genMs, models.GenBasisNative, v
		}
		return e
	}
	read := func(id string) (sql.NullInt64, sql.NullString, sql.NullInt64) {
		var ms, v sql.NullInt64
		var basis sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT gen_ms, gen_basis, gen_timing_v FROM token_usage WHERE source_event_id = ?`, id).Scan(&ms, &basis, &v); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return ms, basis, v
	}
	steps := []struct {
		name   string
		ev     models.TokenEvent
		wantMs int64 // 0 = NULL
		wantV  int64
	}{
		{"first stamp lands", ev("a", 1000, 1), 1000, 1},
		{"same-version re-parse with a different span is a no-op", ev("a", 5000, 1), 1000, 1},
		{"empty re-emit never clears", ev("a", 0, 0), 1000, 1},
		{"strictly newer parser version replaces", ev("a", 2000, 2), 2000, 2},
		{"older version cannot roll back", ev("a", 9000, 1), 2000, 2},
	}
	for _, s := range steps {
		if _, err := st.Ingest(ctx, nil, []models.TokenEvent{s.ev}, IngestOptions{}); err != nil {
			t.Fatalf("%s: insert: %v", s.name, err)
		}
		ms, basis, v := read("a")
		if !ms.Valid || ms.Int64 != s.wantMs || v.Int64 != s.wantV || basis.String != models.GenBasisNative {
			t.Errorf("%s: gen_ms=%v basis=%v v=%v, want %d/native/%d", s.name, ms, basis, v, s.wantMs, s.wantV)
		}
	}
	if _, err := st.Ingest(ctx, nil, []models.TokenEvent{ev("b", 0, 0)}, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	if ms, basis, v := read("b"); ms.Valid || basis.Valid || v.Valid {
		t.Errorf("untimed row: gen_ms=%v basis=%v v=%v, want all NULL", ms, basis, v)
	}
}

// TestSelectUnpushedSince_GenTimingSettle pins the org push's settle
// holdback (pushsettle.go, the REVIEW-IMPL P0 #1 fold): a transcript-timed
// token row whose gen_ms is stamped in a LATER parse must not ship before
// the stamp, because the org ingest is insert-only. One case per rule of
// the unsettled predicate.
func TestSelectUnpushedSince_GenTimingSettle(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	settle := PushSettle{Tools: []string{models.ToolClaudeCode}, Window: 10 * time.Minute, Now: func() time.Time { return now }}
	tok := func(root, id, session, tool string, at time.Time, genMs int64) models.TokenEvent {
		e := models.TokenEvent{
			SourceFile: "f", SourceEventID: id, SessionID: session, ProjectRoot: root, Timestamp: at,
			Tool: tool, Model: "m", OutputTokens: 500,
			Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
		}
		if genMs > 0 {
			e.GenMs, e.GenBasis, e.GenTimingV = genMs, models.GenBasisTranscript, 1
		}
		return e
	}
	push := func(t *testing.T, st *Store, cur PushCursor, s PushSettle) PushBatch {
		t.Helper()
		b, err := st.SelectUnpushedSince(ctx, cur, 1<<20, "org-1", "dev@acme.example", ShareOptions{}, ScopeOptions{Settle: s})
		if err != nil {
			t.Fatalf("SelectUnpushedSince: %v", err)
		}
		return b
	}
	ids := func(b PushBatch) []string {
		var out []string
		for _, r := range b.TokenUsage {
			out = append(out, r.SourceEventID)
		}
		return out
	}
	fresh, stale := now.Add(-30*time.Second), now.Add(-11*time.Minute)
	cases := []struct {
		name   string
		events []models.TokenEvent
		settle PushSettle
		want   []string
	}{
		{"fresh unstamped last-in-session transcript row is held", []models.TokenEvent{tok("", "a", "s1", models.ToolClaudeCode, fresh, 0)}, settle, nil},
		{"stamped row ships", []models.TokenEvent{tok("", "a", "s1", models.ToolClaudeCode, fresh, 4200)}, settle, []string{"a"}},
		{"unstamped row older than the window ships", []models.TokenEvent{tok("", "a", "s1", models.ToolClaudeCode, stale, 0)}, settle, []string{"a"}},
		{"a later row in the session settles the earlier one; the later is held", []models.TokenEvent{
			tok("", "a", "s1", models.ToolClaudeCode, fresh, 0), tok("", "b", "s1", models.ToolClaudeCode, fresh, 0),
		}, settle, []string{"a"}},
		{"a held row stops the lane: rows behind it wait", []models.TokenEvent{
			tok("", "a", "s1", models.ToolClaudeCode, fresh, 0), tok("", "b", "s2", models.ToolCodex, fresh, 0),
		}, settle, nil},
		{"a tool outside the transcript set is never held", []models.TokenEvent{tok("", "a", "s1", models.ToolCodex, fresh, 0)}, settle, []string{"a"}},
		{"zero value disables the holdback", []models.TokenEvent{tok("", "a", "s1", models.ToolClaudeCode, fresh, 0)}, PushSettle{}, []string{"a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, _ := newTestStore(t)
			root := t.TempDir()
			for i := range c.events {
				c.events[i].ProjectRoot = root
			}
			if _, err := st.Ingest(ctx, nil, c.events, IngestOptions{}); err != nil {
				t.Fatal(err)
			}
			got := ids(push(t, st, PushCursor{}, c.settle))
			if len(got) != len(c.want) {
				t.Fatalf("pushed %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("pushed %v, want %v", got, c.want)
				}
			}
		})
	}

	// End to end: insert unstamped -> held; the later parse stamps it ->
	// the first push carries gen_ms.
	t.Run("late stamp reaches the first push", func(t *testing.T) {
		st, _ := newTestStore(t)
		root := t.TempDir()
		if _, err := st.Ingest(ctx, nil, []models.TokenEvent{tok(root, "a", "s1", models.ToolClaudeCode, fresh, 0)}, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		b := push(t, st, PushCursor{}, settle)
		if len(b.TokenUsage) != 0 || b.Cursor.TokenUsage != 0 {
			t.Fatalf("held row shipped: %v cursor %d", ids(b), b.Cursor.TokenUsage)
		}
		if _, err := st.Ingest(ctx, nil, []models.TokenEvent{tok(root, "a", "s1", models.ToolClaudeCode, fresh, 16500)}, IngestOptions{}); err != nil {
			t.Fatal(err)
		}
		b = push(t, st, b.Cursor, settle)
		if len(b.TokenUsage) != 1 || b.TokenUsage[0].GenMs != 16500 || b.TokenUsage[0].GenBasis != models.GenBasisTranscript {
			t.Fatalf("first push = %+v, want one row carrying gen_ms 16500 transcript", b.TokenUsage)
		}
	})
}

// TestIngest_GenStampOnly pins the narrow stamp seam (REVIEW-IMPL #7): a
// stamp-only re-emission fills gen_* on the EXISTING row only - it never
// inserts (a pruned or never-seen row stays absent) and never rewrites a
// token or sidechain column.
func TestIngest_GenStampOnly(t *testing.T) {
	st, db := newTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	base := models.TokenEvent{
		SourceFile: "f", SourceEventID: "m1", SessionID: "s-stamp", ProjectRoot: root,
		Timestamp: time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC),
		Tool:      models.ToolClaudeCode, Model: "m", OutputTokens: 500,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
	}
	if _, err := st.Ingest(ctx, nil, []models.TokenEvent{base}, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	stamp := base
	stamp.OutputTokens, stamp.IsSidechain = 9999, true
	stamp.GenMs, stamp.GenBasis, stamp.GenTimingV, stamp.GenStampOnly = 16500, models.GenBasisTranscript, 1, true
	orphan := stamp
	orphan.SourceEventID = "gone"
	if _, err := st.Ingest(ctx, nil, []models.TokenEvent{stamp, orphan}, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	var ms, out int64
	var side int
	var basis string
	if err := db.QueryRowContext(ctx, `SELECT gen_ms, gen_basis, output_tokens, COALESCE(is_sidechain,0) FROM token_usage WHERE source_event_id='m1'`).Scan(&ms, &basis, &out, &side); err != nil {
		t.Fatal(err)
	}
	if ms != 16500 || basis != models.GenBasisTranscript || out != 500 || side != 0 {
		t.Errorf("m1: gen_ms=%d basis=%q output=%d sidechain=%d, want 16500/transcript/500/0", ms, basis, out, side)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM token_usage WHERE source_event_id='gone'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("stamp-only orphan inserted %d rows, want 0", n)
	}
}
