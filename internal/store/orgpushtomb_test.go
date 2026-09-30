package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	idb "github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/retention"
)

// tombTokenEvent is a claude-code JSONL token event for the tombstone cases.
func tombTokenEvent(session, file, id, msg string, at time.Time, out int64) models.TokenEvent {
	return models.TokenEvent{
		SourceFile: file, SourceEventID: id, MessageID: msg, SessionID: session, ProjectRoot: "/tmp/proj",
		Timestamp: at, Tool: models.ToolClaudeCode, Model: "claude-opus-4-7",
		InputTokens: 1, OutputTokens: out, CacheReadTokens: 1000,
		Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
	}
}

func hasDeletion(b PushBatch, table, key string) bool {
	for _, d := range b.Deletions {
		if d.Table != table {
			continue
		}
		switch table {
		case orgcontract.DeletionSessions:
			if d.SessionID == key {
				return true
			}
		case orgcontract.DeletionAPITurns:
			if d.RequestID == key {
				return true
			}
		default:
			if d.SourceEventID == key {
				return true
			}
		}
	}
	return false
}

// TestTombstonePerDeletePath is the node half of the R2-TOMB contract, one row
// per DELETE path of an already-pushed row (the delete-path inventory in
// docs/teams-operations.md): a CORRECTION (class a) ships a tombstone carrying
// the deleted row's wire identity with a NodeRev newer than the row's own
// send, exactly once; NODE-LOCAL AGEING (class b) ships nothing.
func TestTombstonePerDeletePath(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	type seedFn func(t *testing.T, s *Store, db *sql.DB)
	type mutateFn func(t *testing.T, s *Store, db *sql.DB)
	seedCC := func(extra ...models.TokenEvent) seedFn {
		return func(t *testing.T, s *Store, db *sql.DB) {
			seedPushData(t, s, db)
			if len(extra) > 0 {
				if _, err := s.Ingest(context.Background(), nil, extra, IngestOptions{}); err != nil {
					t.Fatalf("seed tokens: %v", err)
				}
			}
		}
	}
	exec := func(qs ...string) mutateFn {
		return func(t *testing.T, _ *Store, db *sql.DB) {
			for _, q := range qs {
				if _, err := db.Exec(q); err != nil {
					t.Fatalf("%s: %v", q, err)
				}
			}
		}
	}
	cases := []struct {
		name        string
		seed        seedFn
		mutate      mutateFn
		wantTable   string // "" = class b: no tombstone may ship
		wantKey     string
		wantResent  string // a token source_event_id that must re-send instead (superseded)
		wantNoTombs bool
	}{
		{
			name: "(a) store: claude-code tuple dedup drops the older identical re-emission",
			seed: seedCC(tombTokenEvent("s1", "/x/cc.jsonl", "uuid-a", "msg_T", t0, 3283)),
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{
					tombTokenEvent("s1", "/x/cc.jsonl", "uuid-b", "msg_T", t0.Add(time.Second), 3283),
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "uuid-a",
		},
		{
			name: "(a) store: claude-code snapshot-drift dedup drops the lower cumulative snapshot",
			seed: seedCC(tombTokenEvent("s1", "/x/parent.jsonl", "ev-parent", "msg_D", t0, 8)),
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{
					tombTokenEvent("s1", "/x/parent/subagents/agent-acompact-X.jsonl", "ev-acompact", "msg_D", t0.Add(time.Second), 336),
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "ev-parent",
		},
		{
			name: "(a) store: copilot-cli Tier-3 row dropped once its Tier-1 otel row lands",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SourceFile: "/x/events.jsonl", SourceEventID: "req-1:token", SessionID: "s1", Timestamp: t0,
					Tool: models.ToolCopilotCLI, Model: "gpt-5-mini", OutputTokens: 565,
					Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable, MessageID: "req-1",
				}}); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SourceFile: "/x/process.log", SourceEventID: "log:req-1:1", SessionID: "s1", Timestamp: t0,
					Tool: models.ToolCopilotCLI, Model: "gpt-5-mini", InputTokens: 15474, OutputTokens: 565,
					Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate, MessageID: "req-1",
				}}); err != nil {
					t.Fatal(err)
				}
			},
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "req-1:token",
		},
		{
			name: "(a) store: copilot-cli session_summary dropped when an otel row covers its window",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SourceFile: "/x/events.jsonl", SourceEventID: "shut-1:m", SessionID: "s1", Timestamp: t0,
					Tool: models.ToolCopilotCLI, Model: "m", InputTokens: 5000,
					Source: models.TokenSourceSessionSummary, Reliability: models.ReliabilityApproximate, MessageID: "session-shutdown:shut-1",
				}}); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SourceFile: "/x/process.log", SourceEventID: "log:req-9", SessionID: "s1", Timestamp: t0,
					Tool: models.ToolCopilotCLI, Model: "m", InputTokens: 1000, OutputTokens: 50,
					Source: models.TokenSourceOTel, Reliability: models.ReliabilityApproximate, MessageID: "req-9",
				}}); err != nil {
					t.Fatal(err)
				}
			},
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "shut-1:m",
		},
		{
			name: "(a) store: cursor per-generation hook rows dropped for the CLI outcome aggregate",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SessionID: "s1", Timestamp: t0, Tool: models.ToolCursor, Model: "m",
					Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
					SourceFile: "cursor:hook", SourceEventID: "req-7-1-a:stop", MessageID: "req-7-1-a", InputTokens: 10,
				}}); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SessionID: "s1", Timestamp: t0, Tool: models.ToolCursor, Model: "m",
					Source: models.TokenSourceJSONL, Reliability: models.ReliabilityAccurate,
					SourceFile: "/x/cursor.jsonl", SourceEventID: "cursor-cli-outcome:req-7", MessageID: "req-7", InputTokens: 30,
				}}); err != nil {
					t.Fatal(err)
				}
			},
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "req-7-1-a:stop",
		},
		{
			name: "(a) store: proven cursor restatement removed",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				for _, r := range []struct {
					id, ts string
				}{{"49d5d505", "2026-08-17T21:22:11.094541746Z"}, {"648fba3b", "2026-08-17T21:22:11.901704699Z"}} {
					if _, err := db.Exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, source, reliability, source_file, source_event_id, message_id)
						VALUES ('s1', ?, 'cursor', 'default', 8371, 4753, 0, 0, 'hook', 'accurate', 'cursor:hook', ?, ?)`, r.ts, r.id+":stop", r.id); err != nil {
						t.Fatal(err)
					}
				}
			},
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				res, err := s.Ingest(context.Background(), nil, []models.TokenEvent{{
					SessionID: "s1", ProjectRoot: "/tmp/proj", Tool: models.ToolCursor, Model: "default",
					Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate, SourceFile: "cursor:hook",
					SourceEventID: "648fba3b:stop", MessageID: "648fba3b", HookEvent: "stop", Restates: "49d5d505",
					Timestamp:   time.Date(2026, 8, 17, 21, 22, 11, 901_704_699, time.UTC),
					InputTokens: 8371, OutputTokens: 4753,
				}}, IngestOptions{})
				if err != nil || res.TokenRestatementsRemoved != 1 {
					t.Fatalf("restatement: removed %d err %v", res.TokenRestatementsRemoved, err)
				}
			},
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "648fba3b:stop",
		},
		{
			name: "(a) store: cursor squatter evicted and its key rewritten = superseded, re-sent not tombstoned",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				mk := func(gen, kind string, ts time.Time, in int64) models.TokenEvent {
					return models.TokenEvent{
						SessionID: "cc8322af", ProjectRoot: "/tmp/proj", Timestamp: ts, Tool: models.ToolCursor,
						Model: "cursor-grok", Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
						SourceFile: "cursor:hook", SourceEventID: gen + ":stop", MessageID: gen, HookEvent: kind,
						InputTokens: in, OutputTokens: 53139, CacheReadTokens: 15524224,
					}
				}
				for _, b := range [][]models.TokenEvent{
					{mk("93c94255", "stop", t0.Add(1354*time.Millisecond), 420473)},
					{mk("52f30b63", "afterAgentResponse", t0, 420473)},
				} {
					if _, err := s.Ingest(context.Background(), nil, b, IngestOptions{}); err != nil {
						t.Fatal(err)
					}
				}
			},
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.Ingest(context.Background(), nil, []models.TokenEvent{{
					SessionID: "cc8322af", ProjectRoot: "/tmp/proj", Timestamp: t0.Add(40 * time.Second), Tool: models.ToolCursor,
					Model: "cursor-grok", Source: models.TokenSourceHook, Reliability: models.ReliabilityAccurate,
					SourceFile: "cursor:hook", SourceEventID: "93c94255:stop", MessageID: "93c94255", HookEvent: "afterAgentResponse",
					InputTokens: 7000, OutputTokens: 53139, CacheReadTokens: 15524224,
				}}, IngestOptions{}); err != nil {
					t.Fatal(err)
				}
			},
			wantResent: "93c94255:stop", wantNoTombs: true,
		},
		{
			name:      "(a) backfill: codex fork dedup (direct token_usage DELETE)",
			seed:      seedCC(),
			mutate:    exec(`DELETE FROM token_usage WHERE source_file = 'f.jsonl' AND source_event_id IN ('tu1')`),
			wantTable: orgcontract.DeletionTokenUsage, wantKey: "tu1",
		},
		{
			name:      "(a) backfill: antigravity markdown / reasoning convergence (direct actions DELETE)",
			seed:      seedCC(),
			mutate:    exec(`DELETE FROM actions WHERE source_event_id = 'e2'`),
			wantTable: orgcontract.DeletionActions, wantKey: "e2",
		},
		{
			name: "(a) backfill: openclaw session-id merge deletes the moved-from session",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				if _, err := db.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('oc-alias', 1, 'openclaw', '2026-09-27T09:00:00Z')`); err != nil {
					t.Fatal(err)
				}
			},
			mutate: exec(
				`INSERT INTO sessions (id, project_id, tool, started_at) SELECT 'oc-canon', project_id, tool, started_at FROM sessions WHERE id = 'oc-alias'`,
				`DELETE FROM sessions WHERE id = 'oc-alias' AND tool = 'openclaw' AND NOT EXISTS (SELECT 1 FROM actions WHERE session_id = sessions.id) AND NOT EXISTS (SELECT 1 FROM token_usage WHERE session_id = sessions.id)`),
			wantTable: orgcontract.DeletionSessions, wantKey: "oc-alias",
		},
		{
			name:      "(a) future path: an api_turns correction delete",
			seed:      seedCC(),
			mutate:    exec(`DELETE FROM api_turns WHERE request_id = 'req1'`),
			wantTable: orgcontract.DeletionAPITurns, wantKey: "req1",
		},
		{
			name:      "(a) identity change: an UPDATE of source_event_id retires the old identity",
			seed:      seedCC(),
			mutate:    exec(`UPDATE actions SET source_event_id = 'e1-renamed' WHERE source_event_id = 'e1'`),
			wantTable: orgcontract.DeletionActions, wantKey: "e1",
		},
		{
			name: "(b) retention: age pass deletes old actions and the orphaned session",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				if _, err := db.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('old', 1, 'claude-code', '2020-01-01T00:00:00Z')`); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, source_file, source_event_id) VALUES ('old', 1, '2020-01-01T00:00:00Z', 'read_file', 'claude-code', 'old.jsonl', 'old-1')`); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(t *testing.T, _ *Store, db *sql.DB) {
				res, err := retention.New(db).Run(context.Background(), retention.Options{MaxAgeDays: 30})
				if err != nil || res.ActionsDeleted != 1 || res.OrphanedSessionsDeleted != 1 {
					t.Fatalf("retention: %+v err %v", res, err)
				}
			},
			wantNoTombs: true,
		},
		{
			name: "(b) retention: the orphaned-session sweep alone",
			seed: func(t *testing.T, s *Store, db *sql.DB) {
				seedPushData(t, s, db)
				if _, err := db.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('empty', 1, 'claude-code', '2026-09-27T09:00:00Z')`); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(t *testing.T, _ *Store, db *sql.DB) {
				if _, err := retention.New(db).Run(context.Background(), retention.Options{}); err != nil {
					t.Fatal(err)
				}
			},
			wantNoTombs: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, db := newTestStore(t)
			c.seed(t, s, db)
			armResend(t, s)
			first := resendPushCycle(t, s)
			if batchRowCount(first) == 0 {
				t.Fatal("first push shipped nothing")
			}
			c.mutate(t, s, db)
			b := resendPushCycle(t, s)
			if c.wantNoTombs {
				if len(b.Deletions) != 0 {
					t.Fatalf("shipped tombstones %+v, want none", b.Deletions)
				}
			} else {
				if !hasDeletion(b, c.wantTable, c.wantKey) {
					t.Fatalf("no %s tombstone for %q in %+v", c.wantTable, c.wantKey, b.Deletions)
				}
				for _, d := range b.Deletions {
					if d.NodeRev <= first.Acks.Rev {
						t.Errorf("tombstone NodeRev %d not newer than the row's send %d", d.NodeRev, first.Acks.Rev)
					}
					if strings.Contains(d.SourceFileHash, "/") {
						t.Errorf("tombstone carries a raw path %q", d.SourceFileHash)
					}
				}
			}
			if c.wantResent != "" {
				found := false
				for _, r := range b.TokenUsage {
					if r.SourceEventID == c.wantResent && r.InputTokens == 7000 {
						found = true
					}
				}
				if !found {
					t.Fatalf("superseded identity %q not re-sent with the live values: %+v", c.wantResent, b.TokenUsage)
				}
			}
			after := resendPushCycle(t, s)
			if len(after.Deletions) != 0 {
				t.Fatalf("tombstones shipped twice: %+v", after.Deletions)
			}
			if tomb, _, err := s.PushDeletionsPending(context.Background()); err != nil || tomb != 0 {
				t.Fatalf("pending tombstones %d err %v, want 0", tomb, err)
			}
		})
	}
}

// TestTombstoneNotQueued pins the gates a tombstone shares with the re-send
// triggers: a node that is not enrolled, and a row at or below the enrolment
// floor (never shared), queue nothing.
func TestTombstoneNotQueued(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		arm  func(t *testing.T, s *Store)
	}{
		{"not enrolled", func(*testing.T, *Store) {}},
		{"row below the enrolment floor", func(t *testing.T, s *Store) {
			maxIDs, err := s.CurrentMaxIDs(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SavePushCursor(context.Background(), maxIDs); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, db := newTestStore(t)
			seedPushData(t, s, db)
			c.arm(t, s)
			if _, err := db.Exec(`DELETE FROM token_usage`); err != nil {
				t.Fatal(err)
			}
			if tomb, _, err := s.PushDeletionsPending(context.Background()); err != nil || tomb != 0 {
				t.Fatalf("queued %d tombstones (err %v), want 0", tomb, err)
			}
		})
	}
}

// TestTombstoneScopeAndMarker covers the two remaining compose rules: a
// tombstone for a row of a project outside the push scope is acknowledged
// without shipping (its identity must not cross), and a retention marker left
// COMMITTED by a crashed writer is cleared at the next push instead of
// silently suppressing every later correction.
func TestTombstoneScopeAndMarker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	t.Run("out of scope is acked, not shipped", func(t *testing.T) {
		t.Parallel()
		s, db := newTestStore(t)
		seedPushData(t, s, db)
		armResend(t, s)
		resendPushCycle(t, s)
		if _, err := db.Exec(`DELETE FROM token_usage WHERE source_event_id = 'tu1'`); err != nil {
			t.Fatal(err)
		}
		// A second project keeps the resolved scope non-empty.
		if _, err := s.UpsertProject(ctx, "/tmp/other", ""); err != nil {
			t.Fatal(err)
		}
		cur, _ := s.LoadPushCursor(ctx)
		b, err := s.SelectUnpushedSince(ctx, cur, 1<<22, "org", "dev@example.com", ShareOptions{},
			ScopeOptions{ProjectRootDenylist: []string{"/tmp/proj"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Deletions) != 0 || len(b.Acks.deletions) != 1 {
			t.Fatalf("deletions %+v acks %v, want none shipped and one acked", b.Deletions, b.Acks.deletions)
		}
	})
	t.Run("stale committed marker is cleared", func(t *testing.T) {
		t.Parallel()
		s, db := newTestStore(t)
		seedPushData(t, s, db)
		armResend(t, s)
		resendPushCycle(t, s)
		if _, err := db.Exec(`INSERT INTO schema_meta (key, value) VALUES (?, '1')`, idb.RetentionDeleteMarkerKey); err != nil {
			t.Fatal(err)
		}
		resendPushCycle(t, s)
		if v, _ := s.readMeta(ctx, idb.RetentionDeleteMarkerKey); v != "" {
			t.Fatalf("marker still committed: %q", v)
		}
		if _, err := db.Exec(`DELETE FROM actions WHERE source_event_id = 'e1'`); err != nil {
			t.Fatal(err)
		}
		if b := resendPushCycle(t, s); !hasDeletion(b, orgcontract.DeletionActions, "e1") {
			t.Fatalf("correction after the heal not tombstoned: %+v", b.Deletions)
		}
	})
	t.Run("a session re-inserted into a reused rowid re-sends", func(t *testing.T) {
		t.Parallel()
		s, db := newTestStore(t)
		seedPushData(t, s, db)
		if _, err := db.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('tail', 1, 'claude-code', '2026-09-27T09:00:00Z')`); err != nil {
			t.Fatal(err)
		}
		armResend(t, s)
		resendPushCycle(t, s)
		if _, err := db.Exec(`DELETE FROM sessions WHERE id = 'tail'`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('tail-2', 1, 'claude-code', '2026-09-27T09:01:00Z')`); err != nil {
			t.Fatal(err)
		}
		b := resendPushCycle(t, s)
		var shipped bool
		for _, r := range b.Sessions {
			shipped = shipped || r.ID == "tail-2"
		}
		if !shipped || !hasDeletion(b, orgcontract.DeletionSessions, "tail") {
			t.Fatalf("sessions %+v deletions %+v: want tail-2 shipped and tail tombstoned", b.Sessions, b.Deletions)
		}
	})
}

// TestRetentionDeleteMarkerKeyMatchesMigration pins the Go constant to the
// literal migration 141's triggers check.
func TestRetentionDeleteMarkerKeyMatchesMigration(t *testing.T) {
	t.Parallel()
	_, db := newTestStore(t)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'org_push_delete_%' AND sql LIKE '%' || ? || '%'`,
		idb.RetentionDeleteMarkerKey).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("%d of 4 delete triggers check %q", n, idb.RetentionDeleteMarkerKey)
	}
}

// TestSessionManifestHeal pins the resync heal's node half: a queued session
// gets a manifest listing every identity the node still holds there (so the
// org can drop what the node deleted before migration 141), NotBefore is
// raised to the retention cutoff the node recorded, and an oversized session
// is reported rather than queued.
func TestSessionManifestHeal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	armResend(t, s)
	resendPushCycle(t, s)
	cut := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO schema_meta (key, value) VALUES (?, ?)`, idb.AgeingCutoffKey, cut); err != nil {
		t.Fatal(err)
	}
	dry, err := s.EnqueuePushManifests(ctx, PushManifestOptions{Since: time.Now().Add(-24 * time.Hour), Limit: 10, DryRun: true})
	if err != nil || dry.Queued != 1 {
		t.Fatalf("dry run %+v err %v, want 1 session", dry, err)
	}
	if _, m, _ := s.PushDeletionsPending(ctx); m != 0 {
		t.Fatalf("dry run queued %d manifests", m)
	}
	rep, err := s.EnqueuePushManifests(ctx, PushManifestOptions{Since: time.Now().Add(-72 * time.Hour), Limit: 10})
	if err != nil || rep.Queued != 1 {
		t.Fatalf("enqueue %+v err %v", rep, err)
	}
	want, _ := time.Parse(time.RFC3339Nano, cut)
	if rep.NotBefore.Before(want.Add(24 * time.Hour)) {
		t.Errorf("NotBefore %v not raised past the recorded cutoff %v (+1d)", rep.NotBefore, want)
	}
	b := resendPushCycle(t, s)
	if len(b.SessionManifests) != 1 {
		t.Fatalf("manifests %+v, want 1", b.SessionManifests)
	}
	m := b.SessionManifests[0]
	if m.SessionID != "s1" || m.NotBefore == "" || m.NodeRev != b.Acks.Rev {
		t.Fatalf("manifest header %+v (rev %d)", m, b.Acks.Rev)
	}
	if len(m.Actions) != 2 || len(m.TokenUsage) != 1 || len(m.APITurns) != 1 {
		t.Fatalf("manifest lists a=%d t=%d p=%d, want 2/1/1", len(m.Actions), len(m.TokenUsage), len(m.APITurns))
	}
	if m.TokenUsage[0] != orgcontract.ManifestDigest(orgcontract.DeletionTokenUsage, "tu1") {
		t.Errorf("token digest %s does not match tu1", m.TokenUsage[0])
	}
	if again := resendPushCycle(t, s); len(again.SessionManifests) != 0 {
		t.Fatalf("manifest shipped twice")
	}
}

// TestRetentionRecordsAgeingCutoff pins that the age pass raises (never
// lowers) the recorded cutoff the heal's horizon is built on.
func TestRetentionRecordsAgeingCutoff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newTestStore(t)
	for _, days := range []int{30, 90} {
		if _, err := retention.New(db).Run(ctx, retention.Options{MaxAgeDays: days}); err != nil {
			t.Fatal(err)
		}
	}
	v, err := s.readMeta(ctx, idb.AgeingCutoffKey)
	if err != nil || v == "" {
		t.Fatalf("cutoff %q err %v", v, err)
	}
	got, _ := time.Parse(time.RFC3339Nano, v)
	if time.Since(got) > 31*24*time.Hour {
		t.Fatalf("cutoff %v lowered by the 90-day pass", got)
	}
}

// TestTombstoneOnlyBatchIsNotEmpty pins that a node whose only news is a
// deletion still pushes (PushOnce early-returns on Empty), and that the
// tombstone is a control item, not a row.
func TestTombstoneOnlyBatchIsNotEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	armResend(t, s)
	resendPushCycle(t, s)
	if _, err := db.Exec(`DELETE FROM actions WHERE source_event_id = 'e2'`); err != nil {
		t.Fatal(err)
	}
	cur, _ := s.LoadPushCursor(ctx)
	b, err := s.SelectUnpushedSince(ctx, cur, 1<<22, "org", "dev@example.com", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if b.Empty() || b.RowCount() != 0 || len(b.Deletions) != 1 {
		t.Fatalf("empty=%v rows=%d deletions=%d, want a non-empty control-only batch", b.Empty(), b.RowCount(), len(b.Deletions))
	}
}
