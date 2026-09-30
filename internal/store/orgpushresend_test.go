package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/turnmerge"
)

// resendPushCycle is one orgclient.PushOnce round as the store sees it:
// compose from the stored cursor, "deliver", then save the cursor with the
// CAS and acknowledge the re-send queue - exactly the calls the push loop
// makes after a 200.
func resendPushCycle(t *testing.T, s *Store) PushBatch {
	t.Helper()
	ctx := context.Background()
	cur, err := s.LoadPushCursor(ctx)
	if err != nil {
		t.Fatalf("LoadPushCursor: %v", err)
	}
	b, err := s.SelectUnpushedSince(ctx, cur, 1<<22, "org", "dev@example.com",
		ShareOptions{FullContent: true}, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if _, err := s.SavePushCursorIfUnchanged(ctx, cur, b.Cursor); err != nil {
		t.Fatalf("SavePushCursorIfUnchanged: %v", err)
	}
	if err := s.AckPushedChanges(ctx, b.Acks); err != nil {
		t.Fatalf("AckPushedChanges: %v", err)
	}
	return b
}

// armResend enrols the store the way `observer org backfill --all` leaves it:
// cursor and re-send floors at 0, so every row is eligible and tracked.
func armResend(t *testing.T, s *Store) {
	t.Helper()
	if err := s.SavePushCursor(context.Background(), PushCursor{}); err != nil {
		t.Fatalf("SavePushCursor: %v", err)
	}
}

func batchRowCount(b PushBatch) int {
	return len(b.Sessions) + len(b.Actions) + len(b.APITurns) + len(b.TokenUsage)
}

// TestResendPerMutationPath is the node half of the R2-RESEND contract, one
// row per known mutation path of an ALREADY-PUSHED row: after the mutation
// the next push re-sends exactly the changed row, carrying its new value and
// a NodeRev newer than the first send's; the push after that is empty again.
func TestResendPerMutationPath(t *testing.T) {
	t.Parallel()
	type check func(t *testing.T, b PushBatch, firstRev int64)
	cases := []struct {
		name   string
		mutate func(t *testing.T, s *Store, db *sql.DB, pid int64)
		check  check
	}{
		{
			name: "token_usage MAX-upgrade via re-ingest (session-cumulative adapter)",
			mutate: func(t *testing.T, s *Store, _ *sql.DB, _ int64) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SessionID: "s1", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode, Model: "claude",
					InputTokens: 900, OutputTokens: 400, Source: models.TokenSourceProxy,
					SourceFile: "f.jsonl", SourceEventID: "tu1",
				}}); err != nil {
					t.Fatalf("InsertTokenEvents: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, firstRev int64) {
				if len(b.TokenUsage) != 1 || b.TokenUsage[0].InputTokens != 900 || b.TokenUsage[0].OutputTokens != 400 {
					t.Fatalf("re-sent token rows = %+v, want tu1 at 900/400", b.TokenUsage)
				}
				if b.TokenUsage[0].NodeRev <= firstRev {
					t.Errorf("NodeRev %d not newer than first send %d", b.TokenUsage[0].NodeRev, firstRev)
				}
			},
		},
		{
			name: "token_usage gen_ms stamp landing after the push",
			mutate: func(t *testing.T, s *Store, _ *sql.DB, _ int64) {
				if err := s.stampGenTiming(context.Background(), []models.TokenEvent{{
					SourceFile: "f.jsonl", SourceEventID: "tu1", GenMs: 4200, GenBasis: models.GenBasisTranscript, GenTimingV: 1,
				}}); err != nil {
					t.Fatalf("stampGenTiming: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				if len(b.TokenUsage) != 1 || b.TokenUsage[0].GenMs != 4200 {
					t.Fatalf("re-sent token rows = %+v, want gen_ms 4200", b.TokenUsage)
				}
			},
		},
		{
			name: "action outcome filled in at PostToolUse",
			mutate: func(t *testing.T, s *Store, _ *sql.DB, _ int64) {
				if _, err := s.UpdateActionOutcome(context.Background(), "f.jsonl", "e1", false, "boom", 1234, "", "", ""); err != nil {
					t.Fatalf("UpdateActionOutcome: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				if len(b.Actions) != 1 || b.Actions[0].SourceEventID != "e1" || b.Actions[0].Success || b.Actions[0].DurationMs != 1234 {
					t.Fatalf("re-sent actions = %+v, want e1 failed with 1234ms", b.Actions)
				}
			},
		},
		{
			name: "api_turns merge update (merge.go)",
			mutate: func(t *testing.T, s *Store, db *sql.DB, _ int64) {
				var id int64
				if err := db.QueryRow(`SELECT id FROM api_turns WHERE request_id = 'req1'`).Scan(&id); err != nil {
					t.Fatalf("api_turn id: %v", err)
				}
				if err := s.updateMergeTurn(context.Background(), id, turnmerge.Turn{
					InputTokens: 100, OutputTokens: 77, CacheReadTokens: 5000, Fidelity: turnmerge.FidelityNativeExact,
				}); err != nil {
					t.Fatalf("updateMergeTurn: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				if len(b.APITurns) != 1 || b.APITurns[0].OutputTokens != 77 || b.APITurns[0].CacheReadTokens != 5000 {
					t.Fatalf("re-sent api_turns = %+v, want req1 at 77 out / 5000 cache read", b.APITurns)
				}
			},
		},
		{
			name: "transcript folded into its child session (session_source.go reparent)",
			mutate: func(t *testing.T, s *Store, db *sql.DB, pid int64) {
				ctx := context.Background()
				if err := s.UpsertSession(ctx, models.Session{ID: "child", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
					t.Fatalf("UpsertSession child: %v", err)
				}
				if _, err := db.Exec(`UPDATE token_usage SET is_sidechain = 1 WHERE source_event_id = 'tu1'`); err != nil {
					t.Fatalf("mark sidechain: %v", err)
				}
				// The sidechain flag flip above is itself a wire change; ship
				// it so the reparent below is what this case observes.
				resendPushCycle(t, s)
				if err := s.reassignSessionSource(ctx, models.SessionLineage{
					SessionID: "child", ParentThreadID: "s1", SourceFile: "f.jsonl",
				}); err != nil {
					t.Fatalf("reassignSessionSource: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				var tu int
				for _, r := range b.TokenUsage {
					if r.SourceEventID == "tu1" {
						tu++
						if r.SessionID != "child" || r.IsSidechain {
							t.Errorf("re-sent tu1 = session %q sidechain %v, want child/false", r.SessionID, r.IsSidechain)
						}
					}
				}
				if tu != 1 {
					t.Fatalf("tu1 re-sent %d times, want 1 (batch %+v)", tu, b.TokenUsage)
				}
			},
		},
		{
			name: "session ended_at written after the session shipped (session_end arrives later)",
			mutate: func(t *testing.T, s *Store, _ *sql.DB, _ int64) {
				if _, err := s.Ingest(context.Background(), []models.ToolEvent{{
					SessionID: "s1", ProjectRoot: "/tmp/proj", Timestamp: time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC),
					Tool: models.ToolClaudeCode, ActionType: models.ActionSessionEnd,
					SourceFile: "f.jsonl", SourceEventID: "end-1", Success: true,
				}}, nil, IngestOptions{}); err != nil {
					t.Fatalf("Ingest session_end: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				var got string
				for _, r := range b.Sessions {
					if r.ID == "s1" {
						got = r.EndedAt
					}
				}
				if got == "" {
					t.Fatalf("s1 not re-sent with ended_at; sessions = %+v", b.Sessions)
				}
			},
		},
		{
			name: "session capture surface stamped later",
			mutate: func(t *testing.T, s *Store, _ *sql.DB, _ int64) {
				if _, err := s.SetSessionSurface(context.Background(), models.SessionSurface{
					SessionID: "s1", Surface: models.SurfaceSDK, SurfaceHost: "cli",
				}); err != nil {
					t.Fatalf("SetSessionSurface: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				if len(b.Sessions) != 1 || b.Sessions[0].Surface != models.SurfaceSDK || b.Sessions[0].SurfaceHost != "cli" {
					t.Fatalf("re-sent sessions = %+v, want s1 sdk/cli", b.Sessions)
				}
			},
		},
		{
			name: "project learns its identity later (every session of it re-sends)",
			mutate: func(t *testing.T, s *Store, _ *sql.DB, pid int64) {
				if err := s.upsertProjectIdentity(context.Background(), pid, ProjectIdentity{UpstreamRemote: "git@example.com:up/app.git"}); err != nil {
					t.Fatalf("upsertProjectIdentity: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				if len(b.Sessions) != 1 || b.Sessions[0].GitUpstreamRemoteHash == "" {
					t.Fatalf("re-sent sessions = %+v, want s1 with the upstream hash", b.Sessions)
				}
			},
		},
		{
			name: "backfill-style direct SQL repair",
			mutate: func(t *testing.T, _ *Store, db *sql.DB, _ int64) {
				if _, err := db.Exec(`UPDATE token_usage SET message_id = 'msg_fixed' WHERE source_event_id = 'tu1'`); err != nil {
					t.Fatalf("repair: %v", err)
				}
			},
			check: func(t *testing.T, b PushBatch, _ int64) {
				if len(b.TokenUsage) != 1 || b.TokenUsage[0].MessageID != "msg_fixed" {
					t.Fatalf("re-sent token rows = %+v, want message_id msg_fixed", b.TokenUsage)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, db := newTestStore(t)
			pid := seedPushData(t, s, db)
			armResend(t, s)
			first := resendPushCycle(t, s)
			if batchRowCount(first) == 0 {
				t.Fatal("first push shipped nothing")
			}
			if again := resendPushCycle(t, s); batchRowCount(again) != 0 {
				t.Fatalf("an unchanged node re-sent %d rows", batchRowCount(again))
			}
			c.mutate(t, s, db, pid)
			b := resendPushCycle(t, s)
			c.check(t, b, first.Acks.Rev)
			if after := resendPushCycle(t, s); batchRowCount(after) != 0 {
				t.Fatalf("the change re-sent twice: %d rows on the following push", batchRowCount(after))
			}
		})
	}
}

// TestResendNotQueued pins the cases that must NOT re-send: a node-local
// column change, an identical re-parse, a row below the enrolment floor, and a
// node that is not enrolled at all.
func TestResendNotQueued(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		arm    func(t *testing.T, s *Store)
		mutate func(t *testing.T, s *Store, db *sql.DB)
	}{
		{
			name: "node-local score column",
			arm:  armResend,
			mutate: func(t *testing.T, _ *Store, db *sql.DB) {
				if _, err := db.Exec(`UPDATE sessions SET quality_score = 0.9, summary_md = 'x' WHERE id = 's1'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "identical re-parse (upsert rewrites equal values)",
			arm:  armResend,
			mutate: func(t *testing.T, s *Store, _ *sql.DB) {
				if _, err := s.InsertTokenEvents(context.Background(), []models.TokenEvent{{
					SessionID: "s1", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode, Model: "claude",
					InputTokens: 100, OutputTokens: 50, Source: models.TokenSourceProxy,
					SourceFile: "f.jsonl", SourceEventID: "tu1",
				}}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "row below the enrolment floor (never shared)",
			arm: func(t *testing.T, s *Store) {
				// Enrolment seeds cursor AND floor at the current high-water
				// mark: every seeded row is pre-enrolment history.
				maxIDs, err := s.CurrentMaxIDs(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := s.SavePushCursor(context.Background(), maxIDs); err != nil {
					t.Fatal(err)
				}
			},
			mutate: func(t *testing.T, _ *Store, db *sql.DB) {
				if _, err := db.Exec(`UPDATE token_usage SET output_tokens = 999`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "not enrolled",
			arm:  func(*testing.T, *Store) {},
			mutate: func(t *testing.T, _ *Store, db *sql.DB) {
				if _, err := db.Exec(`UPDATE token_usage SET output_tokens = 999`); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, db := newTestStore(t)
			seedPushData(t, s, db)
			c.arm(t, s)
			resendPushCycle(t, s)
			c.mutate(t, s, db)
			pending, err := s.PushResendPending(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) != 0 {
				t.Fatalf("queued %v, want nothing", pending)
			}
			if b := resendPushCycle(t, s); batchRowCount(b) != 0 {
				t.Fatalf("re-sent %d rows, want 0", batchRowCount(b))
			}
		})
	}
}

// TestResendChangeDuringFlight: a change that lands after the batch was read
// but before it was acknowledged must stay queued and ship on the next push.
func TestResendChangeDuringFlight(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	armResend(t, s)
	ctx := context.Background()

	cur, _ := s.LoadPushCursor(ctx)
	b, err := s.SelectUnpushedSince(ctx, cur, 1<<22, "org", "dev@example.com", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// In flight: the token row is upgraded after it was read.
	if _, err := db.Exec(`UPDATE token_usage SET output_tokens = 555 WHERE source_event_id = 'tu1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavePushCursorIfUnchanged(ctx, cur, b.Cursor); err != nil {
		t.Fatal(err)
	}
	if err := s.AckPushedChanges(ctx, b.Acks); err != nil {
		t.Fatal(err)
	}
	next := resendPushCycle(t, s)
	if len(next.TokenUsage) != 1 || next.TokenUsage[0].OutputTokens != 555 {
		t.Fatalf("in-flight change not re-sent: %+v", next.TokenUsage)
	}
	if next.TokenUsage[0].NodeRev <= b.Acks.Rev {
		t.Errorf("re-send NodeRev %d not newer than the in-flight batch's %d", next.TokenUsage[0].NodeRev, b.Acks.Rev)
	}
}

// TestResendUnenrolDisarms: unenrolling removes the floors and the queue, and
// a later re-enrolment re-arms from its own seed.
func TestResendUnenrolDisarms(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	armResend(t, s)
	resendPushCycle(t, s)
	if _, err := db.Exec(`UPDATE token_usage SET output_tokens = 51`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEnrolment(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE token_usage SET output_tokens = 52`); err != nil {
		t.Fatal(err)
	}
	pending, err := s.PushResendPending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("queue after unenrol = %v, want empty", pending)
	}
}

// TestPushResyncHeal: a row that diverged BEFORE tracking was armed (the
// upgrade case: floors start at the cursor) is healed by EnqueuePushResync,
// which lowers the floor only to a provably post-enrolment id and queues a
// bounded window; the push loop then drains it. Rows from before enrolment
// stay unshipped.
func TestPushResyncHeal(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	enrolled := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	pid, err := s.UpsertProject(ctx, "/tmp/heal", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "pre", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: old}); err != nil {
		t.Fatal(err)
	}
	insertTok := func(id string, ts time.Time, out int64) {
		if _, err := db.Exec(`INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
			VALUES('pre', ?, 'claude-code', 'claude', 1, ?, 'jsonl', 'heal.jsonl', ?)`, ts.Format(time.RFC3339), out, id); err != nil {
			t.Fatal(err)
		}
	}
	insertTok("pre-1", old, 10) // pre-enrolment: must never ship
	// Enrolment at this point; recorded like WriteEnrolment would.
	maxIDs, _ := s.CurrentMaxIDs(ctx)
	if _, err := db.Exec(`INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
		VALUES (1, 'org', 'Org', 'https://org', 'u', 'dev@example.com', ?, 'k')`, enrolled.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	insertTok("post-1", enrolled.Add(time.Hour), 20)
	insertTok("post-2", enrolled.Add(2*time.Hour), 30)
	if err := s.SavePushCursor(ctx, maxIDs); err != nil {
		t.Fatal(err)
	}
	resendPushCycle(t, s) // ships post-1, post-2
	// Simulate the pre-upgrade world: the floor sat at the cursor (migration
	// 140's conservative default) and the rows then diverged untracked.
	cur, _ := s.LoadPushCursor(ctx)
	if _, err := db.Exec(`UPDATE schema_meta SET value = ? WHERE key = 'org_push_floor_token_usage'`, cur.TokenUsage); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE token_usage SET output_tokens = output_tokens + 1000`); err != nil {
		t.Fatal(err)
	}
	if b := resendPushCycle(t, s); batchRowCount(b) != 0 {
		t.Fatalf("untracked divergence re-sent without a heal: %d rows", batchRowCount(b))
	}

	dry, err := s.EnqueuePushResync(ctx, PushResyncOptions{Since: time.Time{}, Limit: 100, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range dry.Tables {
		if l.Table == "token_usage" && l.Queued != 2 {
			t.Errorf("dry-run would queue %d token rows, want 2", l.Queued)
		}
	}
	if p, _ := s.PushResendPending(ctx); len(p) != 0 {
		t.Fatalf("dry run wrote to the queue: %v", p)
	}
	rep, err := s.EnqueuePushResync(ctx, PushResyncOptions{Since: time.Time{}, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range rep.Tables {
		if l.Table == "token_usage" && (l.FloorAfter != maxIDs.TokenUsage || l.Queued != 2) {
			t.Errorf("token_usage heal = %+v, want floor lowered to the seed %d and 2 queued", l, maxIDs.TokenUsage)
		}
	}
	b := resendPushCycle(t, s)
	got := map[string]int64{}
	for _, r := range b.TokenUsage {
		got[r.SourceEventID] = r.OutputTokens
	}
	if got["post-1"] != 1020 || got["post-2"] != 1030 {
		t.Errorf("healed rows = %v, want post-1=1020 post-2=1030", got)
	}
	if _, leaked := got["pre-1"]; leaked {
		t.Error("the heal shipped a pre-enrolment row")
	}
	// Limit caps the queue.
	capRep, err := s.EnqueuePushResync(ctx, PushResyncOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, l := range capRep.Tables {
		total += l.Queued
	}
	if total != 1 {
		t.Errorf("Limit 1 queued %d rows", total)
	}
}

// TestResendLaneBounded: a deep queue drains over several pushes instead of
// one oversized envelope.
func TestResendLaneBounded(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	seedPushData(t, s, db)
	ctx := context.Background()
	for i := 0; i < pushResendRowCap+50; i++ {
		if _, err := db.Exec(`INSERT INTO token_usage(session_id, timestamp, tool, model, input_tokens, output_tokens, source, source_file, source_event_id)
			VALUES('s1', ?, 'claude-code', 'claude', 1, 1, 'jsonl', 'bulk.jsonl', ?)`,
			time.Now().UTC().Format(time.RFC3339), "b"+time.Duration(i).String()); err != nil {
			t.Fatal(err)
		}
	}
	armResend(t, s)
	for i := 0; i < 20 && batchRowCount(resendPushCycle(t, s)) != 0; i++ {
	}
	if _, err := db.Exec(`UPDATE token_usage SET output_tokens = 2`); err != nil {
		t.Fatal(err)
	}
	first := resendPushCycle(t, s)
	if n := first.Acks.Resent(); n != pushResendRowCap {
		t.Fatalf("first drain re-sent %d rows, want the cap %d", n, pushResendRowCap)
	}
	second := resendPushCycle(t, s)
	if n := second.Acks.Resent(); n != 51 { // the seeded tu1 row + 50
		t.Fatalf("second drain re-sent %d rows, want 51", n)
	}
	if p, _ := s.PushResendPending(ctx); len(p) != 0 {
		t.Fatalf("queue not drained: %v", p)
	}
}

// TestPushResyncRepairsEndedAt: a historical session whose session_end row was
// stored before ended_at was ever written (so it reads as never closed on
// both the node and the org) gets its end time from the one lifecycle rule
// (internal/sessionend via refreshSessionEnded) and is re-sent.
func TestPushResyncRepairsEndedAt(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	seedPushData(t, s, db)
	end := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SessionID: "s1", ProjectRoot: "/tmp/proj", Timestamp: end, Tool: models.ToolClaudeCode,
		ActionType: models.ActionSessionEnd, SourceFile: "f.jsonl", SourceEventID: "end-1", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	// The pre-fix state: the close is stored, ended_at is not.
	if _, err := db.Exec(`UPDATE sessions SET ended_at = NULL WHERE id = 's1'`); err != nil {
		t.Fatal(err)
	}
	armResend(t, s)
	resendPushCycle(t, s)
	rep, err := s.EnqueuePushResync(ctx, PushResyncOptions{Since: time.Now().Add(-24 * time.Hour), Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if rep.EndedAtChecked != 1 {
		t.Errorf("EndedAtChecked = %d, want 1", rep.EndedAtChecked)
	}
	b := resendPushCycle(t, s)
	if len(b.Sessions) != 1 || b.Sessions[0].EndedAt == "" {
		t.Fatalf("s1 not re-sent with its repaired ended_at: %+v", b.Sessions)
	}
	if got, _ := time.Parse(time.RFC3339Nano, b.Sessions[0].EndedAt); !got.Equal(end) {
		t.Errorf("re-sent ended_at = %s, want %s", b.Sessions[0].EndedAt, end.Format(time.RFC3339))
	}
}

// TestResendLaneIsQueueDriven pins the re-send lane's query plan: the queue
// drives and the tracked table is only probed by id, so a push never scans a
// large table to find a handful of changed rows.
func TestResendLaneIsQueueDriven(t *testing.T) {
	t.Parallel()
	_, db := newTestStore(t)
	for _, c := range []struct{ head, table, id, alias string }{
		{sessionPushSelect, "sessions", "s.rowid", "s"},
		{actionPushSelect, "actions", "a.id", "a"},
		{apiTurnPushSelect, "api_turns", "t.id", "t"},
		{tokenUsagePushSelect("0"), "token_usage", "tu.id", "tu"},
	} {
		q := "EXPLAIN QUERY PLAN " + c.head + pushChangesFilter(c.table, c.id) + " ORDER BY " + c.id
		rows, err := db.Query(q, 1, 1, 0, 10)
		if err != nil {
			t.Fatalf("%s: %v", c.table, err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				t.Fatal(err)
			}
			plan = append(plan, detail)
		}
		rows.Close()
		t.Logf("%s re-send plan: %v", c.table, plan)
		if len(plan) == 0 {
			t.Fatalf("%s: empty query plan", c.table)
		}
		for _, step := range plan {
			if step == "SCAN "+c.alias || strings.HasPrefix(step, "SCAN "+c.alias+" ") {
				t.Errorf("%s re-send lane scans the table: %v", c.table, plan)
			}
		}
	}
}
