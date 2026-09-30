package store

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/migrations"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/turnmerge"
)

// openStoreAtMigration builds a store on a file DB migrated ONLY up to
// version (inclusive), by replaying the embedded migration bodies the way
// db.runMigrations does, then pinning schema_meta.version. Reopening the
// returned path with db.Open upgrades it to head through the real runner.
func openStoreAtMigration(t *testing.T, version int) (*Store, *sql.DB, string) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("at-%03d.db", version))
	dsn := "file:" + path + "?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	if _, err := sqlDB.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatalf("bootstrap schema_meta: %v", err)
	}
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	type mig struct {
		v    int
		name string
	}
	var migs []mig
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".sql" {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			t.Fatalf("migration %q: %v", e.Name(), err)
		}
		migs = append(migs, mig{v, e.Name()})
	}
	sort.Slice(migs, func(i, j int) bool { return migs[i].v < migs[j].v })
	for _, m := range migs {
		if m.v > version {
			continue
		}
		body, err := fs.ReadFile(migrations.Files, m.name)
		if err != nil {
			t.Fatalf("read %s: %v", m.name, err)
		}
		if _, err := sqlDB.ExecContext(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", m.name, err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES ('version', ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.Itoa(version)); err != nil {
		t.Fatalf("pin version %d: %v", version, err)
	}
	return New(sqlDB), sqlDB, path
}

// queueKey names one org_push_changes row a mutation must leave queued.
type queueKey struct {
	tbl   string
	rowID string // SQL returning the tracked row's id
}

// upsertTriggerCase is one real mutation seam run twice in a row on an
// already-pushed row. at141 is what migration 141's INSERT OR REPLACE
// trigger bodies did with the SECOND mutation:
//
//	"unique" - the ingest failed `UNIQUE constraint failed: org_push_changes`
//	           and rolled back (defect D3);
//	"stale"  - it succeeded but the queue row kept the FIRST mutation's seq,
//	           so an in-flight batch could acknowledge a change it never read;
//	"ok"     - a plain UPDATE, which 141 already handled.
//
// From migration 142 every case succeeds and leaves one queue row per key
// carrying the second mutation's seq.
type upsertTriggerCase struct {
	name   string
	at141  string
	mutate func(ctx context.Context, s *Store, sqlDB *sql.DB, pid int64, n int) error
	keys   []queueKey
	// check returns the persisted value and the value mutation 2 wrote.
	check func(t *testing.T, sqlDB *sql.DB) (got, want string)
}

func tokenEvent(out int64) models.TokenEvent {
	return models.TokenEvent{
		SessionID: "s1", Timestamp: time.Now().UTC(), Tool: models.ToolClaudeCode, Model: "claude",
		InputTokens: 100, OutputTokens: out, Source: models.TokenSourceProxy,
		SourceFile: "f.jsonl", SourceEventID: "tu1",
	}
}

func scalar(t *testing.T, sqlDB *sql.DB, q string) string {
	t.Helper()
	var v sql.NullString
	if err := sqlDB.QueryRow(q).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v.String
}

var (
	keySession = queueKey{"sessions", `SELECT rowid FROM sessions WHERE id = 's1'`}
	keyAction  = queueKey{"actions", `SELECT id FROM actions WHERE source_event_id = 'e1'`}
	keyTurn    = queueKey{"api_turns", `SELECT id FROM api_turns WHERE request_id = 'req1'`}
	keyToken   = queueKey{"token_usage", `SELECT id FROM token_usage WHERE source_event_id = 'tu1'`}
)

func upsertTriggerCases() []upsertTriggerCase {
	return []upsertTriggerCase{
		{
			name:  "sessions: store.UpsertSession twice (model change)",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, pid int64, n int) error {
				return s.UpsertSession(ctx, models.Session{
					ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode,
					Model: fmt.Sprintf("claude-%d", n), StartedAt: time.Now().UTC(),
				})
			},
			keys: []queueKey{keySession},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT model FROM sessions WHERE id = 's1'`), "claude-2"
			},
		},
		{
			name:  "sessions: store.Ingest twice (a later batch resolves the session's model)",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, _ int64, n int) error {
				_, err := s.Ingest(ctx, []models.ToolEvent{{
					SessionID: "s1", ProjectRoot: "/tmp/proj", Model: fmt.Sprintf("claude-ingest-%d", n),
					Timestamp: time.Date(2026, 9, 27, 10, n, 0, 0, time.UTC),
					Tool:      models.ToolClaudeCode, ActionType: models.ActionReadFile, Target: "b.go",
					SourceFile: "f.jsonl", SourceEventID: fmt.Sprintf("ing-%d", n), Success: true,
				}}, nil, IngestOptions{})
				return err
			},
			keys: []queueKey{keySession},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT model FROM sessions WHERE id = 's1'`), "claude-ingest-2"
			},
		},
		{
			name:  "projects: store.UpsertProject twice (remote learned, then changed) re-queues its sessions",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, _ int64, n int) error {
				_, err := s.UpsertProject(ctx, "/tmp/proj", fmt.Sprintf("git@example.com:acme/app-%d.git", n))
				return err
			},
			keys: []queueKey{keySession},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT git_remote FROM projects WHERE root_path = '/tmp/proj'`), "git@example.com:acme/app-2.git"
			},
		},
		{
			name:  "sessions -> token_usage: store.UpsertSession twice moving the session's project",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, pid int64, n int) error {
				target := pid
				if n == 1 {
					other, err := s.UpsertProject(ctx, "/tmp/other", "")
					if err != nil {
						return err
					}
					target = other
				}
				return s.UpsertSession(ctx, models.Session{
					ID: "s1", ProjectID: target, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: time.Now().UTC(),
				})
			},
			keys: []queueKey{keySession, keyToken},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = 's1'`), "/tmp/proj"
			},
		},
		{
			name:  "actions: store.InsertActions upsert twice (richer raw_tool_input on re-scan)",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, pid int64, n int) error {
				_, err := s.InsertActions(ctx, []models.Action{{
					SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
					ActionType: models.ActionReadFile, Target: "a.go", Success: true,
					Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e1",
					RawToolInput: strings.Repeat("x", n),
				}})
				return err
			},
			keys: []queueKey{keyAction},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT raw_tool_input FROM actions WHERE source_event_id = 'e1'`), "xx"
			},
		},
		{
			name:  "token_usage: store.InsertTokenEvents MAX-upgrade twice",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, _ int64, n int) error {
				_, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tokenEvent(int64(500 + n))})
				return err
			},
			keys: []queueKey{keyToken},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT output_tokens FROM token_usage WHERE source_event_id = 'tu1'`), "502"
			},
		},
		{
			name:  "token_usage: ONE store.InsertTokenEvents batch upgrading the same row twice (fresh queue)",
			at141: "unique",
			mutate: func(ctx context.Context, s *Store, _ *sql.DB, _ int64, n int) error {
				if n == 1 {
					return nil
				}
				_, err := s.InsertTokenEvents(ctx, []models.TokenEvent{tokenEvent(600), tokenEvent(700)})
				return err
			},
			keys: []queueKey{keyToken},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT output_tokens FROM token_usage WHERE source_event_id = 'tu1'`), "700"
			},
		},
		{
			name:  "api_turns: UPSERT-shaped outer statement twice",
			at141: "unique",
			mutate: func(ctx context.Context, _ *Store, sqlDB *sql.DB, pid int64, n int) error {
				_, err := sqlDB.ExecContext(ctx,
					`INSERT INTO api_turns (id, session_id, project_id, timestamp, provider, model, request_id, input_tokens, output_tokens)
					 SELECT id, session_id, project_id, timestamp, provider, model, request_id, input_tokens, ?
					   FROM api_turns WHERE request_id = 'req1'
					 ON CONFLICT(id) DO UPDATE SET output_tokens = excluded.output_tokens`, 60+n)
				return err
			},
			keys: []queueKey{keyTurn},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT output_tokens FROM api_turns WHERE request_id = 'req1'`), "62"
			},
		},
		{
			name:  "api_turns: store merge update (plain UPDATE) twice",
			at141: "ok",
			mutate: func(ctx context.Context, s *Store, sqlDB *sql.DB, _ int64, n int) error {
				var id int64
				if err := sqlDB.QueryRowContext(ctx, `SELECT id FROM api_turns WHERE request_id = 'req1'`).Scan(&id); err != nil {
					return err
				}
				return s.updateMergeTurn(ctx, id, turnmerge.Turn{
					InputTokens: 100, OutputTokens: int64(70 + n), Fidelity: turnmerge.FidelityNativeExact,
				})
			},
			keys: []queueKey{keyTurn},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT output_tokens FROM api_turns WHERE request_id = 'req1'`), "72"
			},
		},
		{
			name:  "token_usage: UPDATE OR IGNORE twice (outer IGNORE swallowed the queue insert)",
			at141: "stale",
			mutate: func(ctx context.Context, _ *Store, sqlDB *sql.DB, _ int64, n int) error {
				_, err := sqlDB.ExecContext(ctx,
					`UPDATE OR IGNORE token_usage SET output_tokens = ? WHERE source_event_id = 'tu1'`, 800+n)
				return err
			},
			keys: []queueKey{keyToken},
			check: func(t *testing.T, sqlDB *sql.DB) (string, string) {
				return scalar(t, sqlDB, `SELECT output_tokens FROM token_usage WHERE source_event_id = 'tu1'`), "802"
			},
		},
	}
}

func pushRev(t *testing.T, sqlDB *sql.DB) int64 {
	t.Helper()
	v, err := strconv.ParseInt(scalar(t, sqlDB, `SELECT rev FROM org_push_rev WHERE k = 1`), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// queuedSeqs returns the seq of every org_push_changes row for key.
func queuedSeqs(t *testing.T, sqlDB *sql.DB, k queueKey) []int64 {
	t.Helper()
	rows, err := sqlDB.Query(`SELECT seq FROM org_push_changes WHERE tbl = ? AND row_id = (`+k.rowID+`)`, k.tbl)
	if err != nil {
		t.Fatalf("queue for %s: %v", k.tbl, err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var s int64
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

// runUpsertTriggerCase seeds + ships the push data on an enrolled store,
// applies mutation 1 then mutation 2, and returns mutation 2's error plus
// the rev after mutation 1.
func runUpsertTriggerCase(t *testing.T, c upsertTriggerCase, s *Store, sqlDB *sql.DB) (err2 error, rev1 int64) {
	t.Helper()
	ctx := context.Background()
	pid := seedPushData(t, s, sqlDB)
	armResend(t, s)
	if first := resendPushCycle(t, s); batchRowCount(first) == 0 {
		t.Fatal("first push shipped nothing")
	}
	if err := c.mutate(ctx, s, sqlDB, pid, 1); err != nil {
		t.Fatalf("mutation 1 (empty queue for this row): %v", err)
	}
	rev1 = pushRev(t, sqlDB)
	return c.mutate(ctx, s, sqlDB, pid, 2), rev1
}

// TestPushChangeTriggersSurviveUpsert is the D3 regression: an UPSERT (or any
// statement carrying its own conflict algorithm) on an already-queued row of
// an ENROLLED node must not fail, must not roll the ingest back, and must
// leave exactly one queue row carrying the latest change's seq.
func TestPushChangeTriggersSurviveUpsert(t *testing.T) {
	t.Parallel()
	for _, c := range upsertTriggerCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, sqlDB := newTestStore(t)
			err2, rev1 := runUpsertTriggerCase(t, c, s, sqlDB)
			if err2 != nil {
				t.Fatalf("mutation 2 on an already-queued row failed: %v", err2)
			}
			if got, want := c.check(t, sqlDB); got != want {
				t.Fatalf("persisted value = %q, want %q (the mutation rolled back)", got, want)
			}
			revNow := pushRev(t, sqlDB)
			for _, k := range c.keys {
				seqs := queuedSeqs(t, sqlDB, k)
				if len(seqs) != 1 {
					t.Fatalf("%s queue rows = %v, want exactly one", k.tbl, seqs)
				}
				if seqs[0] <= rev1 || seqs[0] > revNow {
					t.Errorf("%s queued seq = %d, want the second change's (in (%d, %d])", k.tbl, seqs[0], rev1, revNow)
				}
			}
			if b := resendPushCycle(t, s); batchRowCount(b) == 0 {
				t.Fatal("the change was not re-sent")
			}
			if after := resendPushCycle(t, s); batchRowCount(after) != 0 {
				t.Fatalf("the change re-sent twice: %d rows on the following push", batchRowCount(after))
			}
		})
	}
}

// TestPushChangeTriggersAt141ThenUpgrade proves the regression test above is
// meaningful: on a DB migrated only to 141 the same mutations fail (or leave
// a stale seq) exactly as defect D3 described, and upgrading that very DB
// through db.Open (migration 142) fixes it with the queue already populated.
func TestPushChangeTriggersAt141ThenUpgrade(t *testing.T) {
	t.Parallel()
	for _, c := range upsertTriggerCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s, sqlDB, path := openStoreAtMigration(t, 141)
			// The push seam (this build's SelectUnpushedSince) reads
			// api_turns.request_class, which agent migration 144 adds after
			// the 141 state this test pins; production never runs this build
			// against a DB below head. Give the 141 DB that one read column
			// for the pre-upgrade half, and take it away again before the
			// real runner upgrades it (144's ALTER must still apply cleanly).
			// The column has no trigger and no bearing on the D3 behaviour.
			if _, err := sqlDB.Exec(`ALTER TABLE api_turns ADD COLUMN request_class TEXT`); err != nil {
				t.Fatalf("add post-141 push column: %v", err)
			}
			err2, rev1 := runUpsertTriggerCase(t, c, s, sqlDB)
			got, want := c.check(t, sqlDB)
			switch c.at141 {
			case "unique":
				if err2 == nil || !strings.Contains(err2.Error(), "UNIQUE constraint failed: org_push_changes") {
					t.Fatalf("at 141: mutation 2 err = %v, want the D3 UNIQUE failure", err2)
				}
				if got == want {
					t.Fatalf("at 141: value %q persisted although the statement failed", got)
				}
			case "stale":
				if err2 != nil {
					t.Fatalf("at 141: mutation 2 err = %v, want success", err2)
				}
				for _, k := range c.keys {
					if seqs := queuedSeqs(t, sqlDB, k); len(seqs) != 1 || seqs[0] > rev1 {
						t.Fatalf("at 141: %s queue = %v, want one row still at the FIRST change's seq (<= %d)", k.tbl, seqs, rev1)
					}
				}
			case "ok":
				if err2 != nil || got != want {
					t.Fatalf("at 141: mutation 2 err = %v, value %q (want %q)", err2, got, want)
				}
			default:
				t.Fatalf("unknown at141 %q", c.at141)
			}
			if _, err := sqlDB.Exec(`ALTER TABLE api_turns DROP COLUMN request_class`); err != nil {
				t.Fatalf("drop post-141 push column: %v", err)
			}
			if err := sqlDB.Close(); err != nil {
				t.Fatal(err)
			}

			// Upgrade THIS database (queue rows present) through the real runner.
			up, err := db.Open(context.Background(), db.Options{Path: path})
			if err != nil {
				t.Fatalf("db.Open upgrade: %v", err)
			}
			t.Cleanup(func() { up.Close() })
			if v, err := db.Version(context.Background(), up); err != nil || v < 142 {
				t.Fatalf("upgraded version = %d (err %v), want >= 142", v, err)
			}
			us := New(up)
			ctx := context.Background()
			pid := scalar(t, up, `SELECT id FROM projects WHERE root_path = '/tmp/proj'`)
			pidN, _ := strconv.ParseInt(pid, 10, 64)
			// Re-run mutation 2 then mutation 1 then 2 again on the queued
			// row: every one must succeed now and land.
			for _, n := range []int{2, 1, 2} {
				if err := c.mutate(ctx, us, up, pidN, n); err != nil {
					t.Fatalf("after 142: mutation %d: %v", n, err)
				}
			}
			if got, want := c.check(t, up); got != want {
				t.Fatalf("after 142: value = %q, want %q", got, want)
			}
			revNow := pushRev(t, up)
			for _, k := range c.keys {
				if seqs := queuedSeqs(t, up, k); len(seqs) != 1 || seqs[0] > revNow || seqs[0] <= rev1 {
					t.Fatalf("after 142: %s queue = %v, want one row at a post-upgrade seq (in (%d, %d])", k.tbl, seqs, rev1, revNow)
				}
			}
		})
	}
}
