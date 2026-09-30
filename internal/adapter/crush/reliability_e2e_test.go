package crush

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// crushTokenRow is the stored token_usage projection the e2e test checks.
type crushTokenRow struct {
	rel     string
	in, out int64
	cost    float64
	model   string
}

func loadCrushTokenRow(t *testing.T, nodeDB *sql.DB, sessionID string) crushTokenRow {
	t.Helper()
	var r crushTokenRow
	if err := nodeDB.QueryRow(`SELECT COALESCE(reliability,''), input_tokens, output_tokens, estimated_cost_usd, COALESCE(model,'')
		FROM token_usage WHERE tool = ? AND source_event_id = ?`, models.ToolCrush, "tokens:"+sessionID).
		Scan(&r.rel, &r.in, &r.out, &r.cost, &r.model); err != nil {
		t.Fatalf("load token row %s: %v", sessionID, err)
	}
	return r
}

// TestReliabilityFollowsReparseEndToEnd is the Crush live-ingest caveat,
// closed: a session first ingested at ONE step (real counts, approximate)
// that grows a second step is re-parsed through the adapter and the real
// store.Ingest the watcher uses, and the stored row follows it to
// unknown / 0/0 / the new larger cost with the model kept - no
// --crush-rescan needed - and the change is queued for the org re-send
// (agent migration 140). The reverse (a cost-only unknown row that later
// reports one step's counts) is promoted to approximate.
func TestReliabilityFollowsReparseEndToEnd(t *testing.T) {
	ctx := context.Background()
	root, dbPath := dbPathUnder(t)
	newCrushDB(t, dbPath, append(simpleSession(),
		// ses_late: Crush recorded a cost before any counters (unknown).
		`INSERT INTO sessions(id,title,prompt_tokens,completion_tokens,cost,updated_at,created_at)
		 VALUES ('ses_late','Late counters',0,0,0.002,1783550930,1783550925)`,
		`INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at) VALUES
		 ('ml_u','ses_late','user','[{"type":"text","data":{"text":"hi"}}]','','',1783550925,1783550925),
		 ('ml_a','ses_late','assistant','[{"type":"text","data":{"text":"ok"}},{"type":"finish","data":{"reason":"end_turn","time":1783550930}}]','gpt-5.4-mini','openai',1783550926,1783550930)`,
	)...)
	a := NewWithOptions(nil, []string{filepath.Join(root, ".crush")})

	nodeDB, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "node.db")})
	if err != nil {
		t.Fatalf("open node db: %v", err)
	}
	t.Cleanup(func() { nodeDB.Close() })
	st := store.New(nodeDB)
	ingest := func(res *adapter.ParseResult) {
		t.Helper()
		if _, err := st.Ingest(ctx, res.ToolEvents, res.TokenEvents, store.IngestOptions{}); err != nil {
			t.Fatalf("Ingest: %v", err)
		}
	}

	first, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatalf("parse1: %v", err)
	}
	ingest(&first)
	if got := loadCrushTokenRow(t, nodeDB, "ses_simple"); got != (crushTokenRow{models.ReliabilityApproximate, 21749, 5, 0.05448195, "gpt-5.4"}) {
		t.Fatalf("one-step row = %+v, want approximate 21749/5", got)
	}
	if got := loadCrushTokenRow(t, nodeDB, "ses_late"); got != (crushTokenRow{models.ReliabilityUnknown, 0, 0, 0.002, "gpt-5.4-mini"}) {
		t.Fatalf("cost-only row = %+v, want unknown 0/0 $0.002", got)
	}

	// The node is enrolled and has shipped everything so far.
	if _, err := nodeDB.Exec(`INSERT INTO schema_meta (key, value) VALUES ('org_push_floor_token_usage', '0')
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`); err != nil {
		t.Fatal(err)
	}

	// ses_simple grows a second successful step (its counters become a
	// last-step snapshot); ses_late now reports one step's counters.
	appendMessage(t, dbPath, `INSERT INTO messages(id,session_id,role,parts,model,provider,created_at,updated_at)
		VALUES ('m_a2','ses_simple','assistant','[{"type":"text","data":{"text":"more"}},{"type":"finish","data":{"reason":"end_turn","time":1790001200}}]','gpt-5.4','openai',1790001150,1790001200)`)
	appendMessage(t, dbPath, `UPDATE sessions SET prompt_tokens = 22000, completion_tokens = 9, cost = 0.1, updated_at = 1790001200 WHERE id = 'ses_simple'`)
	appendMessage(t, dbPath, `UPDATE sessions SET prompt_tokens = 640, completion_tokens = 12, cost = 0.003, updated_at = 1790001300 WHERE id = 'ses_late'`)

	second, err := a.ParseSessionFile(ctx, dbPath, first.NewOffset)
	if err != nil {
		t.Fatalf("parse2: %v", err)
	}
	ingest(&second)

	if got := loadCrushTokenRow(t, nodeDB, "ses_simple"); got != (crushTokenRow{models.ReliabilityUnknown, 0, 0, 0.1, "gpt-5.4"}) {
		t.Errorf("grown row = %+v, want unknown 0/0 $0.1 gpt-5.4 (demoted, counts replaced)", got)
	}
	if got := loadCrushTokenRow(t, nodeDB, "ses_late"); got != (crushTokenRow{models.ReliabilityApproximate, 640, 12, 0.003, "gpt-5.4-mini"}) {
		t.Errorf("late row = %+v, want approximate 640/12 $0.003 (promoted)", got)
	}
	var n int
	if err := nodeDB.QueryRow(`SELECT COUNT(*) FROM org_push_changes WHERE tbl = 'token_usage' AND row_id IN
		(SELECT id FROM token_usage WHERE tool = ? AND source_event_id IN ('tokens:ses_simple','tokens:ses_late'))`,
		models.ToolCrush).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("org_push_changes queued %d of the 2 changed rows", n)
	}

	// Idempotent: a third parse of the unchanged store changes nothing.
	third, err := a.ParseSessionFile(ctx, dbPath, 0)
	if err != nil {
		t.Fatalf("parse3: %v", err)
	}
	ingest(&third)
	if got := loadCrushTokenRow(t, nodeDB, "ses_simple"); got.rel != models.ReliabilityUnknown || got.in != 0 {
		t.Errorf("after full re-parse = %+v, want unchanged unknown 0/0", got)
	}
}
