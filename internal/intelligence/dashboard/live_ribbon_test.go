package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
)

// ribbonGet serves one GET /api/live?view=ribbon and decodes it.
func ribbonGet(t *testing.T, server *Server) (ribbonResponse, string) {
	t.Helper()
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/live?view=ribbon", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	raw := rr.Body.String()
	var got ribbonResponse
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatal(err)
	}
	return got, raw
}

// seedRibbonSession inserts a session (project root /work/<project>) with
// one action at `last`.
func seedRibbonSession(t *testing.T, server *Server, id, tool, project string, started, last time.Time) {
	t.Helper()
	root := "/work/" + project
	mustExec(t, server, `INSERT INTO projects (root_path, name, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
		root, project, started.UTC().Format(time.RFC3339Nano))
	mustExec(t, server, `INSERT INTO sessions (id, project_id, tool, started_at)
		VALUES (?, (SELECT id FROM projects WHERE root_path = ?), ?, ?)`,
		id, root, tool, started.UTC().Format(time.RFC3339Nano))
	mustExec(t, server, `INSERT INTO actions (session_id, project_id, tool, timestamp, action_type, target, success)
		VALUES (?, (SELECT id FROM projects WHERE root_path = ?), ?, ?, 'read_file', '/work/secret/auth.ts', 1)`,
		id, root, tool, last.UTC().Format(time.RFC3339Nano))
}

func mustExec(t *testing.T, server *Server, q string, args ...any) {
	t.Helper()
	if _, err := server.opts.DB.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

// TestLiveRibbonRead pins the ribbon read: newest first, project NAME only
// (no path, no action, no target anywhere in the body), the cost basis flags
// per session, the no-token tool, the active count, and the off switch.
func TestLiveRibbonRead(t *testing.T) {
	server, _ := wizardTestServer(t)
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }

	// recorded: one proxy turn with a recorded cost.
	seedRibbonSession(t, server, "rb-recorded", "claude-code", "app", now.Add(-20*time.Minute), now.Add(-3*time.Minute))
	mustExec(t, server, `INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd)
		VALUES ('rb-recorded', ?, 'anthropic', 'claude-opus-4-8', 'req-r', 1000, 200, 5000, 300, 0.25)`, ts(-2*time.Minute))
	// estimated: a transcript row priced from the table.
	seedRibbonSession(t, server, "rb-estimated", "codex", "api", now.Add(-10*time.Minute), now.Add(-90*time.Second))
	mustExec(t, server, `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
		cache_read_tokens, cache_creation_tokens, source, source_file, source_event_id)
		VALUES ('rb-estimated', ?, 'codex', 'claude-opus-4-8', 100, 10, 0, 0, 'jsonl', 'f', 'e1')`, ts(-80*time.Second))
	// unpriced: a model no table knows.
	seedRibbonSession(t, server, "rb-unpriced", "claude-code", "lab", now.Add(-5*time.Minute), now.Add(-30*time.Second))
	mustExec(t, server, `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
		cache_read_tokens, cache_creation_tokens, source, source_file, source_event_id)
		VALUES ('rb-unpriced', ?, 'claude-code', 'nobody-knows-this-model-9', 40, 4, 0, 0, 'jsonl', 'f', 'e2')`, ts(-20*time.Second))
	// a tool that keeps no tokens locally, actions only.
	seedRibbonSession(t, server, "rb-notokens", "qoder", "docs", now.Add(-4*time.Minute), now.Add(-10*time.Second))
	// stale: outside the window.
	seedRibbonSession(t, server, "rb-stale", "cursor", "old", now.Add(-3*time.Hour), now.Add(-2*time.Hour))

	got, raw := ribbonGet(t, server)
	if !got.Enabled || got.View != "ribbon" || got.WindowMinutes != 15 {
		t.Fatalf("header: %+v", got)
	}
	if got.ActiveCount != 4 || len(got.Sessions) != 4 {
		t.Fatalf("active_count=%d sessions=%d, want 4/4", got.ActiveCount, len(got.Sessions))
	}
	wantOrder := []string{"rb-notokens", "rb-unpriced", "rb-estimated", "rb-recorded"}
	byID := map[string]ribbonSession{}
	for i, rs := range got.Sessions {
		if rs.SessionID != wantOrder[i] {
			t.Fatalf("order[%d] = %s, want %s", i, rs.SessionID, wantOrder[i])
		}
		byID[rs.SessionID] = rs
	}
	for _, forbidden := range []string{"/work", "auth.ts", "recent_actions", "target", "project_root"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("ribbon body carries %q: %s", forbidden, raw)
		}
	}
	cases := []struct {
		id                           string
		project                      string
		estimated, recorded, unknown bool
		turns, tokens                int64
	}{
		{"rb-recorded", "app", false, true, false, 1, 6500},
		{"rb-estimated", "api", true, true, false, 1, 110},
		{"rb-unpriced", "lab", false, true, true, 1, 44},
		{"rb-notokens", "docs", false, false, false, 0, 0},
	}
	for _, c := range cases {
		rs := byID[c.id]
		if rs.Project != c.project || rs.CostEstimated != c.estimated || rs.CostRecorded != c.recorded ||
			rs.PriceUnknown != c.unknown || rs.Turns != c.turns || rs.Tokens != c.tokens {
			t.Errorf("%s: %+v, want project=%s est=%v rec=%v unknown=%v turns=%d tokens=%d",
				c.id, rs, c.project, c.estimated, c.recorded, c.unknown, c.turns, c.tokens)
		}
	}
	if rs := byID["rb-recorded"]; rs.CostUSD < 0.249 || rs.CostUSD > 0.251 || rs.Model != "claude-opus-4-8" || rs.ModelCount != 1 {
		t.Errorf("recorded cost/model: %+v", rs)
	}
	if rs := byID["rb-unpriced"]; rs.CostUSD != 0 {
		t.Errorf("unpriced cost must add nothing: %+v", rs)
	}
	if rs := byID["rb-notokens"]; rs.ActionsTotal != 1 {
		t.Errorf("no-token session actions: %+v", rs)
	}

	// The default /api/live shape is unchanged by the ribbon mode.
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/live", nil))
	if !strings.Contains(rr.Body.String(), `"active":[`) || !strings.Contains(rr.Body.String(), `"recent_actions"`) {
		t.Errorf("default /api/live shape changed: %s", rr.Body.String())
	}

	// Off: the switch is read live from the config file, and no sessions are read.
	if err := os.WriteFile(server.opts.ConfigPath, []byte("[dashboard]\nlive_ribbon = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	off, _ := ribbonGet(t, server)
	if off.Enabled || len(off.Sessions) != 0 || off.ActiveCount != 0 {
		t.Fatalf("off: %+v", off)
	}
}

// TestLiveRibbonQueryStartsFromTimestamps pins the index finding: each arm of
// the active-session CTE is a range search on its table's timestamp index,
// and sessions is reached by key, never scanned.
func TestLiveRibbonQueryStartsFromTimestamps(t *testing.T) {
	server, _ := wizardTestServer(t)
	rows, err := server.opts.DB.Query(`EXPLAIN QUERY PLAN `+ribbonQuery, "x", "x", "x", ribbonLimit)
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
	joined := strings.Join(plan, "\n")
	for _, want := range []string{
		"SEARCH actions USING COVERING INDEX idx_actions_ts_cover (timestamp>?)",
		"SEARCH api_turns USING INDEX idx_api_turns_timestamp (timestamp>?)",
		"SEARCH token_usage USING INDEX idx_token_usage_timestamp (timestamp>?)",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan lacks %q:\n%s", want, joined)
		}
	}
	for _, line := range plan {
		if strings.HasPrefix(line, "SCAN s") && !strings.Contains(line, "USING") {
			t.Errorf("plan scans sessions: %q\n%s", line, joined)
		}
	}
}

// TestCostBasisRules is one case per row of costBasisRules.
func TestCostBasisRules(t *testing.T) {
	cases := []struct {
		name string
		turn dashapi.SpendTurn
		want costBasis
	}{
		{"unpriced", dashapi.SpendTurn{Priced: false, Source: "jsonl"}, basisUnpriced},
		{"proxy recorded", dashapi.SpendTurn{Priced: true, Source: "proxy", Recorded: 0.1}, basisRecorded},
		{"proxy priced from the table", dashapi.SpendTurn{Priced: true, Source: "proxy"}, basisEstimated},
		{"transcript with its own estimate", dashapi.SpendTurn{Priced: true, Source: "jsonl", Recorded: 0.1}, basisEstimated},
	}
	if len(cases) < len(costBasisRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(costBasisRules))
	}
	for _, c := range cases {
		if got := turnCostBasis(c.turn); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

// TestReceiptRules is one case per row of receiptRules.
func TestReceiptRules(t *testing.T) {
	cases := []struct {
		name string
		f    receiptFacts
		want receiptStep
	}{
		{"no state file", receiptFacts{stateless: true}, receiptNone},
		{"dismissed", receiptFacts{dismissed: true, armed: true, fired: true}, receiptNone},
		{"first read arms", receiptFacts{}, receiptArm},
		{"armed looks for a session", receiptFacts{armed: true}, receiptTryFire},
		{"fired long ago is retired", receiptFacts{armed: true, fired: true, stale: true}, receiptNone},
		{"fired shows", receiptFacts{armed: true, fired: true}, receiptShow},
	}
	if len(cases) != len(receiptRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(receiptRules))
	}
	for _, c := range cases {
		if got := receiptStepFor(c.f); got != c.want {
			t.Errorf("%s: got %d want %d", c.name, got, c.want)
		}
	}
}

// TestProjectName: the folder's last element for either separator, the
// stored name only when there is no root.
func TestProjectName(t *testing.T) {
	cases := []struct{ root, name, want string }{
		{"/home/me/code/app", "x", "app"},
		{"/home/me/code/app/", "", "app"},
		{`C:\Users\me\code\api`, "", "api"},
		{"", "named", "named"},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := projectName(c.root, c.name); got != c.want {
			t.Errorf("projectName(%q,%q) = %q want %q", c.root, c.name, got, c.want)
		}
	}
}

// TestLiveRibbonReceipt walks the first-prompt receipt end to end: the first
// read arms it, a session that started BEFORE the arm never fires it, the
// first new session with a turn fires it once with its counts, later reads
// show the same snapshot, a dismissal ends it, and demo data never shows it.
func TestLiveRibbonReceipt(t *testing.T) {
	server, _ := wizardTestServer(t)
	server.opts.DBPath = filepath.Join(t.TempDir(), "observer.db")
	now := time.Now().UTC()

	// An old session, live now, that started before the first visit.
	seedRibbonSession(t, server, "rc-old", "claude-code", "app", now.Add(-time.Hour), now.Add(-time.Minute))
	mustExec(t, server, `INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens, cost_usd) VALUES ('rc-old', ?, 'anthropic', 'claude-opus-4-8', 'r0', 10, 1, 0.01)`,
		now.Add(-time.Minute).Format(time.RFC3339Nano))

	first, _ := ribbonGet(t, server)
	if first.Receipt != nil {
		t.Fatalf("first read showed a receipt: %+v", first.Receipt)
	}
	st := server.firstRunState().Load()
	if st.Receipt == nil || st.Receipt.FiredAt != nil {
		t.Fatalf("first read did not arm: %+v", st.Receipt)
	}
	if again, _ := ribbonGet(t, server); again.Receipt != nil {
		t.Fatalf("a pre-arm session fired the receipt: %+v", again.Receipt)
	}

	// A new session, started after the arm: no turn yet, then one turn.
	started := st.Receipt.ArmedAt.Add(time.Second)
	seedRibbonSession(t, server, "rc-new", "claude-code", "app", started, started.Add(time.Second))
	if r, _ := ribbonGet(t, server); r.Receipt != nil {
		t.Fatalf("fired before the first turn: %+v", r.Receipt)
	}
	mustExec(t, server, `INSERT INTO actions (session_id, project_id, tool, timestamp, action_type, target, success)
		VALUES ('rc-new', (SELECT id FROM projects WHERE root_path = '/work/app'), 'claude-code', ?, 'run_command', 'go test', 1)`, started.Add(2*time.Second).Format(time.RFC3339Nano))
	mustExec(t, server, `INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens, cost_usd) VALUES ('rc-new', ?, 'anthropic', 'claude-opus-4-8', 'r1', 18000, 200, 0.06)`,
		started.Add(3*time.Second).Format(time.RFC3339Nano))
	fired, raw := ribbonGet(t, server)
	rec := fired.Receipt
	if rec == nil || rec.SessionID != "rc-new" || rec.Tokens != 18200 || rec.FilesRead != 1 || rec.Commands != 1 ||
		rec.CostEstimated || rec.Project != "app" || rec.FiredAt == "" {
		t.Fatalf("fired receipt: %+v", rec)
	}
	if strings.Contains(raw, "go test") {
		t.Fatalf("receipt carries a command: %s", raw)
	}

	// More activity later does not change the snapshot.
	mustExec(t, server, `INSERT INTO api_turns (session_id, timestamp, provider, model, request_id,
		input_tokens, output_tokens, cost_usd) VALUES ('rc-new', ?, 'anthropic', 'claude-opus-4-8', 'r2', 50000, 500, 0.5)`,
		started.Add(4*time.Second).Format(time.RFC3339Nano))
	if later, _ := ribbonGet(t, server); later.Receipt == nil || later.Receipt.Tokens != 18200 {
		t.Fatalf("later read: %+v", later.Receipt)
	}

	// Demo data never shows it.
	server.demoDB.Store(server.opts.DB)
	if demo, _ := ribbonGet(t, server); demo.Receipt != nil {
		t.Fatalf("demo showed the receipt: %+v", demo.Receipt)
	}
	server.demoDB.Store(nil)

	// Dismissed: done for good.
	if _, err := server.firstRunState().Dismiss(ribbonReceiptKey, now); err != nil {
		t.Fatal(err)
	}
	if done, _ := ribbonGet(t, server); done.Receipt != nil {
		t.Fatalf("dismissed receipt still shown: %+v", done.Receipt)
	}
	if !uiDismissKeys[ribbonReceiptKey] {
		t.Fatal("the receipt key is not an accepted dismissal")
	}
	_ = firstrunstate.Filename
}
