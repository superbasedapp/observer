package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// wantWatcherRows derives the expected §6.5 watcher-row count from the
// live default adapter roster instead of a literal that goes stale
// every time an adapter joins EnabledAdapters (it has moved at least
// three times: 37 -> 38 -> ...). Every enabled adapter gets a watcher
// row except the *-web browser-extension rows (browserchat capture is
// native-messaging, not a watched local store — no watcher channel).
func wantWatcherRows() int {
	n := 0
	for _, tool := range config.Default().Observer.Watch.EnabledAdapters {
		if !strings.HasSuffix(tool, "-web") {
			n++
		}
	}
	return n
}

// wantBlockerRows derives the expected §6.5 block-capable channel count
// from the same guard.ConformanceMatrix() the endpoint serves, rather
// than a literal that goes stale every time a block-capable hook lane
// joins the matrix (it has moved from 4 — claude-code PreToolUse +
// cursor before×3 — to include the whole prompt-submit intervention
// set: UserPromptSubmit / beforeSubmitPrompt / BeforeAgent /
// transformInput / pre_user_prompt across many clients). The check
// still pins that every CanBlock channel survives the handler's copy
// and the JSON round-trip.
func wantBlockerRows() int {
	n := 0
	for _, e := range guard.ConformanceMatrix() {
		if e.Caps.CanBlock {
			n++
		}
	}
	return n
}

// seedGuardEvents writes three verdict rows through the one-owner
// store helper: two recent (one enforced deny), one old.
func seedGuardEvents(t *testing.T, s *Server) {
	t.Helper()
	st := store.New(s.opts.DB)
	now := time.Now().UTC()
	rows := []store.GuardEventRow{
		{
			TS: now.Add(-10 * time.Minute), SessionID: "sA", Tool: "claude-code",
			EventKind: "shell_exec", RuleID: "R-101", Category: "destructive",
			Severity: "critical", Decision: "flag", Source: "builtin",
			Reason: "rm -rf targeting home", TargetHash: "h1", TargetExcerpt: "rm -rf ~",
		},
		{
			TS: now.Add(-5 * time.Minute), SessionID: "sA", Tool: "cursor",
			EventKind: "shell_exec", RuleID: "R-110", Category: "destructive",
			Severity: "critical", Decision: "deny", Enforced: true, Source: "builtin",
			Reason: "force push to protected branch", TargetHash: "h2", TargetExcerpt: "git push -f origin main",
		},
		{
			TS: now.Add(-72 * time.Hour), SessionID: "sB", Tool: "claude-code",
			EventKind: "file_access", RuleID: "R-152", Category: "boundary",
			Severity: "high", Decision: "flag", Source: "builtin",
			Reason: "sensitive read", TargetHash: "h3", TargetExcerpt: "~/.ssh/id_rsa",
		},
	}
	if _, err := st.InsertGuardEvents(context.Background(), rows); err != nil {
		t.Fatalf("seed guard events: %v", err)
	}
}

// TestAPIGuardSummary pins the Security-page header endpoint: posture
// fields from Options, windowed counts, chain status.
func TestAPIGuardSummary(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	s.opts.GuardEnabled = true
	s.opts.GuardMode = "observe"
	seedGuardEvents(t, s)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/summary", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Enabled   bool   `json:"enabled"`
		Mode      string `json:"mode"`
		Counts24h struct {
			Total    int `json:"total"`
			Enforced int `json:"enforced"`
		} `json:"counts_24h"`
		Counts7d struct {
			Total int `json:"total"`
		} `json:"counts_7d"`
		Chain struct {
			OK      bool `json:"ok"`
			Checked int  `json:"checked"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled || resp.Mode != "observe" {
		t.Errorf("posture = %+v", resp)
	}
	if resp.Counts24h.Total != 2 || resp.Counts24h.Enforced != 1 {
		t.Errorf("24h counts = %+v, want 2 total / 1 enforced", resp.Counts24h)
	}
	if resp.Counts7d.Total != 3 {
		t.Errorf("7d total = %d, want 3", resp.Counts7d.Total)
	}
	if !resp.Chain.OK || resp.Chain.Checked != 3 {
		t.Errorf("chain = %+v, want OK across 3", resp.Chain)
	}
}

// TestAPIGuardRules pins the rule-catalog endpoint the Security page
// uses to resolve a verdict's bare rule_id into its definition: every
// row carries id/category/severity/decisions/doc, and the catalog
// includes the known built-ins (R-151 spot-checked with its doc).
func TestAPIGuardRules(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/rules", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Rules []struct {
			ID       string `json:"id"`
			Category string `json:"category"`
			Severity string `json:"severity"`
			Observe  string `json:"observe"`
			Enforce  string `json:"enforce"`
			Doc      string `json:"doc"`
			Advice   string `json:"advice"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rules) < 40 {
		t.Fatalf("catalog rows = %d, want the full built-in table (>= 40)", len(resp.Rules))
	}
	var found bool
	for _, r := range resp.Rules {
		if r.Doc == "" {
			t.Errorf("rule %s has empty doc — the definition is the endpoint's whole point", r.ID)
		}
		if r.ID == "R-151" {
			found = true
			if r.Category != "boundary" || r.Severity != "high" {
				t.Errorf("R-151 = %+v, want boundary/high", r)
			}
			if !strings.Contains(r.Doc, "cross-project") {
				t.Errorf("R-151 doc = %q, want the cross-project-bleed definition", r.Doc)
			}
			if r.Advice == "" {
				t.Errorf("R-151 advice empty, want the remediation hint")
			}
		}
	}
	if !found {
		t.Errorf("R-151 missing from the catalog")
	}
}

// TestAPIGuardEvents pins the timeline endpoint: window + filters.
func TestAPIGuardEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	seedGuardEvents(t, s)

	get := func(query string) []map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/events"+query, nil))
		if rec.Code != 200 {
			t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return resp.Events
	}

	if evs := get("?hours=24"); len(evs) != 2 {
		t.Errorf("24h window = %d events, want 2", len(evs))
	}
	if evs := get("?hours=168"); len(evs) != 3 {
		t.Errorf("7d window = %d events, want 3", len(evs))
	}
	evs := get("?hours=168&decision=deny")
	if len(evs) != 1 || evs[0]["rule_id"] != "R-110" || evs[0]["enforced"] != true {
		t.Errorf("decision filter = %+v, want the one enforced R-110", evs)
	}
	if evs := get("?hours=168&tool=cursor"); len(evs) != 1 {
		t.Errorf("tool filter = %d events, want 1", len(evs))
	}
	if evs := get("?hours=168&severity=high"); len(evs) != 1 {
		t.Errorf("severity filter = %d events, want 1", len(evs))
	}
}

// TestAPIGuardConformance pins the §6.5 matrix endpoint shape.
func TestAPIGuardConformance(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/conformance", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Entries []struct {
			Client   string `json:"client"`
			Channel  string `json:"channel"`
			CanBlock bool   `json:"can_block"`
			Notes    string `json:"notes"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var blockers, watchers int
	for _, e := range resp.Entries {
		if e.CanBlock {
			blockers++
		}
		if e.Channel == "watcher" {
			watchers++
		}
		if e.Notes == "" {
			t.Errorf("%s/%s missing notes", e.Client, e.Channel)
		}
	}
	if want := wantBlockerRows(); blockers != want {
		t.Errorf("block-capable channels = %d, want %d (every guard.ConformanceMatrix CanBlock channel: claude-code PreToolUse + cursor before×3 + the prompt-submit intervention lanes)", blockers, want)
	}
	if want := wantWatcherRows(); watchers != want {
		t.Errorf("watcher rows = %d, want %d (every enabled non-browser adapter: %d EnabledAdapters minus the *-web browser-extension rows)", watchers, want, len(config.Default().Observer.Watch.EnabledAdapters))
	}
}

// TestAPIGuardSimulate pins the G1.2 pre-enforce evidence endpoint: a
// seeded destructive action replays through a fresh engine, the
// enforce projection counts it as would-block, and nothing persists
// (guard_events stays empty — simulate is a dry run by construction).
func TestAPIGuardSimulate(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	pid, err := st.UpsertProject(ctx, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "sim1", ProjectID: pid, Tool: "claude-code", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertActions(ctx, []models.Action{{
		Tool: "claude-code", SessionID: "sim1", ProjectID: pid,
		ActionType: "run_command", Target: "rm -rf ~/",
		Timestamp:  time.Now().UTC().Add(-time.Hour),
		SourceFile: "f", SourceEventID: "sim-e1",
	}}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/simulate?hours=24&enforce=1", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Mode           string         `json:"mode"`
		Scanned        int            `json:"scanned"`
		Verdicts       int            `json:"verdicts"`
		WouldBlock     int            `json:"would_block"`
		ByRule         map[string]int `json:"by_rule"`
		ByRuleBlocking map[string]int `json:"by_rule_blocking"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Mode != "enforce" {
		t.Errorf("mode = %q, want the enforce projection", resp.Mode)
	}
	if resp.Scanned < 1 || resp.Verdicts < 1 {
		t.Errorf("scanned=%d verdicts=%d, want the seeded action judged", resp.Scanned, resp.Verdicts)
	}
	if resp.ByRule["R-101"] < 1 {
		t.Errorf("by_rule = %+v, want R-101 (rm -rf) present", resp.ByRule)
	}
	if resp.WouldBlock < 1 {
		t.Errorf("would_block = %d, want >= 1 in the enforce projection", resp.WouldBlock)
	}
	// G2.1: the blocking split carries only deny/ask-class verdicts
	// and must sum to would_block exactly.
	if resp.ByRuleBlocking["R-101"] < 1 {
		t.Errorf("by_rule_blocking = %+v, want R-101 present", resp.ByRuleBlocking)
	}
	blockSum := 0
	for _, n := range resp.ByRuleBlocking {
		blockSum += n
	}
	if blockSum != resp.WouldBlock {
		t.Errorf("by_rule_blocking sums to %d, want would_block = %d", blockSum, resp.WouldBlock)
	}
	// Dry run: nothing persisted.
	sum, err := st.SummarizeGuardEvents(ctx, time.Now().UTC().Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if sum.Total != 0 {
		t.Errorf("simulate persisted %d guard events — must persist none", sum.Total)
	}
}

// TestAPIGuardBudget pins the G2.4 budget basis endpoint: configured
// thresholds ride the on-disk config, today's spend + the observed
// distribution come from the enforcement substrate (api_turns here),
// and the MAX-of-substrates dedup carries through.
func TestAPIGuardBudget(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	// Keep the seeded turn after today's UTC midnight regardless of
	// when the test runs — spend_today is computed from that boundary.
	now := time.Now().UTC()
	seedTS := now.Add(-time.Hour)
	if dayStart := now.Truncate(24 * time.Hour); seedTS.Before(dayStart) {
		seedTS = dayStart.Add(time.Minute)
	}
	if _, err := st.InsertAPITurn(ctx, models.APITurn{
		SessionID: "bud1", Provider: models.ProviderAnthropic, Model: "claude-x",
		InputTokens: 10, OutputTokens: 10, CostUSD: 2.5,
		Timestamp: seedTS, RequestID: "msg_bud_1",
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/budget", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		SessionUSD    float64 `json:"session_usd"`
		DailyUSD      float64 `json:"daily_usd"`
		SpendToday    float64 `json:"spend_today_usd"`
		WindowDays    int     `json:"window_days"`
		Sessions      int     `json:"sessions"`
		SessionP95USD float64 `json:"session_p95_usd"`
		DailyP95USD   float64 `json:"daily_p95_usd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.SessionUSD != 0 || resp.DailyUSD != 0 {
		t.Errorf("thresholds = %v/%v, want 0/0 (defaults: budgets off)", resp.SessionUSD, resp.DailyUSD)
	}
	if resp.WindowDays != 30 || resp.Sessions < 1 {
		t.Errorf("window=%d sessions=%d, want 30-day window with the seeded session counted", resp.WindowDays, resp.Sessions)
	}
	if resp.SpendToday < 2.5-1e-9 {
		t.Errorf("spend_today = %.4f, want >= 2.50 (the seeded turn)", resp.SpendToday)
	}
	if resp.SessionP95USD < 2.5-1e-9 || resp.DailyP95USD < 2.5-1e-9 {
		t.Errorf("p95 session/daily = %.4f/%.4f, want >= 2.50", resp.SessionP95USD, resp.DailyP95USD)
	}
}

// TestAPIGuardApprovals pins the G1.3 exception register: grant
// (session + project scopes), list, revoke — through the same store
// seams the CLI uses — plus the validation 400s.
func TestAPIGuardApprovals(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	root := t.TempDir()
	pid, err := st.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{
		ID: "apprv1", ProjectID: pid, Tool: "claude-code", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	do := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Grant: session scope with TTL.
	rec := do("POST", "/api/guard/approvals",
		`{"rule_id":"R-151","scope":"session","session_id":"apprv1","ttl_hours":24}`)
	if rec.Code != 200 {
		t.Fatalf("POST session grant: %d %s", rec.Code, rec.Body.String())
	}
	var granted struct {
		ID        int64  `json:"id"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &granted); err != nil {
		t.Fatal(err)
	}
	if granted.ID <= 0 || granted.ExpiresAt == "" {
		t.Errorf("grant = %+v, want id + expiry", granted)
	}

	// Grant: project scope resolves the session's root to a HASH.
	rec = do("POST", "/api/guard/approvals",
		`{"rule_id":"R-151","scope":"project","session_id":"apprv1","ttl_hours":0}`)
	if rec.Code != 200 {
		t.Fatalf("POST project grant: %d %s", rec.Code, rec.Body.String())
	}

	// List: both grants, project row carries hash never the path.
	rec = do("GET", "/api/guard/approvals", "")
	var list struct {
		Approvals []struct {
			ID              int64  `json:"id"`
			Scope           string `json:"scope"`
			ProjectRootHash string `json:"project_root_hash"`
		} `json:"approvals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Approvals) != 2 {
		t.Fatalf("approvals = %d, want 2", len(list.Approvals))
	}
	for _, a := range list.Approvals {
		if a.Scope == "project" {
			if a.ProjectRootHash == "" || strings.Contains(a.ProjectRootHash, string(root[0])+":") {
				t.Errorf("project anchor = %q, want a hash, never the raw path", a.ProjectRootHash)
			}
		}
	}

	// Revoke the first, list drops to 1.
	rec = do("DELETE", "/api/guard/approvals/"+strconv.FormatInt(granted.ID, 10), "")
	if rec.Code != 200 {
		t.Fatalf("DELETE: %d %s", rec.Code, rec.Body.String())
	}
	rec = do("GET", "/api/guard/approvals", "")
	list.Approvals = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Approvals) != 1 {
		t.Errorf("post-revoke approvals = %d, want 1", len(list.Approvals))
	}

	// Validation 400s.
	for _, bad := range []string{
		`{"scope":"global"}`,                                         // no rule_id
		`{"rule_id":"R-151","scope":"everywhere"}`,                   // bad scope
		`{"rule_id":"R-151","scope":"session"}`,                      // session scope, no id
		`{"rule_id":"R-151","scope":"project","session_id":"ghost"}`, // unresolvable project
	} {
		if rec := do("POST", "/api/guard/approvals", bad); rec.Code != 400 {
			t.Errorf("body %s → %d, want 400", bad, rec.Code)
		}
	}
	// Unknown id revoke → 404.
	if rec := do("DELETE", "/api/guard/approvals/99999", ""); rec.Code != 404 {
		t.Errorf("revoke unknown id → %d, want 404", rec.Code)
	}
}

// TestAPIGuardMCP pins the G1.6 MCP panel: a seeded pin row surfaces
// in the inventory (as a pinned-but-absent orphan — the test box's
// real client configs may add present rows, which is fine), and the
// approve endpoint transitions its status through the same store
// helper the CLI uses.
func TestAPIGuardMCP(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.UpsertGuardPin(ctx, store.GuardPinRow{
		Kind: "mcp_server", Name: "test-srv-zz", Client: "claude-code",
		PinHash: "", FirstSeen: now, LastVerified: now, Status: "unpinned",
	}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/mcp", nil))
	if rec.Code != 200 {
		t.Fatalf("GET mcp: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Servers []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Present bool   `json:"present"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sv := range resp.Servers {
		if sv.Name == "test-srv-zz" {
			found = true
			if sv.Status != "unpinned" || sv.Present {
				t.Errorf("seeded pin = %+v, want unpinned + absent", sv)
			}
		}
	}
	if !found {
		t.Fatalf("seeded pin missing from inventory: %+v", resp.Servers)
	}

	// Approve → status transitions.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/guard/mcp/approve",
		strings.NewReader(`{"server":"test-srv-zz","client":"claude-code"}`)))
	if rec.Code != 200 {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	pins, err := st.LoadGuardPins(ctx, "mcp_server")
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, p := range pins {
		if p.Name == "test-srv-zz" && p.Status == "approved" {
			ok = true
		}
	}
	if !ok {
		t.Errorf("pin not approved: %+v", pins)
	}

	// Unknown server → 404.
	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/api/guard/mcp/approve",
		strings.NewReader(`{"server":"ghost"}`)))
	if rec.Code != 404 {
		t.Errorf("approve unknown server → %d, want 404", rec.Code)
	}
}
