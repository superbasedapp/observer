package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestEnsureOwnAgentSession(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		id, agent string
		wantErr   bool
	}{
		{"creates the session", "ca-aaa", "bot", false},
		{"second call is a no-op", "ca-aaa", "bot", false},
		{"missing agent", "ca-bbb", "", true},
		{"missing id", "", "bot", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.EnsureOwnAgentSession(ctx, tc.id, tc.agent, "[custom-agent]", "claude-sonnet-4", t0)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
	var tool, surface, host string
	if err := db.QueryRowContext(ctx, `SELECT tool, surface, surface_host FROM sessions WHERE id = 'ca-aaa'`).Scan(&tool, &surface, &host); err != nil {
		t.Fatal(err)
	}
	if tool != models.ToolCustomAgent || surface != "sdk" || host != "agent:bot" {
		t.Fatalf("row = %q %q %q", tool, surface, host)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id = 'ca-aaa'`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows = %d", n)
	}

	// A row of another tool under the id is refused, never restamped.
	if _, err := s.EnsureCaptureSession(ctx, "ca-ccc", models.ToolClaudeCode, "/p", "", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureOwnAgentSession(ctx, "ca-ccc", "bot", "[custom-agent]", "", t0); err == nil {
		t.Fatal("restamped another tool's session")
	}
}

func TestListOwnAgents(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		id, agent string
		at        time.Duration
	}{
		{"ca-1", "alpha", 0},
		{"ca-2", "alpha", time.Hour},
		{"ca-3", "beta", 2 * time.Hour},
	} {
		if err := s.EnsureOwnAgentSession(ctx, c.id, c.agent, "[custom-agent]", "m", t0.Add(c.at)); err != nil {
			t.Fatal(err)
		}
	}
	for i, sid := range []string{"ca-1", "ca-2", "ca-2"} {
		if _, err := s.InsertAPITurn(ctx, models.APITurn{
			SessionID: sid, Timestamp: t0.Add(time.Duration(i) * time.Minute), Provider: models.ProviderAnthropic,
			Model: "m", InputTokens: 10, OutputTokens: 2, CostUSD: 0.5,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A coding tool's session never shows up.
	if _, err := s.EnsureCaptureSession(ctx, "cc-1", models.ToolClaudeCode, "/p", "", t0); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListOwnAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("agents = %+v", got)
	}
	want := map[string]OwnAgentSummary{
		"alpha": {Agent: "alpha", SurfaceHost: "agent:alpha", Sessions: 2, Turns: 3, InputTokens: 30, OutputTokens: 6, CostUSD: 1.5, Via: OwnAgentViaProxy},
		"beta":  {Agent: "beta", SurfaceHost: "agent:beta", Sessions: 1, Via: OwnAgentViaProxy},
	}
	for _, a := range got {
		w := want[a.Agent]
		a.LastSeen = ""
		if a != w {
			t.Errorf("agent %s = %+v, want %+v", w.Agent, a, w)
		}
	}
	if got[0].Agent != "beta" {
		t.Errorf("order: want the most recently active first, got %q", got[0].Agent)
	}
}

// TestEnsureOwnAgentSessionFillsModelLater (fix round 2, N4): a session
// whose first turn carried no model takes the model of the first later call
// that names one, and a stored model is never replaced.
func TestEnsureOwnAgentSessionFillsModelLater(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	model := func() string {
		var m sql.NullString
		if err := db.QueryRowContext(ctx, `SELECT model FROM sessions WHERE id = 'ca-m'`).Scan(&m); err != nil {
			t.Fatal(err)
		}
		return m.String
	}
	for _, step := range []struct {
		model, want string
	}{
		{"", ""},
		{"claude-sonnet-4", "claude-sonnet-4"},
		{"claude-opus-4", "claude-sonnet-4"},
		{"", "claude-sonnet-4"},
	} {
		if err := s.EnsureOwnAgentSession(ctx, "ca-m", "bot", "[custom-agent]", step.model, t0); err != nil {
			t.Fatal(err)
		}
		if got := model(); got != step.want {
			t.Fatalf("after ensure with %q: model = %q, want %q", step.model, got, step.want)
		}
	}
}

// TestOwnAgentVia pins the Own agents view's source label (PT-55): one row
// per path combination.
func TestOwnAgentVia(t *testing.T) {
	for _, tc := range []struct {
		proxy, otlp int64
		want        string
	}{
		{0, 0, OwnAgentViaProxy},
		{3, 0, OwnAgentViaProxy},
		{0, 2, OwnAgentViaOTLP},
		{1, 1, OwnAgentViaBoth},
	} {
		if got := ownAgentVia(tc.proxy, tc.otlp); got != tc.want {
			t.Errorf("ownAgentVia(%d, %d) = %q, want %q", tc.proxy, tc.otlp, got, tc.want)
		}
	}
}

// TestListOwnAgentsViaLabel: an agent seen only through spans (a span turn,
// or only a span tool call) reads "otlp", one seen both ways reads
// "proxy+otlp".
func TestListOwnAgentsViaLabel(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	for _, a := range []string{"spans", "both", "toolonly"} {
		if err := s.EnsureOwnAgentSession(ctx, "ca-"+a, a, "[custom-agent]", "m", t0); err != nil {
			t.Fatal(err)
		}
	}
	turn := func(sid, req, src string) {
		if _, err := s.InsertAPITurn(ctx, models.APITurn{SessionID: sid, Timestamp: t0, Provider: "openai", Model: "m", RequestID: req, OutputTokens: 1, Source: src}); err != nil {
			t.Fatal(err)
		}
	}
	turn("ca-spans", "r1", SourceAgentOTel)
	turn("ca-both", "r2", SourceProxy)
	turn("ca-both", "r3", SourceAgentOTel)
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "otlp:" + models.ToolCustomAgent, SourceEventID: "call-1", SessionID: "ca-toolonly",
		ProjectRoot: "[custom-agent]", Timestamp: t0, Tool: models.ToolCustomAgent, ActionType: models.ActionUnknown,
		RawToolName: "list_files", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListOwnAgents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"spans": OwnAgentViaOTLP, "both": OwnAgentViaBoth, "toolonly": OwnAgentViaOTLP}
	if len(got) != len(want) {
		t.Fatalf("agents = %+v", got)
	}
	for _, a := range got {
		if a.Via != want[a.Agent] {
			t.Errorf("%s via = %q, want %q", a.Agent, a.Via, want[a.Agent])
		}
	}
}

// TestAgentOTelRanksBelowProxy (PT-55 scope 3): an own agent's span turn is
// approximate; it keeps its own source label through a merge, a proxy row
// for the same request id is never changed by it, its stated cost is never
// re-priced, and a proxy insert for the same request id replaces it.
func TestAgentOTelRanksBelowProxy(t *testing.T) {
	if fidelityForSource(SourceAgentOTel) >= fidelityForSource(SourceProxy) {
		t.Fatalf("agent_otel must rank below the proxy")
	}
	if !apiTurnCostIsSourceReported(SourceAgentOTel) {
		t.Fatalf("an own agent's stated cost must never be re-priced")
	}
	s, db := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC)
	span := models.APITurn{
		SessionID: "ca-x", Timestamp: t0, Provider: "openai", Model: "m", RequestID: "chatcmpl-1",
		InputTokens: 1234, OutputTokens: 56, Source: SourceAgentOTel,
	}
	// Proxy first: the span merge changes nothing.
	proxy := span
	proxy.InputTokens, proxy.CacheReadTokens, proxy.Source = 234, 1000, SourceProxy
	if _, err := s.InsertAPITurn(ctx, proxy); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertTurnByRequestID(ctx, span); err != nil {
		t.Fatal(err)
	}
	var n int
	var in int64
	var src string
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(input_tokens), MAX(source) FROM api_turns WHERE request_id = 'chatcmpl-1'`).Scan(&n, &in, &src); err != nil {
		t.Fatal(err)
	}
	if n != 1 || in != 234 || src != SourceProxy {
		t.Fatalf("proxy first: rows=%d input=%d source=%q", n, in, src)
	}
	// Span first (re-delivered twice): one row labelled agent_otel, then
	// the proxy insert replaces it.
	span.RequestID = "chatcmpl-2"
	for range 2 {
		if _, _, err := s.UpsertTurnByRequestID(ctx, span); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(source) FROM api_turns WHERE request_id = 'chatcmpl-2'`).Scan(&n, &src); err != nil {
		t.Fatal(err)
	}
	if n != 1 || src != SourceAgentOTel {
		t.Fatalf("span first: rows=%d source=%q, want 1 agent_otel", n, src)
	}
	proxy.RequestID = "chatcmpl-2"
	if _, err := s.InsertAPITurn(ctx, proxy); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*), MAX(input_tokens), MAX(source) FROM api_turns WHERE request_id = 'chatcmpl-2'`).Scan(&n, &in, &src); err != nil {
		t.Fatal(err)
	}
	if n != 1 || in != 234 || src != SourceProxy {
		t.Fatalf("after the proxy insert: rows=%d input=%d source=%q, want the proxy's one row", n, in, src)
	}
	// Only a proxy insert supersedes: another source's insert for the
	// same id leaves an agent_otel row alone.
	span.RequestID = "chatcmpl-3"
	if _, _, err := s.UpsertTurnByRequestID(ctx, span); err != nil {
		t.Fatal(err)
	}
	other := span
	other.Source = SourceNativeOTel
	if _, err := s.InsertAPITurn(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM api_turns WHERE request_id = 'chatcmpl-3'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("a non-proxy insert superseded a span row: rows=%d", n)
	}
}

// spanTurn is an own agent's span turn for request id req.
func spanTurn(session, req string) models.APITurn {
	return models.APITurn{
		SessionID: session, Timestamp: time.Date(2026, 11, 3, 10, 0, 0, 0, time.UTC),
		Provider: "openai", Model: "m", RequestID: req, InputTokens: 1234, OutputTokens: 56, Source: SourceAgentOTel,
	}
}

// proxyTurnFor is the proxy's row for the same call (exact figures).
func proxyTurnFor(session, req string) models.APITurn {
	t := spanTurn(session, req)
	t.InputTokens, t.CacheReadTokens, t.Source = 234, 1000, SourceProxy
	return t
}

func countRequest(t *testing.T, db *sql.DB, req string) (n int, sources string) {
	t.Helper()
	if err := db.QueryRow(`SELECT COUNT(*), COALESCE(group_concat(COALESCE(source, ''), ','), '') FROM api_turns WHERE request_id = ?`, req).Scan(&n, &sources); err != nil {
		t.Fatal(err)
	}
	return n, sources
}

// TestOwnAgentSpanRaceWithProxy (sdk-2 fix round 1, M1): the interleaving
// in which the proxy writes the same call between the span's read and its
// insert (the proxy's own supersede then finds no span row to delete) must
// still leave ONE row, the proxy's. Forced with the mid hook; the generic
// request-id merge leaves two rows under the same interleaving, which the
// first subtest shows.
func TestOwnAgentSpanRaceWithProxy(t *testing.T) {
	ctx := context.Background()
	t.Run("the generic merge double counts", func(t *testing.T) {
		s, db := newTestStore(t)
		if err := s.EnsureOwnAgentSession(ctx, "ca-r", "bot", "[custom-agent]", "m", time.Now()); err != nil {
			t.Fatal(err)
		}
		// UpsertTurnByRequestID, step by step: its read finds nothing...
		if existing, err := s.loadMergeTurn(ctx, "req-race"); err != nil || existing != nil {
			t.Fatalf("read = %v, %v", existing, err)
		}
		// ...the proxy writes the call (its supersede finds no span row)...
		if _, err := s.InsertAPITurn(ctx, proxyTurnFor("ca-r", "req-race")); err != nil {
			t.Fatal(err)
		}
		// ...and the merge's insert lands a second row for the same call.
		if _, err := s.InsertAPITurn(ctx, spanTurn("ca-r", "req-race")); err != nil {
			t.Fatal(err)
		}
		if n, _ := countRequest(t, db, "req-race"); n != 2 {
			t.Fatalf("rows = %d: the interleaving no longer double counts on the generic path", n)
		}
	})
	t.Run("the own-agent seam does not", func(t *testing.T) {
		s, db := newTestStore(t)
		if err := s.EnsureOwnAgentSession(ctx, "ca-r", "bot", "[custom-agent]", "m", time.Now()); err != nil {
			t.Fatal(err)
		}
		orig := ownAgentSpanMidHook
		t.Cleanup(func() { ownAgentSpanMidHook = orig })
		ownAgentSpanMidHook = func() {
			if _, err := s.InsertAPITurn(ctx, proxyTurnFor("ca-r", "req-race")); err != nil {
				t.Error(err)
			}
		}
		got, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-r", "req-race"))
		if err != nil {
			t.Fatal(err)
		}
		if n, src := countRequest(t, db, "req-race"); n != 1 || src != SourceProxy || got != OwnAgentSpanSuperseded {
			t.Fatalf("rows = %d (%s), outcome %s: want only the proxy's row", n, src, got)
		}
	})
}

// TestOwnAgentSpanRaceConcurrent (M1, run under -race): the proxy and two
// copies of the same span write one call concurrently, many times; every
// call ends with exactly one row, and it is the proxy's.
func TestOwnAgentSpanRaceConcurrent(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if err := s.EnsureOwnAgentSession(ctx, "ca-c", "bot", "[custom-agent]", "m", time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		req := fmt.Sprintf("req-%d", i)
		var wg sync.WaitGroup
		start := make(chan struct{})
		run := func(f func() error) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				if err := f(); err != nil {
					t.Error(err)
				}
			}()
		}
		run(func() error { _, err := s.InsertAPITurn(ctx, proxyTurnFor("ca-c", req)); return err })
		for range 2 {
			run(func() error { _, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-c", req)); return err })
		}
		close(start)
		wg.Wait()
		if n, src := countRequest(t, db, req); n != 1 || src != SourceProxy {
			t.Fatalf("%s: rows = %d (%s), want one proxy row", req, n, src)
		}
	}
}

// TestOwnAgentSpanNeverTouchesOtherPlanes (sdk-2 fix round 1, L4): a span
// carrying the request id of another tool's row, or of a session-less row
// (a Plane A otlp_trace reconcile ranks the same as agent_otel), changes
// nothing and adds nothing; one carrying a custom-agent row's id merges into
// it; a span-only call inserts; a redelivery merges.
func TestOwnAgentSpanNeverTouchesOtherPlanes(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if err := s.EnsureOwnAgentSession(ctx, "ca-p", "bot", "[custom-agent]", "m", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureCaptureSession(ctx, "cc-p", models.ToolClaudeCode, "/p", "m", time.Now()); err != nil {
		t.Fatal(err)
	}
	other := spanTurn("cc-p", "req-cc")
	other.Source, other.InputTokens = SourceCCOTel, 10
	planeA := spanTurn("", "req-planea")
	planeA.Source, planeA.InputTokens = SourceObsOTLP, 10
	for _, row := range []models.APITurn{other, planeA} {
		if _, err := s.InsertAPITurn(ctx, row); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, req string
		want      OwnAgentSpanOutcome
		wantSrc   string
		wantInput int64
	}{
		{"another tool's row", "req-cc", OwnAgentSpanYielded, SourceCCOTel, 10},
		{"a Plane A row with no session, equally ranked", "req-planea", OwnAgentSpanYielded, SourceObsOTLP, 10},
		{"a span-only call", "req-own", OwnAgentSpanInserted, SourceAgentOTel, 1234},
		{"its redelivery", "req-own", OwnAgentSpanMerged, SourceAgentOTel, 1234},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-p", tc.req))
			if err != nil {
				t.Fatal(err)
			}
			var n int
			var src string
			var in int64
			if err := db.QueryRow(`SELECT COUNT(*), MAX(source), MAX(input_tokens) FROM api_turns WHERE request_id = ?`, tc.req).Scan(&n, &src, &in); err != nil {
				t.Fatal(err)
			}
			if got != tc.want || n != 1 || src != tc.wantSrc || in != tc.wantInput {
				t.Fatalf("outcome %s rows %d source %q input %d, want %s 1 %q %d", got, n, src, in, tc.want, tc.wantSrc, tc.wantInput)
			}
		})
	}
	if _, err := s.UpsertOwnAgentSpanTurn(ctx, proxyTurnFor("ca-p", "x")); err == nil {
		t.Fatal("a non-span turn must be refused")
	}
}

// TestOwnAgentPlaceholderProjectUpgrade (sdk-2 fix round 1, L1): a session
// the agent's spans opened on the placeholder project moves, with its
// actions and turns, to the real working directory a later proxy turn
// resolved; a placeholder never replaces a real project, and a real project
// is never replaced by another.
func TestOwnAgentPlaceholderProjectUpgrade(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	if err := s.EnsureOwnAgentSession(ctx, "ca-u", "bot", "[custom-agent]", "m", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, []models.ToolEvent{{
		SourceFile: "otlp:custom-agent", SourceEventID: "c1", SessionID: "ca-u", ProjectRoot: "[custom-agent]",
		Timestamp: now, Tool: models.ToolCustomAgent, ActionType: models.ActionUnknown, RawToolName: "x", Success: true,
	}}, nil, IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	root := func(q string) string {
		t.Helper()
		var r string
		if err := db.QueryRow(q, "ca-u").Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	sessRoot := `SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?`
	actRoot := `SELECT p.root_path FROM actions a JOIN projects p ON p.id = a.project_id WHERE a.session_id = ?`
	for _, step := range []struct {
		root, want string
	}{
		{"[custom-agent]", "[custom-agent]"}, // a placeholder never upgrades
		{"/work/bot", "/work/bot"},           // a real root replaces the placeholder
		{"[custom-agent]", "/work/bot"},      // never the reverse
		{"/elsewhere", "/work/bot"},          // a real project is kept
	} {
		if err := s.EnsureOwnAgentSession(ctx, "ca-u", "bot", step.root, "m", now); err != nil {
			t.Fatal(err)
		}
		if got := root(sessRoot); got != step.want {
			t.Fatalf("after %q: session project %q, want %q", step.root, got, step.want)
		}
		if got := root(actRoot); got != step.want {
			t.Fatalf("after %q: action project %q, want %q", step.root, got, step.want)
		}
	}
}

// TestOwnAgentSpanFailedRecheckThenRetry (sdk-2 lows, N1): the proxy writes
// the call between the span's read and insert, then the span's re-check
// fails once. The export returns an error (two rows stand for a moment);
// the exporter's retry takes the merge path, which removes the span row, so
// exactly one row, the proxy's, remains.
func TestOwnAgentSpanFailedRecheckThenRetry(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	if err := s.EnsureOwnAgentSession(ctx, "ca-f", "bot", "[custom-agent]", "m", time.Now()); err != nil {
		t.Fatal(err)
	}
	origMid, origRecheck := ownAgentSpanMidHook, ownAgentSpanRecheckHook
	t.Cleanup(func() { ownAgentSpanMidHook, ownAgentSpanRecheckHook = origMid, origRecheck })
	ownAgentSpanMidHook = func() {
		ownAgentSpanMidHook = nil
		if _, err := s.InsertAPITurn(ctx, proxyTurnFor("ca-f", "req-f")); err != nil {
			t.Error(err)
		}
	}
	ownAgentSpanRecheckHook = func() error {
		ownAgentSpanRecheckHook = nil
		return errors.New("database is locked (injected)")
	}
	if _, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-f", "req-f")); err == nil {
		t.Fatal("the failed re-check must be reported so the exporter retries")
	}
	if n, _ := countRequest(t, db, "req-f"); n != 2 {
		t.Fatalf("rows after the failed re-check = %d, want 2 (the window the retry closes)", n)
	}
	got, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-f", "req-f"))
	if err != nil {
		t.Fatal(err)
	}
	if n, src := countRequest(t, db, "req-f"); n != 1 || src != SourceProxy || got != OwnAgentSpanSuperseded {
		t.Fatalf("after the retry: rows %d (%s), outcome %s; want only the proxy's row", n, src, got)
	}
	// Two stale span copies with no proxy row: the retry keeps the oldest.
	for range 2 {
		if _, err := s.InsertAPITurn(ctx, spanTurn("ca-f", "req-dup")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-f", "req-dup")); err != nil {
		t.Fatal(err)
	}
	if n, _ := countRequest(t, db, "req-dup"); n != 1 {
		t.Fatalf("span copies after a redelivery = %d, want 1", n)
	}
}

// TestOwnAgentSpanCancelledCaller (N1): a caller whose context is cancelled
// after the read (the export request went away) does not stop the insert,
// re-check and self-delete half way: the call keeps one row.
func TestOwnAgentSpanCancelledCaller(t *testing.T) {
	s, db := newTestStore(t)
	if err := s.EnsureOwnAgentSession(context.Background(), "ca-x", "bot", "[custom-agent]", "m", time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	orig := ownAgentSpanMidHook
	t.Cleanup(func() { ownAgentSpanMidHook = orig })
	ownAgentSpanMidHook = func() {
		if _, err := s.InsertAPITurn(context.Background(), proxyTurnFor("ca-x", "req-x")); err != nil {
			t.Error(err)
		}
		cancel()
	}
	got, err := s.UpsertOwnAgentSpanTurn(ctx, spanTurn("ca-x", "req-x"))
	if err != nil {
		t.Fatal(err)
	}
	if n, src := countRequest(t, db, "req-x"); n != 1 || src != SourceProxy || got != OwnAgentSpanSuperseded {
		t.Fatalf("rows %d (%s), outcome %s; want only the proxy's row", n, src, got)
	}
}

// TestOwnAgentPlaceholderNotWrittenBack (sdk-2 lows, N2): once the proxy
// moved a span-opened session onto its working directory, a span tool-call
// ingest that only knows the placeholder never moves it back, written in
// sequence or concurrently with the upgrade (run under -race); a real
// project still replaces another real one through UpsertSession.
func TestOwnAgentPlaceholderNotWrittenBack(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	sessRoot := func(id string) string {
		t.Helper()
		var r string
		if err := db.QueryRow(`SELECT p.root_path FROM sessions s JOIN projects p ON p.id = s.project_id WHERE s.id = ?`, id).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	spanAction := func(id, call string) error {
		_, err := s.Ingest(ctx, []models.ToolEvent{{
			SourceFile: "otlp:custom-agent", SourceEventID: call, SessionID: id, ProjectRoot: "[custom-agent]",
			Timestamp: now, Tool: models.ToolCustomAgent, ActionType: models.ActionUnknown, RawToolName: "x", Success: true,
		}}, nil, IngestOptions{})
		return err
	}
	// Sequential: upgrade, then a placeholder write.
	if err := s.EnsureOwnAgentSession(ctx, "ca-seq", "bot", "[custom-agent]", "m", now); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureOwnAgentSession(ctx, "ca-seq", "bot", "/work/bot", "m", now); err != nil {
		t.Fatal(err)
	}
	if err := spanAction("ca-seq", "c1"); err != nil {
		t.Fatal(err)
	}
	if got := sessRoot("ca-seq"); got != "/work/bot" {
		t.Fatalf("a placeholder write moved the session back to %q", got)
	}
	// Concurrent: the upgrade races span tool-call ingests.
	for i := range 10 {
		id := fmt.Sprintf("ca-con-%d", i)
		if err := s.EnsureOwnAgentSession(ctx, id, "bot", "[custom-agent]", "m", now); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			if err := s.EnsureOwnAgentSession(ctx, id, "bot", "/work/bot", "m", now); err != nil {
				t.Error(err)
			}
		}()
		for c := range 2 {
			go func() {
				defer wg.Done()
				<-start
				if err := spanAction(id, fmt.Sprintf("c-%d", c)); err != nil {
					t.Error(err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if got := sessRoot(id); got != "/work/bot" {
			t.Fatalf("%s: session project %q after the race, want /work/bot", id, got)
		}
	}
	// Real to real still updates through UpsertSession (unchanged behaviour).
	pid, err := s.UpsertProject(ctx, "/elsewhere", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "ca-seq", ProjectID: pid, Tool: models.ToolCustomAgent, StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	if got := sessRoot("ca-seq"); got != "/elsewhere" {
		t.Fatalf("real to real = %q, want /elsewhere", got)
	}
}
