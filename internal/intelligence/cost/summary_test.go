package cost

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cost.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

type fixture struct {
	projectRoot string
	projectID   int64
	sessionID   string
}

func seedSession(t *testing.T, database *sql.DB, root, sessionID, tool string) fixture {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := database.ExecContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, ?)`, root, now)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := res.LastInsertId()
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		sessionID, pid, tool, now); err != nil {
		t.Fatal(err)
	}
	return fixture{projectRoot: root, projectID: pid, sessionID: sessionID}
}

// seedSessionInProject adds a second session under the same project row
// as an existing fixture. Needed because seedSession's INSERT INTO projects
// fails on UNIQUE(root_path) when re-invoked with the same path.
func seedSessionInProject(t *testing.T, database *sql.DB, parent fixture, sessionID, tool string) fixture {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, ?)`,
		sessionID, parent.projectID, tool, now); err != nil {
		t.Fatal(err)
	}
	return fixture{projectRoot: parent.projectRoot, projectID: parent.projectID, sessionID: sessionID}
}

func insertAPITurn(t *testing.T, database *sql.DB, f fixture, ts time.Time, model string, in, out int64) {
	t.Helper()
	insertAPITurnWithRequestID(t, database, f, ts, model, in, out, "")
}

// insertAPITurnWithRequestID is the per-turn-dedup-aware helper. Pass a
// non-empty requestID to populate api_turns.request_id (which the cost
// engine uses as turnID). Both insertTokenUsageWithEventID and this
// helper accept the same id when you want to exercise the per-turn
// match path; pass "" on either side to leave the field empty and
// force the fingerprint fallback.
func insertAPITurnWithRequestID(t *testing.T, database *sql.DB, f fixture, ts time.Time, model string, in, out int64, requestID string) {
	t.Helper()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, request_id)
		 VALUES (?, ?, ?, 'anthropic', ?, ?, ?, ?)`,
		f.sessionID, f.projectID, ts.UTC().Format(time.RFC3339Nano), model, in, out, nullableString(requestID))
	if err != nil {
		t.Fatalf("insert api_turn: %v", err)
	}
}

func insertTokenUsage(t *testing.T, database *sql.DB, f fixture, ts time.Time, tool, model string, in, out int64, reliability string) {
	t.Helper()
	insertTokenUsageWithEventID(t, database, f, ts, tool, model, in, out, reliability, "")
}

// insertTokenUsageWithEventID overrides the synthesised source_event_id
// so tests can pin the per-turn dedup key. Pass "" to use the
// timestamp-derived auto value (no per-turn match likely).
func insertTokenUsageWithEventID(t *testing.T, database *sql.DB, f fixture, ts time.Time, tool, model string, in, out int64, reliability, eventID string) {
	t.Helper()
	if eventID == "" {
		eventID = "evt-" + ts.Format("150405.000000000")
	}
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO token_usage (session_id, timestamp, tool, model,
			input_tokens, output_tokens, source, reliability, source_file, source_event_id)
		 VALUES (?, ?, ?, ?, ?, ?, 'jsonl', ?, ?, ?)`,
		f.sessionID, ts.UTC().Format(time.RFC3339Nano), tool, model, in, out, reliability,
		"file-"+f.sessionID, eventID)
	if err != nil {
		t.Fatalf("insert token_usage: %v", err)
	}
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// TestSummary_DropsNoiseRows guards Round 2 issues #5 + #6 from the
// dashboard audit: synthetic-model and all-zero-token rows must NOT
// surface as their own bucket on the Cost tab. The C4 forward filter
// drops <synthetic> at the adapter and B2 drops zero-usage at the
// proxy, but historical residue exists in any DB that ran the older
// binary. The cost engine's load layer is the right place to filter:
// turn_count and total_tokens stay coherent with the visible rows.
// TestSummary_UntilUpperBound pins the closed-window contract for the
// Analysis movers endpoint: rows at-or-after Until must NOT contribute,
// while Since remains a >= lower bound. Lets callers express the
// prior-period window as [Since, Until) without subtracting current
// from a wider summary.
func TestSummary_UntilUpperBound(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/u", "sess-U", "claude-code")
	now := time.Now().UTC()
	// Two turns: one in the prior window, one in the current.
	insertAPITurn(t, database, f, now.Add(-10*24*time.Hour), "claude-sonnet-4-6", 10_000, 5_000)
	insertAPITurn(t, database, f, now.Add(-1*24*time.Hour), "claude-sonnet-4-6", 10_000, 5_000)

	e := NewEngine(config.IntelligenceConfig{})

	// Prior window: [now-14d, now-7d). Should see only the -10d turn.
	priorOnly, err := e.Summary(context.Background(), database, Options{
		Since:   now.Add(-14 * 24 * time.Hour),
		Until:   now.Add(-7 * 24 * time.Hour),
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("prior summary: %v", err)
	}
	if priorOnly.TurnCount != 1 {
		t.Errorf("prior turn count: got %d want 1", priorOnly.TurnCount)
	}

	// Current window: [now-7d, now]. Should see only the -1d turn.
	currentOnly, err := e.Summary(context.Background(), database, Options{
		Since:   now.Add(-7 * 24 * time.Hour),
		Until:   now,
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("current summary: %v", err)
	}
	if currentOnly.TurnCount != 1 {
		t.Errorf("current turn count: got %d want 1", currentOnly.TurnCount)
	}

	// Sanity: no Until → both turns visible.
	noUntil, err := e.Summary(context.Background(), database, Options{
		Since:   now.Add(-14 * 24 * time.Hour),
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("no-until summary: %v", err)
	}
	if noUntil.TurnCount != 2 {
		t.Errorf("no-until turn count: got %d want 2", noUntil.TurnCount)
	}
}

func TestSummary_DropsNoiseRows(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/noise", "sess-noise", "claude-code")
	now := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)

	// Real call — should survive.
	insertAPITurn(t, database, f, now, "claude-sonnet-4-20250514", 1_000_000, 500_000)
	// All-zero proxy row (pre-B2 residue) — should be dropped.
	insertAPITurn(t, database, f, now.Add(time.Minute), "claude-haiku-4-5-20251001", 0, 0)
	// <synthetic> JSONL row (pre-C4 residue) — should be dropped.
	insertTokenUsage(t, database, f, now.Add(2*time.Minute), "claude-code",
		"<synthetic>", 0, 0, "unreliable")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("TurnCount: got %d want 1 (noise rows must drop)", got.TurnCount)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("Rows: got %d want 1", len(got.Rows))
	}
	if got.Rows[0].Key != "claude-sonnet-4-20250514" {
		t.Errorf("surviving row: got %q want claude-sonnet-4-20250514", got.Rows[0].Key)
	}
	for _, row := range got.Rows {
		if row.Key == "<synthetic>" {
			t.Errorf("<synthetic> bucket leaked into rollup: %+v", row)
		}
		if row.Tokens.Input == 0 && row.Tokens.Output == 0 &&
			row.Tokens.CacheRead == 0 && row.Tokens.CacheCreation == 0 {
			t.Errorf("zero-token bucket leaked into rollup: %+v", row)
		}
	}
}

func TestSummary_GroupByModel_ProxyOnly(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()
	insertAPITurn(t, database, f, now, "claude-sonnet-4-20250514", 1_000_000, 500_000)
	insertAPITurn(t, database, f, now.Add(-time.Hour), "claude-opus-4-20250514", 100_000, 50_000)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 2 {
		t.Errorf("TurnCount: got %d, want 2", got.TurnCount)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("Rows: got %d, want 2", len(got.Rows))
	}
	// Sorted by cost desc → sonnet row has 1M input + 0.5M output. The
	// 1M-token prompt clears the 200K long-context threshold for Sonnet 4
	// so the turn is priced at LC rates: 1M × $6 + 0.5M × $22.50 = $17.25.
	if got.Rows[0].Key != "claude-sonnet-4-20250514" {
		t.Errorf("first row key: %s", got.Rows[0].Key)
	}
	if diff := got.Rows[0].CostUSD - 17.25; diff > 1e-6 || diff < -1e-6 {
		t.Errorf("sonnet cost: got %v, want 17.25", got.Rows[0].CostUSD)
	}
	if got.Reliability != "accurate" {
		t.Errorf("reliability: %s", got.Reliability)
	}
}

// TestSummary_PricingSource pins the Phase C audit fix: every Row in
// the summary tags how the pricing-table lookup resolved (exact /
// date-stripped / family / miss / mixed). The dashboard surfaces a
// "~" indicator on the Reliability column when the result is anything
// other than "exact", so users can see which numbers came from
// fallback rates and which came from a baked-in entry.
func TestSummary_PricingSource(t *testing.T) {
	database := openTestDB(t)
	root := "/repo/p"
	now := time.Now().UTC()

	// Seed three sessions, each with a single proxy turn against a
	// different model that exercises a different lookup path:
	//   - sess-exact:  claude-sonnet-4-20250514 — exact entry exists.
	//   - sess-family: claude-opus-4-99 — no exact, falls back via the
	//     "claude-opus-4" family prefix.
	//   - sess-miss:   total-bogus-model — no match anywhere.
	exact := seedSession(t, database, root, "sess-exact", "claude-code")
	insertAPITurn(t, database, exact, now, "claude-sonnet-4-20250514", 1_000_000, 0)
	family := seedSessionInProject(t, database, exact, "sess-family", "claude-code")
	insertAPITurn(t, database, family, now, "claude-opus-4-99", 1_000, 0)
	miss := seedSessionInProject(t, database, exact, "sess-miss", "claude-code")
	insertAPITurn(t, database, miss, now, "total-bogus-model", 1_000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupBySession, Source: SourceProxy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rows) != 3 {
		t.Fatalf("rows: got %d want 3", len(got.Rows))
	}
	bySession := map[string]string{}
	for _, r := range got.Rows {
		bySession[r.Key] = r.PricingSource
	}
	for _, tc := range []struct{ session, want string }{
		{"sess-exact", "exact"},
		{"sess-family", "family"},
		{"sess-miss", "miss"},
	} {
		if got, ok := bySession[tc.session]; !ok {
			t.Errorf("missing session row %q", tc.session)
		} else if got != tc.want {
			t.Errorf("%s: pricing_source = %q, want %q", tc.session, got, tc.want)
		}
	}
}

// TestSummary_CursorGrokAliasCost pins the dashboard cost-summary path for
// the live Cursor hook model shape. The row must use the explicit Cursor
// pricing entry, include cached-input tokens, and retain a non-zero cost.
func TestSummary_CursorGrokAliasCost(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/cursor", "sess-cursor-grok", "cursor")
	now := time.Now().UTC()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO token_usage (session_id, timestamp, tool, model,
			input_tokens, output_tokens, cache_read_tokens, source, reliability,
			source_file, source_event_id)
		 VALUES (?, ?, 'cursor', ?, ?, ?, ?, 'watcher', 'accurate', ?, ?)`,
		f.sessionID, now.Format(time.RFC3339Nano), "cursor-grok-4.6-medium",
		12_000, 400, 50_000, "cursor.jsonl", "cursor-grok-cost")
	if err != nil {
		t.Fatalf("insert Cursor token usage: %v", err)
	}

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel,
		Source:  SourceJSONL,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("rows: got %d want 1 (%+v)", len(got.Rows), got.Rows)
	}
	row := got.Rows[0]
	if row.Key != "cursor-grok-4.6-medium" {
		t.Fatalf("row key = %q", row.Key)
	}
	if row.Tokens.Input != 12_000 || row.Tokens.Output != 400 || row.Tokens.CacheRead != 50_000 {
		t.Fatalf("tokens = %+v, want input=12000 output=400 cache_read=50000", row.Tokens)
	}
	if diff := row.CostUSD - 0.0514; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("cost = %.9f want 0.0514", row.CostUSD)
	}
	if row.PricingSource != "exact" {
		t.Fatalf("pricing_source = %q want exact", row.PricingSource)
	}
}

// TestSummary_SourceAuto_PerTurnDedup_MatchingTurnID covers the
// per-turn dedup happy path. When the proxy intercepted a turn AND
// the JSONL adapter wrote a row for the SAME turn (same upstream
// message id), the engine must drop the JSONL row and keep the
// proxy row.
//
// This replaces the pre-2026-04-29 per-session dedup test. Old
// behaviour was: any proxy row in a session caused ALL JSONL rows
// for that session to be dropped, even ones representing turns the
// proxy never saw — which silently dropped 80%+ of tokens for the
// b9bd459d session (see docs/cost-accuracy-audit-2026-04-29.md
// Finding 1).
func TestSummary_SourceAuto_PerTurnDedup_MatchingTurnID(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()
	// Proxy and JSONL rows for the SAME upstream turn — both reference
	// the same Anthropic msg_xxx id. Engine should keep proxy.
	insertAPITurnWithRequestID(t, database, f, now, "claude-sonnet-4-20250514", 1_000_000, 500_000, "msg_abc123")
	insertTokenUsageWithEventID(t, database, f, now, "claude-code", "claude-sonnet-4-20250514", 999, 999, "unreliable", "msg_abc123")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("TurnCount: got %d, want 1 (per-turn dedup should keep proxy)", got.TurnCount)
	}
	if got.TotalTokens.Input != 1_000_000 {
		t.Errorf("TotalTokens.Input: got %d, want 1_000_000 (proxy values, not JSONL)", got.TotalTokens.Input)
	}
	if got.Reliability != "accurate" {
		t.Errorf("reliability: got %q, want accurate (proxy row kept)", got.Reliability)
	}
}

// TestSummary_SourceAuto_PerTurnDedup_GapFill is the regression test
// for the bug docs/cost-accuracy-audit-2026-04-29.md Finding 1 ships:
// when the proxy only intercepted SOME turns of a session, JSONL rows
// for the OTHER turns must NOT be dropped. They fill the gap.
func TestSummary_SourceAuto_PerTurnDedup_GapFill(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()
	// Turn 1: proxy intercepted it AND the JSONL adapter wrote a row.
	insertAPITurnWithRequestID(t, database, f, now, "claude-sonnet-4-20250514", 100_000, 50_000, "msg_001")
	insertTokenUsageWithEventID(t, database, f, now, "claude-code", "claude-sonnet-4-20250514", 100_000, 50_000, "unreliable", "msg_001")
	// Turn 2: only JSONL has a row (proxy was not engaged for this turn).
	// The pre-fix engine would have dropped this because *some* proxy row
	// exists for sess-A. The fix keeps it.
	insertTokenUsageWithEventID(t, database, f, now.Add(time.Minute), "claude-code", "claude-sonnet-4-20250514", 200_000, 80_000, "unreliable", "msg_002")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	// 2 turns kept: proxy (turn 1) + JSONL (turn 2). Pre-fix only turn 1
	// would survive.
	if got.TurnCount != 2 {
		t.Fatalf("TurnCount: got %d, want 2 (proxy turn 1 + JSONL gap-fill turn 2)", got.TurnCount)
	}
	wantInput := int64(100_000 + 200_000)
	if got.TotalTokens.Input != wantInput {
		t.Errorf("TotalTokens.Input: got %d, want %d (proxy + JSONL gap-fill)", got.TotalTokens.Input, wantInput)
	}
	// Mixed source = at least one accurate proxy row + at least one
	// approximate/unreliable JSONL row → reliability falls to the
	// weakest in the bundle ("unreliable").
	if got.Reliability != "unreliable" {
		t.Errorf("reliability: got %q, want unreliable (mixed = weakest wins)", got.Reliability)
	}
}

// TestSummary_SourceAuto_PerTurnDedup_CodexKeyShapeMismatch is the
// regression test for the operator-reported 2026-06-10 double-count
// bug. Codex's proxy ingest stores OpenAI's "resp_<hex>" id as
// api_turns.request_id; Codex's JSONL adapter writes a synthetic
// "tk:<file>:L<line>" id as token_usage.source_event_id. Same logical
// turn, completely different identifier shapes — level-1 turnID
// dedup cannot match them. Pre-fix the loadRows loop bailed early on
// any proxy row with a turnID, so the session+shape fallback was
// never populated and the JSONL row escaped dedup entirely. Result
// on the operator's gpt-5.4 session: /api/sessions returned
// input_tokens=15,020 against a real 7,510 (exact 2×).
//
// Post-fix: proxy rows populate BOTH proxyTurns (for level-1 match)
// AND proxySessionShapes (for level-2 fallback), so adapters with
// mismatched id shapes still dedup against the proxy correctly.
func TestSummary_SourceAuto_PerTurnDedup_CodexKeyShapeMismatch(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/needlehaystack", "019eadd3-codex-mock", "codex")
	now := time.Now().UTC()
	// Proxy api_turn — OpenAI response id as turnID.
	insertAPITurnWithRequestID(t, database, f, now, "gpt-5.4", 7510, 66,
		"resp_031de95fdbc04dde016a286769e8f0819185d8aadcb5b15e38")
	// JSONL token_usage — Codex's "tk:<file>:L<line>" id. Different
	// shape, same logical turn. Timestamp is a few seconds later
	// (JSONL flush lags proxy insert); same minute bucket.
	insertTokenUsageWithEventID(t, database, f, now.Add(4*time.Second), "codex", "gpt-5.4", 7510, 66,
		"approximate", "tk:rollout-2026-06-10T00-50-04-019eadd3.jsonl:L11")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("TurnCount = %d, want 1 (codex JSONL must dedup against proxy via session+shape fallback)", got.TurnCount)
	}
	if got.TotalTokens.Input != 7510 {
		t.Errorf("TotalTokens.Input = %d, want 7510 (pre-fix returned 15,020 = exact 2×)", got.TotalTokens.Input)
	}
	if got.TotalTokens.Output != 66 {
		t.Errorf("TotalTokens.Output = %d, want 66 (pre-fix returned 132)", got.TotalTokens.Output)
	}
}

func TestSummary_SourceAuto_KeepsJSONLWhenSessionMissingFromProxy(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()
	// JSONL row only — the proxy never saw this session.
	insertTokenUsage(t, database, f, now, "claude-code", "claude-sonnet-4-20250514", 1_000_000, 500_000, "unreliable")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("TurnCount: got %d, want 1", got.TurnCount)
	}
	if got.Reliability != "unreliable" {
		t.Errorf("reliability: got %s, want unreliable", got.Reliability)
	}
}

// TestSummary_SourceAuto_FingerprintDedup_NullProxySession guards against
// audit item A2: when an api_turns row landed with session_id=NULL (typical
// for pre-v1.2.1 pidbridge behaviour), the JSONL row for the same logical
// turn used to escape the dedup and get summed on top. The fingerprint
// fallback (model + ts-bucketed-to-minute + token columns) must catch it.
func TestSummary_SourceAuto_FingerprintDedup_NullProxySession(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	// Pin to second 0 of a minute so the +15s offset below stays inside
	// the same minute bucket the fingerprint hashes against. Using
	// time.Now() made the test flake whenever it ran in the last 45s
	// of a minute.
	now := time.Date(2026, 4, 25, 10, 0, 0, 0, time.UTC)

	// Proxy row landed with NULL session_id (the bug shape) but otherwise
	// matches the JSONL row's token signature. Insert directly so we can
	// override session_id to NULL without a fixture session.
	if _, err := database.ExecContext(
		context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens)
		 VALUES (NULL, ?, ?, 'anthropic', ?, ?, ?, ?, ?)`,
		f.projectID, now.Format(time.RFC3339Nano),
		"claude-sonnet-4-20250514",
		int64(1_000_000), int64(500_000), int64(50_000), int64(0),
	); err != nil {
		t.Fatalf("insert null-session api_turn: %v", err)
	}

	// JSONL row with the same model + tokens, second-precision matching
	// timestamp. Without the fingerprint fallback this row would be summed
	// on top of the proxy row, doubling the totals.
	if _, err := database.ExecContext(
		context.Background(),
		`INSERT INTO token_usage (session_id, timestamp, tool, model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			source, reliability, source_file, source_event_id)
		 VALUES (?, ?, 'claude-code', ?, ?, ?, ?, ?, 'jsonl', 'unreliable', ?, ?)`,
		f.sessionID, now.Add(15*time.Second).Format(time.RFC3339Nano),
		"claude-sonnet-4-20250514",
		int64(1_000_000), int64(500_000), int64(50_000), int64(0),
		"file-A", "evt-A",
	); err != nil {
		t.Fatalf("insert token_usage: %v", err)
	}

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("TurnCount: got %d want 1 (fingerprint should drop the JSONL dupe)", got.TurnCount)
	}
	if got.TotalTokens.Input != 1_000_000 {
		t.Errorf("TotalTokens.Input: got %d want 1_000_000 (no double-count)", got.TotalTokens.Input)
	}
	if got.TotalTokens.Output != 500_000 {
		t.Errorf("TotalTokens.Output: got %d want 500_000", got.TotalTokens.Output)
	}
}

// TestSummary_SourceAuto_FingerprintDoesNotMergeDistinctCalls guards the
// false-positive direction: a JSONL row whose tokens differ from the
// NULL-session proxy row must remain in the summary.
func TestSummary_SourceAuto_FingerprintDoesNotMergeDistinctCalls(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()

	if _, err := database.ExecContext(
		context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens)
		 VALUES (NULL, ?, ?, 'anthropic', 'claude-sonnet-4-20250514', 1000, 500, 50, 0)`,
		f.projectID, now.Format(time.RFC3339Nano),
	); err != nil {
		t.Fatalf("insert null-session api_turn: %v", err)
	}
	// JSONL row with DIFFERENT tokens — must survive.
	insertTokenUsage(t, database, f, now, "claude-code",
		"claude-sonnet-4-20250514", 9999, 4444, "unreliable")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 2 {
		t.Errorf("TurnCount: got %d want 2 (proxy + distinct JSONL)", got.TurnCount)
	}
}

// insertCodexProxyTurn / insertCodexJSONLTurn seed the codex shape where the
// proxy request_id (resp_…) and the JSONL source_event_id (tk:…) are DISJOINT
// id schemes — the exact shape that defeated the per-turn dedup and made every
// codex proxy+jsonl turn double-count (audit F1, 2026-06-08).
func insertCodexProxyTurn(t *testing.T, database *sql.DB, f fixture, ts time.Time, model string, in, out, cR int64, requestID string, costUSD float64, fast int) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, cache_read_tokens, request_id, cost_usd, fast)
		 VALUES (?, ?, ?, 'openai', ?, ?, ?, ?, ?, ?, ?)`,
		f.sessionID, f.projectID, ts.UTC().Format(time.RFC3339Nano), model, in, out, cR, requestID, costUSD, fast); err != nil {
		t.Fatalf("insert codex api_turn: %v", err)
	}
}

func insertCodexJSONLTurn(t *testing.T, database *sql.DB, f fixture, ts time.Time, model string, in, out, cR int64, eventID string, fast int) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO token_usage (session_id, timestamp, tool, model,
			input_tokens, output_tokens, cache_read_tokens, source, reliability,
			source_file, source_event_id, fast)
		 VALUES (?, ?, 'codex', ?, ?, ?, ?, 'jsonl', 'approximate', ?, ?, ?)`,
		f.sessionID, ts.UTC().Format(time.RFC3339Nano), model, in, out, cR,
		"file-"+f.sessionID, eventID, fast); err != nil {
		t.Fatalf("insert codex token_usage: %v", err)
	}
}

// TestSummary_SourceAuto_CodexShapeDedup is the audit F1 regression: a codex
// turn captured by BOTH the proxy (api_turns, request_id=resp_…, fast=0) and
// the watcher (token_usage, source_event_id=tk:…, fast=1) must collapse to ONE
// turn — even though the two ids share no scheme so the turnID match can't
// fire. The (session, sessionShapeKey) level must catch it. Pre-fix the shape
// maps were populated only from turnID-LESS proxy rows, so codex (always
// request_id-bearing) escaped dedup and double-counted.
func TestSummary_SourceAuto_CodexShapeDedup(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/codex", "sess-codex", "codex")
	now := time.Date(2026, 6, 7, 21, 26, 5, 0, time.UTC)
	// Same turn, disjoint id schemes. Proxy wire = standard tier (fast=0),
	// recorded cost is the STANDARD price ($0.40); the watcher carries the
	// config-sourced priority flag (fast=1).
	insertCodexProxyTurn(t, database, f, now, "gpt-5.4", 100_000, 10_000, 0, "resp_abc", 0.40, 0)
	insertCodexJSONLTurn(t, database, f, now.Add(11*time.Second), "gpt-5.4", 100_000, 10_000, 0, "tk:rollout-x:L15", 1)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{GroupBy: GroupByNone, Source: SourceAuto})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Fatalf("TurnCount: got %d, want 1 (codex shape-dedup must collapse proxy+jsonl)", got.TurnCount)
	}
	if got.TotalTokens.Input != 100_000 {
		t.Errorf("TotalTokens.Input: got %d, want 100_000 (proxy kept, not doubled)", got.TotalTokens.Input)
	}
	// "Keep proxy, OR-in fast": the surviving proxy row inherits fast=1 from
	// its dropped jsonl twin and re-prices WITH the gpt-5.4 FastMultiplier
	// (2×). Standard AI = 100k*2.5/1e6 + 10k*15/1e6 = $0.40 → premium $0.80.
	if d := got.TotalCost - 0.80; d < -1e-9 || d > 1e-9 {
		t.Errorf("TotalCost: got %.6f, want 0.80 (proxy inherits fast premium)", got.TotalCost)
	}
	if got.FastTurnCount != 1 {
		t.Errorf("FastTurnCount: got %d, want 1 (inherited fast counts toward the premium subtotal)", got.FastTurnCount)
	}
}

// TestSummary_SourceAuto_CodexShapeDedup_MinuteBoundary proves the dedup
// survives a minute boundary between the two captures. The proxy logs at
// :26:58 and the rollout flush lands at :27:09 — different minute buckets, so
// the minute-bucketed shapeKey would MISS and double-count. sessionShapeKey
// drops the minute (the session_id anchors the match), so they still collapse.
func TestSummary_SourceAuto_CodexShapeDedup_MinuteBoundary(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/codex", "sess-codex", "codex")
	proxyTS := time.Date(2026, 6, 7, 21, 26, 58, 0, time.UTC)
	jsonlTS := time.Date(2026, 6, 7, 21, 27, 9, 0, time.UTC) // next minute
	insertCodexProxyTurn(t, database, f, proxyTS, "gpt-5.4", 50_000, 5_000, 0, "resp_x", 0.20, 0)
	insertCodexJSONLTurn(t, database, f, jsonlTS, "gpt-5.4", 50_000, 5_000, 0, "tk:rollout-y:L9", 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{GroupBy: GroupByNone, Source: SourceAuto})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Fatalf("TurnCount: got %d, want 1 (sessionShapeKey must ignore the minute boundary)", got.TurnCount)
	}
	if got.TotalTokens.Input != 50_000 {
		t.Errorf("TotalTokens.Input: got %d, want 50_000 (single turn)", got.TotalTokens.Input)
	}
}

// TestSummary_SourceAuto_CodexDedup_NonFastKeepsRecorded confirms the no-flip
// path: when the dropped jsonl twin is NOT fast, the surviving proxy row keeps
// its recorded (standard) cost untouched and contributes no fast premium.
func TestSummary_SourceAuto_CodexDedup_NonFastKeepsRecorded(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/codex", "sess-codex", "codex")
	now := time.Date(2026, 6, 7, 21, 26, 5, 0, time.UTC)
	insertCodexProxyTurn(t, database, f, now, "gpt-5.4", 100_000, 10_000, 0, "resp_abc", 0.40, 0)
	insertCodexJSONLTurn(t, database, f, now.Add(11*time.Second), "gpt-5.4", 100_000, 10_000, 0, "tk:rollout-x:L15", 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{GroupBy: GroupByNone, Source: SourceAuto})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Fatalf("TurnCount: got %d, want 1", got.TurnCount)
	}
	if d := got.TotalCost - 0.40; d < -1e-9 || d > 1e-9 {
		t.Errorf("TotalCost: got %.6f, want 0.40 (recorded standard cost preserved, no premium)", got.TotalCost)
	}
	if got.FastTurnCount != 0 {
		t.Errorf("FastTurnCount: got %d, want 0 (no fast twin → no premium)", got.FastTurnCount)
	}
}

func TestSummary_GroupByDay(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	base := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	insertAPITurn(t, database, f, base, "claude-sonnet-4-20250514", 1_000_000, 0)
	insertAPITurn(t, database, f, base.Add(-24*time.Hour), "claude-sonnet-4-20250514", 500_000, 0)
	insertAPITurn(t, database, f, base.Add(-24*time.Hour+time.Hour), "claude-sonnet-4-20250514", 500_000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByDay, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(got.Rows) != 2 {
		t.Fatalf("Rows: got %d, want 2 (2 distinct days)", len(got.Rows))
	}
	// 2026-04-15 has 2 turns, 1M tokens total; 2026-04-16 has 1 turn, 1M tokens.
	// Both cost the same → sorted by token count stable-first.
	for _, r := range got.Rows {
		if r.Key != "2026-04-15" && r.Key != "2026-04-16" {
			t.Errorf("unexpected key: %s", r.Key)
		}
	}
}

func TestSummary_ProjectFilter(t *testing.T) {
	database := openTestDB(t)
	a := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	b := seedSession(t, database, "/repo/b", "sess-B", "codex")
	now := time.Now().UTC()
	insertAPITurn(t, database, a, now, "claude-sonnet-4-20250514", 1_000_000, 0)
	insertAPITurn(t, database, b, now, "claude-sonnet-4-20250514", 9_000_000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceProxy, ProjectRoot: "/repo/a",
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("project filter did not restrict: TurnCount=%d", got.TurnCount)
	}
	if got.TotalTokens.Input != 1_000_000 {
		t.Errorf("TotalTokens wrong: %+v", got.TotalTokens)
	}
}

func TestSummary_UnknownModel_ZeroCost(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()
	insertAPITurn(t, database, f, now, "definitely-fake-model-99", 1_000_000, 500_000)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TotalCost != 0 {
		t.Errorf("unknown model should cost 0: got %v", got.TotalCost)
	}
	if got.UnknownModelCount != 1 {
		t.Errorf("UnknownModelCount: got %d", got.UnknownModelCount)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("Rows: %d", len(got.Rows))
	}
	if len(got.Rows[0].UnknownModels) != 1 {
		t.Errorf("UnknownModels on row: %v", got.Rows[0].UnknownModels)
	}
}

// TestSummary_UnpricedTokensVolumeWeighted pins audit §11.B: Summary reports
// UnpricedTokens (input+output volume on $0-missed rows) and UnpricedTurnCount
// alongside the distinct-model UnknownModelCount, so a whole-adapter
// attribution regression is loud rather than hidden behind a tiny distinct
// count. A priced row's tokens must NOT be counted toward the unpriced totals.
func TestSummary_UnpricedTokensVolumeWeighted(t *testing.T) {
	database := openTestDB(t)
	now := time.Now().UTC()
	// One unknown-model turn (billed $0 → unpriced) and one priced turn.
	fUnknown := seedSession(t, database, "/repo/u", "sess-U", "claude-code")
	insertAPITurn(t, database, fUnknown, now, "definitely-fake-model-99", 1_000_000, 500_000)
	fPriced := seedSessionInProject(t, database, fUnknown, "sess-P", "claude-code")
	insertAPITurn(t, database, fPriced, now, "claude-sonnet-4-6", 200_000, 100_000)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByNone, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.UnknownModelCount != 1 {
		t.Errorf("UnknownModelCount: got %d want 1", got.UnknownModelCount)
	}
	if got.UnpricedTurnCount != 1 {
		t.Errorf("UnpricedTurnCount: got %d want 1 (only the unknown turn)", got.UnpricedTurnCount)
	}
	// Only the unknown turn's input+output; the priced turn's 300k excluded.
	if got.UnpricedTokens != 1_500_000 {
		t.Errorf("UnpricedTokens: got %d want 1_500_000 (priced row's tokens must be excluded)", got.UnpricedTokens)
	}
	if got.TotalCost <= 0 {
		t.Errorf("TotalCost: got %v want > 0 (the priced claude-sonnet-4-6 turn bills)", got.TotalCost)
	}
}

// TestSummary_CopilotOutputShadowDeduped pins the copilot-family output-only
// shadow dedup: each copilot adapter emits a full-usage token_usage row AND a
// separate output-only row for the same turn (the intended (session,message_id)
// merge never happens because the store keys on (source_file,source_event_id)),
// double-counting output. The full row's output must win and the shadow drop.
// A non-copilot session with the same shape must NOT be deduped (scoping).
func TestSummary_CopilotOutputShadowDeduped(t *testing.T) {
	database := openTestDB(t)
	now := time.Now().UTC()

	// copilot-cli: full-usage row (Tier-1) + output-only shadow (Tier-3),
	// same output. The adapter gives them different models (dated vs dotted).
	cp := seedSession(t, database, "/repo/cp", "sess-cp", "copilot-cli")
	insertTokenUsageWithEventID(t, database, cp, now, "copilot-cli", "claude-haiku-4-5-20251001", 16267, 152, "approximate", "log:null:1")
	insertTokenUsageWithEventID(t, database, cp, now, "copilot-cli", "claude-haiku-4.5", 0, 152, "unreliable", "evt:token")

	// claude-code with the SAME shape must NOT be deduped — only the copilot
	// family is treated as multi-row-per-turn.
	cc := seedSessionInProject(t, database, cp, "sess-cc", "claude-code")
	insertTokenUsageWithEventID(t, database, cc, now, "claude-code", "claude-sonnet-4-6", 500, 152, "approximate", "cc-full")
	insertTokenUsageWithEventID(t, database, cc, now, "claude-code", "claude-sonnet-4-6", 0, 152, "approximate", "cc-shadow")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{GroupBy: GroupBySession, Source: SourceJSONL})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	byID := map[string]Row{}
	for _, r := range got.Rows {
		byID[r.Key] = r
	}
	cpRow, ok := byID["sess-cp"]
	if !ok {
		t.Fatal("copilot-cli session missing from rollup")
	}
	if cpRow.Tokens.Output != 152 {
		t.Errorf("copilot-cli output = %d, want 152 (shadow deduped, not 304)", cpRow.Tokens.Output)
	}
	if cpRow.Tokens.Input != 16267 {
		t.Errorf("copilot-cli input = %d, want 16267 (full row preserved)", cpRow.Tokens.Input)
	}
	ccRow, ok := byID["sess-cc"]
	if !ok {
		t.Fatal("claude-code session missing from rollup")
	}
	if ccRow.Tokens.Output != 304 {
		t.Errorf("claude-code output = %d, want 304 (NOT deduped — scoping guard)", ccRow.Tokens.Output)
	}
}

func TestSummary_DaysFilter(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	base := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	insertAPITurn(t, database, f, base, "claude-sonnet-4-20250514", 1_000_000, 0)
	insertAPITurn(t, database, f, base.Add(-10*24*time.Hour), "claude-sonnet-4-20250514", 9_000_000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy, Days: 3,
		Now: func() time.Time { return base.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("Days filter: got %d, want 1", got.TurnCount)
	}
	if got.TotalTokens.Input != 1_000_000 {
		t.Errorf("Days filter wrong tokens: %+v", got.TotalTokens)
	}
}

func TestSummary_ProxyCostUSDRespected(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	now := time.Now().UTC()
	// Insert a turn with an explicit cost_usd that differs from what our
	// pricing table would compute. The recorded value wins.
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, cost_usd)
		 VALUES (?, ?, ?, 'anthropic', 'claude-sonnet-4-20250514', 1000000, 0, ?)`,
		f.sessionID, f.projectID, now.Format(time.RFC3339Nano), 42.0)
	if err != nil {
		t.Fatal(err)
	}

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TotalCost != 42.0 {
		t.Errorf("recorded cost_usd should win: got %v, want 42", got.TotalCost)
	}
}

// TestSummary_FastTierAggregation pins the v1.8.2 fast-tier rollup:
// rows flagged fast=1 (Anthropic Opus 4.8 speed:"fast") accumulate into
// Row.FastTurnCount / Row.FastCostUSD and the window totals
// Summary.FastTurnCount / Summary.TotalFastCostUSD. The fast cost must
// already carry the FastMultiplier premium — a fast Opus 4.8 turn costs
// exactly 2× the same standard turn — so the dashboard's fast-tier
// badge + stat line reflect real premium spend.
func TestSummary_FastTierAggregation(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/fast", "sess-fast", "claude-code")
	now := time.Now().UTC()

	// Two JSONL token rows for the SAME model (claude-opus-4-8,
	// FastMultiplier=2), identical tokens, estimated_cost_usd=0 so the
	// engine computes — one standard, one fast.
	insertTokenUsageFast(t, database, f, now, "claude-code", "claude-opus-4-8", 1_000_000, 0, false, "evt-std")
	insertTokenUsageFast(t, database, f, now.Add(time.Second), "claude-code", "claude-opus-4-8", 1_000_000, 0, true, "evt-fast")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceJSONL,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	// Standard opus-4-8: 1M input × $5/1M = $5. Fast: 2× = $10.
	const stdCost, fastCost = 5.0, 10.0
	if got.TurnCount != 2 {
		t.Fatalf("turn count: got %d want 2", got.TurnCount)
	}
	if got.FastTurnCount != 1 {
		t.Errorf("Summary.FastTurnCount: got %d want 1", got.FastTurnCount)
	}
	if diff := got.TotalFastCostUSD - fastCost; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Summary.TotalFastCostUSD: got %v want %v (2× standard)", got.TotalFastCostUSD, fastCost)
	}
	// Window total = standard + fast = $5 + $10 = $15.
	if diff := got.TotalCost - (stdCost + fastCost); diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Summary.TotalCost: got %v want %v", got.TotalCost, stdCost+fastCost)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("rows: got %d want 1 (single model bucket)", len(got.Rows))
	}
	row := got.Rows[0]
	if row.FastTurnCount != 1 {
		t.Errorf("Row.FastTurnCount: got %d want 1", row.FastTurnCount)
	}
	if diff := row.FastCostUSD - fastCost; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Row.FastCostUSD: got %v want %v", row.FastCostUSD, fastCost)
	}
	// The fast turn really is 2× the standard one.
	if diff := row.FastCostUSD - 2*stdCost; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("fast turn should be exactly 2× standard: fast=%v std=%v", row.FastCostUSD, stdCost)
	}
}

// TestSummary_FastTierGatedByPremium pins the gate added 2026-06-08: a
// token row flagged fast=1 counts toward FastTurnCount / FastCostUSD only
// when the model actually has a FastMultiplier > 0. Codex sends
// service_tier:"priority" globally so every codex row carries fast=1, but
// only gpt-5.5 / gpt-5.4 bill a premium — gpt-5.4-mini (FastMultiplier 0)
// must NOT inflate the fast-tier subtotal even though its row is fast=1.
// Inputs stay below the 272K long-context threshold so the standard rate
// is the baseline.
func TestSummary_FastTierGatedByPremium(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/codexfast", "sess-codexfast", "codex")
	now := time.Now().UTC()

	// Both rows fast=1. gpt-5.4 has FastMultiplier=2 (premium); gpt-5.4-mini
	// has FastMultiplier=0 (no premium).
	insertTokenUsageFast(t, database, f, now, "codex", "gpt-5.4", 100_000, 0, true, "evt-54")
	insertTokenUsageFast(t, database, f, now.Add(time.Second), "codex", "gpt-5.4-mini", 100_000, 0, true, "evt-mini")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceJSONL,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	// Only the gpt-5.4 row is a premium fast turn.
	if got.FastTurnCount != 1 {
		t.Errorf("Summary.FastTurnCount: got %d want 1 (only gpt-5.4 has a premium)", got.FastTurnCount)
	}
	// gpt-5.4 fast: 100K × $2.50/1M × 2 = $0.50. mini excluded from fast cost.
	const wantFastCost = 0.50
	if diff := got.TotalFastCostUSD - wantFastCost; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("Summary.TotalFastCostUSD: got %v want %v (gpt-5.4 only)", got.TotalFastCostUSD, wantFastCost)
	}
	for _, row := range got.Rows {
		switch row.Key {
		case "gpt-5.4":
			if row.FastTurnCount != 1 {
				t.Errorf("gpt-5.4 Row.FastTurnCount: got %d want 1", row.FastTurnCount)
			}
		case "gpt-5.4-mini":
			if row.FastTurnCount != 0 {
				t.Errorf("gpt-5.4-mini Row.FastTurnCount: got %d want 0 (no premium → not counted fast)", row.FastTurnCount)
			}
		}
	}
}

// insertTokenUsageFast inserts a JSONL token row with an explicit fast
// flag (migration 035). estimated_cost_usd stays 0 so the cost engine
// computes — exercising the FastMultiplier path end to end.
func insertTokenUsageFast(t *testing.T, database *sql.DB, f fixture, ts time.Time, tool, model string, in, out int64, fast bool, eventID string) {
	t.Helper()
	fastInt := 0
	if fast {
		fastInt = 1
	}
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO token_usage (session_id, timestamp, tool, model,
			input_tokens, output_tokens, source, reliability, source_file, source_event_id, fast)
		 VALUES (?, ?, ?, ?, ?, ?, 'jsonl', 'accurate', ?, ?, ?)`,
		f.sessionID, ts.UTC().Format(time.RFC3339Nano), tool, model, in, out,
		"file-"+f.sessionID, eventID, fastInt)
	if err != nil {
		t.Fatalf("insert token_usage (fast): %v", err)
	}
}

func TestSummary_WeakestReliability(t *testing.T) {
	// One proxy row (accurate) + one jsonl row (approximate) in the same
	// group → the group is "mixed" source, weakest reliability = approximate.
	database := openTestDB(t)
	a := seedSession(t, database, "/repo/a", "sess-A", "claude-code")
	b := seedSessionInProject(t, database, a, "sess-B", "codex")
	now := time.Now().UTC()
	insertAPITurn(t, database, a, now, "claude-sonnet-4-20250514", 100, 50)
	insertTokenUsage(t, database, b, now, "codex", "claude-sonnet-4-20250514", 100, 50, "approximate")

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceAuto,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("rows: %d", len(got.Rows))
	}
	if got.Rows[0].Source != "mixed" {
		t.Errorf("expected mixed source: %s", got.Rows[0].Source)
	}
	if got.Rows[0].Reliability != "approximate" {
		t.Errorf("expected approximate reliability: %s", got.Rows[0].Reliability)
	}
}

func TestSummaryAggregatesCompressionSavings(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/comp", "sess-C", "claude-code")
	now := time.Now().UTC()

	// Three proxy turns, two with compression stats recorded, one without.
	for i, stats := range []struct {
		orig, comp int64
		count      int64
		dropped    int64
	}{
		{10000, 3000, 2, 1},
		{20000, 5000, 3, 0},
		{0, 0, 0, 0}, // no compression — old pre-phase-5 turn
	} {
		_, err := database.ExecContext(
			context.Background(),
			`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
				input_tokens, output_tokens,
				compression_original_bytes, compression_compressed_bytes,
				compression_count, compression_dropped_count, compression_marker_count)
			 VALUES (?, ?, ?, 'anthropic', 'claude-sonnet-4-20250514',
				1000, 500, ?, ?, ?, ?, ?)`,
			f.sessionID, f.projectID,
			now.Add(time.Duration(i)*time.Minute).Format(time.RFC3339Nano),
			nullableOrInt(stats.orig), nullableOrInt(stats.comp),
			nullableOrInt(stats.count), nullableOrInt(stats.dropped), nullableOrInt(0),
		)
		if err != nil {
			t.Fatalf("seed turn %d: %v", i, err)
		}
	}

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TotalCompression.OriginalBytes != 30000 {
		t.Errorf("TotalCompression.OriginalBytes = %d, want 30000", got.TotalCompression.OriginalBytes)
	}
	if got.TotalCompression.CompressedBytes != 8000 {
		t.Errorf("TotalCompression.CompressedBytes = %d, want 8000", got.TotalCompression.CompressedBytes)
	}
	if got.TotalCompression.CompressedCount != 5 {
		t.Errorf("CompressedCount = %d, want 5", got.TotalCompression.CompressedCount)
	}
	if got.TotalCompression.DroppedCount != 1 {
		t.Errorf("DroppedCount = %d, want 1", got.TotalCompression.DroppedCount)
	}
	if got.TotalCompression.Turns != 2 {
		t.Errorf("Compression.Turns = %d, want 2 (the 3rd turn had no stats)", got.TotalCompression.Turns)
	}
	if saved := got.TotalCompression.SavedBytes(); saved != 22000 {
		t.Errorf("SavedBytes() = %d, want 22000", saved)
	}
	ratio := got.TotalCompression.SavedRatio()
	if ratio < 0.7 || ratio > 0.75 {
		t.Errorf("SavedRatio() = %.3f, want ~0.73", ratio)
	}
}

// nullableOrInt returns nil when v == 0 so the INSERT leaves the column
// NULL (matching how the production store writer behaves) — exercises
// the COALESCE path in loadProxyRows.
func nullableOrInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// insertSummaryCall seeds one row into the D20 summary_calls ledger.
// Used by the summary_calls source-coverage tests below.
func insertSummaryCall(t *testing.T, database *sql.DB, sessionID string, ts time.Time, model string, in, out int64, costUSD float64) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(),
		`INSERT INTO summary_calls (session_id, timestamp, model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cost_usd)
		 VALUES (?, ?, ?, ?, ?, 0, 0, ?)`,
		sessionID, ts.UTC().Format(time.RFC3339Nano), model, in, out, costUSD); err != nil {
		t.Fatalf("insert summary_call: %v", err)
	}
}

// TestSummary_SourceAuto_IncludesSummaryCalls pins the v1.4.43+ cost-
// engine extension: SourceAuto includes the D20 summary_calls ledger
// alongside proxy/JSONL rows so observer cost / get_cost_summary /
// dashboard cost-by-model see the Haiku rolling-summary spend that
// goes direct to api.anthropic.com (bypassing the proxy). Without
// this, totals understated the user's true Anthropic bill by the
// rolling-summ spend.
func TestSummary_SourceAuto_IncludesSummaryCalls(t *testing.T) {
	database := openTestDB(t)
	now := time.Now().UTC()
	insertSummaryCall(t, database, "sess-D20", now.Add(-time.Hour), "claude-haiku-4-5", 5000, 200, 0.0042)
	insertSummaryCall(t, database, "sess-D20", now.Add(-30*time.Minute), "claude-haiku-4-5", 7000, 250, 0.0058)

	got, err := NewEngine(config.IntelligenceConfig{}).Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceAuto, Days: 1,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 2 {
		t.Errorf("TurnCount: got %d want 2 (both summary_calls counted)", got.TurnCount)
	}
	if delta := got.TotalCost - 0.01; delta > 1e-6 || delta < -1e-6 {
		t.Errorf("TotalCost: got %v want 0.01 (sum of cost_usd from ledger)", got.TotalCost)
	}
	if len(got.Rows) != 1 || got.Rows[0].Key != "claude-haiku-4-5" {
		t.Errorf("rows: got %v want one Haiku row", got.Rows)
	}
}

// TestSummary_SourceAuto_TaggedAsObserverTool pins that summary_calls
// rows surface under tool = "observer-rolling-summary" when grouped by
// tool, so the user can see exactly how much of their bill is observer-
// initiated rolling-summ vs natural usage.
func TestSummary_SourceAuto_TaggedAsObserverTool(t *testing.T) {
	database := openTestDB(t)
	now := time.Now().UTC()
	insertSummaryCall(t, database, "sess-D20", now, "claude-haiku-4-5", 1000, 100, 0.001)
	// Add a real proxy turn so we have a non-summary row to compare.
	f := seedSession(t, database, "/repo/r", "sess-real", "claude-code")
	insertAPITurn(t, database, f, now, "claude-sonnet-4-20250514", 100_000, 50_000)

	got, err := NewEngine(config.IntelligenceConfig{}).Summary(context.Background(), database, Options{
		GroupBy: GroupByTool, Source: SourceAuto, Days: 1,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	tools := map[string]bool{}
	for _, row := range got.Rows {
		tools[row.Key] = true
	}
	if !tools["observer-rolling-summary"] {
		t.Errorf("expected an 'observer-rolling-summary' tool row, got %v", tools)
	}
}

// TestSummary_SourceSummaryCallsOnly pins that explicitly selecting the
// summary_calls source skips proxy + jsonl entirely.
func TestSummary_SourceSummaryCallsOnly(t *testing.T) {
	database := openTestDB(t)
	now := time.Now().UTC()
	f := seedSession(t, database, "/repo/r", "sess-real", "claude-code")
	insertAPITurn(t, database, f, now, "claude-sonnet-4-20250514", 100_000, 50_000)
	insertSummaryCall(t, database, "sess-D20", now, "claude-haiku-4-5", 1000, 100, 0.001)

	got, err := NewEngine(config.IntelligenceConfig{}).Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceSummaryCalls, Days: 1,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if got.TurnCount != 1 {
		t.Errorf("TurnCount: got %d want 1 (only the summary_call)", got.TurnCount)
	}
	if len(got.Rows) != 1 || got.Rows[0].Key != "claude-haiku-4-5" {
		t.Errorf("rows: got %v", got.Rows)
	}
}

// seedCompressedTurn inserts a single proxy turn with explicit token
// counts AND compression stats, returning nothing. Used by the V7-6
// tier-weighting tests to set up controlled mixes of Input vs
// CacheRead before asserting on the derived CostSavedUSDEst* columns.
func seedCompressedTurn(t *testing.T, database *sql.DB, f fixture, model string, ts time.Time,
	input, output, cacheRead, cacheCreation, origBytes, compBytes int64,
) {
	t.Helper()
	_, err := database.ExecContext(
		context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
			compression_original_bytes, compression_compressed_bytes,
			compression_count, compression_dropped_count, compression_marker_count)
		 VALUES (?, ?, ?, 'anthropic', ?,
			?, ?, ?, ?,
			?, ?, 1, 0, 0)`,
		f.sessionID, f.projectID, ts.UTC().Format(time.RFC3339Nano), model,
		input, output, cacheRead, cacheCreation,
		nullableOrInt(origBytes), nullableOrInt(compBytes),
	)
	if err != nil {
		t.Fatalf("seedCompressedTurn: %v", err)
	}
}

// TestCostSummary_CompressionSavings_AllInputUsesInputRate pins the
// V7-6 fix's Anthropic-regression case: when the row's tokens are
// all Input (no CacheRead), the weighted CostSavedUSDEst equals the
// upper-bound input-tier column. This is the pre-v1.7.6 behavior —
// Anthropic sessions are largely Input-dominant, so the column
// shouldn't move.
func TestCostSummary_CompressionSavings_AllInputUsesInputRate(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/v76", "sess-input", "claude-code")
	now := time.Now().UTC()
	// 4000 saved bytes → 1000 saved tokens. claude-sonnet-4-20250514:
	// Input=$3/MTok, CacheRead=$0.30/MTok. All Input → weighted == $0.003.
	seedCompressedTurn(t, database, f, "claude-sonnet-4-20250514", now,
		1000, 500, 0, 0,
		4000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(got.Rows))
	}
	c := got.Rows[0].Compression
	if c.TokensSavedEst != 1000 {
		t.Fatalf("TokensSavedEst: got %d want 1000", c.TokensSavedEst)
	}
	const wantInputTier = 0.003 // 1000 * $3/MTok
	if !floatNearV76(c.CostSavedUSDEstInputTier, wantInputTier) {
		t.Errorf("CostSavedUSDEstInputTier: got %f want %f", c.CostSavedUSDEstInputTier, wantInputTier)
	}
	if !floatNearV76(c.CostSavedUSDEst, wantInputTier) {
		t.Errorf("CostSavedUSDEst (weighted): got %f want %f (all-input → matches input tier)", c.CostSavedUSDEst, wantInputTier)
	}
	const wantCacheTier = 0.0003 // 1000 * $0.30/MTok
	if !floatNearV76(c.CostSavedUSDEstCacheReadTier, wantCacheTier) {
		t.Errorf("CostSavedUSDEstCacheReadTier: got %f want %f", c.CostSavedUSDEstCacheReadTier, wantCacheTier)
	}
}

// TestCostSummary_CompressionSavings_AllCacheReadUsesCachedRate pins
// the V7-6 fix's codex-regression case: when the row's tokens are
// all CacheRead (no Input), the weighted CostSavedUSDEst equals the
// lower-bound cache_read-tier column (~10× cheaper than input).
// Pre-v1.7.6 this column showed the input-tier number, overstating
// codex savings ~10×.
func TestCostSummary_CompressionSavings_AllCacheReadUsesCachedRate(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/v76b", "sess-cache", "claude-code")
	now := time.Now().UTC()
	seedCompressedTurn(t, database, f, "claude-sonnet-4-20250514", now,
		0, 500, 1000, 0,
		4000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	c := got.Rows[0].Compression
	const wantCacheTier = 0.0003 // 1000 * $0.30/MTok
	if !floatNearV76(c.CostSavedUSDEstCacheReadTier, wantCacheTier) {
		t.Errorf("CostSavedUSDEstCacheReadTier: got %f want %f", c.CostSavedUSDEstCacheReadTier, wantCacheTier)
	}
	if !floatNearV76(c.CostSavedUSDEst, wantCacheTier) {
		t.Errorf("CostSavedUSDEst (weighted): got %f want %f (all-cache_read → matches cache tier)", c.CostSavedUSDEst, wantCacheTier)
	}
	// Sanity: input-tier column is still populated independently.
	if c.CostSavedUSDEstInputTier <= c.CostSavedUSDEstCacheReadTier {
		t.Errorf("upper-bound input tier (%f) must exceed lower-bound cache_read tier (%f)",
			c.CostSavedUSDEstInputTier, c.CostSavedUSDEstCacheReadTier)
	}
}

// TestCostSummary_CompressionSavings_MixedTierWeightedBlend pins the
// 50/50 mix: weighted lands midway between the two tier columns.
func TestCostSummary_CompressionSavings_MixedTierWeightedBlend(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/v76c", "sess-mix", "claude-code")
	now := time.Now().UTC()
	// 500 Input + 500 CacheRead = 50/50.
	seedCompressedTurn(t, database, f, "claude-sonnet-4-20250514", now,
		500, 200, 500, 0,
		4000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	c := got.Rows[0].Compression
	// 1000 saved tokens × (0.5*$3 + 0.5*$0.30) / 1M = $0.00165.
	const wantWeighted = 0.00165
	if !floatNearV76(c.CostSavedUSDEst, wantWeighted) {
		t.Errorf("CostSavedUSDEst (weighted): got %f want %f", c.CostSavedUSDEst, wantWeighted)
	}
	// Both tier columns still anchored to their pure values.
	if !floatNearV76(c.CostSavedUSDEstInputTier, 0.003) {
		t.Errorf("CostSavedUSDEstInputTier: got %f want 0.003", c.CostSavedUSDEstInputTier)
	}
	if !floatNearV76(c.CostSavedUSDEstCacheReadTier, 0.0003) {
		t.Errorf("CostSavedUSDEstCacheReadTier: got %f want 0.0003", c.CostSavedUSDEstCacheReadTier)
	}
}

// TestCostSummary_CompressionSavings_NoInputSideTokensFallsBackToInputTier
// pins the V7-6 fix's edge case: when a row has compression data and
// output_tokens (so it isn't noise-filtered) but zero input-side
// tokens (rare; e.g. an output-only follow-up turn the proxy logged),
// the weighted column falls back to the upper-bound (input-tier) so
// the value stays consistent with pre-v1.7.6 behavior rather than
// evaluating to 0.
func TestCostSummary_CompressionSavings_NoInputSideTokensFallsBackToInputTier(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/v76d", "sess-out-only", "claude-code")
	now := time.Now().UTC()
	// output_tokens=10 escapes isNoiseRow's all-zero filter; input-side
	// tokens stay at 0 so the inputSlot==0 branch fires in the V7-6
	// weighted-blend logic.
	seedCompressedTurn(t, database, f, "claude-sonnet-4-20250514", now,
		0, 10, 0, 0,
		4000, 0)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(got.Rows))
	}
	c := got.Rows[0].Compression
	const wantInputTier = 0.003
	if !floatNearV76(c.CostSavedUSDEst, wantInputTier) {
		t.Errorf("no-input-side-tokens row weighted column: got %f want %f (input-tier fallback)", c.CostSavedUSDEst, wantInputTier)
	}
}

// TestCostSummary_CompressionSavings_NegativeClippedToZero pins the
// V7-18 fix: when CompressedBytes > OriginalBytes (conversation
// pipeline pass-through under codex-variant recipe inflates wire
// bytes via JSON re-marshaling + envelope overhead), the derived
// TokensSavedEst and all three CostSavedUSDEst* columns clip to 0
// instead of going negative. Raw original_bytes / compressed_bytes
// on the row are preserved so operators can still see the wire
// inflation through observer cost / dashboard / direct SQL.
func TestCostSummary_CompressionSavings_NegativeClippedToZero(t *testing.T) {
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/v718", "sess-passthrough", "claude-code")
	now := time.Now().UTC()
	// origBytes=4000 < compBytes=5000 — pipeline added 1000 bytes of
	// envelope/marker overhead despite no per-type compression firing.
	seedCompressedTurn(t, database, f, "claude-sonnet-4-20250514", now,
		1000, 500, 0, 0,
		4000, 5000)

	e := NewEngine(config.IntelligenceConfig{})
	got, err := e.Summary(context.Background(), database, Options{
		GroupBy: GroupByModel, Source: SourceProxy,
	})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(got.Rows))
	}
	c := got.Rows[0].Compression
	if c.TokensSavedEst != 0 {
		t.Errorf("TokensSavedEst: got %d want 0 (clip-negative)", c.TokensSavedEst)
	}
	if c.CostSavedUSDEst != 0 {
		t.Errorf("CostSavedUSDEst (weighted): got %f want 0", c.CostSavedUSDEst)
	}
	if c.CostSavedUSDEstInputTier != 0 {
		t.Errorf("CostSavedUSDEstInputTier: got %f want 0", c.CostSavedUSDEstInputTier)
	}
	if c.CostSavedUSDEstCacheReadTier != 0 {
		t.Errorf("CostSavedUSDEstCacheReadTier: got %f want 0", c.CostSavedUSDEstCacheReadTier)
	}
	// Raw byte measurements preserved unchanged so operators can still
	// see wire inflation via observer cost / direct SQL.
	if c.OriginalBytes != 4000 {
		t.Errorf("OriginalBytes mutated: got %d want 4000", c.OriginalBytes)
	}
	if c.CompressedBytes != 5000 {
		t.Errorf("CompressedBytes mutated: got %d want 5000", c.CompressedBytes)
	}
}

// floatNearV76 compares two doubles to within $0.00001 — enough
// precision for the V7-6 fixtures (we operate at MTok granularity, so
// the smallest meaningful delta is ~1e-6).
func floatNearV76(a, b float64) bool {
	const eps = 0.00001
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= eps
}

// insertAPITurnWithLatency inserts a proxy row with an explicit
// total_response_ms value. V3-5 surfaces the bucket mean of these.
func insertAPITurnWithLatency(t *testing.T, database *sql.DB, f fixture, ts time.Time, model string, in, out int64, latencyMS int64) {
	t.Helper()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
			input_tokens, output_tokens, total_response_ms)
		 VALUES (?, ?, ?, 'anthropic', ?, ?, ?, ?)`,
		f.sessionID, f.projectID, ts.UTC().Format(time.RFC3339Nano), model, in, out, latencyMS)
	if err != nil {
		t.Fatalf("insert api_turn with latency: %v", err)
	}
}

// TestSummary_AvgLatencyMS (V3-5) pins the per-bucket mean latency.
// Three turns: 100ms, 200ms, 300ms → mean = 200.
func TestSummary_AvgLatencyMS(t *testing.T) {
	t.Parallel()
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/lat", "sess-lat", "claude-code")
	now := time.Now()
	insertAPITurnWithLatency(t, database, f, now.Add(-3*time.Hour), "claude-sonnet-4-6", 1000, 500, 100)
	insertAPITurnWithLatency(t, database, f, now.Add(-2*time.Hour), "claude-sonnet-4-6", 1000, 500, 200)
	insertAPITurnWithLatency(t, database, f, now.Add(-1*time.Hour), "claude-sonnet-4-6", 1000, 500, 300)

	engine := NewEngine(config.IntelligenceConfig{})
	sum, err := engine.Summary(context.Background(), database, Options{Days: 1, GroupBy: GroupByModel, Source: SourceAuto, Limit: 50})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(sum.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(sum.Rows))
	}
	if got := sum.Rows[0].AvgLatencyMS; got != 200 {
		t.Errorf("AvgLatencyMS: got %d, want 200", got)
	}
}

// TestSummary_AvgLatencyMS_ZeroWhenNoProxyRows: JSONL-only buckets
// emit AvgLatencyMS=0 (which JSON omits via omitempty). The text
// renderer in cmd/observer/cost.go shows "-" for the cell.
func TestSummary_AvgLatencyMS_ZeroWhenNoProxyRows(t *testing.T) {
	t.Parallel()
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/lat", "sess-lat", "claude-code")
	now := time.Now()
	insertTokenUsage(t, database, f, now.Add(-1*time.Hour), "claude-code", "claude-sonnet-4-6", 1000, 500, "accurate")

	engine := NewEngine(config.IntelligenceConfig{})
	sum, err := engine.Summary(context.Background(), database, Options{Days: 1, GroupBy: GroupByModel, Source: SourceAuto, Limit: 50})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(sum.Rows) == 0 {
		t.Fatalf("expected at least 1 row")
	}
	if got := sum.Rows[0].AvgLatencyMS; got != 0 {
		t.Errorf("AvgLatencyMS for JSONL-only bucket: got %d, want 0", got)
	}
}

// TestSummary_AvgLatencyMS_IgnoresZeroProxy: a proxy row with
// total_response_ms=0 (unrecorded — old data, mid-flight error)
// shouldn't drag the mean down. Two turns with latency 100 + 0 (zero
// excluded) → mean = 100, not 50.
func TestSummary_AvgLatencyMS_IgnoresZeroProxy(t *testing.T) {
	t.Parallel()
	database := openTestDB(t)
	f := seedSession(t, database, "/repo/lat", "sess-lat", "claude-code")
	now := time.Now()
	insertAPITurnWithLatency(t, database, f, now.Add(-2*time.Hour), "claude-sonnet-4-6", 1000, 500, 100)
	insertAPITurnWithLatency(t, database, f, now.Add(-1*time.Hour), "claude-sonnet-4-6", 1000, 500, 0)

	engine := NewEngine(config.IntelligenceConfig{})
	sum, err := engine.Summary(context.Background(), database, Options{Days: 1, GroupBy: GroupByModel, Source: SourceAuto, Limit: 50})
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(sum.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(sum.Rows))
	}
	if got := sum.Rows[0].AvgLatencyMS; got != 100 {
		t.Errorf("AvgLatencyMS: got %d, want 100 (zero-latency row excluded)", got)
	}
}
