package main

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// cloud_astra_test.go holds the regressions for the 2026-09 adversarial review
// of the cloud evidence lane. Every one of them runs the REAL path — a temp
// store seeded with hostile rows, then buildCloudEnvelope → Serialize — and
// asserts on the SERIALIZED BYTES, because "the builder is careful" is not the
// claim being made. The claim is that nothing reaches the wire.

// astraSeed is one action row, spelled the way the tests need to talk about it.
type astraSeed struct {
	kind       string
	target     string
	toolName   string
	rawInput   string
	errMsg     string
	success    bool
	sidechain  bool
	minute     int
	model      string
	tokenRow   bool
	fast       bool
	cost       float64
	inTok      int
	outTok     int
	webSearch  int
	cacheWrite int
}

// seedAstraSession creates an eligible personal session and its rows. It writes
// the DB directly (not through the store's ingest seams) so a test can express
// row shapes the adapters produce but the seams normalize away — which is
// exactly where the reviewed defects lived.
func seedAstraSession(t *testing.T, dbPath, sessionID, model string, rows []astraSeed) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-08-01T00:00:00Z') RETURNING id`,
		"/tmp/astra/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions,
		                       authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, ?, '2026-08-01T00:00:00Z', '', 0, 'personal', 1)`,
		sessionID, projectID, model); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i, r := range rows {
		ts := base.Add(time.Duration(r.minute) * time.Minute).Format(time.RFC3339Nano)
		if r.tokenRow {
			fast := 0
			if r.fast {
				fast = 1
			}
			if _, err := database.ExecContext(ctx,
				`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
				                          cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens,
				                          reasoning_tokens, web_search_requests, fast, estimated_cost_usd,
				                          source, reliability)
				 VALUES (?, ?, 'claude-code', ?, ?, ?, 0, ?, 0, 0, ?, ?, ?, 'jsonl', 'estimated')`,
				sessionID, ts, r.model, r.inTok, r.outTok, r.cacheWrite, r.webSearch, fast, r.cost); err != nil {
				t.Fatalf("insert token_usage %d: %v", i, err)
			}
			continue
		}
		ok, side := 1, 0
		if !r.success {
			ok = 0
		}
		if r.sidechain {
			side = 1
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
			                      raw_tool_name, raw_tool_input, error_message, is_sidechain,
			                      source_file, source_event_id)
			 VALUES (?, ?, ?, ?, 'claude-code', ?, ?, ?, ?, ?, ?, 'f', ?)`,
			sessionID, projectID, ts, r.kind, ok, r.target, r.toolName, r.rawInput, r.errMsg, side,
			sessionID+"-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
}

// buildAstraEnvelope runs the real build for one purpose and returns the bytes
// plus the parsed envelope.
func buildAstraEnvelope(t *testing.T, dbPath, sessionID string, purpose cloudcontract.Purpose, pricer *cost.Engine) (cloudEnvelopeResult, string) {
	t.Helper()
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	res, err := buildCloudEnvelope(context.Background(), st, sessionID, purpose, pricer)
	if err != nil {
		t.Fatalf("buildCloudEnvelope(%s): %v", purpose, err)
	}
	return res, string(res.Bytes)
}

// --- A1: sub-agent content is never the developer's prompt -------------------

// TestSidechainRowsNeverBecomeExcerpts is the A1 pin, through the real DB.
//
// A Claude sub-agent shares the PARENT session's id, so its delegation brief
// lands as a `user_prompt` row and its reply as an `assistant_message` row in
// the very same table. Both then qualified as the developer's own words: the
// brief as first_user_prompt (it is EARLIER than the real prompt here, exactly
// as a delegation is), the reply as final_assistant_message. A delegation brief
// is where a parent pastes the record it wants analyzed, so this is not a
// cosmetic mislabel — it is the highest-content row in the table shipping under
// the label of the lowest.
func TestSidechainRowsNeverBecomeExcerpts(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	const secret = "customer_balance=12345"
	seedAstraSession(t, dbPath, "side1", "claude-sonnet-5", []astraSeed{
		// The sub-agent's brief arrives FIRST and carries copied tool output.
		{kind: "user_prompt", target: "Analyze this row dump: " + secret, sidechain: true, success: true, minute: 0},
		{kind: "user_prompt", target: "Wire the retry-safe device auth flow", success: true, minute: 1},
		{kind: "run_command", target: "go test ./...", success: true, minute: 2},
		{
			kind: "tool_failure", target: "Bash", errMsg: "row dump follows: " + secret + " (exit code 1)",
			sidechain: true, minute: 3,
		},
		{kind: "tool_failure", target: "Bash", errMsg: "no such file or directory", minute: 4},
		{kind: "assistant_message", target: "Sub-agent report: " + secret, sidechain: true, success: true, minute: 5},
		{kind: "assistant_message", target: "Wired the exchange and the tests are green.", success: true, minute: 6},
	})

	res, body := buildAstraEnvelope(t, dbPath, "side1", cloudcontract.PurposeContextEnrichment, nil)
	if strings.Contains(body, secret) {
		t.Fatalf("a sub-agent row's content reached the upload bytes: %q\n%s", secret, body)
	}
	if len(res.Envelope.Context) == 0 {
		t.Fatal("no excerpts were produced at all — the test would pass vacuously")
	}
	first := res.Envelope.Context[0]
	if first.Source != cloudevidence.SourceFirstUserPrompt {
		t.Fatalf("first excerpt source = %q, want first_user_prompt", first.Source)
	}
	if !strings.HasPrefix(first.Text, "Wire the retry-safe device auth flow") {
		t.Errorf("first_user_prompt = %q, want the developer's OWN first prompt — "+
			"a sub-agent's delegation brief is not the session's prompt", first.Text)
	}
	for _, c := range res.Envelope.Context {
		if c.Source == cloudevidence.SourceFinalAssistantMessage &&
			!strings.HasPrefix(c.Text, "Wired the exchange") {
			t.Errorf("final_assistant_message = %q, want the main thread's last message", c.Text)
		}
	}
	// The main thread's own failure still classifies: the sidechain filter must
	// narrow the population, not empty it.
	sawClass := false
	for _, c := range res.Envelope.Context {
		if c.Source == cloudevidence.SourceErrorClass || c.Source == cloudevidence.SourceErrorClassLast {
			sawClass = true
			if want := cloudevidence.ErrorClassFileNotFound + " x1"; c.Text != want {
				t.Errorf("error class = %q, want %q (only the MAIN-thread failure counts)", c.Text, want)
			}
		}
	}
	if !sawClass {
		t.Error("the main thread's own failure produced no error class")
	}
}

// --- A2: every outbound label is a closed-vocabulary member ------------------

// TestStructuralLabelsAreClosedVocabulary is the A2 pin, through the real DB.
// Three fields carried user-authored strings on the STRUCTURAL lane, which
// promises to carry none: an action's kind, a path-derived category, and the
// model family.
func TestStructuralLabelsAreClosedVocabulary(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedAstraSession(t, dbPath, "labels1", "acme-internal-llm-v3", []astraSeed{
		{kind: "payroll.csv", target: "/tmp/astra/x", success: true, minute: 0},
		{kind: "read_file", target: "/tmp/astra/plan.acme-merger", success: true, minute: 1},
		{kind: "read_file", target: "/tmp/astra/notes.projectthunderclap", success: true, minute: 2},
		{kind: "read_file", target: "/tmp/astra/main.go", success: true, minute: 3},
		{kind: "mcp_call", target: "query", toolName: "mcp__acme-holdings-payroll__query", success: true, minute: 4},
	})

	res, body := buildAstraEnvelope(t, dbPath, "labels1", cloudcontract.PurposeStructuralInsights, nil)
	for _, forbidden := range []string{
		"payroll", "acme-merger", "acmemerger", "projectthunderclap",
		"acme-internal-llm-v3", "acme-holdings",
	} {
		if strings.Contains(body, forbidden) {
			t.Errorf("the structural upload bytes carry the developer-authored string %q\n%s", forbidden, body)
		}
	}
	if res.Envelope.ModelFamily != cloudcontract.ModelFamilyUnknown {
		t.Errorf("model_family = %q, want %q for an unrecognized local model",
			res.Envelope.ModelFamily, cloudcontract.ModelFamilyUnknown)
	}

	kinds := map[string]int{}
	cats := map[string]int{}
	for _, a := range res.Envelope.Actions {
		kinds[a.Kind]++
		cats[a.Category]++
	}
	if kinds["unclassified"] != 1 {
		t.Errorf("kinds = %v, want the off-vocabulary action_type folded into exactly one 'unclassified'", kinds)
	}
	if cats["go"] != 1 {
		t.Errorf("categories = %v, want the real .go extension to survive", cats)
	}
	// The two codename-shaped "extensions" both bucket to other, alongside the
	// MCP call (an unknown server) — which is "mcp", not "other".
	if cats["other"] != 3 {
		t.Errorf("categories = %v, want the two codename extensions plus the untyped path in 'other'", cats)
	}
	if cats[cloudcontract.MCPFamilyFallback] != 1 {
		t.Errorf("categories = %v, want the unknown MCP server in the %q bucket",
			cats, cloudcontract.MCPFamilyFallback)
	}

	// And the whole envelope, field by field: every kind and category is a
	// vocabulary member, so this holds for rows nobody thought to seed.
	assertClosedLabels(t, res.Bytes)
}

// assertClosedLabels re-reads the serialized bytes and checks every action label
// against the closed vocabularies, independently of what the test seeded.
func assertClosedLabels(t *testing.T, raw []byte) {
	t.Helper()
	var env struct {
		ModelFamily string `json:"model_family"`
		Actions     []struct {
			Kind     string `json:"kind"`
			Category string `json:"category"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	families := map[string]bool{}
	for _, f := range cloudcontract.ModelFamilyLabels() {
		families[f] = true
	}
	if !families[env.ModelFamily] {
		t.Errorf("model_family %q is not a member of the closed vocabulary", env.ModelFamily)
	}
	for _, a := range env.Actions {
		if got := cloudevidence.NormalizeActionKind(a.Kind); got != a.Kind {
			t.Errorf("action kind %q is not a vocabulary member (normalizes to %q)", a.Kind, got)
		}
		if got := cloudevidence.NormalizeCategory(a.Category); got != a.Category {
			t.Errorf("action category %q is not a vocabulary member (normalizes to %q)", a.Category, got)
		}
	}
}

// --- A5: whole-session outcomes -------------------------------------------

// TestOutcomesCoverTheWholeSessionAndLongTargets is the A5 pin. Two independent
// truncations each produced a WRONG whole-session claim:
//
//   - the outcome population was a 40k head + 10k tail window, so a build in the
//     middle of a 60k-row session was invisible and "build" reported the outcome
//     of a build that was not the last one;
//   - a row's target was read at 512 bytes, so a command whose program sat past
//     that — `KEY=<600 bytes> go test ./...` — classified as nothing at all.
//
// This session has both shapes. It is deliberately large; the assertion is about
// what the SQL can see, so a smaller one would not exercise it.
func TestOutcomesCoverTheWholeSessionAndLongTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a 60k-action session")
	}
	_, dbPath, _ := writeCloudTestConfig(t)
	const (
		sessionID = "long-outcomes"
		total     = 60000
		buildRow  = 45000
	)
	seedLongAstraSession(t, dbPath, sessionID, total, buildRow)

	res, _ := buildAstraEnvelope(t, dbPath, sessionID, cloudcontract.PurposeStructuralInsights, nil)
	out := res.Envelope.Outcomes
	if out.Build != "failed" {
		t.Errorf("build = %q, want failed — the session's LAST build sits at row %d of %d, "+
			"inside the window a head+tail read omits", out.Build, buildRow, total)
	}
	// Two test runs: the plain one and the long-env-prefixed one, both known.
	if out.TestsRun != 2 || out.TestsPassed != 2 {
		t.Errorf("tests = %d/%d, want 2/2 — one of them carries a 600-byte inline env "+
			"assignment ahead of the program, which a 512-byte target window decapitated",
			out.TestsPassed, out.TestsRun)
	}
}

// seedLongAstraSession writes `total` actions: read_file everywhere except one
// FAILED build in the middle, and two test runs near the end — one of them
// behind a 600-byte inline env assignment.
func seedLongAstraSession(t *testing.T, dbPath, sessionID string, total, buildRow int) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-08-01T00:00:00Z') RETURNING id`,
		"/tmp/astra-long/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions,
		                       authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-sonnet-5', '2026-08-01T00:00:00Z', '', 0, 'personal', 1)`,
		sessionID, projectID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	longEnv := "SBO_LONG_VALUE=" + strings.Repeat("x", 600) + " "
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, raw_tool_input, error_message, is_sidechain, source_file, source_event_id)
		VALUES (?, ?, ?, ?, 'claude-code', ?, ?, '', '', '', 0, 'f', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < total; i++ {
		// edit_file, not read_file: the filler rows must be OUTCOME-BEARING, so
		// the kind-bounded head+tail population is genuinely 60k rows deep and
		// the build below genuinely falls in its omitted middle.
		kind, target, success := "edit_file", "/tmp/astra-long/f"+strconv.Itoa(i)+".go", 1
		switch i {
		case buildRow:
			// The LAST build of the session, and it FAILED. It sits deep in the
			// middle, followed by far more than a tail window's worth of rows.
			kind, target, success = "run_command", "go build ./cmd/observer", 0
		case total - 2:
			kind, target = "run_command", "go test ./internal/store/..."
		case total - 1:
			kind, target = "run_command", longEnv+"go test ./cmd/..."
		}
		if _, err := stmt.ExecContext(ctx, sessionID, projectID,
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			kind, success, target, sessionID+"-a"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("close stmt: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// --- A6: per-row pricing ---------------------------------------------------

// astraPricer builds a cost engine with a fast-tier model, so the fast
// multiplier and the web-search fee are both exercised.
func astraPricer(t *testing.T) *cost.Engine {
	t.Helper()
	e := cost.NewEngine(config.Config{}.Intelligence)
	if _, ok := e.LookupAt(astraPricedModel, astraTokenRowTime(1)); !ok {
		t.Skipf("the seeded pricing table has no %q entry", astraPricedModel)
	}
	return e
}

// astraPricedModel is a model the baked-in dated table prices WITH a fast-tier
// multiplier and a web-search fee, so the complete-bundle assertion has
// something to be complete about.
const astraPricedModel = "gpt-5.6-terra"

// astraTokenRowTime is the instant a seeded row at minute n carries — the same
// instant the envelope prices it at.
func astraTokenRowTime(minute int) time.Time {
	return time.Date(2026, 8, 1, 0, minute, 0, 0, time.UTC)
}

// TestPricingUsesTheCompleteBundlePerRow is the A6 pin. Two independent
// arithmetic defects, each of which makes the reported cost a different number
// rather than a rounder one:
//
//   - the per-row bundle dropped `fast`, `cache_creation_1h_tokens` and
//     `web_search_requests`, so a fast-mode turn priced at the standard rate;
//   - the recorded-vs-estimated choice was made once for the whole session from
//     an aggregate, so ONE adapter-recorded row made every other row free.
func TestPricingUsesTheCompleteBundlePerRow(t *testing.T) {
	pricer := astraPricer(t)
	_, dbPath, _ := writeCloudTestConfig(t)
	seedAstraSession(t, dbPath, "priced-fast", astraPricedModel, []astraSeed{
		{kind: "run_command", target: "go test ./...", success: true, minute: 0},
		{
			tokenRow: true, model: astraPricedModel, inTok: 10000, outTok: 4000,
			cacheWrite: 2000, webSearch: 3, fast: true, minute: 1,
		},
	})
	res, _ := buildAstraEnvelope(t, dbPath, "priced-fast", cloudcontract.PurposeStructuralInsights, pricer)

	want, ok := pricer.ComputeBreakdownAt(astraPricedModel, cost.TokenBundle{
		Input: 10000, Output: 4000, CacheCreation: 2000, WebSearchRequests: 3, Fast: true,
	}, astraTokenRowTime(1))
	if !ok {
		t.Fatal("the pricer could not price the reference bundle")
	}
	if !nearlyEqualUSD(res.Envelope.Metrics.CostUSD, want.Total) {
		t.Errorf("cost = %v, want %v — the envelope must price the COMPLETE bundle "+
			"(fast tier, 1h cache tier, web-search fee), not a subset of it",
			res.Envelope.Metrics.CostUSD, want.Total)
	}
	// Sanity: the defect this pins is not a rounding difference. The same bundle
	// without the fast flag is materially cheaper.
	slow, _ := pricer.ComputeBreakdownAt(astraPricedModel, cost.TokenBundle{
		Input: 10000, Output: 4000, CacheCreation: 2000,
	}, astraTokenRowTime(1))
	if nearlyEqualUSD(slow.Total, want.Total) {
		t.Skip("this pricing table gives fast mode no premium; the assertion above is still exact")
	}
	if nearlyEqualUSD(res.Envelope.Metrics.CostUSD, slow.Total) {
		t.Errorf("cost = %v, which is the STANDARD-tier price of a fast-tier turn", res.Envelope.Metrics.CostUSD)
	}
}

// TestPricingMixesRecordedAndEstimatedRows is the second half of A6: a session
// where one row recorded its own cost and one did not must sum BOTH, not
// suppress pricing for the whole session because the aggregate was non-zero.
func TestPricingMixesRecordedAndEstimatedRows(t *testing.T) {
	pricer := astraPricer(t)
	_, dbPath, _ := writeCloudTestConfig(t)
	seedAstraSession(t, dbPath, "priced-mixed", astraPricedModel, []astraSeed{
		{kind: "run_command", target: "go test ./...", success: true, minute: 0},
		{tokenRow: true, model: astraPricedModel, inTok: 1000, outTok: 500, cost: 0.25, minute: 1},
		{tokenRow: true, model: astraPricedModel, inTok: 20000, outTok: 9000, minute: 2},
	})
	res, _ := buildAstraEnvelope(t, dbPath, "priced-mixed", cloudcontract.PurposeStructuralInsights, pricer)

	priced, ok := pricer.ComputeBreakdownAt(astraPricedModel, cost.TokenBundle{Input: 20000, Output: 9000},
		astraTokenRowTime(2))
	if !ok {
		t.Fatal("the pricer could not price the reference bundle")
	}
	want := 0.25 + priced.Total
	if !nearlyEqualUSD(res.Envelope.Metrics.CostUSD, want) {
		t.Errorf("cost = %v, want %v (the recorded row's 0.25 PLUS the priced row) — "+
			"one recorded row must not make the rest of the session free",
			res.Envelope.Metrics.CostUSD, want)
	}
	if nearlyEqualUSD(res.Envelope.Metrics.CostUSD, 0.25) {
		t.Error("the session priced as its ONE recorded row and nothing else")
	}
}

func nearlyEqualUSD(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}

// --- A8: the error-class distribution is the session's ----------------------

// TestErrorClassesCoverEveryFailure is the A8 pin. The counts are presented as
// whole-session facts, but only `tool_failure` rows entered and only a
// 1,600-head + 400-tail window of them. This session's DOMINANT class lives in
// the omitted middle and is carried on rows of another kind, so both halves of
// the defect are exercised at once.
func TestErrorClassesCoverEveryFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a 4k-failure session")
	}
	_, dbPath, _ := writeCloudTestConfig(t)
	seedFailureHeavyAstraSession(t, dbPath, "errors1")

	res, _ := buildAstraEnvelope(t, dbPath, "errors1", cloudcontract.PurposeContextEnrichment, nil)
	classes := map[string]string{}
	for _, c := range res.Envelope.Context {
		if c.Source == cloudevidence.SourceErrorClass || c.Source == cloudevidence.SourceErrorClassLast {
			field := strings.Fields(c.Text)
			classes[field[0]] = c.Text
		}
	}
	if _, ok := classes[cloudevidence.ErrorClassTestFailure]; !ok {
		t.Fatalf("the session's DOMINANT failure class is missing from %v — it lives in the "+
			"middle of the population, which a head+tail window omits", classes)
	}
	if got := classes[cloudevidence.ErrorClassTestFailure]; got != cloudevidence.ErrorClassTestFailure+" x3000" {
		t.Errorf("test_failure count = %q, want the WHOLE population's count (x3000)", got)
	}
	if got := classes[cloudevidence.ErrorClassRateLimited]; got != cloudevidence.ErrorClassRateLimited+" x800" {
		t.Errorf("rate_limited = %q, want %q — a failure recorded on a non-tool_failure row "+
			"(success = 0 with an error message) is still a failure of this session, and this "+
			"one is the session's SECOND most frequent class",
			got, cloudevidence.ErrorClassRateLimited+" x800")
	}
	if got := classes[cloudevidence.ErrorClassPermissionDenied]; got == "" {
		t.Errorf("classes = %v — the session's LAST observed class must ride along even when "+
			"it is not one of the top two", classes)
	}
}

// seedFailureHeavyAstraSession writes 4,000 failures: a head of file_not_found,
// a MIDDLE of 3,000 test_failure (the dominant class, sitting inside the window
// a 1,600-head + 400-tail read omits), a run of 800 rate_limited recorded on
// `run_command` rows rather than `tool_failure` (so the kind filter is exercised
// on a class that RANKS, not one that would be dropped anyway), and a tail of
// permission_denied — which is the session's LAST class.
func seedFailureHeavyAstraSession(t *testing.T, dbPath, sessionID string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-08-01T00:00:00Z') RETURNING id`,
		"/tmp/astra-fail/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions,
		                       authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-sonnet-5', '2026-08-01T00:00:00Z', '', 0, 'personal', 1)`,
		sessionID, projectID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, raw_tool_input, error_message, is_sidechain, source_file, source_event_id)
		VALUES (?, ?, ?, ?, 'claude-code', 0, 'Bash', '', '', ?, 0, 'f', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	// A real prompt, so the excerpt set is not empty.
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, raw_tool_input, error_message, is_sidechain, source_file, source_event_id)
		VALUES (?, ?, ?, 'user_prompt', 'claude-code', 1, 'make the suite green', '', '', '', 0, 'f', ?)`,
		sessionID, projectID, base.Format(time.RFC3339Nano), sessionID+"-prompt"); err != nil {
		t.Fatalf("insert prompt: %v", err)
	}
	type band struct {
		kind, msg string
		n         int
	}
	bands := []band{
		{"tool_failure", "no such file or directory", 100},
		{"tool_failure", "--- FAIL: TestThing (0.01s)", 3000},
		{"run_command", "http 429 from the provider", 800},
		{"tool_failure", "permission denied", 100},
	}
	i := 1
	for _, b := range bands {
		for k := 0; k < b.n; k++ {
			if _, err := stmt.ExecContext(ctx, sessionID, projectID,
				base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
				b.kind, b.msg, sessionID+"-e"+strconv.Itoa(i)); err != nil {
				t.Fatalf("insert failure %d: %v", i, err)
			}
			i++
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("close stmt: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
