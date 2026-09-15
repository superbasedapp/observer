package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudclient"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestCloudStandardTaxonomyTags pins the auto-merge rule: only slugs from the
// curated vocabulary reach the user's own session_tags. An off-vocabulary slug
// is dropped silently here (it stays visible on the result itself).
func TestCloudStandardTaxonomyTags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"all standard", []string{"bugfix", "backend"}, []string{"bugfix", "backend"}},
		{"off-vocab dropped", []string{"bugfix", "not-a-real-tag", "backend"}, []string{"bugfix", "backend"}},
		{"all off-vocab", []string{"weird", "thing"}, nil},
		{"dedupes", []string{"test", "test", "cli"}, []string{"test", "cli"}},
		{"trims", []string{"  test  "}, []string{"test"}},
		{"empty in", nil, nil},
		{"blank entries", []string{"", "   "}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cloudStandardTaxonomyTags(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// seedRichCloudSession seeds a session with the shape a real one has: no
// ended_at, total_actions=0, a mix of action kinds, a harness-injected prompt
// ahead of the real one, tests and a build, and a failure.
func seedRichCloudSession(t *testing.T, dbPath, sessionID string) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/cloud-rich/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	// No ended_at and total_actions = 0: the common real shape.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions, authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-sonnet-5', '2026-06-09T00:00:00Z', '', 0, 'personal', 1)`,
		sessionID, projectID); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	type row struct {
		kind, target, toolName, errMsg, rawInput string
		success                                  bool
		minute                                   int
	}
	rows := []row{
		{kind: "user_prompt", target: "<command-name>/clear</command-name>", success: true, minute: 0},
		{kind: "user_prompt", target: "▎ Wire the retry-safe device auth flow", rawInput: "▎ Wire the retry-safe device auth flow\n▎ and cover it with tests.", success: true, minute: 1},
		{kind: "read_file", target: "/tmp/cloud-rich/internal/store/store.go", success: true, minute: 2},
		{kind: "run_command", target: "SECRET=/tmp/private/token git status --porcelain", success: true, minute: 3},
		{kind: "edit_file", target: "/tmp/cloud-rich/internal/store/store.go", success: true, minute: 4},
		{kind: "run_command", target: "go test ./internal/store/...", success: false, minute: 5},
		{kind: "tool_failure", target: "Bash", errMsg: "Exit code 1", success: false, minute: 6},
		{kind: "run_command", target: "go test ./internal/store/...", success: true, minute: 7},
		{kind: "run_command", target: "go build ./cmd/observer", success: true, minute: 8},
		{kind: "mcp_call", target: "navigate", toolName: "mcp__claude-in-chrome__navigate", success: true, minute: 9},
		{kind: "assistant_message", target: "Wired the exchange and the tests are green.", success: true, minute: 10},
		{kind: "task_complete", target: "done", success: true, minute: 11},
	}
	for i, r := range rows {
		ok := 0
		if r.success {
			ok = 1
		}
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
			                      raw_tool_name, raw_tool_input, error_message, source_file, source_event_id)
			 VALUES (?, ?, ?, ?, 'claude-code', ?, ?, ?, ?, ?, 'f', ?)`,
			sessionID, projectID, base.Add(time.Duration(r.minute)*time.Minute).Format(time.RFC3339Nano),
			r.kind, ok, r.target, r.toolName, r.rawInput, r.errMsg,
			sessionID+"-"+r.kind+"-"+string(rune('a'+i))); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
		                          cache_read_tokens, cache_creation_tokens, estimated_cost_usd, source, reliability)
		 VALUES (?, '2026-06-09T00:05:00Z', 'claude-code', 'claude-sonnet-5', 1200, 4300, 55000, 900, 0, 'jsonl', 'estimated')`,
		sessionID); err != nil {
		t.Fatalf("insert token usage: %v", err)
	}
}

// TestCloudEnvelopeCarriesStructuralSignal proves the structural envelope now
// carries the whole-session shape (metrics, activity mix, milestones, outcomes,
// a real duration) and STILL carries zero content.
func TestCloudEnvelopeCarriesStructuralSignal(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "rich1")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	res, err := buildCloudEnvelope(context.Background(), st, "rich1", cloudcontract.PurposeStructuralInsights, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	env := res.Envelope

	if env.Metrics.TokensIn != 1200 || env.Metrics.TokensOut != 4300 || env.Metrics.CacheReadTokens != 55000 {
		t.Errorf("metrics = %+v, want the summed token_usage row", env.Metrics)
	}
	// 2 of 12 actions failed.
	if env.Metrics.ErrorRate <= 0.16 || env.Metrics.ErrorRate >= 0.17 {
		t.Errorf("error_rate = %v, want ~0.1667", env.Metrics.ErrorRate)
	}
	// ended_at is empty, so the duration must fall back to the action span.
	if env.DurationSeconds != 11*60 {
		t.Errorf("duration = %d s, want %d (action-span fallback)", env.DurationSeconds, 11*60)
	}

	mix := map[string]int{}
	for _, e := range env.ActivityMix {
		mix[e.Key] = e.Count
	}
	if mix["run_command"] != 4 || mix["user_prompt"] != 2 || mix["edit_file"] != 1 {
		t.Errorf("activity_mix = %+v, want the whole-session histogram", env.ActivityMix)
	}

	milestones := map[string]int{}
	for _, m := range env.Milestones {
		milestones[m.Kind] = m.ElapsedSeconds
	}
	for kind, want := range map[string]int{
		"first_command": 180, "first_edit": 240, "first_test": 300,
		"first_error": 300, "first_task_complete": 660,
	} {
		if got, ok := milestones[kind]; !ok || got != want {
			t.Errorf("milestone %s = %d (present %v), want %d", kind, got, ok, want)
		}
	}

	if env.Outcomes.TestsRun != 2 || env.Outcomes.TestsPassed != 1 {
		t.Errorf("outcomes tests = %d/%d, want 1/2", env.Outcomes.TestsPassed, env.Outcomes.TestsRun)
	}
	if env.Outcomes.Build != "passed" {
		t.Errorf("outcomes build = %q, want passed", env.Outcomes.Build)
	}

	cats := map[string]bool{}
	for _, a := range env.Actions {
		cats[a.Category] = true
	}
	for _, want := range []string{"git", "test", "build", "go", "browser"} {
		if !cats[want] {
			t.Errorf("category %q missing from %v", want, cats)
		}
	}

	// The "Title only" set (2026-09-16): a structural build under today's
	// per-upload receipt carries EXACTLY the first real prompt - the one
	// excerpt every consent screen at that level names - and nothing else.
	if !env.ContextIsFirstPromptOnly() {
		t.Fatalf("structural envelope context = %+v, want exactly one first_user_prompt excerpt", env.Context)
	}
	if !strings.HasPrefix(env.Context[0].Text, "Wire the retry-safe device auth flow") {
		t.Errorf("first excerpt = %q; want the first REAL prompt (harness injections skipped)", env.Context[0].Text)
	}
	// The privacy floor: no fragment of a command, a path, an error message or
	// the assistant's text - only that one prompt.
	body := string(res.Bytes)
	for _, forbidden := range []string{"/tmp/private/token", "SECRET=", "Exit code 1", "internal/store/store.go"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("structural upload bytes leaked %q", forbidden)
		}
	}

	// A receipt minted BEFORE the first-prompt class existed rebuilds to the
	// classless bytes: no context at all, no prompt text - the send-time
	// digest re-check depends on this.
	legacy, err := buildCloudEnvelopeFor(context.Background(), st, "rich1", cloudcontract.PurposeStructuralInsights, []string{
		string(cloudcontract.FieldClassIdentityLinkage),
		string(cloudcontract.FieldClassStructuralMetrics),
		string(cloudcontract.FieldClassPaths),
	}, nil)
	if err != nil {
		t.Fatalf("legacy build: %v", err)
	}
	if len(legacy.Envelope.Context) != 0 {
		t.Fatalf("classless structural envelope carried %d excerpts", len(legacy.Envelope.Context))
	}
	if strings.Contains(string(legacy.Bytes), "retry-safe") {
		t.Errorf("classless structural upload bytes leaked the first prompt")
	}
	if legacy.Digests.Upload == res.Digests.Upload {
		t.Errorf("the title-only and classless builds must not share an upload digest")
	}
}

// TestCloudEnvelopeContextPurposeCarriesExcerpts proves --purpose
// bounded_context_enrichment produces the excerpt set end to end, in priority
// order, with the harness prompt skipped and the paste bars stripped.
func TestCloudEnvelopeContextPurposeCarriesExcerpts(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "rich2")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	res, err := buildCloudEnvelope(context.Background(), st, "rich2", cloudcontract.PurposeContextEnrichment, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	env := res.Envelope
	if len(env.Context) == 0 {
		t.Fatal("bounded_context_enrichment produced no excerpts")
	}
	if env.Context[0].Source != cloudevidence.SourceFirstUserPrompt {
		t.Fatalf("first excerpt source = %q, want first_user_prompt", env.Context[0].Source)
	}
	if !strings.HasPrefix(env.Context[0].Text, "Wire the retry-safe device auth flow") {
		t.Errorf("first excerpt = %q; want the first REAL prompt with paste bars stripped", env.Context[0].Text)
	}
	sources := map[string]bool{}
	for _, c := range env.Context {
		sources[c.Source] = true
		if c.LengthCapBytes > cloudcontract.MaxExcerptBytes {
			t.Errorf("excerpt cap %d exceeds MaxExcerptBytes", c.LengthCapBytes)
		}
		if strings.Contains(c.Text, "<command-name>") {
			t.Errorf("harness prompt reached the envelope: %q", c.Text)
		}
	}
	if !sources[cloudevidence.SourceFinalAssistantMessage] {
		t.Error("the final assistant message is missing")
	}
	if !sources[cloudevidence.SourceErrorClass] {
		t.Error("the recorded tool failure is missing")
	}
	// F1 + Q1: the failure ships as a CLASS LABEL plus an occurrence count,
	// never as the message.
	for _, c := range env.Context {
		if c.Source != cloudevidence.SourceErrorClass && c.Source != cloudevidence.SourceErrorClassLast {
			continue
		}
		if want := cloudevidence.ErrorClassExitCodeNonzero + " x1"; c.Text != want {
			t.Errorf("error_class excerpt = %q, want the closed label + count %q", c.Text, want)
		}
	}
	// Commands, tool outputs and paths still never ship.
	body := string(res.Bytes)
	for _, forbidden := range []string{"/tmp/private/token", "SECRET=", "go build ./cmd/observer", "internal/store/store.go"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("context upload bytes leaked %q", forbidden)
		}
	}
}

// TestCloudEnvelopeRebuildIsByteStable pins that the richer envelope is still
// deterministic — the whole reconfirmation protocol rests on it.
func TestCloudEnvelopeRebuildIsByteStable(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "rich3")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	ctx := context.Background()
	for _, p := range []cloudcontract.Purpose{
		cloudcontract.PurposeStructuralInsights,
		cloudcontract.PurposeContextEnrichment,
	} {
		a, err := buildCloudEnvelope(ctx, st, "rich3", p, nil)
		if err != nil {
			t.Fatalf("%s build A: %v", p, err)
		}
		b, err := buildCloudEnvelope(ctx, st, "rich3", p, nil)
		if err != nil {
			t.Fatalf("%s build B: %v", p, err)
		}
		if string(a.Bytes) != string(b.Bytes) || a.Digests.Upload != b.Digests.Upload {
			t.Fatalf("%s: rebuild was not byte-stable", p)
		}
	}
}

// TestCloudFieldClassesJSONUsesTheClosedVocabulary pins that a per-upload
// receipt binds real cloudcontract.FieldClass values, never a purpose name in
// the field-class slot, and that the context purpose is a strict superset of
// the structural one.
func TestCloudFieldClassesJSONUsesTheClosedVocabulary(t *testing.T) {
	valid := map[string]bool{}
	for _, fc := range cloudcontract.AllFieldClasses() {
		valid[string(fc)] = true
	}
	decode := func(p cloudcontract.Purpose) []string {
		var out []string
		if err := json.Unmarshal([]byte(cloudFieldClassesJSON(p)), &out); err != nil {
			t.Fatalf("%s: field classes are not a JSON array: %v", p, err)
		}
		for _, c := range out {
			if !valid[c] {
				t.Errorf("%s: %q is not a cloudcontract field class", p, c)
			}
		}
		return out
	}
	structural := decode(cloudcontract.PurposeStructuralInsights)
	contextual := decode(cloudcontract.PurposeContextEnrichment)
	if len(structural) == 0 || len(contextual) <= len(structural) {
		t.Fatalf("structural=%v contextual=%v; the context purpose must be a strict superset", structural, contextual)
	}
	for _, c := range structural {
		found := false
		for _, d := range contextual {
			if c == d {
				found = true
			}
		}
		if !found {
			t.Errorf("structural class %q missing from the context purpose", c)
		}
	}
	sawExcerpts := false
	for _, c := range contextual {
		if c == string(cloudcontract.FieldClassContentExcerpts) {
			sawExcerpts = true
		}
	}
	if !sawExcerpts {
		t.Error("the context purpose does not bind content_excerpts")
	}
	// An unmodelled purpose says nothing rather than fabricating a class.
	if got := cloudFieldClassesJSON(cloudcontract.PurposeResearch); got != "[]" {
		t.Errorf("unmodelled purpose = %s, want []", got)
	}
}

// seedPricedCloudSession seeds an eligible session whose token_usage rows carry
// NO recorded cost, so the envelope's cost must come from the pricer.
func seedPricedCloudSession(t *testing.T, dbPath, sessionID string, rows []pricedTokenRow) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/cloud-priced/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions, authority, authority_classifier_version)
		 VALUES (?, 'codex', ?, ?, ?, '', 0, 'personal', 1)`,
		sessionID, projectID, rows[0].model, rows[0].ts); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	for i, r := range rows {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
			                         cache_read_tokens, cache_creation_tokens, reasoning_tokens,
			                         estimated_cost_usd, source, reliability, source_file, source_event_id)
			VALUES (?, ?, 'codex', ?, ?, ?, 0, 0, 0, 0, 'jsonl', 'estimated', 'f', ?)`,
			sessionID, r.ts, r.model, r.in, r.out, sessionID+"-t"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert token row %d: %v", i, err)
		}
	}
}

type pricedTokenRow struct {
	ts    string
	model string
	in    int
	out   int
}

// TestCloudSessionCostIsPricedPerTokenRow is the F5 pin. Pricing the SESSION's
// summed tokens as one turn is wrong in two independent ways, and this exercises
// both: it crosses a long-context threshold the session never crossed, and it
// collapses two models onto one rate card. The cost must be the SUM of per-row
// prices.
func TestCloudSessionCostIsPricedPerTokenRow(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	rows := []pricedTokenRow{
		// Three big-but-not-long-context turns on one model...
		{ts: "2026-08-01T00:00:00Z", model: "gpt-5.6-terra", in: 150_000, out: 2_000},
		{ts: "2026-08-01T01:00:00Z", model: "gpt-5.6-terra", in: 150_000, out: 2_000},
		// ...plus one on a DIFFERENT model, at a different rate card.
		{ts: "2026-08-01T02:00:00Z", model: "gpt-5.6-luna", in: 50_000, out: 1_000},
	}
	seedPricedCloudSession(t, dbPath, "priced1", rows)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	engine := cost.NewEngine(config.Config{}.Intelligence)
	res, err := buildCloudEnvelope(context.Background(), st, "priced1", cloudcontract.PurposeStructuralInsights, engine)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	var want float64
	for _, r := range rows {
		ts, perr := time.Parse(time.RFC3339, r.ts)
		if perr != nil {
			t.Fatalf("parse ts: %v", perr)
		}
		b, ok := engine.ComputeBreakdownAt(r.model, cost.TokenBundle{
			Input: int64(r.in), Output: int64(r.out),
		}, ts)
		if !ok {
			t.Fatalf("no pricing for %q — pick a modelled model for this test", r.model)
		}
		want += b.Total
	}
	if want <= 0 {
		t.Fatal("fixture produced a zero expected cost")
	}
	if diff := res.Envelope.Metrics.CostUSD - want; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("cost = %v, want the per-row sum %v", res.Envelope.Metrics.CostUSD, want)
	}

	// The pre-fix behaviour, for contrast: ONE bundle of every token on the
	// session's own model, priced at the session start. It must differ.
	oneShot, ok := engine.ComputeBreakdownAt("gpt-5.6-terra", cost.TokenBundle{
		Input: 350_000, Output: 5_000,
	}, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if !ok {
		t.Fatal("no pricing for the one-shot control")
	}
	if diff := oneShot.Total - want; diff < 1e-6 && diff > -1e-6 {
		t.Fatal("the one-shot control equals the per-row sum — this fixture cannot detect the defect")
	}
	if res.Envelope.Metrics.CostUSD >= oneShot.Total {
		t.Errorf("cost %v is not below the one-shot long-context price %v — the surcharge was invented",
			res.Envelope.Metrics.CostUSD, oneShot.Total)
	}
}

// TestCloudSessionCostPrefersRecordedCost keeps the existing rule: when an
// adapter recorded a non-zero per-turn cost, that wins over any estimate.
func TestCloudSessionCostPrefersRecordedCost(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedRichCloudSession(t, dbPath, "priced2")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`UPDATE token_usage SET estimated_cost_usd = 1.25 WHERE session_id = ?`, "priced2"); err != nil {
		t.Fatalf("set recorded cost: %v", err)
	}
	database.Close()

	res, err := buildCloudEnvelope(ctx, st, "priced2", cloudcontract.PurposeStructuralInsights,
		cost.NewEngine(config.Config{}.Intelligence))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if diff := res.Envelope.Metrics.CostUSD - 1.25; diff > 1e-9 || diff < -1e-9 {
		t.Errorf("cost = %v, want the recorded 1.25", res.Envelope.Metrics.CostUSD)
	}
}

// TestCloudEnvelopeOutcomesComeFromTheWholeSession is the F6 pin at the CLI
// surface: a test run past the action SAMPLE must still be counted.
func TestCloudEnvelopeOutcomesComeFromTheWholeSession(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedWideCloudSession(t, dbPath, "wide1", 3000)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	res, err := buildCloudEnvelope(context.Background(), st, "wide1", cloudcontract.PurposeStructuralInsights, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	env := res.Envelope
	if env.Outcomes.TestsRun != 1 || env.Outcomes.TestsPassed != 1 {
		t.Errorf("outcomes tests = %d/%d, want 1/1 from the session tail", env.Outcomes.TestsPassed, env.Outcomes.TestsRun)
	}
	if env.Outcomes.Build != "passed" {
		t.Errorf("build = %q, want passed from the session tail", env.Outcomes.Build)
	}
	if env.Overflow == nil || env.Overflow.ActionsOmitted != 3000-len(env.Actions) {
		t.Errorf("overflow = %+v, want %d omitted of a 3000-action session", env.Overflow, 3000-len(env.Actions))
	}
	if len(env.Actions) == 0 || env.Actions[len(env.Actions)-1].Ref != "a2999" {
		t.Errorf("last sampled ref = %q, want a2999", env.Actions[len(env.Actions)-1].Ref)
	}
	milestones := map[string]bool{}
	for _, m := range env.Milestones {
		milestones[m.Kind] = true
	}
	if !milestones["first_test"] {
		t.Error("first_test milestone missing — milestones were derived from the sample")
	}
}

// seedWideCloudSession seeds n actions where only the LAST few are outcome-
// bearing, so anything derived from a 256-row sample misses them.
func seedWideCloudSession(t *testing.T, dbPath, sessionID string, n int) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/cloud-wide/"+sessionID).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions, authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-sonnet-5', '2026-06-09T00:00:00Z', '', 0, 'personal', 1)`,
		sessionID, projectID); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, raw_tool_input, error_message, source_file, source_event_id)
		VALUES (?, ?, ?, ?, 'claude-code', 1, ?, '', '', '', 'f', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	for i := 0; i < n; i++ {
		kind, target := "read_file", "/tmp/cloud-wide/f"+strconv.Itoa(i)+".go"
		switch i {
		case n - 2:
			kind, target = "run_command", "go build ./cmd/observer"
		case n - 1:
			kind, target = "run_command", "go test ./internal/..."
		}
		if _, err := stmt.ExecContext(ctx, sessionID, projectID,
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			kind, target, sessionID+"-a"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// TestDigestMismatchStaysTerminalAndExplainsItself pins the F4 disposition: a
// server 422 digest_mismatch is TERMINAL today (re-sending identical bytes to
// the same server cannot succeed) and it stays that way — but the CLI must name
// the likeliest cause, which is a server that predates this node's envelope
// version, rather than leaving the operator with a bare "FAILED (terminal)".
func TestDigestMismatchStaysTerminalAndExplainsItself(t *testing.T) {
	err422 := &cloudclient.APIError{
		StatusCode: http.StatusUnprocessableEntity,
		Body:       `{"error":"upload digest does not match the body","code":"digest_mismatch"}`,
	}
	if !cloudUploadTerminal(err422) {
		t.Fatal("precondition changed: 422 digest_mismatch is no longer terminal — revisit the hint copy")
	}
	if got := cloudErrClass(err422); got != "http_422" {
		t.Errorf("error class = %q, want http_422", got)
	}
	d, ok := cloudgateway.HTTPError(err422)
	if !ok || d.Code != cloudErrCodeDigestMismatch {
		t.Fatalf("HTTPError = (%+v, %v), want code %q", d, ok, cloudErrCodeDigestMismatch)
	}
	for _, want := range []string{"PREDATES", "rolls BEFORE nodes", "observer cloud consent"} {
		if !strings.Contains(cloudDigestMismatchHint, want) {
			t.Errorf("the digest-mismatch hint does not mention %q: %s", want, cloudDigestMismatchHint)
		}
	}
}
