package store

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// seedLongCloudSession seeds one eligible session with n actions in time order.
// Action i is a read_file, EXCEPT the two at the very end, which are a build and
// a test run — deliberately past every historical scan bound, so a test can
// assert that outcomes come from the whole population and not from a prefix.
func seedLongCloudSession(t *testing.T, s *Store, database *sql.DB, sessionID string, n int) {
	t.Helper()
	ctx := context.Background()
	seedEligibleSession(t, s, sessionID)

	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, sessionID).Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, error_message, source_file, source_event_id)
		VALUES (?, ?, ?, ?, 'claude-code', ?, ?, '', ?, 'f', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		kind, target, errMsg := "read_file", "/tmp/long/file"+strconv.Itoa(i)+".go", ""
		success := 1
		switch {
		case i == n-2:
			kind, target = "run_command", "go build ./cmd/observer"
		case i == n-1:
			kind, target = "run_command", "go test ./internal/store/..."
		case i == n-3:
			kind, target, errMsg, success = "tool_failure", "Bash", "Exit code 1", 0
		}
		if _, err := stmt.ExecContext(ctx, sessionID, projectID,
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			kind, success, target, errMsg, sessionID+"-a"+strconv.Itoa(i)); err != nil {
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

// TestLoadCloudEvidenceFactsSamplesTheWholePopulation is the F6 pin for actions:
// a session far past the old 20,000-row scan bound must still be SAMPLED across
// its whole length — the last action present, the omission count true, and the
// outcome-bearing rows in the TAIL still counted.
func TestLoadCloudEvidenceFactsSamplesTheWholePopulation(t *testing.T) {
	s, database := cloudTestStore(t)
	const total = 30000
	seedLongCloudSession(t, s, database, "long1", total)

	const maxActions = 256
	facts, ok, err := s.LoadCloudEvidenceFacts(context.Background(), "long1", maxActions)
	if err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceFacts: ok=%v err=%v", ok, err)
	}
	if facts.ActionCount != total {
		t.Fatalf("ActionCount = %d, want %d", facts.ActionCount, total)
	}
	if len(facts.Actions) == 0 || len(facts.Actions) > maxActions+1 {
		t.Fatalf("sampled %d actions, want 1..%d", len(facts.Actions), maxActions+1)
	}
	first, last := facts.Actions[0], facts.Actions[len(facts.Actions)-1]
	if first.Ref != "a0" {
		t.Errorf("first sampled ref = %q, want a0", first.Ref)
	}
	if want := "a" + strconv.Itoa(total-1); last.Ref != want {
		t.Errorf("last sampled ref = %q, want %q — the tail of the session was truncated away", last.Ref, want)
	}
	// The sample must SPAN the session, not cluster in its prefix: the median
	// sampled ref should sit near the middle.
	mid := facts.Actions[len(facts.Actions)/2]
	midIdx, err := strconv.Atoi(mid.Ref[1:])
	if err != nil {
		t.Fatalf("ref %q is not aN: %v", mid.Ref, err)
	}
	if midIdx < total/4 || midIdx > 3*total/4 {
		t.Errorf("median sampled ref %q is not near the middle of a %d-action session", mid.Ref, total)
	}

	// Outcome-bearing rows live past the old bound; the kind-bounded population
	// must still carry them.
	sawTest, sawBuild, sawFailure := false, false, false
	for _, a := range facts.OutcomeActions {
		switch {
		case a.Kind == "run_command" && a.Target == "go test ./internal/store/...":
			sawTest = true
		case a.Kind == "run_command" && a.Target == "go build ./cmd/observer":
			sawBuild = true
		case a.Kind == "tool_failure":
			sawFailure = true
		}
	}
	if !sawTest || !sawBuild || !sawFailure {
		t.Errorf("outcome population missing tail rows: test=%v build=%v failure=%v (%d rows)",
			sawTest, sawBuild, sawFailure, len(facts.OutcomeActions))
	}
	// The population is KIND-bounded, not a second full scan.
	if len(facts.OutcomeActions) > 100 {
		t.Errorf("outcome population = %d rows, want only the outcome-bearing kinds", len(facts.OutcomeActions))
	}

	// Whole-session aggregates stay exact past every bound.
	mix := map[string]int{}
	for _, kc := range facts.ActivityMix {
		mix[kc.Kind] = kc.Count
	}
	if mix["read_file"] != total-3 || mix["run_command"] != 2 || mix["tool_failure"] != 1 {
		t.Errorf("activity mix = %v, want the whole-session histogram", mix)
	}
	if facts.FailedActions != 1 {
		t.Errorf("FailedActions = %d, want 1", facts.FailedActions)
	}
}

// TestLoadCloudSessionTextsSamplesPromptsAcrossTheSession is the F6 pin for
// prompts: past the old 200-row head window the LAST prompt must still be
// reachable, while the first REAL prompt (the harness injections skipped) is
// still the earliest one.
func TestLoadCloudSessionTextsSamplesPromptsAcrossTheSession(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	seedEligibleSession(t, s, "prompts1")
	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, "prompts1").Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	const total = 500
	for i := 0; i < total; i++ {
		body := fmt.Sprintf("real prompt number %d with enough words to be distinct", i)
		if i < 2 {
			body = "<command-name>/clear</command-name>"
		}
		if _, err := database.ExecContext(ctx, `
			INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
			                     raw_tool_name, error_message, source_file, source_event_id)
			VALUES (?, ?, ?, 'user_prompt', 'claude-code', 1, ?, '', '', 'f', ?)`,
			"prompts1", projectID, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			body, "prompts1-p"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert prompt %d: %v", i, err)
		}
	}

	texts, err := s.LoadCloudSessionTexts(ctx, "prompts1")
	if err != nil {
		t.Fatalf("LoadCloudSessionTexts: %v", err)
	}
	if len(texts.UserPrompts) == 0 {
		t.Fatal("no prompts returned")
	}
	if len(texts.UserPrompts) > cloudMaxPromptRows {
		t.Fatalf("returned %d prompts, exceeds the %d bound", len(texts.UserPrompts), cloudMaxPromptRows)
	}
	// The harness injections come first and the first REAL prompt right after
	// them, so the pure selector's "first real prompt" is still the earliest one.
	if texts.UserPrompts[0] != "<command-name>/clear</command-name>" {
		t.Errorf("first returned prompt = %q, want the earliest row", texts.UserPrompts[0])
	}
	joined := texts.UserPrompts
	hasFirstReal, hasLast := false, false
	for _, p := range joined {
		if p == "real prompt number 2 with enough words to be distinct" {
			hasFirstReal = true
		}
		if p == fmt.Sprintf("real prompt number %d with enough words to be distinct", total-1) {
			hasLast = true
		}
	}
	if !hasFirstReal {
		t.Error("the first REAL prompt is missing from the head window")
	}
	if !hasLast {
		t.Error("the session's LAST prompt is missing — prompts are still prefix-truncated")
	}
}

// TestLoadCloudEvidenceFactsCarriesPerTurnTokenRows is the F5 pin: the CLI must
// be able to price each token_usage row on its OWN model and date, so the store
// hands the per-row facts through the seam rather than only a summed bundle.
func TestLoadCloudEvidenceFactsCarriesPerTurnTokenRows(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	seedEligibleSession(t, s, "tok1")
	rows := []struct {
		ts     string
		model  string
		in     int
		out    int
		cached int
		cost   float64
	}{
		{"2026-06-09T00:01:00Z", "claude-sonnet-5", 1000, 500, 200, 0},
		{"2026-06-09T00:02:00Z", "claude-opus-4-8", 2000, 900, 0, 0},
	}
	for i, r := range rows {
		if _, err := database.ExecContext(ctx, `
			INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, output_tokens,
			                         cache_read_tokens, cache_creation_tokens, reasoning_tokens,
			                         estimated_cost_usd, source, reliability, source_file, source_event_id)
			VALUES (?, ?, 'claude-code', ?, ?, ?, ?, 0, 0, ?, 'jsonl', 'estimated', 'f', ?)`,
			"tok1", r.ts, r.model, r.in, r.out, r.cached, r.cost, "tok1-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert token row %d: %v", i, err)
		}
	}

	facts, ok, err := s.LoadCloudEvidenceFacts(ctx, "tok1", 256)
	if err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceFacts: ok=%v err=%v", ok, err)
	}
	if len(facts.Metrics.Turns) != len(rows) {
		t.Fatalf("Turns = %d rows, want %d", len(facts.Metrics.Turns), len(rows))
	}
	for i, want := range rows {
		got := facts.Metrics.Turns[i]
		if got.Model != want.model || got.Input != want.in || got.Output != want.out || got.CacheRead != want.cached {
			t.Errorf("turn %d = %+v, want model=%s in=%d out=%d cached=%d", i, got, want.model, want.in, want.out, want.cached)
		}
		if got.Timestamp.IsZero() {
			t.Errorf("turn %d carries no timestamp — it cannot be priced at its own date", i)
		}
	}
	// Determinism: turns come back in a stable order.
	again, _, err := s.LoadCloudEvidenceFacts(ctx, "tok1", 256)
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	for i := range facts.Metrics.Turns {
		if again.Metrics.Turns[i] != facts.Metrics.Turns[i] {
			t.Fatalf("turn %d differs between loads: %+v vs %+v", i, again.Metrics.Turns[i], facts.Metrics.Turns[i])
		}
	}
}

// seedOutcomeHeavyCloudSession seeds one eligible session with n outcome-bearing
// rows: a FAILING build early (inside any head window), a PASSING build and the
// terminal milestones at the very end. It is the shape that makes a head-only
// truncation observable — the early build outcome is the wrong one.
func seedOutcomeHeavyCloudSession(t *testing.T, s *Store, database *sql.DB, sessionID string, n int) {
	t.Helper()
	ctx := context.Background()
	seedEligibleSession(t, s, sessionID)

	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, sessionID).Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
		                     raw_tool_name, error_message, source_file, source_event_id)
		VALUES (?, ?, ?, ?, 'claude-code', ?, ?, '', '', 'f', ?)`)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	for i := 0; i < n; i++ {
		kind, target, success := "run_command", "git status --porcelain", 1
		switch i {
		case 10:
			target, success = "go build ./cmd/observer", 0 // the EARLY, failing build
		case n - 3:
			target = "go build ./cmd/observer" // the LAST build, and it passed
		case n - 2:
			kind, target = "task_complete", ""
		case n - 1:
			kind, target = "session_end", ""
		}
		if _, err := stmt.ExecContext(ctx, sessionID, projectID,
			base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			kind, success, target, sessionID+"-o"+strconv.Itoa(i)); err != nil {
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

// TestOutcomePopulationKeepsHeadAndTail is the N3 pin. The outcome bound used to
// keep the EARLIEST rows only, so a session past it asserted the wrong build
// outcome (an early failed build standing in for a later passing one) and lost
// its terminal milestones (session_end, first_task_complete) entirely.
func TestOutcomePopulationKeepsHeadAndTail(t *testing.T) {
	s, database := cloudTestStore(t)
	const total = cloudMaxOutcomeRows + 60
	seedOutcomeHeavyCloudSession(t, s, database, "outcomes1", total)

	facts, ok, err := s.LoadCloudEvidenceFacts(context.Background(), "outcomes1", 256)
	if err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceFacts: ok=%v err=%v", ok, err)
	}
	if len(facts.OutcomeActions) != cloudMaxOutcomeRows {
		t.Fatalf("outcome population = %d rows, want the %d bound", len(facts.OutcomeActions), cloudMaxOutcomeRows)
	}

	// The TAIL survived: the last build is the passing one, and the terminal
	// milestones are present.
	lastBuildOK, sawSessionEnd, sawTaskComplete, sawEarlyFailedBuild := false, false, false, false
	for _, a := range facts.OutcomeActions {
		switch {
		case a.Kind == "run_command" && a.Target == "go build ./cmd/observer":
			lastBuildOK = a.Success
			if !a.Success {
				sawEarlyFailedBuild = true
			}
		case a.Kind == "session_end":
			sawSessionEnd = true
		case a.Kind == "task_complete":
			sawTaskComplete = true
		}
	}
	if !lastBuildOK {
		t.Error("the LAST build row is missing — the population is still head-only, so the build outcome is the wrong one")
	}
	if !sawSessionEnd || !sawTaskComplete {
		t.Errorf("terminal milestones lost: session_end=%v task_complete=%v", sawSessionEnd, sawTaskComplete)
	}
	// The HEAD survived too: first-occurrence milestones still have their rows.
	if !sawEarlyFailedBuild {
		t.Error("the early failing build is missing — the population lost its head")
	}
	if got := facts.OutcomeActions[len(facts.OutcomeActions)-1].Kind; got != "session_end" {
		t.Errorf("last outcome row kind = %q, want session_end (rows must stay in time order)", got)
	}
}

// TestActionScanSelectsTheLastRowAgainstItsOwnCount is the N4 pin, exercised
// deterministically: the sample query used to receive the population size as a
// LITERAL computed by an earlier, separate read (`rn = ?`), so any row inserted
// between the two reads dropped the session's LAST action from the sample and
// made the omission count disagree with the activity mix — which a rebuild then
// reads as tampering. Handing the loader a STALE count is exactly what a
// concurrent insert did, and the last row must still be selected.
func TestActionScanSelectsTheLastRowAgainstItsOwnCount(t *testing.T) {
	s, database := cloudTestStore(t)
	const total = 900
	seedLongCloudSession(t, s, database, "race1", total)

	facts := CloudSessionFacts{ActionCount: total - 5} // the stale, pre-insert count
	if err := loadCloudActionScan(context.Background(), database, "race1", 64, &facts); err != nil {
		t.Fatalf("loadCloudActionScan: %v", err)
	}
	if len(facts.Actions) == 0 {
		t.Fatal("no actions sampled")
	}
	last := facts.Actions[len(facts.Actions)-1]
	if want := "a" + strconv.Itoa(total-1); last.Ref != want {
		t.Errorf("last sampled ref = %q, want %q — the sample still depends on a count read outside the statement", last.Ref, want)
	}
}

// TestLoadCloudEvidenceFactsIsOneConsistentRead pins the invariant the whole
// two-digest rebuild protocol rests on: within ONE load, the counted population,
// the whole-session activity mix and the sample's own refs all describe the same
// snapshot, so `ActionsOmitted + len(actions)` equals the mix total.
func TestLoadCloudEvidenceFactsIsOneConsistentRead(t *testing.T) {
	s, database := cloudTestStore(t)
	const total = 5000
	seedLongCloudSession(t, s, database, "snap1", total)

	const maxActions = 256
	facts, ok, err := s.LoadCloudEvidenceFacts(context.Background(), "snap1", maxActions)
	if err != nil || !ok {
		t.Fatalf("LoadCloudEvidenceFacts: ok=%v err=%v", ok, err)
	}
	mixTotal := 0
	for _, kc := range facts.ActivityMix {
		mixTotal += kc.Count
	}
	if mixTotal != facts.ActionCount {
		t.Errorf("activity mix totals %d but ActionCount is %d — the two reads saw different snapshots", mixTotal, facts.ActionCount)
	}
	// omitted + sampled == the population the omission count is reported against.
	omitted := facts.ActionCount - len(facts.Actions)
	if omitted+len(facts.Actions) != mixTotal {
		t.Errorf("ActionsOmitted(%d) + sampled(%d) = %d, want the mix total %d", omitted, len(facts.Actions), omitted+len(facts.Actions), mixTotal)
	}
	last := facts.Actions[len(facts.Actions)-1]
	if want := "a" + strconv.Itoa(facts.ActionCount-1); last.Ref != want {
		t.Errorf("last sampled ref = %q, want %q", last.Ref, want)
	}
}

// TestLoadCloudSessionTextsReadsTheWholeFailurePopulation is the Q1 store half:
// the failure rows are CLASSIFIED and COUNTED, never carried, so the read covers
// the population (bounded head+tail) rather than the earliest handful — and the
// LAST failure, which the pure layer always retains a slot for, must be present.
func TestLoadCloudSessionTextsReadsTheWholeFailurePopulation(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	seedEligibleSession(t, s, "fails1")
	var projectID int64
	if err := database.QueryRowContext(ctx, `SELECT project_id FROM sessions WHERE id = ?`, "fails1").Scan(&projectID); err != nil {
		t.Fatalf("read project id: %v", err)
	}
	base := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	const total = 60
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i := 0; i < total; i++ {
		msg := "Exit code 1"
		switch {
		case i >= 10 && i < 50:
			msg = "--- FAIL: TestThing (0.01s)"
		case i == total-1:
			msg = "EACCES: permission denied" // the LAST failure, a distinct class
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target,
			                     raw_tool_name, error_message, source_file, source_event_id)
			VALUES (?, ?, ?, 'tool_failure', 'claude-code', 0, 'Bash', '', ?, 'f', ?)`,
			"fails1", projectID, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano),
			msg+" "+strings.Repeat("x", 900), "fails1-e"+strconv.Itoa(i)); err != nil {
			t.Fatalf("insert failure %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	texts, err := s.LoadCloudSessionTexts(ctx, "fails1")
	if err != nil {
		t.Fatalf("LoadCloudSessionTexts: %v", err)
	}
	if len(texts.Errors) != total {
		t.Fatalf("read %d failure rows, want all %d (the old bound was the earliest 8)", len(texts.Errors), total)
	}
	if !strings.HasPrefix(texts.Errors[len(texts.Errors)-1], "EACCES") {
		t.Errorf("the LAST failure is missing: %q", texts.Errors[len(texts.Errors)-1])
	}
	for i, e := range texts.Errors {
		if len(e) > cloudErrorScanBytes {
			t.Fatalf("failure row %d is %d bytes, exceeds the %d-byte scan bound", i, len(e), cloudErrorScanBytes)
		}
	}
}
