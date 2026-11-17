package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestGuardEventsSessionless pins CG-18: the session-less list carries only
// verdicts with no session id (the ones no session view can show), newest
// first, and the table and JSON forms both render them.
func TestGuardEventsSessionless(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		{TS: now.Add(-3 * time.Minute), RuleID: "R-205", Decision: "flag", Severity: "high", Source: "org", Reason: "org policy bundle rejected:\nsignature mismatch"},
		{TS: now.Add(-2 * time.Minute), SessionID: "s-1", Tool: "claude-code", EventKind: "command", RuleID: "R-101", Decision: "deny", Severity: "high", Enforced: true, Reason: "dangerous command"},
		{TS: now.Add(-1 * time.Minute), RuleID: "G-901", Decision: "flag", Severity: "medium", Reason: "hook disabled"},
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rows, err := st.LoadRecentSessionlessGuardEvents(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := len(rows); got != 2 {
		t.Fatalf("session-less rows = %d, want 2", got)
	}
	if rows[0].RuleID != "G-901" || rows[1].RuleID != "R-205" {
		t.Fatalf("order = %s, %s; want newest first", rows[0].RuleID, rows[1].RuleID)
	}
	if since, _ := st.LoadRecentSessionlessGuardEvents(ctx, now.Add(-90*time.Second), 10); len(since) != 1 {
		t.Fatalf("--since kept %d rows, want 1", len(since))
	}

	var table bytes.Buffer
	writeGuardEventsTable(&table, rows, true)
	out := table.String()
	for _, want := range []string{"R-205", "G-901", "org policy bundle rejected: signature mismatch"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "R-101") {
		t.Errorf("table lists a session verdict:\n%s", out)
	}

	var js bytes.Buffer
	if err := writeGuardEventsJSON(&js, rows); err != nil {
		t.Fatalf("json: %v", err)
	}
	var doc struct {
		Events []guardEventView `json:"events"`
	}
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil || len(doc.Events) != 2 {
		t.Fatalf("json = %s (err %v)", js.String(), err)
	}

	var empty bytes.Buffer
	writeGuardEventsTable(&empty, nil, true)
	if !strings.Contains(empty.String(), "no session-less guard verdicts") {
		t.Errorf("empty table = %q", empty.String())
	}
}
