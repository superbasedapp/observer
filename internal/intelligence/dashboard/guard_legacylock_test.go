package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestGuardEventsExplainLegacyOrgLockNote (round-3 finding): a verdict row
// written before the org-lock note named its cause reads, on the timeline,
// the cause its stored source establishes, with the stored text kept in
// stored_reason; the stored row itself is untouched (the chain still
// verifies) and a row whose source establishes nothing reads as stored.
func TestGuardEventsExplainLegacyOrgLockNote(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	now := time.Now().UTC()
	const oldS793 = "commit while dirty [org_locked: an org policy locks S-793; the local approval was ignored]"
	const oldR172 = "paste site [org_locked: an org policy locks R-172; the local approval was ignored]"
	rows := []store.GuardEventRow{
		{
			TS: now.Add(-2 * time.Minute), SessionID: "sA", Tool: "claude-code", EventKind: "shell_exec", RuleID: "S-793",
			Category: "code_security", Severity: "warn", Decision: "ask", Source: "pack:security", Reason: oldS793, TargetHash: "h1",
		},
		{
			TS: now.Add(-1 * time.Minute), SessionID: "sA", Tool: "claude-code", EventKind: "shell_exec", RuleID: "R-172",
			Category: "exfil", Severity: "warn", Decision: "ask", Source: "user", Reason: oldR172, TargetHash: "h2",
		},
	}
	if _, err := st.InsertGuardEvents(context.Background(), rows); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/events", nil))
	var resp struct {
		Events []guardEventJSON `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	byRule := map[string]guardEventJSON{}
	for _, e := range resp.Events {
		byRule[e.RuleID] = e
	}
	cases := []struct {
		rule, want, stored string
	}{
		{"S-793", "the organization's guard bundle does not name S-793", oldS793},
		{"R-172", "an org policy locks R-172", ""},
	}
	for _, tc := range cases {
		e, ok := byRule[tc.rule]
		if !ok {
			t.Fatalf("%s missing from the timeline", tc.rule)
		}
		if !strings.Contains(e.Reason, tc.want) {
			t.Errorf("%s reason = %q, want %q", tc.rule, e.Reason, tc.want)
		}
		if e.StoredReason != tc.stored {
			t.Errorf("%s stored_reason = %q, want %q", tc.rule, e.StoredReason, tc.stored)
		}
	}
	report, err := st.VerifyGuardChain(context.Background())
	if err != nil || !report.OK {
		t.Fatalf("chain after a read = %+v, %v", report, err)
	}
}
