package dashboard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestApprovalLastUsed is the scope table behind the Approvals card's "last
// used" column (P-232): a use counts for a grant when the grant's scope
// covers it (global: any; session: its session; project: a session whose
// root hashes to the anchor) and it came at or after the grant.
func TestApprovalLastUsed(t *testing.T) {
	t.Parallel()
	t0 := time.Date(2026, 11, 3, 8, 0, 0, 0, time.UTC)
	uses := []store.GuardApprovalUse{
		{SessionID: "sA", ProjectRoot: "/repo", LastTS: t0.Add(time.Hour)},
		{SessionID: "sB", ProjectRoot: "/repo", LastTS: t0.Add(2 * time.Hour)},
		{SessionID: "sC", ProjectRoot: "/other", LastTS: t0.Add(3 * time.Hour)},
		{SessionID: "sD", ProjectRoot: "", LastTS: t0.Add(-time.Hour)},
	}
	cases := []struct {
		name  string
		grant store.GuardApprovalRow
		want  time.Time
	}{
		{"global takes the latest use", store.GuardApprovalRow{Scope: "global", TS: t0}, t0.Add(3 * time.Hour)},
		{"session takes its own session", store.GuardApprovalRow{Scope: "session", SessionID: "sA", TS: t0}, t0.Add(time.Hour)},
		{"project takes its project's sessions", store.GuardApprovalRow{Scope: "project", ProjectRootHash: guard.HashProjectRoot("/repo"), TS: t0}, t0.Add(2 * time.Hour)},
		{"a use before the grant does not count", store.GuardApprovalRow{Scope: "session", SessionID: "sD", TS: t0}, time.Time{}},
		{"an unused session grant", store.GuardApprovalRow{Scope: "session", SessionID: "nobody", TS: t0}, time.Time{}},
		{"once never applies", store.GuardApprovalRow{Scope: "once", SessionID: "sA", TS: t0}, time.Time{}},
	}
	for _, tc := range cases {
		if got := approvalLastUsed(tc.grant, uses); !got.Equal(tc.want) {
			t.Errorf("%s: last used = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAPIGuardApprovalsLastUsed: GET lists a grant's last use from the
// approved verdicts the guard recorded for its scope.
func TestAPIGuardApprovalsLastUsed(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	pid, err := st.UpsertProject(ctx, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{ID: "lu1", ProjectID: pid, Tool: "claude-code", StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GrantGuardApproval(ctx, store.GuardApprovalRow{TS: now.Add(-time.Hour), RuleID: "S-793", Scope: "session", SessionID: "lu1", GrantedBy: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.GrantGuardApproval(ctx, store.GuardApprovalRow{TS: now.Add(-time.Hour), RuleID: "S-794", Scope: "global", GrantedBy: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	used := now.Add(-10 * time.Minute)
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		{TS: used, SessionID: "lu1", RuleID: "S-793", Decision: "flag", DegradedFrom: "approved", Source: "pack:security"},
		{TS: now.Add(-5 * time.Minute), SessionID: "lu1", RuleID: "S-793", Decision: "ask", Enforced: true, Source: "pack:security"},
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/approvals", nil))
	var list struct {
		Approvals []struct {
			RuleID     string `json:"rule_id"`
			LastUsedAt string `json:"last_used_at"`
		} `json:"approvals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range list.Approvals {
		got[a.RuleID] = a.LastUsedAt
	}
	if got["S-793"] != used.Format(time.RFC3339) {
		t.Errorf("S-793 last used = %q, want %q (the approved verdict, not the later ask)", got["S-793"], used.Format(time.RFC3339))
	}
	if got["S-794"] != "" {
		t.Errorf("S-794 last used = %q, want empty (never used)", got["S-794"])
	}
}

// TestAPIGuardEventsProjectRootHash: each verdict row carries its session's
// project anchor, hashed the way a project grant stores it, never the path;
// a row that recorded the gate's project (GRANT-20) carries that one.
func TestAPIGuardEventsProjectRootHash(t *testing.T) {
	t.Parallel()
	s, _ := newTestServer(t)
	st := store.New(s.opts.DB)
	ctx := context.Background()
	now := time.Now().UTC()
	root := t.TempDir()
	pid, err := st.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{ID: "ph1", ProjectID: pid, Tool: "claude-code", StartedAt: now}); err != nil {
		t.Fatal(err)
	}
	stored, err := st.ProjectRootForSession(ctx, "ph1")
	if err != nil || stored == "" {
		t.Fatalf("project root for session = %q, %v", stored, err)
	}
	if _, err := st.InsertGuardEvents(ctx, []store.GuardEventRow{
		{TS: now.Add(-time.Minute), SessionID: "ph1", RuleID: "S-793", Decision: "ask", Enforced: true, Source: "pack:security"},
		{TS: now.Add(-time.Minute), SessionID: "nobody", RuleID: "S-793", Decision: "ask", Enforced: true, Source: "pack:security"},
		// GRANT-20: a row that recorded the gate's project (agent 253) carries
		// that one, not its session's.
		{
			TS: now.Add(-time.Minute), SessionID: "gated", RuleID: "S-793", Decision: "ask", Enforced: true, Source: "pack:security",
			ProjectRootHash: guard.HashProjectRoot("/r/other-repo"), ProjectRoot: "/r/other-repo",
		},
	}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/guard/events?hours=1", nil))
	var resp struct {
		Events []struct {
			SessionID       string `json:"session_id"`
			ProjectRootHash string `json:"project_root_hash"`
		} `json:"events"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range resp.Events {
		got[e.SessionID] = e.ProjectRootHash
	}
	if got["ph1"] != guard.HashProjectRoot(stored) {
		t.Errorf("ph1 project_root_hash = %q, want %q", got["ph1"], guard.HashProjectRoot(stored))
	}
	if got["gated"] != guard.HashProjectRoot("/r/other-repo") {
		t.Errorf("gated project_root_hash = %q, want the recorded gate project's", got["gated"])
	}
	if strings.Contains(rec.Body.String(), "/r/other-repo") {
		t.Error("the events API carries the raw recorded project root")
	}
	if got["nobody"] != "" {
		t.Errorf("an unknown session carries project_root_hash %q, want empty", got["nobody"])
	}
}
