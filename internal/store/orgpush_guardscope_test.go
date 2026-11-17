package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestSelectUnpushedSince_GuardEventScope pins CG-13: the local
// [org_client.scope] lists narrow guard verdicts through their session's
// project on an individual node, but a SESSION-LESS verdict (R-205, posture,
// hook-disabled, user-policy-invalid) always ships (metadata only under a
// scope), and on a node whose scope the org governs (a managed node) every
// verdict ships whatever the lists say.
func TestSelectUnpushedSince_GuardEventScope(t *testing.T) {
	s, db := newTestStore(t)
	seedPushData(t, s, db) // project /tmp/proj, session s1
	ctx := context.Background()
	other, err := s.UpsertProject(ctx, "/tmp/other", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "s2", ProjectID: other, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{
		{TS: now, SessionID: "s1", RuleID: "R-101", Decision: "deny", Enforced: true, Reason: "in scope"},
		{TS: now, SessionID: "s2", RuleID: "R-102", Decision: "deny", Enforced: true, Reason: "out of scope"},
		{TS: now, RuleID: "R-205", Decision: "flag", Source: "org", Reason: "bundle rejected at /home/dev/.observer/x"},
	}); err != nil {
		t.Fatal(err)
	}

	type want struct {
		rules         []string
		sessionlessOK bool // the session-less row keeps its reason
	}
	allow := []string{"/tmp/proj"}
	cases := []struct {
		name  string
		scope ScopeOptions
		want  want
	}{
		{"no scope", ScopeOptions{}, want{[]string{"R-101", "R-102", "R-205"}, true}},
		{"allowlist, individual node", ScopeOptions{ProjectRootAllowlist: allow}, want{[]string{"R-101", "R-205"}, false}},
		{"denylist, individual node", ScopeOptions{ProjectRootDenylist: []string{"/tmp/other"}}, want{[]string{"R-101", "R-205"}, false}},
		{"allowlist matching nothing, individual node", ScopeOptions{ProjectRootAllowlist: []string{"/no/such"}}, want{[]string{"R-205"}, false}},
		{"allowlist, managed node", ScopeOptions{ProjectRootAllowlist: allow, GuardEventsUnscoped: true}, want{[]string{"R-101", "R-102", "R-205"}, true}},
		{"allowlist matching nothing, managed node", ScopeOptions{ProjectRootAllowlist: []string{"/no/such"}, GuardEventsUnscoped: true}, want{[]string{"R-101", "R-102", "R-205"}, true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "o", "u", ShareOptions{FullContent: true}, tc.scope)
			if err != nil {
				t.Fatalf("SelectUnpushedSince: %v", err)
			}
			var got []string
			for _, r := range batch.GuardEvents {
				got = append(got, r.RuleID)
				if r.RuleID == "R-205" && (r.Reason != "") != tc.want.sessionlessOK {
					t.Errorf("session-less reason = %q, want kept=%v", r.Reason, tc.want.sessionlessOK)
				}
				if r.RuleID == "R-205" && r.TargetHash == "" && r.ChainHash == "" {
					t.Errorf("session-less row lost its chain link")
				}
			}
			if len(got) != len(tc.want.rules) {
				t.Fatalf("guard events = %v, want %v", got, tc.want.rules)
			}
			for i := range got {
				if got[i] != tc.want.rules[i] {
					t.Fatalf("guard events = %v, want %v", got, tc.want.rules)
				}
			}
			if batch.Cursor.GuardEvents == 0 {
				t.Fatal("guard cursor did not move")
			}
		})
	}
}

// TestGuardEventScopeTable is guardEventScope's rule table, one row each.
func TestGuardEventScopeTable(t *testing.T) {
	scoped := ScopeOptions{ProjectRootAllowlist: []string{"/p"}}
	for _, tc := range []struct {
		name      string
		scope     ScopeOptions
		filter    string
		noMatch   bool
		wantWhere string
		wantStrip bool
	}{
		{"unscoped", ScopeOptions{}, "", false, "", false},
		{"org-governed", ScopeOptions{ProjectRootAllowlist: []string{"/p"}, GuardEventsUnscoped: true}, "1", false, "", false},
		{"no match", scoped, "", true, ` AND COALESCE(ge.session_id,'') = ''`, true},
		{"matched", scoped, "1,2", false, ` AND (COALESCE(ge.session_id,'') = '' OR s.project_id IN (1,2))`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			where, strip := guardEventScope(tc.scope, tc.filter, tc.noMatch)
			if where != tc.wantWhere || strip != tc.wantStrip {
				t.Fatalf("guardEventScope = (%q, %v), want (%q, %v)", where, strip, tc.wantWhere, tc.wantStrip)
			}
		})
	}
}
