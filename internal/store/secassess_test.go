package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func runApproval(session string, expires time.Time) GuardApprovalRow {
	return GuardApprovalRow{
		RuleID: "R-179", Scope: "session", SessionID: session, GrantedBy: "assessment:0123456789abcdef",
		ExpiresAt: expires, Channel: "assessment",
	}
}

// TestCreateApprovalIfAbsent: one statement, never an extend; a taken key (a
// developer's row, another run's, an expired one) is left exactly as it was.
func TestCreateApprovalIfAbsent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	t.Run("creates a row and its audit event", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		id, created, err := s.CreateApprovalIfAbsent(ctx, runApproval("s1", now.Add(10*time.Minute)))
		if err != nil || !created || id <= 0 {
			t.Fatalf("got %d %v %v", id, created, err)
		}
		reasons := approvalAuditReasons(t, s)
		if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "assessment|approval create: rule R-179 scope session") {
			t.Fatalf("audit %v", reasons)
		}
	})
	t.Run("a developer's own row is never extended or taken over", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		own := GuardApprovalRow{RuleID: "R-179", Scope: "session", SessionID: "s1", GrantedBy: "alice", ExpiresAt: now.Add(time.Minute), Channel: "dashboard"}
		ownID, err := s.InsertGuardApproval(ctx, own)
		if err != nil {
			t.Fatal(err)
		}
		id, created, err := s.CreateApprovalIfAbsent(ctx, runApproval("s1", now.Add(time.Hour)))
		if err != nil || created || id != 0 {
			t.Fatalf("got %d %v %v", id, created, err)
		}
		got, ok, err := s.ActiveApprovalOnKey(ctx, "R-179", "session", "s1", "", now)
		if err != nil || !ok || got.ID != ownID || got.GrantedBy != "alice" || !got.ExpiresAt.Equal(now.Add(time.Minute)) {
			t.Fatalf("the developer's row changed: %+v %v %v", got, ok, err)
		}
	})
	t.Run("an expired row on the key is not overwritten either", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		if _, err := s.InsertGuardApproval(ctx, GuardApprovalRow{RuleID: "R-179", Scope: "session", SessionID: "s1", GrantedBy: "alice", ExpiresAt: now.Add(-time.Hour), Channel: "cli"}); err != nil {
			t.Fatal(err)
		}
		if _, created, err := s.CreateApprovalIfAbsent(ctx, runApproval("s1", now.Add(time.Hour))); err != nil || created {
			t.Fatalf("created=%v err=%v", created, err)
		}
		var by string
		if err := s.db.QueryRowContext(ctx, `SELECT granted_by FROM guard_approvals WHERE rule_id='R-179'`).Scan(&by); err != nil || by != "alice" {
			t.Fatalf("grantor %q %v", by, err)
		}
	})
	t.Run("an incomplete row is refused", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		bad := runApproval("s1", time.Time{})
		if _, _, err := s.CreateApprovalIfAbsent(ctx, bad); err == nil {
			t.Fatal("a row with no expiry was created")
		}
		bad = runApproval("s1", now.Add(time.Hour))
		bad.GrantedBy = ""
		if _, _, err := s.CreateApprovalIfAbsent(ctx, bad); err == nil {
			t.Fatal("a row with no grantor was created")
		}
	})
}

// TestOwnedApprovalRenewAndDelete: a renew or delete matches only the row the
// run created, by id, grantor and the expiry it last wrote.
func TestOwnedApprovalRenewAndDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	exp1 := now.Add(10 * time.Minute)
	setup := func(t *testing.T) (*Store, int64) {
		t.Helper()
		s, _ := newTestStore(t)
		id, created, err := s.CreateApprovalIfAbsent(ctx, runApproval("s1", exp1))
		if err != nil || !created {
			t.Fatalf("create %v %v", created, err)
		}
		return s, id
	}
	t.Run("renew moves the expiry", func(t *testing.T) {
		t.Parallel()
		s, id := setup(t)
		ok, err := s.RenewOwnedApproval(ctx, id, "assessment:0123456789abcdef", exp1, exp1.Add(time.Minute))
		if err != nil || !ok {
			t.Fatalf("renew %v %v", ok, err)
		}
		got, _, _ := s.ActiveApprovalOnKey(ctx, "R-179", "session", "s1", "", now)
		if !got.ExpiresAt.Equal(exp1.Add(time.Minute)) {
			t.Fatalf("expiry %v", got.ExpiresAt)
		}
	})
	t.Run("a developer's later extension is never shortened", func(t *testing.T) {
		t.Parallel()
		s, id := setup(t)
		// The developer extends the same key (GrantGuardApproval's extend).
		if _, err := s.InsertGuardApproval(ctx, GuardApprovalRow{RuleID: "R-179", Scope: "session", SessionID: "s1", GrantedBy: "alice", ExpiresAt: now.Add(5 * time.Hour), Channel: "dashboard"}); err != nil {
			t.Fatal(err)
		}
		if ok, err := s.RenewOwnedApproval(ctx, id, "assessment:0123456789abcdef", exp1, exp1.Add(time.Minute)); err != nil || ok {
			t.Fatalf("renew over an extension: %v %v", ok, err)
		}
		if ok, err := s.DeleteOwnedApproval(ctx, id, "assessment:0123456789abcdef", exp1); err != nil || ok {
			t.Fatalf("delete over an extension: %v %v", ok, err)
		}
		got, ok, _ := s.ActiveApprovalOnKey(ctx, "R-179", "session", "s1", "", now)
		if !ok || !got.ExpiresAt.Equal(now.Add(5*time.Hour)) {
			t.Fatalf("the extended row changed: %+v", got)
		}
	})
	t.Run("another grantor's row matches nothing", func(t *testing.T) {
		t.Parallel()
		s, id := setup(t)
		if ok, _ := s.DeleteOwnedApproval(ctx, id, "assessment:ffffffffffffffff", exp1); ok {
			t.Fatal("deleted another run's row")
		}
	})
	t.Run("delete removes the owned row once", func(t *testing.T) {
		t.Parallel()
		s, id := setup(t)
		if ok, err := s.DeleteOwnedApproval(ctx, id, "assessment:0123456789abcdef", exp1); err != nil || !ok {
			t.Fatalf("delete %v %v", ok, err)
		}
		if ok, _ := s.DeleteOwnedApproval(ctx, id, "assessment:0123456789abcdef", exp1); ok {
			t.Fatal("deleted twice")
		}
		if _, ok, _ := s.ActiveApprovalOnKey(ctx, "R-179", "session", "s1", "", now); ok {
			t.Fatal("the row is still there")
		}
	})
	t.Run("ids and grantors are required", func(t *testing.T) {
		t.Parallel()
		s, _ := newTestStore(t)
		if _, err := s.RenewOwnedApproval(ctx, 0, "x", exp1, exp1); err == nil {
			t.Error("renew with no id")
		}
		if _, err := s.DeleteOwnedApproval(ctx, 1, "", exp1); err == nil {
			t.Error("delete with no grantor")
		}
	})
}

// TestApprovalCoverFor: the same scope matching as ApprovalActiveFor, with the
// narrowest scope winning and then the lowest id.
func TestApprovalCoverFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	s, _ := newTestStore(t)
	mk := func(scope, session, hash, by string, exp time.Time) int64 {
		id, err := s.InsertGuardApproval(ctx, GuardApprovalRow{RuleID: "R-179", Scope: scope, SessionID: session, ProjectRootHash: hash, GrantedBy: by, ExpiresAt: exp, Channel: "cli"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	glob := mk("global", "", "", "g", now.Add(time.Hour))
	proj := mk("project", "", "ph", "p", now.Add(time.Hour))
	sess := mk("session", "s1", "", "s", now.Add(time.Hour))
	mk("session", "s2", "", "other", now.Add(time.Hour))
	mk("project", "", "ph2", "expired", now.Add(-time.Hour))
	cases := []struct {
		name    string
		session string
		hash    string
		found   bool
		id      int64
		by      string
	}{
		{"the session row is the narrowest", "s1", "ph", true, sess, "s"},
		{"a project row beats global", "sX", "ph", true, proj, "p"},
		{"global covers anything", "sX", "phX", true, glob, "g"},
		{"an expired project row covers nothing narrower than global", "sX", "ph2", true, glob, "g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := s.ApprovalCoverFor(ctx, "R-179", tc.session, tc.hash, now)
			if err != nil || c.Found != tc.found || c.ID != tc.id || c.GrantedBy != tc.by {
				t.Fatalf("got %+v %v", c, err)
			}
			// The plain lookup agrees on whether anything covers.
			ok, _ := s.ApprovalActiveFor(ctx, "R-179", tc.session, tc.hash, now)
			if ok != c.Found {
				t.Fatalf("ApprovalActiveFor=%v, ApprovalCoverFor=%v", ok, c.Found)
			}
		})
	}
	if c, _ := s.ApprovalCoverFor(ctx, "R-130", "s1", "ph", now); c.Found {
		t.Fatalf("another rule is covered: %+v", c)
	}
	// An empty session or hash never matches a session or project row.
	if c, _ := s.ApprovalCoverFor(ctx, "R-179", "", "", now); c.ID != glob {
		t.Fatalf("empty scope matched a narrower row: %+v", c)
	}
}

// TestRecordSecAssessEventAndCount: the audit row is a marker (never a
// verdict) with the phase in tool, and the count reads the cover reason
// exactly and org grants approximately.
func TestRecordSecAssessEventAndCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.RecordSecAssessEvent(ctx, SecAssessEvent{Phase: "nope"}); err == nil {
		t.Fatal("an unknown phase was recorded")
	}
	if err := s.RecordSecAssessEvent(ctx, SecAssessEvent{TS: now, Phase: "launch", ProjectRootHash: "ph", Detail: "run 0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	// Every phase of the closed vocabulary is accepted, the model check's too.
	for _, ph := range []string{"held", "end", "import", "validated", "cancel"} {
		if err := s.RecordSecAssessEvent(ctx, SecAssessEvent{TS: now.Add(time.Second), Phase: ph, ProjectRootHash: "other", Detail: "run 0123456789abcdef"}); err != nil {
			t.Fatalf("phase %s: %v", ph, err)
		}
	}
	var tool, kind, rule, cat, sev, dec, hash, reason string
	if err := s.db.QueryRowContext(ctx, `SELECT tool, event_kind, rule_id, category, severity, decision, target_hash, reason FROM guard_events WHERE rule_id = ? AND target_hash = 'ph'`, SecAssessEventRuleID).
		Scan(&tool, &kind, &rule, &cat, &sev, &dec, &hash, &reason); err != nil {
		t.Fatal(err)
	}
	if tool != "assessment.launch" || kind != "audit" || cat != "posture" || sev != "info" || dec != "allow" || hash != "ph" || !strings.Contains(reason, "run 0123456789abcdef") {
		t.Fatalf("row %s %s %s %s %s %s %s %q", tool, kind, rule, cat, sev, dec, hash, reason)
	}
	// Verdict rows: two lifted by the run's approval, one by someone else's,
	// two by an org grant in the run's session.
	rows := []GuardEventRow{
		{TS: now, SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", DegradedFrom: "approved", Reason: "scan [approved: approval #3 (assessment:0123456789abcdef) covers this rule for this scope]"},
		{TS: now, SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", DegradedFrom: "approved", Reason: "scan [approved: approval #3 (assessment:0123456789abcdef) covers this rule for this scope]"},
		{TS: now, SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", DegradedFrom: "approved", Reason: "scan [approved: approval #4 (alice) covers this rule for this scope]"},
		{TS: now, SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", DegradedFrom: "org_grant", Reason: "scan [granted: G-1]"},
		{TS: now, SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "ask", DegradedFrom: "org_grant_soften", Reason: "scan [granted: G-2]"},
		{TS: now, SessionID: "s9", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", DegradedFrom: "org_grant", Reason: "other session"},
		{TS: now.Add(-time.Hour), SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", DegradedFrom: "org_grant", Reason: "before the run"},
	}
	if _, err := s.InsertGuardEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := s.CountRelaxedVerdicts(ctx, "assessment:0123456789abcdef", []string{"s1"}, []string{"R-179"}, now.Add(-time.Minute), time.Time{})
	if err != nil || got.Exact != 2 || got.Approx != 2 {
		t.Fatalf("counts %+v %v", got, err)
	}
	if got, _ := s.CountRelaxedVerdicts(ctx, "assessment:0123456789abcdef", nil, nil, now.Add(-time.Minute), time.Time{}); got.Exact != 0 || got.Approx != 0 {
		t.Fatalf("no rules must count nothing: %+v", got)
	}
	if got, _ := s.CountRelaxedVerdicts(ctx, "", []string{"s1"}, []string{"R-179"}, now.Add(-time.Minute), time.Time{}); got.Exact != 0 || got.Approx != 2 {
		t.Fatalf("no grantor counts no local approval: %+v", got)
	}
}

// TestRecordSecAssessEventKeepsTheWholeDetailUpToItsCap: the launch row's line
// is longer than the 1024 runes every other guard row's Reason may keep, and its
// tail is the relaxations, so the stored Reason keeps the whole Detail up to
// SecAssessDetailMax (and the words before it), without the cut mark, while the
// detail past the cap is dropped and another rule's Reason is still bounded at
// the guard store's own limit.
func TestRecordSecAssessEventKeepsTheWholeDetailUpToItsCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	whole := strings.Repeat("k", SecAssessDetailMax)
	if err := s.RecordSecAssessEvent(ctx, SecAssessEvent{TS: now, Phase: "launch", ProjectRootHash: "p1", Detail: whole}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordSecAssessEvent(ctx, SecAssessEvent{TS: now.Add(time.Second), Phase: "validated", ProjectRootHash: "p2", Detail: whole + "tail"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{{TS: now, SessionID: "s1", EventKind: "tool_call", RuleID: "R-179", Decision: "flag", Reason: strings.Repeat("x", guardMaxReasonRunes+10)}}); err != nil {
		t.Fatal(err)
	}
	reasonOf := func(where string, arg any) string {
		var r string
		if err := s.db.QueryRowContext(ctx, `SELECT reason FROM guard_events WHERE `+where, arg).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if got, want := reasonOf(`target_hash = ?`, "p1"), "security assessment launch: "+whole; got != want {
		t.Errorf("the launch Reason lost part of its Detail: %d runes, want %d", len([]rune(got)), len([]rune(want)))
	}
	if got, want := reasonOf(`target_hash = ?`, "p2"), "security assessment validated: "+whole; got != want {
		t.Errorf("a Detail past the cap is cut at the cap, with the longest words before it, and no cut mark: %d runes, want %d", len([]rune(got)), len([]rune(want)))
	}
	if got, want := reasonOf(`rule_id = ?`, "R-179"), strings.Repeat("x", guardMaxReasonRunes)+"…"; got != want {
		t.Errorf("another rule's Reason is still bounded at %d runes: %d", guardMaxReasonRunes, len([]rune(got)))
	}
	if report, err := s.VerifyGuardChain(ctx); err != nil || !report.OK {
		t.Errorf("the chain verifies over the longer Reason: %+v %v", report, err)
	}
}
