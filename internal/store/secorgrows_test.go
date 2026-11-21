//go:build !sbo_omit_security

package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

func TestResolveSecurityShare(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   ResolveSecurityShareFacts
		want SecurityShare
	}{
		{"individual default posture (ruling R1)", ResolveSecurityShareFacts{}, SecurityShare{Level: "posture"}},
		{"individual explicit off", ResolveSecurityShareFacts{LocalLevel: "off"}, SecurityShare{Level: "off"}},
		{"individual posture", ResolveSecurityShareFacts{LocalLevel: "posture"}, SecurityShare{Level: "posture"}},
		{"individual findings", ResolveSecurityShareFacts{LocalLevel: "findings"}, SecurityShare{Level: "findings"}},
		{"individual unknown fails closed", ResolveSecurityShareFacts{LocalLevel: "everything"}, SecurityShare{Level: "off"}},
		{"individual ignores a pull (never remote)", ResolveSecurityShareFacts{LocalLevel: "off", PullLevel: "findings", PullOrgKey: true}, SecurityShare{Level: "off"}},
		{"individual default ignores a pull", ResolveSecurityShareFacts{PullLevel: "findings", PullOrgKey: true}, SecurityShare{Level: "posture"}},
		{"individual never holds the org key", ResolveSecurityShareFacts{LocalLevel: "findings", PullOrgKey: true}, SecurityShare{Level: "findings"}},
		{"managed default posture", ResolveSecurityShareFacts{Managed: true, LocalLevel: "findings"}, SecurityShare{Level: "posture"}},
		{"managed pull findings", ResolveSecurityShareFacts{Managed: true, PullLevel: "findings"}, SecurityShare{Level: "findings"}},
		{"managed pull findings with key", ResolveSecurityShareFacts{Managed: true, PullLevel: "findings", PullOrgKey: true}, SecurityShare{Level: "findings", HoldsOrgKey: true}},
		{"managed pull posture keeps no key", ResolveSecurityShareFacts{Managed: true, PullLevel: "posture", PullOrgKey: true}, SecurityShare{Level: "posture"}},
		{"managed pull off", ResolveSecurityShareFacts{Managed: true, PullLevel: "off"}, SecurityShare{Level: "off"}},
	}
	for _, c := range cases {
		if got := ResolveSecurityShare(c.in); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

// secOrgProviders binds the store's own reads, the way the cmd layer does.
func secOrgProviders(s *Store, level SecurityShare) SecurityOrgProviders {
	return SecurityOrgProviders{
		Level: func(context.Context, ShareOptions) SecurityShare { return level },
		Posture: func(ctx context.Context, day string, scope SecurityScope) (orgcontract.SecurityPostureRow, bool, error) {
			r, err := s.SecurityPostureFacts(ctx, day, time.Now().UTC(), scope)
			return r, err == nil, err
		},
		Findings: s.SelectSecurityFindingRows,
	}
}

func seedSecOrgFinding(t *testing.T, s *Store, now time.Time) string {
	t.Helper()
	f := secFinding("root-1", "key-1")
	f.OrgKey = strings.Repeat("f", 64)
	f.EvidenceRedacted = "aws_key = [aws_access_key]"
	f.EvidenceHash = secfinding.EvidenceHash(f.EvidenceRedacted)
	f.Project.IdentityHash = strings.Repeat("1", 64)
	id, _, err := s.UpsertSecFinding(context.Background(), f, now)
	if err != nil {
		t.Fatalf("UpsertSecFinding: %v", err)
	}
	return id
}

func TestComposeSecurityUnboundIsByteIdentical(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedSecOrgFinding(t, s, time.Now().UTC())
	share := ShareOptions{FullContent: true}
	before, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@x", share, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if before.SecurityPosture != nil || before.SecurityFindings != nil || before.AIChangeRecords != nil {
		t.Fatalf("an unbound seam composed security rows")
	}
	// Bound at level off: still nothing.
	s.SetSecurityOrgProviders(secOrgProviders(s, SecurityShare{Level: "off"}))
	off, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@x", share, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if off.SecurityPosture != nil || off.SecurityFindings != nil {
		t.Fatalf("level off composed security rows")
	}
}

func TestComposeSecurityLevelsAndGates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	cases := []struct {
		name         string
		level        SecurityShare
		share        ShareOptions
		wantPosture  bool
		wantFindings bool
		wantRaw      bool
		wantOrgKey   bool
	}{
		{"posture only", SecurityShare{Level: "posture"}, ShareOptions{FullContent: true}, true, false, false, false},
		{"findings metadata only", SecurityShare{Level: "findings"}, ShareOptions{}, true, true, false, false},
		{"findings raw", SecurityShare{Level: "findings"}, ShareOptions{FullContent: true}, true, true, true, false},
		{"findings with org key", SecurityShare{Level: "findings", HoldsOrgKey: true}, ShareOptions{EnterpriseGranted: true}, true, true, true, true},
		{"tool bodies alone is not raw", SecurityShare{Level: "findings"}, ShareOptions{FullToolBodies: true}, true, true, false, false},
	}
	for _, c := range cases {
		s, _ := newTestStore(t)
		seedSecOrgFinding(t, s, now)
		s.SetSecurityOrgProviders(secOrgProviders(s, c.level))
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@x", c.share, ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(b.SecurityPosture) == 1; got != c.wantPosture {
			t.Errorf("%s: posture %v, want %v", c.name, got, c.wantPosture)
		}
		if got := len(b.SecurityFindings) == 1; got != c.wantFindings {
			t.Fatalf("%s: findings %d, want one=%v", c.name, len(b.SecurityFindings), c.wantFindings)
		}
		if c.wantPosture {
			p := b.SecurityPosture[0]
			if p.ShareLevel != c.level.Level || len(p.Findings) != 1 || p.Findings[0].Count != 1 || p.Projects != 1 {
				t.Errorf("%s: posture %+v", c.name, p)
			}
		}
		if !c.wantFindings {
			continue
		}
		f := b.SecurityFindings[0]
		if (f.RelPath != "") != c.wantRaw || (f.EvidenceRedacted != "") != c.wantRaw {
			t.Errorf("%s: raw fields %q %q, want raw=%v", c.name, f.RelPath, f.EvidenceRedacted, c.wantRaw)
		}
		if (f.OrgKey != "") != c.wantOrgKey {
			t.Errorf("%s: org_key %q, want present=%v", c.name, f.OrgKey, c.wantOrgKey)
		}
		if f.EvidenceHash == "" || f.ProjectIdentityHash == "" || f.RuleID != "S-721" || f.UserEmail != "dev@x" {
			t.Errorf("%s: always fields missing: %+v", c.name, f)
		}
		raw, _ := json.Marshal(f)
		if strings.Contains(string(raw), "secret in code") {
			t.Errorf("%s: the rendered message reached the wire: %s", c.name, raw)
		}
	}
}

// TestSecurityFindingRePushUpdates proves a re-pushed finding carries the
// same handle (so the server updates, never duplicates) and its new state.
func TestSecurityFindingRePushUpdates(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	id := seedSecOrgFinding(t, s, now)
	first, err := s.SelectSecurityFindingRows(ctx, 10, SecurityScope{})
	if err != nil || len(first) != 1 {
		t.Fatalf("first read: %v %v", first, err)
	}
	if first[0].FindingRef == id || first[0].FindingRef != SecurityFindingRef(id) {
		t.Fatalf("the handle must be the digest of the id, never the id: %q", first[0].FindingRef)
	}
	if err := s.SetSecFindingStatus(ctx, id, policy.FindingStatusFalsePositive, "", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	second, err := s.SelectSecurityFindingRows(ctx, 10, SecurityScope{})
	if err != nil || len(second) != 1 {
		t.Fatalf("second read: %v %v", second, err)
	}
	if second[0].FindingRef != first[0].FindingRef || second[0].Status != "false_positive" {
		t.Errorf("re-push: %+v", second[0])
	}
}

func TestSecurityPostureFactsFreshness(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"": "never", "garbage": "never",
		now.Add(-time.Minute).Format(secTime):         "under_1h",
		now.Add(-3 * time.Hour).Format(secTime):       "under_1d",
		now.Add(-72 * time.Hour).Format(secTime):      "under_7d",
		now.Add(-30 * 24 * time.Hour).Format(secTime): "over_7d",
	} {
		if got := secFreshness(in, now); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}

// TestSecScanRunNotRunIsNotAScan: a run recorded for a scheduled scanner run
// that never executed (reason not_run) keeps the schedule's last-run time but
// is no scan: the last-scan time, the scanner notes and the org posture
// freshness and outcome counts all leave it out (lane SEC-POLISH audit
// finding 2).
func TestSecScanRunNotRunIsNotAScan(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	day := now.Format("2006-01-02")
	old := now.Add(-3 * time.Hour)
	if err := s.InsertSecScanRun(ctx, SecScanRun{
		ProjectRootHash: "p1", Driver: "custom.x", Scope: policy.FindingScopeScheduled,
		Coverage: map[string]any{"Outcome": "clean", "Notes": []string{"an earlier note"}},
		Outcome:  "clean", StartedAt: old, Duration: time.Second,
	}); err != nil {
		t.Fatal(err)
	}
	notRun := SecScanRun{
		ProjectRootHash: "p1", Driver: "custom.x", Scope: policy.FindingScopeScheduled,
		Coverage: map[string]any{"outcome": "failed", "reason": SecRunReasonNotRun, "error": "the runner is not wired"},
		Outcome:  "failed", StartedAt: now.Add(-time.Minute),
	}
	if err := s.InsertSecScanRun(ctx, notRun); err != nil {
		t.Fatal(err)
	}
	if last, err := s.SecLastScan(ctx, "p1"); err != nil || !last.Equal(old) {
		t.Fatalf("SecLastScan: %v %v, want the executed run's %v", last, err, old)
	}
	if notes, err := s.SecLatestRunNotes(ctx, "custom.x"); err != nil || len(notes) != 1 || notes[0] != "an earlier note" {
		t.Fatalf("SecLatestRunNotes: %v %v, want the earlier run's note", notes, err)
	}
	// Lane SEC-G2 audit finding 4: the card's "last run" skips it too.
	if r, ok, err := s.SecLatestRun(ctx, "custom.x"); err != nil || !ok || !r.StartedAt.Equal(old) || r.Outcome != "clean" {
		t.Fatalf("SecLatestRun: %+v %v %v, want the executed run", r, ok, err)
	}
	if last, err := s.SecLastDriverRun(ctx, "p1", "custom.x", policy.FindingScopeScheduled); err != nil || !last.Equal(notRun.StartedAt) {
		t.Fatalf("SecLastDriverRun: %v %v, want the not-run row (the schedule's last run)", last, err)
	}
	row, err := s.SecurityPostureFacts(ctx, day, now, SecurityScope{})
	if err != nil {
		t.Fatal(err)
	}
	if row.ScanFreshness != "under_1d" {
		t.Fatalf("freshness %q, want under_1d (the not-run row is not fresh)", row.ScanFreshness)
	}
	for _, o := range row.ScanOutcomes {
		if o.Outcome == "failed" {
			t.Fatalf("outcomes count the not-run row: %+v", row.ScanOutcomes)
		}
	}
	// A real failed run (the scanner ran) still counts everywhere.
	if err := s.InsertSecScanRun(ctx, SecScanRun{
		ProjectRootHash: "p1", Driver: "custom.x", Scope: policy.FindingScopeManual,
		Coverage: map[string]any{"Outcome": "failed", "Reason": "budget_exceeded"},
		Outcome:  "failed", StartedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if last, _ := s.SecLastScan(ctx, "p1"); !last.Equal(now) {
		t.Fatalf("SecLastScan after a real failed run: %v", last)
	}
	row, _ = s.SecurityPostureFacts(ctx, day, now, SecurityScope{})
	var failed int64
	for _, o := range row.ScanOutcomes {
		if o.Outcome == "failed" {
			failed = o.Runs
		}
	}
	if row.ScanFreshness != "under_1h" || failed != 1 {
		t.Fatalf("after a real failed run: %q %+v", row.ScanFreshness, row.ScanOutcomes)
	}
}

// TestSecurityPostureGateOutcomesAndTrustVerdicts (lane SEC-H2): the day's
// commit-gate outcomes (asked, denied, waited, unknown; overlapping by
// design) and launch trust verdicts, from guard events; a launch that fires
// two untrusted rules counts once; both facts are named as reported even
// when empty, so the org tells "none" from "not reported".
func TestSecurityPostureGateOutcomesAndTrustVerdicts(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	day := now.Format("2006-01-02")
	empty, err := s.SecurityPostureFacts(ctx, day, now, SecurityScope{})
	if err != nil || len(empty.GateOutcomes) != 0 || len(empty.TrustVerdicts) != 0 ||
		strings.Join(empty.Reported, ",") != "trust_verdicts,gate_outcomes" {
		t.Fatalf("empty: %+v %v", empty, err)
	}
	ev := func(rule, decision string, at time.Time) GuardEventRow {
		e := guardEventFixture("s1", rule, at)
		e.Decision = decision
		return e
	}
	launch := now.Add(-time.Minute)
	rows := []GuardEventRow{
		ev("S-791", "ask", now.Add(-5*time.Minute)),
		ev("S-792", "deny", now.Add(-4*time.Minute)),
		ev("S-793", "ask", now.Add(-3*time.Minute)),
		ev("S-794", "ask", now.Add(-2*time.Minute)),
		ev("S-701", "flag", launch),
		ev("S-704", "flag", launch), // the same launch: one untrusted verdict
		ev("S-705", "flag", now.Add(-30*time.Second)),
		ev("R-101", "deny", now.Add(-10*time.Second)), // not a gate or trust rule
	}
	if _, err := s.InsertGuardEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := s.SecurityPostureFacts(ctx, day, now, SecurityScope{})
	if err != nil {
		t.Fatal(err)
	}
	gate := map[string]int64{}
	for _, g := range got.GateOutcomes {
		gate[g.Outcome] = g.Events
	}
	if gate["asked"] != 3 || gate["denied"] != 1 || gate["waited"] != 1 || gate["unknown"] != 1 {
		t.Errorf("gate outcomes %v", gate)
	}
	trust := map[string]int64{}
	for _, v := range got.TrustVerdicts {
		trust[v.Verdict] = v.Count
	}
	if trust["untrusted"] != 1 || trust["flagged"] != 1 {
		t.Errorf("trust verdicts %v", trust)
	}
	if n, ok := orgcontract.NormalizeSecurityPosture(orgcontract.SecurityPostureRow{Day: day, ShareLevel: "posture", GateOutcomes: got.GateOutcomes, TrustVerdicts: got.TrustVerdicts, Reported: got.Reported}); !ok ||
		len(n.GateOutcomes) != 4 || len(n.TrustVerdicts) != 2 || len(n.Reported) != 2 {
		t.Errorf("normalized: %+v", n)
	}
}
