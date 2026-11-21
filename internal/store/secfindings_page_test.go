//go:build !sbo_omit_security

package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestSecFindingPagingAndSort: Offset pages, CountSecFindings shares the
// WHERE clause, the severity sort ranks by policy.FindingSeverities()
// (ties by last_seen DESC, id), and a filter with no Sort keeps the old
// last_seen DESC order.
func TestSecFindingPagingAndSort(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)
	sevs := []secfinding.Severity{
		policy.FindingSeverityLow, policy.FindingSeverityCritical, policy.FindingSeverityInfo,
		policy.FindingSeverityHigh, policy.FindingSeverityMedium, policy.FindingSeverityCritical,
	}
	for i, sev := range sevs {
		f := secFinding("p1", fmt.Sprintf("k%d", i))
		f.Severity = sev
		// k0 is the oldest sighting, k5 the newest.
		if _, _, err := s.UpsertSecFinding(ctx, f, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.UpsertSecFinding(ctx, secFinding("p2", "other"), t0); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"}); err != nil || n != 6 {
		t.Fatalf("count: %d %v", n, err)
	}
	if n, _ := s.CountSecFindings(ctx, SecFindingFilter{}); n != 7 {
		t.Fatalf("count all: %d", n)
	}
	if n, _ := s.CountSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1", Status: policy.FindingStatusFixedVerified}); n != 0 {
		t.Fatalf("count by status: %d", n)
	}
	keys := func(f SecFindingFilter) []string {
		t.Helper()
		got, err := s.ListSecFindings(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, x := range got {
			out = append(out, x.LocalKey)
		}
		return out
	}
	eq := func(name string, got, want []string) {
		t.Helper()
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: %v, want %v", name, got, want)
		}
	}
	eq("default order", keys(SecFindingFilter{ProjectRootHash: "p1"}), []string{"k5", "k4", "k3", "k2", "k1", "k0"})
	eq("default ignores Desc", keys(SecFindingFilter{ProjectRootHash: "p1", Desc: true}), []string{"k5", "k4", "k3", "k2", "k1", "k0"})
	eq("severity desc", keys(SecFindingFilter{ProjectRootHash: "p1", Sort: SecSortSeverity, Desc: true}), []string{"k5", "k1", "k3", "k4", "k0", "k2"})
	eq("severity asc", keys(SecFindingFilter{ProjectRootHash: "p1", Sort: SecSortSeverity}), []string{"k2", "k0", "k4", "k3", "k5", "k1"})
	eq("first_seen asc", keys(SecFindingFilter{ProjectRootHash: "p1", Sort: SecSortFirstSeen}), []string{"k0", "k1", "k2", "k3", "k4", "k5"})
	eq("last_seen asc", keys(SecFindingFilter{ProjectRootHash: "p1", Sort: SecSortLastSeen}), []string{"k0", "k1", "k2", "k3", "k4", "k5"})
	eq("page 2", keys(SecFindingFilter{ProjectRootHash: "p1", Sort: SecSortSeverity, Desc: true, Limit: 2, Offset: 2}), []string{"k3", "k4"})
	eq("past the end", keys(SecFindingFilter{ProjectRootHash: "p1", Limit: 2, Offset: 10}), nil)
	eq("unknown sort is the default", keys(SecFindingFilter{ProjectRootHash: "p1", Sort: "rel_path; DROP TABLE x"}), []string{"k5", "k4", "k3", "k2", "k1", "k0"})
}

// TestSecDependencyEvidence: only a dependency finding's evidence is
// returned; a secret's redacted excerpt never is.
func TestSecDependencyEvidence(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	sec := secFinding("p1", "secret")
	sec.EvidenceRedacted = "AKIA****************"
	secID, _, err := s.UpsertSecFinding(ctx, sec, now)
	if err != nil {
		t.Fatal(err)
	}
	dep := secfinding.Normalize(secfinding.Finding{
		LocalKey: "dep", Rule: secfinding.Rule{ID: "GHSA-35jh-r3h4-6jhm", Pack: "osv"}, Category: policy.FindingVulnerableDependency,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh,
		Project: secfinding.Project{RootHash: "p1"}, Location: secfinding.Location{RelPath: "package-lock.json"},
		EvidenceRedacted: "npm lodash@4.17.20", Message: "Known vulnerability in a npm dependency (GHSA-35jh-r3h4-6jhm).",
	})
	depID, _, err := s.UpsertSecFinding(ctx, dep, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SecDependencyEvidence(ctx, []string{secID, depID, "nope"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[depID] != "npm lodash@4.17.20" {
		t.Fatalf("evidence: %v", got)
	}
	if _, leaked := got[secID]; leaked {
		t.Fatal("a secret's evidence left the store")
	}
	if got, err := s.SecDependencyEvidence(ctx, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
}
