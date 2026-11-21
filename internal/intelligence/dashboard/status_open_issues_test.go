//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// openIssueRow is one finding of the open-issue fixture.
type openIssueRow struct {
	key, project, rule, rel, evidence string
	cat                               policy.FindingCategory
	sev                               policy.FindingSeverity
	// closed moves the finding out of open after it is stored.
	closed bool
}

// seedOpenIssueRows stores rows as findings.
func seedOpenIssueRows(t *testing.T, s *Server, rows []openIssueRow) {
	t.Helper()
	ctx := context.Background()
	st := store.New(s.db())
	t0 := time.Now().Add(-time.Hour)
	for i, x := range rows {
		id, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
			LocalKey: x.key, Rule: secfinding.Rule{ID: x.rule}, Engine: secfinding.Engine{Driver: "native"},
			Category: x.cat, Severity: x.sev, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
			Project: secfinding.Project{RootHash: x.project}, Location: secfinding.Location{RelPath: x.rel},
			EvidenceRedacted: x.evidence, Message: "m", Status: policy.FindingStatusOpen,
		}), t0.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if x.closed {
			if _, err := s.db().ExecContext(ctx, `UPDATE sec_findings SET status = ? WHERE id = ?`,
				string(policy.FindingStatusFixedVerified), id); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// statusOpenIssuesOf reads counts.open_issues off GET /api/status; ok is
// false when the key is absent.
func statusOpenIssuesOf(t *testing.T, s *Server) (diag.OpenIssueCounts, bool) {
	t.Helper()
	got := getStatus(t, s)
	counts, _ := got["counts"].(map[string]any)
	raw, ok := counts["open_issues"]
	if !ok {
		return diag.OpenIssueCounts{}, false
	}
	body, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var c diag.OpenIssueCounts
	if err := json.Unmarshal(body, &c); err != nil {
		t.Fatal(err)
	}
	return c, true
}

// TestAPIStatusOpenIssues: /api/status's open_issues counts open issues the
// way the Code security page header does (each issue once, however many
// projects repeat it; a closed finding left out), and agrees with the
// groups route the header reads for the same filter.
func TestAPIStatusOpenIssues(t *testing.T) {
	cases := []struct {
		name string
		rows []openIssueRow
		want diag.OpenIssueCounts
	}{
		{name: "no findings is a counted zero", want: diag.OpenIssueCounts{}},
		{
			name: "one advisory repeated across worktrees is one issue",
			rows: []openIssueRow{
				{"d1", "p1", "GHSA-1", "package-lock.json", "npm lodash@4.17.20", policy.FindingVulnerableDependency, policy.FindingSeverityCritical, false},
				{"d1", "p2", "GHSA-1", "package-lock.json", "npm lodash@4.17.20", policy.FindingVulnerableDependency, policy.FindingSeverityCritical, false},
				{"d1", "p3", "GHSA-1", "package-lock.json", "npm lodash@4.17.20", policy.FindingVulnerableDependency, policy.FindingSeverityCritical, false},
			},
			want: diag.OpenIssueCounts{Total: 1, Critical: 1},
		},
		{
			name: "severities split and a closed finding left out",
			rows: []openIssueRow{
				{"d1", "p1", "GHSA-1", "package-lock.json", "npm lodash@4.17.20", policy.FindingVulnerableDependency, policy.FindingSeverityCritical, false},
				{"s1", "p1", "S-721", "cmd/main.go", "AKIA****", policy.FindingSecret, policy.FindingSeverityHigh, false},
				{"s1", "p2", "S-721", "cmd/main.go", "AKIA****", policy.FindingSecret, policy.FindingSeverityHigh, false},
				{"s2", "p1", "S-721", "cmd/other.go", "AKIA****", policy.FindingSecret, policy.FindingSeverityHigh, false},
				{"c1", "p1", "KICS-1", "infra/Dockerfile", "", policy.FindingIaC, policy.FindingSeverityMedium, false},
				{"c2", "p1", "KICS-2", "infra/main.tf", "", policy.FindingIaC, policy.FindingSeverityCritical, true},
			},
			want: diag.OpenIssueCounts{Total: 4, Critical: 1, High: 2},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			seedOpenIssueRows(t, s, tc.rows)
			got, ok := statusOpenIssuesOf(t, s)
			if !ok {
				t.Fatal("counts.open_issues absent from /api/status")
			}
			if got != tc.want {
				t.Errorf("open_issues = %+v, want %+v", got, tc.want)
			}
			// The header's own read: the same total and split.
			var page securityFindingGroupsJS
			getSecurityJSON(t, s.handleSecurityFindingsGroups,
				"/api/security/findings/groups?by=issue&status=open&limit=5&sort=severity&dir=desc", &page)
			header := diag.OpenIssueCounts{
				Total:    page.Total,
				Critical: page.BySeverity[string(policy.FindingSeverityCritical)],
				High:     page.BySeverity[string(policy.FindingSeverityHigh)],
			}
			if got != header {
				t.Errorf("open_issues = %+v, the page header reads %+v", got, header)
			}
		})
	}
}

// TestAPIStatusOpenIssuesRidesTheStatusCache: the count is computed inside
// the memoized status scan, not per request, so a finding stored after the
// scan shows once the entry is refreshed, never on a cache hit.
func TestAPIStatusOpenIssuesRidesTheStatusCache(t *testing.T) {
	s, _ := newTestServer(t)
	advance := pinClock(s)
	first, _ := statusOpenIssuesOf(t, s)
	if first.Total != 0 {
		t.Fatalf("open_issues before seeding = %+v, want zero", first)
	}
	seedOpenIssueRows(t, s, []openIssueRow{
		{"s1", "p1", "S-721", "cmd/main.go", "AKIA****", policy.FindingSecret, policy.FindingSeverityHigh, false},
	})
	if hit, _ := statusOpenIssuesOf(t, s); hit.Total != 0 {
		t.Errorf("a cache hit recounted: %+v, want the memoized zero", hit)
	}
	// Past the TTL: the stale entry is served once while the background
	// scan refreshes it (getStatus waits for that), then the fresh one.
	advance(statusSnapshotTTL)
	statusOpenIssuesOf(t, s)
	if fresh, _ := statusOpenIssuesOf(t, s); fresh != (diag.OpenIssueCounts{Total: 1, High: 1}) {
		t.Errorf("after the refresh open_issues = %+v, want one high issue", fresh)
	}
}

// TestStatusOpenIssuesCost measures the count on a few thousand findings,
// the size of a busy node, since it runs on every /api/status scan (at most
// one per statusSnapshotTTL). The timing is logged, not asserted (a shared
// CI runner under -race is not a benchmark); the counts are asserted.
func TestStatusOpenIssuesCost(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds thousands of findings")
	}
	s, _ := newTestServer(t)
	ctx := context.Background()
	// 5,000 findings over 1,250 distinct issues: projects p and p+5 carry
	// the same issues (worktrees of one repository), every 10th issue is
	// closed everywhere.
	const projects, perProject = 20, 250
	tx, err := s.db().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	sevs := []policy.FindingSeverity{
		policy.FindingSeverityCritical, policy.FindingSeverityHigh,
		policy.FindingSeverityMedium, policy.FindingSeverityLow,
	}
	openIssues := map[int]policy.FindingSeverity{}
	for p := 0; p < projects; p++ {
		for i := 0; i < perProject; i++ {
			issue := i + (p%5)*perProject
			status := policy.FindingStatusOpen
			if i%10 == 9 {
				status = policy.FindingStatusFixedVerified
			} else {
				openIssues[issue] = sevs[issue%len(sevs)]
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO sec_findings
				(id, project_root_hash, local_key, rel_path, rule_id, category, severity, confidence,
				 evidence_redacted, message, status, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, 'high', '', 'm', ?, ?, ?)`,
				fmt.Sprintf("f-%d-%d", p, i), fmt.Sprintf("p%d", p), fmt.Sprintf("k%d", issue),
				fmt.Sprintf("src/file%d.go", issue), fmt.Sprintf("R-%d", issue%40),
				string(policy.FindingSecret), string(sevs[issue%len(sevs)]), string(status), ts, ts); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got := s.statusOpenIssues(ctx, s.db())
	elapsed := time.Since(start)
	if got == nil {
		t.Fatal("statusOpenIssues = nil on a readable store")
	}
	want := diag.OpenIssueCounts{Total: len(openIssues)}
	for _, sev := range openIssues {
		switch sev {
		case policy.FindingSeverityCritical:
			want.Critical++
		case policy.FindingSeverityHigh:
			want.High++
		}
	}
	if want.Total != 1125 {
		t.Fatalf("fixture: %d open issues, want 1125", want.Total)
	}
	if *got != want {
		t.Errorf("statusOpenIssues = %+v, want %+v", *got, want)
	}
	t.Logf("open-issue count over %d findings: %v", projects*perProject, elapsed)
}
