package delivery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func boolp(b bool) *bool { return &b }

// TestMapGitHubPRRows is one case per row of githubRows, in table order.
func TestMapGitHubPRRows(t *testing.T) {
	t.Parallel()
	failing := []CheckRun{{Status: "completed", Conclusion: "failure"}}
	pending := []CheckRun{{Status: "in_progress"}}
	changes := []Review{{Login: "rev", State: "CHANGES_REQUESTED", SubmittedAt: "2026-10-15T10:00:00Z"}}
	cases := []struct {
		row       string
		in        GitHubPRInput
		state     PRState
		readiness Readiness
	}{
		{"merged", GitHubPRInput{State: "closed", Merged: true, MergeableState: "unknown"}, PRMerged, ""},
		{"merged (list endpoint, merged_at only)", GitHubPRInput{State: "closed", MergedAt: "2026-10-15T15:15:11Z"}, PRMerged, ""},
		{"closed", GitHubPRInput{State: "closed"}, PRClosedUnmerged, ""},
		{"draft", GitHubPRInput{State: "open", Draft: true, Mergeable: boolp(true), MergeableState: "clean"}, PRDraft, ""},
		{"conflicts", GitHubPRInput{State: "open", Mergeable: boolp(false), MergeableState: "dirty"}, PROpen, ReadyConflicts},
		{"unknown", GitHubPRInput{State: "open", MergeableState: "unknown"}, PROpen, ReadyUnknown},
		{"behind", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "behind"}, PROpen, ReadyBehind},
		{"blocked_checks_failing", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "blocked", CheckRuns: failing}, PROpen, ReadyChecksFail},
		{"blocked_changes_requested", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "blocked", Reviews: changes}, PROpen, ReadyChangesReq},
		{"blocked_checks_pending", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "blocked", CheckRuns: pending}, PROpen, ReadyChecksPend},
		{"blocked_review_inferred", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "blocked"}, PROpen, ReadyReviewReq},
		{"unstable", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "unstable", CheckRuns: failing}, PROpen, ReadyToMerge},
		{"clean", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "clean"}, PROpen, ReadyToMerge},
		{"clean (has_hooks)", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "has_hooks"}, PROpen, ReadyToMerge},
		{"other", GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "something_new"}, PROpen, ReadyUnknown},
	}
	if len(cases) < len(githubRows) {
		t.Fatalf("%d cases for %d rows: every row needs a case", len(cases), len(githubRows))
	}
	for _, tc := range cases {
		state, readiness, _, _ := MapGitHubPR(tc.in)
		if state != tc.state || readiness != tc.readiness {
			t.Errorf("row %s: got (%q, %q), want (%q, %q)", tc.row, state, readiness, tc.state, tc.readiness)
		}
	}
}

func TestMapGitHubPRFacets(t *testing.T) {
	t.Parallel()
	_, _, f, raw := MapGitHubPR(GitHubPRInput{
		State: "open", Mergeable: boolp(true), MergeableState: "unstable",
		CheckRuns: []CheckRun{{Status: "completed", Conclusion: "failure"}, {Status: "completed", Conclusion: "success"}},
		Reviews: []Review{
			{Login: "a", State: "CHANGES_REQUESTED", SubmittedAt: "2026-10-15T10:00:00Z"},
			{Login: "a", State: "COMMENTED", SubmittedAt: "2026-10-15T11:00:00Z"},
			{Login: "a", State: "APPROVED", SubmittedAt: "2026-10-15T12:00:00Z"},
		},
	})
	if f.Checks != ChecksNonRequiredFailing || f.Review != ReviewApproved || f.Conflicts != ConflictsNone || f.Behind {
		t.Fatalf("facets = %+v", f)
	}
	if raw != "open/unstable" {
		t.Fatalf("raw = %q", raw)
	}
	_, _, f, _ = MapGitHubPR(GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "blocked"})
	if f.Review != ReviewRequiredInferred || f.Checks != ChecksNone {
		t.Fatalf("inferred review facets = %+v", f)
	}
	// Combined status with total_count 0 is "no statuses", never pending (12.1).
	_, _, f, _ = MapGitHubPR(GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "clean", StatusTotal: 0, StatusState: "pending"})
	if f.Checks != ChecksNone {
		t.Fatalf("empty combined status read as %q, want none", f.Checks)
	}
	// A dismissed review clears the reviewer's changes request.
	_, _, f, _ = MapGitHubPR(GitHubPRInput{State: "open", Mergeable: boolp(true), MergeableState: "clean", Reviews: []Review{
		{Login: "b", State: "CHANGES_REQUESTED", SubmittedAt: "2026-10-15T10:00:00Z"},
		{Login: "b", State: "DISMISSED", SubmittedAt: "2026-10-15T11:00:00Z"},
	}})
	if f.Review != ReviewNone {
		t.Fatalf("dismissed review facet = %q", f.Review)
	}
}

// ghFixturePR is the subset of the single-PR / list JSON the fixture test
// decodes (the same fields internal/deliverynet reads).
type ghFixturePR struct {
	Number         int64  `json:"number"`
	State          string `json:"state"`
	Draft          bool   `json:"draft"`
	Merged         bool   `json:"merged"`
	MergedAt       string `json:"merged_at"`
	Mergeable      *bool  `json:"mergeable"`
	MergeableState string `json:"mergeable_state"`
}

func (p ghFixturePR) input() GitHubPRInput {
	return GitHubPRInput{State: p.State, Draft: p.Draft, Merged: p.Merged, MergedAt: p.MergedAt, Mergeable: p.Mergeable, MergeableState: p.MergeableState}
}

func readFixture(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "delivery", "github", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
}

// TestMapGitHubPRFixtures runs the mapping over the Phase 0 fixtures
// (12.1) so every grounded finding stays pinned.
func TestMapGitHubPRFixtures(t *testing.T) {
	t.Parallel()

	var draft, unstable, merged ghFixturePR
	readFixture(t, "pull_draft_clean.json", &draft)
	readFixture(t, "pull_open_unstable.json", &unstable)
	readFixture(t, "pull_merged_mergecommit.json", &merged)

	var checks struct {
		CheckRuns []struct {
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
		} `json:"check_runs"`
	}
	readFixture(t, "check_runs_mixed.json", &checks)
	var status struct {
		State      string `json:"state"`
		TotalCount int    `json:"total_count"`
	}
	readFixture(t, "combined_status_empty.json", &status)
	var reviews []struct {
		State string `json:"state"`
		User  struct {
			Login string `json:"login"`
		} `json:"user"`
		SubmittedAt string `json:"submitted_at"`
	}
	readFixture(t, "reviews_commented.json", &reviews)

	// Draft with mergeable_state "clean" is a draft (draft row before
	// mergeable_state).
	if st, rd, _, _ := MapGitHubPR(draft.input()); st != PRDraft || rd != "" {
		t.Errorf("draft fixture = (%q, %q), want draft", st, rd)
	}

	// Open, unstable, a failing non-required check, a commented review and an
	// empty combined status: ready, with the non-required facet.
	in := unstable.input()
	for _, c := range checks.CheckRuns {
		in.CheckRuns = append(in.CheckRuns, CheckRun{Status: c.Status, Conclusion: c.Conclusion})
	}
	in.StatusTotal, in.StatusState = status.TotalCount, status.State
	for _, r := range reviews {
		in.Reviews = append(in.Reviews, Review{Login: r.User.Login, State: r.State, SubmittedAt: r.SubmittedAt})
	}
	st, rd, f, raw := MapGitHubPR(in)
	if st != PROpen || rd != ReadyToMerge || f.Checks != ChecksNonRequiredFailing || f.Review != ReviewNone || raw != "open/unstable" {
		t.Errorf("unstable fixture = (%q, %q, %+v, %q)", st, rd, f, raw)
	}

	// Merged reports mergeable null / unknown: still merged.
	if st, rd, _, _ := MapGitHubPR(merged.input()); st != PRMerged || rd != "" {
		t.Errorf("merged fixture = (%q, %q), want merged", st, rd)
	}

	// The list endpoint has no mergeable fields: open PRs are unknown,
	// merged ones merged (merged_at), closed ones closed.
	var list []ghFixturePR
	readFixture(t, "pulls_list_cli.json", &list)
	if len(list) == 0 {
		t.Fatal("empty list fixture")
	}
	for _, p := range list {
		st, rd, _, _ := MapGitHubPR(p.input())
		switch {
		case p.MergedAt != "":
			if st != PRMerged {
				t.Errorf("list #%d merged_at set but state %q", p.Number, st)
			}
		case p.State == "closed":
			if st != PRClosedUnmerged {
				t.Errorf("list #%d closed but state %q", p.Number, st)
			}
		case p.Draft:
			if st != PRDraft {
				t.Errorf("list #%d draft but state %q", p.Number, st)
			}
		default:
			if st != PROpen || rd != ReadyUnknown {
				t.Errorf("list #%d open = (%q, %q), want open/unknown", p.Number, st, rd)
			}
		}
	}
}
