package delivery

import (
	"sort"
	"strings"
)

// github.go maps a GitHub pull request, as the REST API reports it, onto
// Observer's closed vocabulary (plan 5.1 / 5.2, grounded in 12.1 against the
// fixtures in testdata/delivery/github). internal/deliverynet decodes the
// JSON into GitHubPRInput; this file only decides.

// CheckRun is one GitHub check run (GET /commits/{head}/check-runs).
type CheckRun struct {
	Status     string // queued | in_progress | completed | waiting | requested | pending
	Conclusion string // success | failure | neutral | cancelled | skipped | timed_out | action_required | stale | ""
}

// Review is one PR review (GET /pulls/{n}/reviews).
type Review struct {
	Login       string
	State       string // APPROVED | CHANGES_REQUESTED | COMMENTED | DISMISSED | PENDING
	SubmittedAt string // RFC3339; reviews are compared in this order
}

// GitHubPRInput is the subset of a GitHub PR the mapping reads. The fields
// come from the single-PR endpoint (GET /pulls/{n}); the list endpoint has no
// merged / mergeable / mergeable_state (12.1), so a PR known only from the
// list has Mergeable nil and MergeableState "" and maps to unknown readiness.
type GitHubPRInput struct {
	State          string // open | closed
	Draft          bool
	Merged         bool
	MergedAt       string
	Mergeable      *bool
	MergeableState string // clean | unstable | has_hooks | blocked | behind | dirty | draft | unknown
	CheckRuns      []CheckRun
	// StatusTotal / StatusState are the legacy combined status
	// (GET /commits/{head}/status). StatusTotal 0 means "no legacy statuses
	// at all", never pending, whatever StatusState says (12.1).
	StatusTotal int
	StatusState string // success | failure | error | pending
	Reviews     []Review
}

// Check facet values.
const (
	ChecksPassing            = "passing"
	ChecksFailing            = "failing"
	ChecksPending            = "pending"
	ChecksNone               = "none"
	ChecksNonRequiredFailing = "nonrequired_failing"
)

// Review facet values.
const (
	ReviewApproved         = "approved"
	ReviewChangesRequested = "changes_requested"
	ReviewRequiredInferred = "review_required_inferred"
	ReviewNone             = "none"
)

// Conflicts facet values.
const (
	ConflictsNone    = "none"
	ConflictsPresent = "conflicts"
	ConflictsUnknown = "unknown"
)

// githubSignals are the facts every mapping row reads, derived once.
type githubSignals struct {
	in               GitHubPRInput
	state            string // lowercased
	mstate           string // lowercased mergeable_state
	merged           bool
	checks           string
	changesRequested bool
	approved         bool
}

// githubRow is one row of githubRows: when match accepts the signals, the PR
// gets that state and readiness (and readiness is only set for PROpen).
type githubRow struct {
	name      string
	match     func(g githubSignals) bool
	state     PRState
	readiness Readiness
}

// githubRows is the ordered GitHub mapping table (plan 5.2 as corrected by
// 12.1), walked top down; the first matching row decides.
//
//   - merged and closed are lifecycle states and come first: a merged PR
//     reports mergeable null and mergeable_state "unknown" (12.1), which must
//     not read as an open PR.
//   - draft is checked BEFORE mergeable_state: a draft PR was observed with
//     mergeable_state "clean" (12.1).
//   - conflicts (mergeable false or dirty) before unknown: an explicit false
//     is an answer even when the state string lags.
//   - mergeable null or mergeable_state unknown/empty: GitHub computes
//     mergeability lazily, so this is unknown and deliverysvc re-polls.
//   - behind, then the "blocked" family with the reason we can see (failing
//     checks, changes requested, pending checks) and finally review_required
//     inferred from "blocked" with no other visible reason (REST has no
//     reviewDecision, 12.1; the facet says it is inferred).
//   - unstable is mergeable with a NON-required check failing: ready, with
//     the nonrequired_failing checks facet (12.1).
//   - clean and has_hooks are ready.
var githubRows = []githubRow{
	{"merged", func(g githubSignals) bool { return g.merged }, PRMerged, ""},
	{"closed", func(g githubSignals) bool { return g.state == "closed" }, PRClosedUnmerged, ""},
	{"draft", func(g githubSignals) bool { return g.in.Draft || g.mstate == "draft" }, PRDraft, ""},
	{"conflicts", func(g githubSignals) bool {
		return (g.in.Mergeable != nil && !*g.in.Mergeable) || g.mstate == "dirty"
	}, PROpen, ReadyConflicts},
	{"unknown", func(g githubSignals) bool {
		return g.in.Mergeable == nil || g.mstate == "" || g.mstate == "unknown"
	}, PROpen, ReadyUnknown},
	{"behind", func(g githubSignals) bool { return g.mstate == "behind" }, PROpen, ReadyBehind},
	{"blocked_checks_failing", func(g githubSignals) bool {
		return g.mstate == "blocked" && g.checks == ChecksFailing
	}, PROpen, ReadyChecksFail},
	{"blocked_changes_requested", func(g githubSignals) bool {
		return g.mstate == "blocked" && g.changesRequested
	}, PROpen, ReadyChangesReq},
	{"blocked_checks_pending", func(g githubSignals) bool {
		return g.mstate == "blocked" && g.checks == ChecksPending
	}, PROpen, ReadyChecksPend},
	{"blocked_review_inferred", func(g githubSignals) bool { return g.mstate == "blocked" }, PROpen, ReadyReviewReq},
	{"unstable", func(g githubSignals) bool { return g.mstate == "unstable" }, PROpen, ReadyToMerge},
	{"clean", func(g githubSignals) bool { return g.mstate == "clean" || g.mstate == "has_hooks" }, PROpen, ReadyToMerge},
	{"other", func(githubSignals) bool { return true }, PROpen, ReadyUnknown},
}

// MapGitHubPR maps one GitHub PR onto (state, readiness, facets) plus the
// provider's own strings for a tooltip ("open/unstable", "closed/merged").
// Readiness is "" unless the state is PROpen. Facets are filled for every
// state so the expanded row can list them.
func MapGitHubPR(in GitHubPRInput) (PRState, Readiness, Facets, string) {
	g := githubSignals{
		in:     in,
		state:  strings.ToLower(strings.TrimSpace(in.State)),
		mstate: strings.ToLower(strings.TrimSpace(in.MergeableState)),
		merged: in.Merged || strings.TrimSpace(in.MergedAt) != "",
	}
	g.checks = githubChecks(in)
	g.changesRequested, g.approved = githubReviews(in.Reviews)

	var row githubRow
	for _, r := range githubRows {
		if r.match(g) {
			row = r
			break
		}
	}

	facets := Facets{Checks: g.checks, Review: ReviewNone, Conflicts: ConflictsUnknown}
	switch {
	case g.changesRequested:
		facets.Review = ReviewChangesRequested
	case g.approved:
		facets.Review = ReviewApproved
	}
	if row.readiness == ReadyReviewReq {
		facets.Review = ReviewRequiredInferred
	}
	switch {
	case (in.Mergeable != nil && !*in.Mergeable) || g.mstate == "dirty":
		facets.Conflicts = ConflictsPresent
	case in.Mergeable != nil && *in.Mergeable:
		facets.Conflicts = ConflictsNone
	}
	facets.Behind = g.mstate == "behind"
	if g.mstate == "unstable" && row.state == PROpen && facets.Checks != ChecksPending {
		facets.Checks = ChecksNonRequiredFailing
	}

	raw := g.state
	switch {
	case g.merged:
		raw += "/merged"
	case g.mstate != "":
		raw += "/" + g.mstate
	}
	return row.state, row.readiness, facets, raw
}

// failingConclusions are the check-run conclusions that mean "this check did
// not pass". neutral and skipped are not failures.
var failingConclusions = map[string]bool{
	"failure": true, "timed_out": true, "cancelled": true, "action_required": true, "stale": true,
}

// githubChecks folds check runs and the legacy combined status into one
// facet: failing beats pending beats passing; nothing at all is none.
func githubChecks(in GitHubPRInput) string {
	var failing, pending, seen bool
	for _, c := range in.CheckRuns {
		seen = true
		status := strings.ToLower(c.Status)
		concl := strings.ToLower(c.Conclusion)
		switch {
		case status != "" && status != "completed":
			pending = true
		case failingConclusions[concl]:
			failing = true
		}
	}
	if in.StatusTotal > 0 {
		seen = true
		switch strings.ToLower(in.StatusState) {
		case "failure", "error":
			failing = true
		case "pending":
			pending = true
		}
	}
	switch {
	case failing:
		return ChecksFailing
	case pending:
		return ChecksPending
	case seen:
		return ChecksPassing
	}
	return ChecksNone
}

// githubReviews reduces reviews to the latest decisive review per reviewer
// (COMMENTED and PENDING never change a reviewer's standing; DISMISSED clears
// it) and reports whether any reviewer currently requests changes or
// approves.
func githubReviews(reviews []Review) (changesRequested, approved bool) {
	rs := append([]Review(nil), reviews...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].SubmittedAt < rs[j].SubmittedAt })
	latest := map[string]string{}
	for _, r := range rs {
		switch st := strings.ToUpper(r.State); st {
		case "APPROVED", "CHANGES_REQUESTED":
			latest[r.Login] = st
		case "DISMISSED":
			delete(latest, r.Login)
		}
	}
	for _, st := range latest {
		switch st {
		case "CHANGES_REQUESTED":
			changesRequested = true
		case "APPROVED":
			approved = true
		}
	}
	return changesRequested, approved
}
