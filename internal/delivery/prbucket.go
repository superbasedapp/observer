package delivery

// prbucket.go is the ONE definition of "mergeable" and "blocked" for a PR
// (plan 5.1). The node's Projects page (Summarise), the node's org wire
// (internal/store/deliverysummary.go) and the org rollup
// (internal/orgserver/rollup/delivery.go) all call PRBucket, so a PR can
// never read as blocked in one place and not in another.

// Bucket is where one PR falls in the delivery counts.
type Bucket string

// The closed Bucket vocabulary.
const (
	// BucketDraft is a draft PR: never mergeable, never blocked.
	BucketDraft Bucket = "draft"
	// BucketOpenReady is an open PR the provider would merge right now:
	// the one MERGEABLE bucket.
	BucketOpenReady Bucket = "open_ready"
	// BucketOpenBlocked is an open PR with a known blocking reason
	// (conflicts, failing or running required checks, changes requested,
	// review required, behind base, blocked by something else).
	BucketOpenBlocked Bucket = "open_blocked"
	// BucketOpenUnknown is an open PR whose readiness is unknown (the
	// provider is still computing it, or it was never read). Unknown is
	// unknown: it is neither mergeable nor blocked.
	BucketOpenUnknown Bucket = "open_unknown"
	// BucketMerged is a merged PR.
	BucketMerged Bucket = "merged"
	// BucketClosedUnmerged is a PR closed without merging.
	BucketClosedUnmerged Bucket = "closed_unmerged"
	// BucketOther is a state outside the closed vocabulary (a newer node
	// or a corrupt row): counted nowhere.
	BucketOther Bucket = "other"
)

// blockingReadiness is the set of readiness values that block an open PR.
// ReadyToMerge, ReadyUnknown and "" are deliberately absent.
var blockingReadiness = map[Readiness]bool{
	ReadyConflicts:    true,
	ReadyChecksFail:   true,
	ReadyChecksPend:   true,
	ReadyChangesReq:   true,
	ReadyReviewReq:    true,
	ReadyBehind:       true,
	ReadyBlockedOther: true,
}

// PRBucket places a PR by its state and, for an open PR, its readiness.
// Readiness is ignored for every state but PROpen.
func PRBucket(state PRState, r Readiness) Bucket {
	switch state {
	case PRDraft:
		return BucketDraft
	case PRMerged:
		return BucketMerged
	case PRClosedUnmerged:
		return BucketClosedUnmerged
	case PROpen:
		switch {
		case r == ReadyToMerge:
			return BucketOpenReady
		case blockingReadiness[r]:
			return BucketOpenBlocked
		default:
			return BucketOpenUnknown
		}
	}
	return BucketOther
}

// IsMergeable reports whether a PR is open and ready to merge (plan 5.1).
func IsMergeable(state PRState, r Readiness) bool {
	return PRBucket(state, r) == BucketOpenReady
}

// IsBlocked reports whether a PR is open with a known blocking reason. An
// open PR whose readiness is unknown is NOT blocked.
func IsBlocked(state PRState, r Readiness) bool {
	return PRBucket(state, r) == BucketOpenBlocked
}
