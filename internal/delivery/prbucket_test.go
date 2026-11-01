package delivery

import "testing"

// TestPRBucket pins the one definition of mergeable and blocked, one case
// per row of the readiness vocabulary.
func TestPRBucket(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		state PRState
		r     Readiness
		want  Bucket
	}{
		{PROpen, ReadyToMerge, BucketOpenReady},
		{PROpen, ReadyConflicts, BucketOpenBlocked},
		{PROpen, ReadyChecksFail, BucketOpenBlocked},
		{PROpen, ReadyChecksPend, BucketOpenBlocked},
		{PROpen, ReadyChangesReq, BucketOpenBlocked},
		{PROpen, ReadyReviewReq, BucketOpenBlocked},
		{PROpen, ReadyBehind, BucketOpenBlocked},
		{PROpen, ReadyBlockedOther, BucketOpenBlocked},
		{PROpen, ReadyUnknown, BucketOpenUnknown},
		{PROpen, "", BucketOpenUnknown},
		{PROpen, "something_new", BucketOpenUnknown},
		{PRDraft, ReadyToMerge, BucketDraft},
		{PRDraft, ReadyConflicts, BucketDraft},
		{PRMerged, "", BucketMerged},
		{PRMerged, ReadyConflicts, BucketMerged},
		{PRClosedUnmerged, "", BucketClosedUnmerged},
		{"", "", BucketOther},
		{"reopened", ReadyToMerge, BucketOther},
	} {
		got := PRBucket(tc.state, tc.r)
		if got != tc.want {
			t.Errorf("PRBucket(%q, %q) = %s, want %s", tc.state, tc.r, got, tc.want)
		}
		if IsMergeable(tc.state, tc.r) != (tc.want == BucketOpenReady) {
			t.Errorf("IsMergeable(%q, %q) disagrees with the bucket", tc.state, tc.r)
		}
		if IsBlocked(tc.state, tc.r) != (tc.want == BucketOpenBlocked) {
			t.Errorf("IsBlocked(%q, %q) disagrees with the bucket", tc.state, tc.r)
		}
	}
}
