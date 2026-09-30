package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/projectroi"
)

// TestLoadCommitOwnershipForeignAuthor is review 2026-09-29 finding 8 at the
// store seam: the fixture's commits are authored by hash "au". When the
// repository's local identity (project_commit_scan.local_author_hash, written
// by the commit scanner through SetCommitScanState) is a DIFFERENT hash, the
// co-contributed commit is a teammate's pulled commit: no owner, reason
// foreign_author. The same local hash, or an UNKNOWN one, keeps the
// pre-author-check owner.
func TestLoadCommitOwnershipForeignAuthor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		localHash  string // "" = never written / unknown
		wantOwner  string
		wantReason string
	}{
		{name: "unknown local identity keeps the owner", localHash: "", wantOwner: "sA", wantReason: projectroi.OwnerMostCodeLines},
		{name: "matching local identity keeps the owner", localHash: "au", wantOwner: "sA", wantReason: projectroi.OwnerMostCodeLines},
		{name: "different local identity: foreign_author, no owner", localHash: "someone-else", wantOwner: "", wantReason: projectroi.OwnerNoneForeignAuthor},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, projectID, base := ownershipFixture(t)
			ctx := context.Background()
			if tc.localHash != "" {
				if err := s.SetCommitScanState(ctx, ScanState{ProjectID: projectID, LastScanAt: base, LocalAuthorHash: tc.localHash}); err != nil {
					t.Fatalf("SetCommitScanState: %v", err)
				}
			}
			res, err := s.LoadCommitOwnership(ctx, projectID, base.Add(-time.Hour), base.Add(2*time.Hour), 0, OwnershipCaps{})
			if err != nil {
				t.Fatalf("LoadCommitOwnership: %v", err)
			}
			c1 := res.Ownership[commitIDBySHA(t, res, "c1sha")]
			if c1.OwnerSessionID != tc.wantOwner || c1.Reason != tc.wantReason {
				t.Fatalf("c1 owner = %q/%q, want %q/%q", c1.OwnerSessionID, c1.Reason, tc.wantOwner, tc.wantReason)
			}
		})
	}
}

// TestSetCommitScanStateKeepsLastKnownLocalAuthor pins the write rule: a scan
// whose identity read came back unknown ("") never forgets the last known
// local identity.
func TestSetCommitScanStateKeepsLastKnownLocalAuthor(t *testing.T) {
	t.Parallel()
	s, projectID, base := ownershipFixture(t)
	ctx := context.Background()
	if err := s.SetCommitScanState(ctx, ScanState{ProjectID: projectID, LastScanAt: base, LocalAuthorHash: "au"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCommitScanState(ctx, ScanState{ProjectID: projectID, LastScanAt: base.Add(time.Minute), LastError: "boom", ConsecutiveFailures: 1}); err != nil {
		t.Fatal(err)
	}
	st, ok, err := s.CommitScanState(ctx, projectID)
	if err != nil || !ok {
		t.Fatalf("CommitScanState: ok=%v err=%v", ok, err)
	}
	if st.LocalAuthorHash != "au" {
		t.Fatalf("local author hash = %q, want the last known %q", st.LocalAuthorHash, "au")
	}
	if st.LastError != "boom" {
		t.Fatalf("the rest of the state did not update: %+v", st)
	}
}

// TestProbeProjectCommitsMovesOnLocalIdentity pins that resolving the local
// identity (which can change every commit's owner without touching
// project_commits) moves the commit-ownership snapshot probe, so the org push
// re-sends the family instead of waiting for the freshness floor.
func TestProbeProjectCommitsMovesOnLocalIdentity(t *testing.T) {
	t.Parallel()
	s, projectID, base := ownershipFixture(t)
	ctx := context.Background()
	before, err := s.probeProjectCommits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCommitScanState(ctx, ScanState{ProjectID: projectID, LastScanAt: base, LocalAuthorHash: "someone-else"}); err != nil {
		t.Fatal(err)
	}
	after, err := s.probeProjectCommits(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatalf("probe did not move on a local identity change: %q", after)
	}
}
