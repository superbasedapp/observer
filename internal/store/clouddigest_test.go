package store

import (
	"context"
	"testing"
	"time"
)

// TestUpsertCloudDigestRoundTrip pins the basic store/read path: a digest
// round-trips through ListCloudDigests scoped to its local project id, and
// is included in the "every project" (localProjectID="") listing too.
func TestUpsertCloudDigestRoundTrip(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	receivedAt := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)

	if err := s.UpsertCloudDigest(ctx, CloudDigest{
		ID: "digest-1", CloudProjectID: "cp_abc", LocalProjectID: "42",
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"busy week"}`,
		ReceivedAt: receivedAt,
	}); err != nil {
		t.Fatalf("UpsertCloudDigest: %v", err)
	}

	scoped, err := s.ListCloudDigests(ctx, "42", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (scoped): %v", err)
	}
	if len(scoped) != 1 {
		t.Fatalf("scoped digests = %d, want 1", len(scoped))
	}
	got := scoped[0]
	if got.ID != "digest-1" || got.CloudProjectID != "cp_abc" || got.LocalProjectID != "42" {
		t.Fatalf("digest = %+v", got)
	}
	if got.PeriodStart != "2026-09-08" || got.PeriodEnd != "2026-09-14" {
		t.Fatalf("period = %s..%s", got.PeriodStart, got.PeriodEnd)
	}
	if got.ResultJSON != `{"headline":"busy week"}` {
		t.Fatalf("result_json = %q", got.ResultJSON)
	}
	if !got.ReceivedAt.Equal(receivedAt) {
		t.Fatalf("received_at = %v, want %v", got.ReceivedAt, receivedAt)
	}
	if got.SupersededBy != nil {
		t.Fatalf("expected no superseded_by on the head digest, got %v", *got.SupersededBy)
	}

	all, err := s.ListCloudDigests(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (all): %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("all-projects digests = %d, want 1", len(all))
	}

	// A different project's digests are excluded from the scoped listing.
	other, err := s.ListCloudDigests(ctx, "99", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (other project): %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other-project digests = %d, want 0", len(other))
	}
}

func TestCloudDigestReplaysKeepNewestServerResult(t *testing.T) {
	for _, order := range [][]int{{1, 2, 1, 2}, {2, 1, 2, 1}} {
		s, _ := cloudTestStore(t)
		ctx := context.Background()
		for _, sequence := range order {
			id := "first"
			if sequence == 2 {
				id = "second"
			}
			if err := s.UpsertCloudDigest(ctx, CloudDigest{
				ID: id, CloudProjectID: "p", PeriodStart: "2026-09-07",
				PeriodEnd: "2026-09-14", SchemaVersion: "project_digest.v1", ResultJSON: `{}`, ServerSequence: int64(sequence), ServerStream: "prod/global-v1",
			}); err != nil {
				t.Fatal(err)
			}
		}
		current, err := s.ListCloudDigests(ctx, "", 10)
		if err != nil || len(current) != 1 || current[0].ID != "second" {
			t.Fatalf("pull order %v lost newest digest: %+v, %v", order, current, err)
		}
	}
}

// TestUpsertCloudDigestSupersedes pins the supersede rule: a newer digest id
// for the SAME project+period marks the prior head superseded and becomes
// the new head; re-upserting the SAME id updates the row in place without
// touching any superseded_by chain.
func TestUpsertCloudDigestSupersedes(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	first := CloudDigest{
		ID: "digest-1", CloudProjectID: "cp_abc", LocalProjectID: "42",
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"first pass"}`,
	}
	if err := s.UpsertCloudDigest(ctx, first); err != nil {
		t.Fatalf("upsert first: %v", err)
	}

	// A regenerated digest for the SAME period, a DIFFERENT server id,
	// supersedes the first.
	second := CloudDigest{
		ID: "digest-2", CloudProjectID: "cp_abc", LocalProjectID: "42",
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"regenerated"}`,
	}
	if err := s.UpsertCloudDigest(ctx, second); err != nil {
		t.Fatalf("upsert second: %v", err)
	}

	current, err := s.ListCloudDigests(ctx, "42", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests: %v", err)
	}
	if len(current) != 1 || current[0].ID != "digest-2" {
		t.Fatalf("current digests = %+v, want exactly digest-2", current)
	}

	// Re-upserting the SAME id (a re-pull) updates the row in place — still
	// exactly one current digest.
	second.ResultJSON = `{"headline":"regenerated, re-pulled"}`
	if err := s.UpsertCloudDigest(ctx, second); err != nil {
		t.Fatalf("re-upsert second: %v", err)
	}
	current2, err := s.ListCloudDigests(ctx, "42", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (after re-pull): %v", err)
	}
	if len(current2) != 1 || current2[0].ResultJSON != `{"headline":"regenerated, re-pulled"}` {
		t.Fatalf("current digests after re-pull = %+v", current2)
	}

	// A different period for the same project does not supersede anything —
	// both periods stay current, newest period first.
	thirdPeriod := CloudDigest{
		ID: "digest-3", CloudProjectID: "cp_abc", LocalProjectID: "42",
		PeriodStart: "2026-09-15", PeriodEnd: "2026-09-21",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"next week"}`,
	}
	if err := s.UpsertCloudDigest(ctx, thirdPeriod); err != nil {
		t.Fatalf("upsert third (different period): %v", err)
	}
	both, err := s.ListCloudDigests(ctx, "42", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (two periods): %v", err)
	}
	if len(both) != 2 {
		t.Fatalf("digests across two periods = %d, want 2", len(both))
	}
	if both[0].ID != "digest-3" {
		t.Fatalf("newest period first: got %+v", both)
	}
}

// TestUpsertCloudDigestUnresolvedLocalProject pins the "unknown pseudonym"
// path: a digest whose cloud_project_id this device never minted is still
// stored, with local_project_id empty, and shows up in the "every project"
// listing but never a specific project's scoped one.
func TestUpsertCloudDigestUnresolvedLocalProject(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	if err := s.UpsertCloudDigest(ctx, CloudDigest{
		ID: "digest-unmapped", CloudProjectID: "cp_never_minted", LocalProjectID: "",
		PeriodStart: "2026-09-08", PeriodEnd: "2026-09-14",
		SchemaVersion: "project_digest.v1", ResultJSON: `{"headline":"unmapped"}`,
	}); err != nil {
		t.Fatalf("UpsertCloudDigest: %v", err)
	}

	all, err := s.ListCloudDigests(ctx, "", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (all): %v", err)
	}
	if len(all) != 1 || all[0].LocalProjectID != "" {
		t.Fatalf("all digests = %+v, want one row with empty local_project_id", all)
	}

	scoped, err := s.ListCloudDigests(ctx, "42", 10)
	if err != nil {
		t.Fatalf("ListCloudDigests (scoped): %v", err)
	}
	if len(scoped) != 0 {
		t.Fatalf("scoped digests = %d, want 0 for an unrelated project id", len(scoped))
	}
}

// TestLookupLocalProjectByCloudPseudonym pins the reverse pseudonym lookup:
// a minted pseudonym resolves back to its local project id; an unrecognized
// one is a routine ok=false, never an error.
func TestLookupLocalProjectByCloudPseudonym(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	pseudonym, err := s.GetOrCreateCloudProjectPseudonym(ctx, "42")
	if err != nil {
		t.Fatalf("GetOrCreateCloudProjectPseudonym: %v", err)
	}

	local, ok, err := s.LookupLocalProjectByCloudPseudonym(ctx, pseudonym)
	if err != nil {
		t.Fatalf("LookupLocalProjectByCloudPseudonym: %v", err)
	}
	if !ok || local != "42" {
		t.Fatalf("lookup = (%q, %v), want (42, true)", local, ok)
	}

	_, ok, err = s.LookupLocalProjectByCloudPseudonym(ctx, "cp_never_minted")
	if err != nil {
		t.Fatalf("LookupLocalProjectByCloudPseudonym (unknown): %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for an unrecognized pseudonym")
	}

	_, ok, err = s.LookupLocalProjectByCloudPseudonym(ctx, "")
	if err != nil || ok {
		t.Fatalf("empty pseudonym: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestCloudDigestOrderingAcrossEstates(t *testing.T) {
	for _, streams := range [][2]string{{"staging/global-v1", "prod/global-v1"}, {"", "prod/global-v1"}} {
		s, _ := cloudTestStore(t)
		ctx := context.Background()
		first := CloudDigest{ID: "staging", CloudProjectID: "p", PeriodStart: "2026-09-07", PeriodEnd: "2026-09-14", SchemaVersion: "project_digest.v1", ResultJSON: `{}`, ServerSequence: 50, ServerStream: streams[0], ReceivedAt: time.Now().UTC()}
		second := first
		second.ID, second.ServerSequence, second.ServerStream, second.ReceivedAt = "prod", 2, streams[1], first.ReceivedAt.Add(time.Hour)
		for _, d := range []CloudDigest{first, second, first, second} {
			if err := s.UpsertCloudDigest(ctx, d); err != nil {
				t.Fatal(err)
			}
		}
		current, err := s.ListCloudDigests(ctx, "", 10)
		if err != nil || len(current) != 1 || current[0].ID != "prod" {
			t.Fatalf("streams %v: %+v, %v", streams, current, err)
		}
	}
}
