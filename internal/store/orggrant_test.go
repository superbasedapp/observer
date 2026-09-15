package store

import (
	"context"
	"testing"
	"time"
)

func testGrantRow() EnrolmentGrant {
	return EnrolmentGrant{
		OrgKey:       "org-key-1",
		Generation:   3,
		OrgID:        "org-1",
		OrgName:      "Acme",
		OrgServerURL: "https://org.example.com",
		KeyPinSHA256: "abc123",
		Authority:    []string{"dashboard.visibility"},
		ConsentMode:  "interactive",
		ConsentActor: "dev@example.com",
		GrantedAt:    time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC),
		ExpiresAt:    time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC),
		Signature:    "sig",
		ReceiptHash:  "rh",
	}
}

func TestEnrolmentGrantRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)

	if _, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1"); err != nil || ok {
		t.Fatalf("fresh DB: ok=%v err=%v, want a grant-free node", ok, err)
	}

	want := testGrantRow()
	if err := s.WriteEnrolmentGrant(ctx, want); err != nil {
		t.Fatalf("WriteEnrolmentGrant: %v", err)
	}
	got, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1")
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGrant: ok=%v err=%v", ok, err)
	}
	if got.Generation != want.Generation || got.OrgName != want.OrgName ||
		got.KeyPinSHA256 != want.KeyPinSHA256 || got.ConsentMode != want.ConsentMode ||
		got.ConsentActor != want.ConsentActor || got.Signature != want.Signature {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", got, want)
	}
	if len(got.Authority) != 1 || got.Authority[0] != "dashboard.visibility" {
		t.Fatalf("Authority = %v", got.Authority)
	}
	if !got.GrantedAt.Equal(want.GrantedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("times = %v / %v, want %v / %v", got.GrantedAt, got.ExpiresAt, want.GrantedAt, want.ExpiresAt)
	}
}

// TestEnrolmentGrantReplacedNotMerged pins the "no partial update" rule: a
// re-enrolment writes a WHOLE new grant, so a narrower second grant can never
// inherit the wider first one's authority.
func TestEnrolmentGrantReplacedNotMerged(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	wide := testGrantRow()
	// capture.raise is RETIRED in Phase 1b (it grants nothing), which is
	// exactly why it still serves here: this test is about the WIDTH of the
	// stored token list, not about what any token authorises.
	wide.Authority = []string{"dashboard.visibility", "capture.raise"}
	if err := s.WriteEnrolmentGrant(ctx, wide); err != nil {
		t.Fatalf("write wide: %v", err)
	}
	narrow := testGrantRow()
	narrow.Authority = []string{"dashboard.visibility"}
	narrow.Generation = 4
	if err := s.WriteEnrolmentGrant(ctx, narrow); err != nil {
		t.Fatalf("write narrow: %v", err)
	}
	got, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if len(got.Authority) != 1 {
		t.Fatalf("Authority = %v, want the replacing grant's single token (authority must never accumulate)", got.Authority)
	}
	if got.Generation != 4 {
		t.Fatalf("Generation = %d, want 4", got.Generation)
	}
}

// TestDeleteEnrolmentGrant pins the revocation half: `observer unenroll`
// leaves nothing behind that could govern the machine, and running it twice
// is not an error.
func TestDeleteEnrolmentGrant(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	if err := s.WriteEnrolmentGrant(ctx, testGrantRow()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.DeleteEnrolmentGrant(ctx, "org-key-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1"); err != nil || ok {
		t.Fatalf("after delete: ok=%v err=%v, want gone", ok, err)
	}
	if err := s.DeleteEnrolmentGrant(ctx, "org-key-1"); err != nil {
		t.Fatalf("second delete must be idempotent: %v", err)
	}

	// DeleteAll is the belt-and-braces path for an unenrol that can no
	// longer derive its org_key.
	if err := s.WriteEnrolmentGrant(ctx, testGrantRow()); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := s.DeleteAllEnrolmentGrants(ctx); err != nil {
		t.Fatalf("delete all: %v", err)
	}
	if _, ok, _ := s.LoadEnrolmentGrant(ctx, "org-key-1"); ok {
		t.Fatal("DeleteAllEnrolmentGrants left a grant behind")
	}
}

// TestWriteEnrolmentGrantRequiresOrgKey pins the one hard precondition: a
// grant with no identity could never be invalidated by the generation fence.
func TestWriteEnrolmentGrantRequiresOrgKey(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	g := testGrantRow()
	g.OrgKey = ""
	if err := s.WriteEnrolmentGrant(ctx, g); err == nil {
		t.Fatal("WriteEnrolmentGrant accepted a grant with no org_key")
	}
}

// TestReplaceEnrolmentGrant_FreshRow pins the INSERT path (Plane B dual-mode
// design §5.3 item 5): a node that has never held a grant before can still
// accept a replacement as its very first grant.
func TestReplaceEnrolmentGrant_FreshRow(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)

	r := testGrantRow()
	r.ReplacementGeneration = 1
	applied, err := s.ReplaceEnrolmentGrant(ctx, r)
	if err != nil {
		t.Fatalf("ReplaceEnrolmentGrant: %v", err)
	}
	if !applied {
		t.Fatal("first-ever replacement was not applied")
	}
	got, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1")
	if err != nil || !ok {
		t.Fatalf("load after fresh-row replace: ok=%v err=%v", ok, err)
	}
	if got.ReplacementGeneration != 1 {
		t.Fatalf("ReplacementGeneration = %d, want 1", got.ReplacementGeneration)
	}
	if got.Generation != r.Generation {
		t.Fatalf("Generation = %d, want %d carried through on the INSERT path", got.Generation, r.Generation)
	}
}

// TestReplaceEnrolmentGrant_UpdatePathLeavesGenerationUntouched pins the most
// load-bearing invariant of this method: a replacement supersedes AUTHORITY
// within the current enrolment epoch, and must never move the identity
// generation column — migration 094's header comment explains why a spurious
// bump there would make a legitimately-replaced grant misread as stale.
func TestReplaceEnrolmentGrant_UpdatePathLeavesGenerationUntouched(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)

	original := testGrantRow()
	original.Generation = 7 // the P0-5 enrolment-identity fence value
	if err := s.WriteEnrolmentGrant(ctx, original); err != nil {
		t.Fatalf("seed original: %v", err)
	}

	replacement := testGrantRow()
	replacement.Generation = 999 // a caller bug or a stale value — must be IGNORED
	replacement.Authority = []string{"settings.pin"}
	replacement.ReplacementGeneration = 1
	applied, err := s.ReplaceEnrolmentGrant(ctx, replacement)
	if err != nil {
		t.Fatalf("ReplaceEnrolmentGrant: %v", err)
	}
	if !applied {
		t.Fatal("first replacement (generation 1 > current 0) was refused")
	}

	got, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.Generation != 7 {
		t.Fatalf("Generation = %d, want 7 (untouched by the replacement's own Generation=999 field)", got.Generation)
	}
	if len(got.Authority) != 1 || got.Authority[0] != "settings.pin" {
		t.Fatalf("Authority = %v, want the replacement's authority to fully replace, not merge", got.Authority)
	}
	if got.ReplacementGeneration != 1 {
		t.Fatalf("ReplacementGeneration = %d, want 1", got.ReplacementGeneration)
	}
}

// TestReplaceEnrolmentGrant_MonotonicOrdering pins the ordering fence: a
// stale or replayed replacement (ReplacementGeneration <= current) is
// refused with applied=false, err=nil, and the last-good grant is left
// completely untouched — never even partially applied.
func TestReplaceEnrolmentGrant_MonotonicOrdering(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)

	first := testGrantRow()
	first.ReplacementGeneration = 3
	first.Authority = []string{"dashboard.visibility"}
	if applied, err := s.ReplaceEnrolmentGrant(ctx, first); err != nil || !applied {
		t.Fatalf("seed first replacement: applied=%v err=%v", applied, err)
	}

	stale := testGrantRow()
	stale.ReplacementGeneration = 3 // equal, not greater — must be refused
	stale.Authority = []string{"settings.pin", "capture.raise", "process.detail"}
	applied, err := s.ReplaceEnrolmentGrant(ctx, stale)
	if err != nil {
		t.Fatalf("ReplaceEnrolmentGrant (equal generation): %v", err)
	}
	if applied {
		t.Fatal("a replacement with ReplacementGeneration == current was applied, want refused")
	}

	older := testGrantRow()
	older.ReplacementGeneration = 1 // strictly less — must be refused
	older.Authority = []string{"settings.pin", "capture.raise", "process.detail"}
	applied, err = s.ReplaceEnrolmentGrant(ctx, older)
	if err != nil {
		t.Fatalf("ReplaceEnrolmentGrant (lower generation): %v", err)
	}
	if applied {
		t.Fatal("a replacement with a LOWER ReplacementGeneration was applied, want refused")
	}

	// The last-good grant (from `first`) must be exactly what's still on
	// file — a rejected replacement is not even partially applied.
	got, ok, err := s.LoadEnrolmentGrant(ctx, "org-key-1")
	if err != nil || !ok {
		t.Fatalf("load: ok=%v err=%v", ok, err)
	}
	if got.ReplacementGeneration != 3 {
		t.Fatalf("ReplacementGeneration = %d, want 3 (unchanged by the refused replacements)", got.ReplacementGeneration)
	}
	if len(got.Authority) != 1 || got.Authority[0] != "dashboard.visibility" {
		t.Fatalf("Authority = %v, want only the first accepted replacement's single token", got.Authority)
	}

	// A strictly-greater generation now applies cleanly.
	next := testGrantRow()
	next.ReplacementGeneration = 4
	next.Authority = []string{"settings.pin"}
	applied, err = s.ReplaceEnrolmentGrant(ctx, next)
	if err != nil {
		t.Fatalf("ReplaceEnrolmentGrant (generation 4): %v", err)
	}
	if !applied {
		t.Fatal("a strictly-greater replacement generation was refused")
	}
	got, ok, err = s.LoadEnrolmentGrant(ctx, "org-key-1")
	if err != nil || !ok {
		t.Fatalf("load after generation-4 replace: ok=%v err=%v", ok, err)
	}
	if got.ReplacementGeneration != 4 || len(got.Authority) != 1 || got.Authority[0] != "settings.pin" {
		t.Fatalf("got = %+v, want ReplacementGeneration=4 Authority=[settings.pin]", got)
	}
}

// TestReplaceEnrolmentGrant_RequiresOrgKey mirrors
// TestWriteEnrolmentGrantRequiresOrgKey for the replacement path.
func TestReplaceEnrolmentGrant_RequiresOrgKey(t *testing.T) {
	ctx := context.Background()
	s := newPolicyResourceTestStore(t)
	g := testGrantRow()
	g.OrgKey = ""
	g.ReplacementGeneration = 1
	if _, err := s.ReplaceEnrolmentGrant(ctx, g); err == nil {
		t.Fatal("ReplaceEnrolmentGrant accepted a grant with no org_key")
	}
}
