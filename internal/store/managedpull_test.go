package store

import (
	"context"
	"errors"
	"testing"
)

// TestManagedPullCacheRoundTrip: one row per rail, bound to the enrolment
// identity; another identity reads as absent; a clear leaves a tombstone
// that keeps the version (the anti-rollback floor).
func TestManagedPullCacheRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, ok, err := s.LoadManagedPull(ctx, "security", "k", 1); ok || err != nil {
		t.Fatalf("empty: %v %v", ok, err)
	}
	row := ManagedPullCache{
		Rail: "security", OrgKey: "k", Generation: 1, Version: 3, ExpiresAt: 2_000_000_000,
		BodyHash: "h", DocJSON: `{"schema":"sbo-security-managed-v1"}`, SignerFingerprint: "fp", FetchedAt: "2026-10-21T00:00:00Z",
	}
	if err := s.SaveManagedPull(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Version = 4
	if err := s.SaveManagedPull(ctx, row); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.LoadManagedPull(ctx, "security", "k", 1)
	if err != nil || !ok || got != row {
		t.Fatalf("load: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := s.LoadManagedPull(ctx, "security", "k", 2); ok {
		t.Fatal("another generation must read as absent")
	}
	if _, ok, _ := s.LoadManagedPull(ctx, "sandbox", "k", 1); ok {
		t.Fatal("rails are separate")
	}
	if err := s.SaveManagedPull(ctx, ManagedPullCache{Rail: "security"}); err == nil {
		t.Fatal("an incomplete row must be refused")
	}
	if err := s.SaveManagedPull(ctx, ManagedPullCache{Rail: "security", OrgKey: "k", Version: 5}); err == nil {
		t.Fatal("a row without a document must be refused (only a clear writes one)")
	}
	if err := s.ClearManagedPull(ctx, ManagedPullCache{Rail: "security"}); err == nil {
		t.Fatal("a clear without an identity and version must be refused")
	}
	tomb := ManagedPullCache{
		Rail: "security", OrgKey: "k", Generation: 1, Version: 5, BodyHash: "e",
		ExpiresAt: 2_000_000_000, DocJSON: "ignored", SignerFingerprint: "fp", FetchedAt: "2026-10-21T01:00:00Z",
	}
	if err := s.ClearManagedPull(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	got, ok, err = s.LoadManagedPull(ctx, "security", "k", 1)
	if err != nil || !ok || !got.Tombstone || got.DocJSON != "" || got.ExpiresAt != 0 || got.Version != 5 || got.BodyHash != "e" {
		t.Fatalf("clear must leave a tombstone holding the version: %+v %v %v", got, ok, err)
	}
	if _, ok, _ := s.LoadManagedPull(ctx, "security", "k", 2); ok {
		t.Fatal("another generation's tombstone must read as absent")
	}
}

// TestManagedPullFloorNeverLowers: the store keeps the highest accepted
// version per (rail, org_key, generation) whatever the document: neither a
// lower save nor a lower clear lands for the same identity, an equal one
// does (a re-clear, a re-signed document over one that no longer verifies),
// and a new enrolment identity starts its own floor.
func TestManagedPullFloorNeverLowers(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	row := ManagedPullCache{
		Rail: "sandbox", OrgKey: "k", Generation: 1, Version: 6, ExpiresAt: 2_000_000_000,
		BodyHash: "h6", DocJSON: `{"v":6}`, SignerFingerprint: "fp", FetchedAt: "t",
	}
	if err := s.SaveManagedPull(ctx, row); err != nil {
		t.Fatal(err)
	}
	lower := row
	lower.Version, lower.BodyHash, lower.DocJSON = 5, "h5", `{"v":5}`
	if err := s.SaveManagedPull(ctx, lower); !errors.Is(err, ErrManagedPullFloor) {
		t.Fatalf("a lower save must be refused: %v", err)
	}
	if err := s.ClearManagedPull(ctx, ManagedPullCache{Rail: "sandbox", OrgKey: "k", Generation: 1, Version: 5, BodyHash: "e"}); !errors.Is(err, ErrManagedPullFloor) {
		t.Fatalf("a lower clear must be refused: %v", err)
	}
	if err := s.ClearManagedPull(ctx, ManagedPullCache{Rail: "sandbox", OrgKey: "k", Generation: 1, Version: 6, BodyHash: "e"}); err != nil {
		t.Fatalf("an equal clear lands: %v", err)
	}
	if err := s.SaveManagedPull(ctx, lower); !errors.Is(err, ErrManagedPullFloor) {
		t.Fatalf("a lower save over the tombstone must be refused: %v", err)
	}
	got, _, _ := s.LoadManagedPull(ctx, "sandbox", "k", 1)
	if got.Version != 6 || !got.Tombstone {
		t.Fatalf("floor moved: %+v", got)
	}
	fresh := lower
	fresh.Generation = 2
	if err := s.SaveManagedPull(ctx, fresh); err != nil {
		t.Fatalf("a new enrolment generation starts its own floor: %v", err)
	}
}
