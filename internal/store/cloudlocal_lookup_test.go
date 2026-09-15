package store

import (
	"context"
	"testing"
)

// TestLookupCloudSessionPseudonym pins the read-only forward lookup added for
// the "show the local uuid <-> cloud pseudonym mapping to the user" issue:
// it must return exactly what this device already minted (via
// GetOrCreateCloudSessionPseudonym), and it must NEVER mint one itself.
func TestLookupCloudSessionPseudonym(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	// Before anything mints a pseudonym for this local id, the lookup is a
	// routine miss — not an error, and critically not a side-effecting mint.
	got, ok, err := s.LookupCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil {
		t.Fatalf("pre-mint lookup: %v", err)
	}
	if ok || got != "" {
		t.Fatalf("pre-mint lookup = (%q, %v), want (\"\", false) — the read must not mint", got, ok)
	}

	// Empty local id is also a routine miss (mirrors
	// LookupLocalSessionByCloudPseudonym's empty-input handling).
	if got, ok, err := s.LookupCloudSessionPseudonym(ctx, ""); err != nil || ok || got != "" {
		t.Fatalf("empty id lookup = (%q, %v, %v), want (\"\", false, nil)", got, ok, err)
	}

	// Once GetOrCreateCloudSessionPseudonym (the real enrollment write path)
	// has minted a pseudonym, the read-only lookup must return that exact
	// value — not mint a second, different one.
	minted, err := s.GetOrCreateCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if minted == "" {
		t.Fatal("minted pseudonym is empty")
	}
	got, ok, err = s.LookupCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil {
		t.Fatalf("post-mint lookup: %v", err)
	}
	if !ok || got != minted {
		t.Fatalf("post-mint lookup = (%q, %v), want (%q, true)", got, ok, minted)
	}
	// Calling the lookup again must not mint a second pseudonym or otherwise
	// change the stored value.
	got2, ok2, err := s.LookupCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil || !ok2 || got2 != minted {
		t.Fatalf("repeat lookup = (%q, %v, %v), want (%q, true, nil)", got2, ok2, err, minted)
	}

	// A distinct local id that was never minted stays a miss even after a
	// DIFFERENT local id has a pseudonym.
	if got, ok, err := s.LookupCloudSessionPseudonym(ctx, "local-sess-never-enrolled"); err != nil || ok || got != "" {
		t.Fatalf("unminted sibling id lookup = (%q, %v, %v), want (\"\", false, nil)", got, ok, err)
	}
}
