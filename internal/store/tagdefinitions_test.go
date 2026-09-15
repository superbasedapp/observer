package store

import (
	"context"
	"testing"
)

// TestTagDefinitionUpsertOverwriteClearList is the table-driven pin on the
// tag_definitions seam: upsert, overwrite in place, an empty definition
// clears the row, and TagDefinitions lists whatever remains.
func TestTagDefinitionUpsertOverwriteClearList(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Upsert a fresh definition.
	if err := s.UpsertTagDefinition(ctx, "Backend", "server-side work", "area"); err != nil {
		t.Fatalf("UpsertTagDefinition: %v", err)
	}
	defs, err := s.TagDefinitions(ctx)
	if err != nil {
		t.Fatalf("TagDefinitions: %v", err)
	}
	got, ok := defs["backend"]
	if !ok {
		t.Fatalf("TagDefinitions missing normalized key %q: %v", "backend", defs)
	}
	if got != (TagDefinition{Tag: "backend", Definition: "server-side work", Category: "area"}) {
		t.Fatalf("TagDefinitions[backend] = %+v, want {backend server-side work area}", got)
	}

	// Overwrite in place.
	if err := s.UpsertTagDefinition(ctx, "backend", "server + infra work", "area"); err != nil {
		t.Fatalf("UpsertTagDefinition overwrite: %v", err)
	}
	defs, err = s.TagDefinitions(ctx)
	if err != nil {
		t.Fatalf("TagDefinitions: %v", err)
	}
	if defs["backend"].Definition != "server + infra work" {
		t.Fatalf("TagDefinitions[backend].Definition = %q, want %q", defs["backend"].Definition, "server + infra work")
	}
	if len(defs) != 1 {
		t.Fatalf("TagDefinitions has %d rows, want 1: %v", len(defs), defs)
	}

	// A second tag coexists.
	if err := s.UpsertTagDefinition(ctx, "frontend", "UI work", "area"); err != nil {
		t.Fatalf("UpsertTagDefinition second tag: %v", err)
	}
	defs, err = s.TagDefinitions(ctx)
	if err != nil {
		t.Fatalf("TagDefinitions: %v", err)
	}
	if len(defs) != 2 {
		t.Fatalf("TagDefinitions has %d rows, want 2: %v", len(defs), defs)
	}

	// An empty definition (after TrimSpace) clears the row.
	if err := s.UpsertTagDefinition(ctx, "backend", "   ", "area"); err != nil {
		t.Fatalf("UpsertTagDefinition empty-clears: %v", err)
	}
	defs, err = s.TagDefinitions(ctx)
	if err != nil {
		t.Fatalf("TagDefinitions: %v", err)
	}
	if _, ok := defs["backend"]; ok {
		t.Fatalf("TagDefinitions still carries backend after empty-definition clear: %v", defs)
	}
	if len(defs) != 1 {
		t.Fatalf("TagDefinitions has %d rows after clear, want 1 (frontend only): %v", len(defs), defs)
	}

	// DeleteTagDefinition removes the remaining row.
	if err := s.DeleteTagDefinition(ctx, "frontend"); err != nil {
		t.Fatalf("DeleteTagDefinition: %v", err)
	}
	defs, err = s.TagDefinitions(ctx)
	if err != nil {
		t.Fatalf("TagDefinitions: %v", err)
	}
	if len(defs) != 0 {
		t.Fatalf("TagDefinitions has %d rows after delete-all, want 0: %v", len(defs), defs)
	}
}

// TestTagDefinitionInvalidTagRejected pins that an invalid tag is rejected
// (never silently normalized-away or treated as a no-op) on both write paths.
func TestTagDefinitionInvalidTagRejected(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertTagDefinition(ctx, "junk🔥", "x", ""); err == nil {
		t.Fatal("UpsertTagDefinition(invalid tag) = nil error, want ErrInvalidTag")
	}
	if err := s.DeleteTagDefinition(ctx, "junk🔥"); err == nil {
		t.Fatal("DeleteTagDefinition(invalid tag) = nil error, want ErrInvalidTag")
	}
}

// TestTagDefinitionsEmpty pins that a store with no definitions returns an
// empty (non-nil) map.
func TestTagDefinitionsEmpty(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	defs, err := s.TagDefinitions(ctx)
	if err != nil {
		t.Fatalf("TagDefinitions: %v", err)
	}
	if defs == nil {
		t.Fatal("TagDefinitions returned nil map, want empty map")
	}
	if len(defs) != 0 {
		t.Fatalf("TagDefinitions has %d rows, want 0: %v", len(defs), defs)
	}
}
