package mcp

import (
	"strings"
	"testing"
)

// TestKnownWarnings_AreStable pins the closed tag set. Adding a new
// warning is fine; renaming an existing constant trips this test so
// downstream agents pattern-matching on the literal don't silently
// break.
func TestKnownWarnings_AreStable(t *testing.T) {
	t.Parallel()
	want := map[string]bool{
		"index_unavailable":                   true,
		"index_stale":                         true,
		"index_changed_mid_query":             true,
		"regex_fallback_language_unsupported": true,
		// Corpus archival P2.3: the project's code index moved to cold
		// storage. Its own tag, not a flavour of index_unavailable —
		// "missing" and "one rehydrate away" lead an agent to different
		// next actions.
		"project_archived": true,
	}
	got := allKnownWarnings()
	if len(got) != len(want) {
		t.Errorf("warning count: got %d, want %d", len(got), len(want))
	}
	for _, tag := range got {
		if !want[tag] {
			t.Errorf("unexpected warning tag: %q", tag)
		}
		// Tag hygiene: no spaces, lowercase, no leading/trailing
		// whitespace.
		if tag != strings.TrimSpace(tag) {
			t.Errorf("tag %q has surrounding whitespace", tag)
		}
		if strings.ContainsAny(tag, " \t\n") {
			t.Errorf("tag %q contains whitespace", tag)
		}
		if tag != strings.ToLower(tag) {
			t.Errorf("tag %q has uppercase characters", tag)
		}
	}
}

// TestAppendWarning_Dedup: adding the same tag twice keeps the slice
// at length 1. Critical for the "stale + index_changed" overlap case
// where both signals could try to add index_stale.
func TestAppendWarning_Dedup(t *testing.T) {
	t.Parallel()
	var w []string
	w = appendWarning(w, WarningIndexStale)
	w = appendWarning(w, WarningIndexStale)
	w = appendWarning(w, WarningIndexStale)
	if len(w) != 1 || w[0] != WarningIndexStale {
		t.Errorf("dedup failed: %v", w)
	}
}

// TestAppendWarning_OrderPreserved: distinct tags accumulate in
// insertion order. Pinned because agents pattern-matching on the
// JSON shouldn't depend on alphabetical ordering, but tools
// emitting tags in a deterministic order help cache-stable responses.
func TestAppendWarning_OrderPreserved(t *testing.T) {
	t.Parallel()
	var w []string
	w = appendWarning(w, WarningIndexUnavailable)
	w = appendWarning(w, WarningRegexFallbackLanguageUnsupported)
	w = appendWarning(w, WarningIndexStale)
	if len(w) != 3 {
		t.Fatalf("got %v", w)
	}
	if w[0] != WarningIndexUnavailable ||
		w[1] != WarningRegexFallbackLanguageUnsupported ||
		w[2] != WarningIndexStale {
		t.Errorf("order changed: %v", w)
	}
}

// TestAppendWarning_NilSliceSafe: appending to a nil slice doesn't
// panic and produces a length-1 result. Lets callers initialise lazily.
func TestAppendWarning_NilSliceSafe(t *testing.T) {
	t.Parallel()
	got := appendWarning(nil, WarningIndexStale)
	if len(got) != 1 || got[0] != WarningIndexStale {
		t.Errorf("got %v", got)
	}
}
