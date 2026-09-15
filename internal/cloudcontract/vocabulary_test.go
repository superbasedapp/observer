package cloudcontract

import (
	"strings"
	"testing"
)

// TestErrorClassesIsAClosedStableSet pins the failure-class vocabulary: nine
// labels, each a plain lowercase slug (never a path, a message fragment, or a
// value with whitespace), returned as a COPY so a caller cannot mutate it.
func TestErrorClassesIsAClosedStableSet(t *testing.T) {
	got := ErrorClasses()
	want := []string{
		"exit_code_nonzero", "timeout", "file_not_found", "permission_denied",
		"file_too_large", "syntax_error", "test_failure", "network_error", "rate_limited",
	}
	if len(got) != len(want) {
		t.Fatalf("ErrorClasses() = %v (%d), want %d labels", got, len(got), len(want))
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("ErrorClasses()[%d] = %q, want %q", i, got[i], w)
		}
	}
	assertClosedSlugs(t, "ErrorClasses", got)

	got[0] = "mutated"
	if ErrorClasses()[0] != "exit_code_nonzero" {
		t.Fatal("ErrorClasses() returned the backing array — a caller can mutate the vocabulary")
	}
}

// TestMCPFamilyLabelsIsAClosedStableSet pins the MCP family vocabulary and that
// the honest fallback bucket is its last member.
func TestMCPFamilyLabelsIsAClosedStableSet(t *testing.T) {
	got := MCPFamilyLabels()
	if len(got) < 10 {
		t.Fatalf("MCPFamilyLabels() = %v, want the full family vocabulary", got)
	}
	if got[len(got)-1] != MCPFamilyFallback {
		t.Errorf("last label = %q, want the fallback %q", got[len(got)-1], MCPFamilyFallback)
	}
	assertClosedSlugs(t, "MCPFamilyLabels", got)

	seen := map[string]bool{}
	for _, l := range got {
		if seen[l] {
			t.Errorf("duplicate label %q", l)
		}
		seen[l] = true
	}

	got[0] = "mutated"
	if MCPFamilyLabels()[0] == "mutated" {
		t.Fatal("MCPFamilyLabels() returned the backing array — a caller can mutate the vocabulary")
	}
}

// assertClosedSlugs asserts every label is a short, bounded, path-free slug —
// the shape that makes "a label can never carry user data" checkable.
func assertClosedSlugs(t *testing.T, name string, labels []string) {
	t.Helper()
	for _, l := range labels {
		if l == "" {
			t.Errorf("%s: empty label", name)
		}
		if len(l) > MaxShortLabelBytes {
			t.Errorf("%s: label %q exceeds MaxShortLabelBytes %d", name, l, MaxShortLabelBytes)
		}
		if strings.ContainsAny(l, "/\\ \t\n.:") || strings.ToLower(l) != l {
			t.Errorf("%s: label %q is not a plain lowercase slug", name, l)
		}
	}
}
