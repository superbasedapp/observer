//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestEngineCoverageNote (WINFIX4 audit finding 6): doctor names a refused
// manifest that does not cover this platform, and says what stays.
func TestEngineCoverageNote(t *testing.T) {
	if s := engineCoverageNote(content.State{}, "linux", "amd64"); s != "" {
		t.Fatalf("a clean state printed %q", s)
	}
	st := content.State{LastFailure: content.ContentReasonNotCoveredHere, LastFailureAt: "2026-10-26T00:00:00Z", Accepted: &content.Accepted{ManifestVersion: 12}}
	s := engineCoverageNote(st, "linux", "amd64")
	for _, want := range []string{"not_covered_here", "linux/amd64", "manifest version 12", "stays in use"} {
		if !strings.Contains(s, want) {
			t.Fatalf("%q lacks %q", s, want)
		}
	}
	st.Accepted = nil
	if s := engineCoverageNote(st, "windows", "amd64"); !strings.Contains(s, "compiled pins") {
		t.Fatalf("no accepted manifest: %q", s)
	}
}
