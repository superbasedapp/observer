package sectrust

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestKnownVulnerable: one case per table row on each side of its fix,
// plus the unknown-version and other-tool cases.
func TestKnownVulnerable(t *testing.T) {
	cases := []struct {
		tool, version string
		want          []string
	}{
		{"claude-code", "1.0.110", []string{"CVE-2025-59536", "CVE-2026-21852"}},
		{"claude-code", "1.0.111", []string{"CVE-2026-21852"}},
		{"claude-code", "2.0.64 (Claude Code)", []string{"CVE-2026-21852"}},
		{"claude-code", "2.0.65", nil},
		{"claude-code", "2.1.304", nil},
		{"codex", "0.22.9", []string{"CVE-2025-61260", "CVE-2026-19592"}},
		{"codex", "v0.130.0", []string{"CVE-2026-19592"}},
		{"codex", "0.131.0", nil},
		{"cursor", "1.2.4", []string{"CVE-2025-54136"}},
		{"cursor", "1.3.0", nil},
		{"claude-code", "", nil},
		{"claude-code", "nightly", nil},
		{"gemini-cli", "0.1.0", nil},
	}
	for _, tc := range cases {
		var got []string
		for _, r := range KnownVulnerable(tc.tool, tc.version) {
			got = append(got, r.CVE)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s %q: %v, want %v", tc.tool, tc.version, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s %q: %v, want %v", tc.tool, tc.version, got, tc.want)
			}
		}
	}
}

// TestVulnerableVersionsGrounded: every row names a registry tool, a
// parseable fixed version and its source.
func TestVulnerableVersionsGrounded(t *testing.T) {
	for _, r := range VulnerableVersions() {
		if _, ok := integration.For(r.Tool); !ok {
			t.Errorf("%s: tool %q is not in the integration registry", r.CVE, r.Tool)
		}
		if _, ok := parseVersion(r.FixedIn); !ok || r.Source == "" || r.Grounded == "" || r.Summary == "" {
			t.Errorf("%s: malformed row %+v", r.CVE, r)
		}
	}
}
