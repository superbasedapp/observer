package invariant

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPublicListingsMakeNoTelemetryPromise pins the public package listing
// metadata (npm, PyPI, VS Code Marketplace, browser store) to the
// 2026-10-21 public wording rule (D-808, T-959): listing text states
// present-tense facts and never promises that statistics are not
// collected, because default pseudonymous usage statistics are planned
// (docs/plans/default-usage-statistics-plan-2026-10-21.md, release-day
// rows R26 and R27). The same rule is pinned for `observer privacy` in
// cmd/observer/privacy_test.go.
//
// The match is case-insensitive and covers the description and keyword
// spellings ("no telemetry", "no-telemetry", "notelemetry") plus the
// "nothing leaves your machine" promise.
func TestPublicListingsMakeNoTelemetryPromise(t *testing.T) {
	root := repoRoot(t)
	files := []string{
		"npm/observer/package.json",
		"pypi/observer/pyproject.toml",
		"vscode/package.json",
		"browser-extension/manifest.json",
	}
	banned := []string{
		"no telemetry",
		"no-telemetry",
		"notelemetry",
		"nothing leaves your machine",
	}
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		lower := strings.ToLower(string(raw))
		for _, b := range banned {
			if strings.Contains(lower, b) {
				t.Errorf("%s carries the retired listing claim %q (public wording rule D-808: state present-tense facts, never promise that statistics are not collected)", rel, b)
			}
		}
	}
}
