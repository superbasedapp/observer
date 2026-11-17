package dashboard

import (
	"strings"
	"testing"
)

// TestGuardLayerOf is guardLayerRows' table, one case per row plus the
// unknown and empty sources.
func TestGuardLayerOf(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ source, layer, labelHas string }{
		{"org", "org", "organization guard bundle"},
		{"org_budget", "org", "budget"},
		{"user", "local", "your local rules"},
		{"project", "project", "this project's rules"},
		{"pack:security", "pack", "Code security pack"},
		{"pack:other", "pack", "a security pack"},
		{"builtin", "builtin", "built-in"},
		{"llm_judge", "judge", "LLM judge"},
		{"observer", "builtin", "Observer"},
		{"something-new", "other", "something-new"},
		{"", "", ""},
	} {
		layer, label := guardLayerOf(tc.source)
		if layer != tc.layer || (tc.labelHas != "" && !strings.Contains(label, tc.labelHas)) || (tc.labelHas == "" && label != "") {
			t.Errorf("guardLayerOf(%q) = (%q, %q), want layer %q with %q", tc.source, layer, label, tc.layer, tc.labelHas)
		}
	}
}
