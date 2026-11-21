package configschema

import (
	"strings"
	"testing"
)

// TestDetectorKeysAreIDs: a prompt-guard detector override named after what
// it finds (slack_token, bearer_token, aws_secret_key) is a mode, not a
// credential. The dry-run diff shows it, no credential warning fires, and a
// value the detector recognizes under the same table is still masked.
func TestDetectorKeysAreIDs(t *testing.T) {
	detect := func(s string) bool { return strings.HasPrefix(s, "sk-live") }
	leaf, ok := Lookup("guard.prompt.detectors")
	if !ok || !leaf.KeysAreIDs {
		t.Fatalf("guard.prompt.detectors must carry KeysAreIDs: %+v ok=%v", leaf, ok)
	}

	cases := []struct {
		name string
		leaf Leaf
		v    any
		want bool
	}{
		{"detector modes", leaf, map[string]string{"slack_token": "block", "bearer_token": "warn", "aws_secret_key": "redact"}, false},
		{"detected value under an id key", leaf, map[string]string{"slack_token": "sk-live-1"}, true},
		{"same keys on an ordinary map", Leaf{}, map[string]string{"slack_token": "block"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SecretShapedLeaf(tc.leaf, tc.v, detect); got != tc.want {
				t.Fatalf("SecretShapedLeaf(%v) = %v, want %v", tc.v, got, tc.want)
			}
		})
	}

	in := "[guard.prompt.detectors]\nslack_token = \"block\"\nbearer_token = \"warn\"\njwt = \"sk-live-9\"\n\n[custom]\nslack_token = \"block\"\n"
	got := MaskTOMLSecrets(in, detect)
	for _, keep := range []string{`slack_token = "block"`, `bearer_token = "warn"`} {
		if !strings.Contains(got, keep) {
			t.Fatalf("masked text lost %q:\n%s", keep, got)
		}
	}
	if strings.Contains(got, "sk-live-9") {
		t.Fatalf("a detected value must stay masked:\n%s", got)
	}
	// The [custom] table has no id-key annotation: its credential-named key
	// is still masked, so the guard table's slack_token line is the only one
	// left showing its value.
	if strings.Count(got, `slack_token = "block"`) != 1 || strings.Count(got, SecretPlaceholder) != 2 {
		t.Fatalf("want the guard line kept and two placeholders:\n%s", got)
	}
}
