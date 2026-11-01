package nodegov

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// TestSandboxImagePinsNeedADigest: the org image pins (lane SBX-P3B) accept
// only an image pinned by digest, at publish and accept alike; a tag, an
// empty value or a non-string is refused before it reaches a node.
func TestSandboxImagePinsNeedADigest(t *testing.T) {
	good := "registry.example/team/sandbox@sha256:" + strings.Repeat("b", 64)
	for _, key := range []string{"terminal.sandbox.oci.image", "terminal.sandbox.apple_container.image"} {
		row, ok := LookupPinnableKey(key)
		if !ok || row.Kind != "string" || row.Direction != DirFree || row.Format != postureop.FormatImageDigestRef {
			t.Fatalf("%s: %+v", key, row)
		}
		if _, err := compilePinned(map[string]any{key: good}); err != nil {
			t.Errorf("%s: a digest-pinned image refused: %v", key, err)
		}
		for _, bad := range []any{"alpine:3", "", "alpine", 7} {
			if _, err := compilePinned(map[string]any{key: bad}); err == nil {
				t.Errorf("%s = %v accepted", key, bad)
			}
		}
	}
}

// TestEveryPinnableFormatIsKnown: a row naming a format this build does not
// check would refuse every value; pin the table instead.
func TestEveryPinnableFormatIsKnown(t *testing.T) {
	for _, k := range PinnableKeys {
		if !postureop.KnownFormat(k.Format) {
			t.Errorf("%s: unknown format %q", k.Key, k.Format)
		}
		if k.Format != "" && k.Kind != "string" {
			t.Errorf("%s: a format applies to a string row only", k.Key)
		}
	}
}
