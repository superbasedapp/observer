package nodegov

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/postureop"
)

// TestEveryPinnableRowHasAKnownDirection: every PinnableKeys row names a
// direction of the postureop table that applies to its kind (roadmap F0-8;
// no row changed in that lane).
func TestEveryPinnableRowHasAKnownDirection(t *testing.T) {
	for _, k := range PinnableKeys {
		r, ok := postureop.LookupRule(k.Direction)
		if !ok {
			t.Errorf("%s: direction %q is not in the postureop table", k.Key, k.Direction)
			continue
		}
		if !r.AppliesTo(k.Kind) {
			t.Errorf("%s: direction %s does not apply to kind %s", k.Key, k.Direction, k.Kind)
		}
	}
}

// TestCompilePinnedWalksTheDirectionTable registers synthetic rows for the
// new directions and checks compilePinned refuses the impossible values the
// table names, for every direction, at publish and accept alike.
func TestCompilePinnedWalksTheDirectionTable(t *testing.T) {
	synthetic := []PinnableKey{
		{Key: "test.raise", Kind: "int", Direction: DirRaisingOnly},
		{Key: "test.retention", Kind: "int", Direction: DirRetention},
		{Key: "test.filter", Kind: "string_list", Direction: DirOrderedFilter},
		{Key: "test.intersect", Kind: "string_list", Direction: DirSetIntersection},
		{Key: "test.mask", Kind: "string_list", Direction: DirAdditiveMask},
		{Key: "test.badkind", Kind: "bool", Direction: DirRetention},
		{Key: "test.unknown", Kind: "int", Direction: Direction("narrowing_list")},
	}
	for _, k := range synthetic {
		pinnableByKey[k.Key] = k
	}
	t.Cleanup(func() {
		for _, k := range synthetic {
			delete(pinnableByKey, k.Key)
		}
	})
	cases := []struct {
		key     string
		val     any
		wantErr string
	}{
		{"test.raise", float64(3), ""},
		{"test.raise", float64(-1), "negative"},
		{"test.retention", float64(0), ""},
		{"test.retention", float64(-30), "negative"},
		{"test.filter", []any{"gvisor"}, ""},
		{"test.filter", []any{}, "allow nothing"},
		{"test.intersect", []any{}, "allow nothing"},
		{"test.intersect", []any{"a", "b"}, ""},
		{"test.mask", []any{}, ""},
		{"test.badkind", true, "does not apply"},
		{"test.unknown", float64(1), "unknown direction"},
	}
	for _, c := range cases {
		_, err := compilePinned(map[string]any{c.key: c.val})
		switch {
		case c.wantErr == "" && err != nil:
			t.Errorf("%s=%v: unexpected %v", c.key, c.val, err)
		case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
			t.Errorf("%s=%v: got %v, want an error containing %q", c.key, c.val, err, c.wantErr)
		}
	}
}
