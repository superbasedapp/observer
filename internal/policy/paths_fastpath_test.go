package policy

import "testing"

// TestNormPathFastPathNeverChangesAnAnswer pins demo bug #14's fast path:
// isNormalizedPath may only answer true for a string the full rewrite returns
// unchanged, so normPath and normPathSlow agree on every input. One row per
// shape the slow path rewrites, plus the canonical shapes the fast path keeps.
func TestNormPathFastPathNeverChangesAnAnswer(t *testing.T) {
	cases := []struct {
		in       string
		wantFast bool // the fast path takes it
	}{
		{"/", true},
		{"/a/b", true},
		{"a/b", true},
		{"~", true},
		{"~/x", true},
		{"c:", true},
		{"c:/", true},
		{"c:/x/y", true},
		{"/mnt/c/Users/u", true},
		{"C:/x", false},    // uppercase drive is lowercased
		{"c:x", false},     // drive-relative becomes c:/x
		{"/a//b", false},   // repeated separator
		{"/a/b/", false},   // trailing separator
		{"/a/./b", false},  // dot segment
		{"/a/../b", false}, // dot-dot resolved
		{"../a", false},    // kept by the slow path, but not taken fast
		{"./a", false},     // dot segment
		{`C:\x\y`, false},  // backslashes
		{`\\srv\share`, false},
		{`\\?\C:\x`, false}, // extended-length prefix dropped
		{"//x", false},      // POSIX // folds to /x
		{"", false},         // handled before the fast path
		{".", false},
		{"..", false},
		{"a/", false},
	}
	for _, c := range cases {
		if got := isNormalizedPath(c.in); got != c.wantFast {
			t.Errorf("isNormalizedPath(%q) = %v, want %v", c.in, got, c.wantFast)
		}
		if c.wantFast && normPathSlow(c.in) != c.in {
			t.Errorf("fast path kept %q but the slow path rewrites it to %q", c.in, normPathSlow(c.in))
		}
		if normPath(c.in) != normPathSlow(c.in) {
			t.Errorf("normPath(%q) = %q, slow path %q", c.in, normPath(c.in), normPathSlow(c.in))
		}
	}
}

// TestNormPathFastPathAgreesOnGeneratedPaths walks every short string over an
// alphabet of the characters the rewrite cares about, so an unlisted shape
// cannot slip through the table above.
func TestNormPathFastPathAgreesOnGeneratedPaths(t *testing.T) {
	alphabet := []byte{'/', '\\', '.', ':', 'a', 'C', '~', '?'}
	var walk func(prefix []byte, depth int)
	walk = func(prefix []byte, depth int) {
		s := string(prefix)
		if s != "" {
			if isNormalizedPath(s) && normPathSlow(s) != s {
				t.Fatalf("fast path kept %q but the slow path rewrites it to %q", s, normPathSlow(s))
			}
			if normPath(s) != normPathSlow(s) {
				t.Fatalf("normPath(%q) = %q, slow path %q", s, normPath(s), normPathSlow(s))
			}
		}
		if depth == 0 {
			return
		}
		for _, c := range alphabet {
			walk(append(prefix, c), depth-1)
		}
	}
	walk(nil, 6)
}
