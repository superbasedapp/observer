package cidrcanon

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCanonical: a masked prefix in any spelling answers its canonical
// form; an unmasked or malformed one is refused.
func TestCanonical(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"::ffff:0:0/96", "::ffff:0.0.0.0/96", true},
		{"::ffff:0.0.0.0/96", "::ffff:0.0.0.0/96", true},
		{"10.0.0.0/8", "10.0.0.0/8", true},
		{"FD00::/8", "fd00::/8", true},
		{"10.0.0.1/8", "", false},
		{"10.0.0.0", "", false},
		{"not a cidr", "", false},
	}
	for _, tc := range cases {
		got, ok := Canonical(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("Canonical(%q) = %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestImportsAreStandardLibraryOnly pins the package as a leaf (FX1-A7).
func TestImportsAreStandardLibraryOnly(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			if p := strings.Trim(im.Path.Value, `"`); strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				t.Errorf("%s imports %s; the package must stay standard-library only", f, p)
			}
		}
	}
}
