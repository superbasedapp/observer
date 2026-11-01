package codexpatch

import "testing"

// TestResolveHeaderRows (lane LEFT2-SEC item R-024): one case per row of
// the resolution table, plus the subdirectory case the residual named.
func TestResolveHeaderRows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		row, header, cwd, want string
	}{
		{"an empty header stays empty", " ", "/repo", ""},
		{"an absolute header stays as written", "/repo/pkg/a.go", "/repo/sub", "/repo/pkg/a.go"},
		{"an absolute header stays as written", `C:\repo\a.go`, "/repo", `C:\repo\a.go`},
		{"with no working directory a header stays as written", "pkg/a.go", "", "pkg/a.go"},
		{"a Windows working directory joins with backslashes", "pkg/a.go", `C:\repo\sub`, `C:\repo\sub\pkg\a.go`},
		{"a POSIX working directory joins and cleans", "pkg/a.go", "/repo/sub", "/repo/sub/pkg/a.go"},
		{"a POSIX working directory joins and cleans", "../lib/b.go", "/repo/sub/", "/repo/lib/b.go"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.row] = true
		if got := ResolveHeader(c.header, c.cwd); got != c.want {
			t.Errorf("%s: ResolveHeader(%q, %q) = %q, want %q", c.row, c.header, c.cwd, got, c.want)
		}
	}
	for _, n := range HeaderRuleNames() {
		if !seen[n] {
			t.Errorf("row %q has no case", n)
		}
	}
}

// TestHeaderBaseAndAnchor: the directory a resolution reveals, and the
// other headers of the same envelope anchored with it.
func TestHeaderBaseAndAnchor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, target, header string
		base                 string
		ok                   bool
	}{
		{"root working directory", "pkg/a.go", "pkg/a.go", "", true},
		{"a subdirectory, project-relative target", "sub/pkg/a.go", "pkg/a.go", "sub/", true},
		{"a subdirectory, absolute target", "/repo/sub/pkg/a.go", "pkg/a.go", "/repo/sub/", true},
		{"a Windows target", `C:\repo\sub\pkg\a.go`, "pkg/a.go", "C:/repo/sub/", true},
		{"a header that is not the target's tail", "sub/pkg/a.go", "other.go", "", false},
		{"a partial file name is not a tail", "sub/xa.go", "a.go", "", false},
		{"an absolute header", "/repo/a.go", "/repo/a.go", "", false},
	}
	for _, c := range cases {
		base, ok := HeaderBase(c.target, c.header)
		if base != c.base || ok != c.ok {
			t.Errorf("%s: HeaderBase(%q, %q) = %q %v, want %q %v", c.name, c.target, c.header, base, ok, c.base, c.ok)
		}
	}
	for _, c := range []struct{ base, header, want string }{
		{"sub/", "pkg/b.go", "sub/pkg/b.go"},
		{"sub/", "./pkg/../pkg/c.go", "sub/pkg/c.go"},
		{"", "pkg/b.go", "pkg/b.go"},
		{"sub/", "/abs/d.go", "/abs/d.go"},
	} {
		if got := AnchorHeader(c.base, c.header); got != c.want {
			t.Errorf("AnchorHeader(%q, %q) = %q, want %q", c.base, c.header, got, c.want)
		}
	}
}
