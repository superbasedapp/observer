package toolresolve

import (
	"io/fs"
	"testing"
)

// TestResolveSkipsCommandWrappingShims pins the recursion guard between the
// command-wrapping shims (internal/shellwrap) and the observer launchers: a
// shim named `opencode` runs `observer opencode`, so the launcher resolving
// its vendor binary must never pick the shim - neither in the excluded shim
// dir nor, by marker, anywhere else - and must never hand the shim dir back
// as a login-only PATH dir to prepend to the child.
func TestResolveSkipsCommandWrappingShims(t *testing.T) {
	shimDir := p("/home/u/.observer/shims")
	otherShimDir := p("/home/u/custom-shims")
	real := p("/usr/local/bin/opencode")
	const marker = "SBO-SHELLWRAP-SHIM"
	heads := map[string]string{
		p("/home/u/custom-shims/opencode"): "#!/bin/sh\n# " + marker + " v1 tool=opencode command=opencode\n",
		real:                               "\x7fELF...",
	}
	readHead := func(path string, n int) ([]byte, error) {
		h, ok := heads[path]
		if !ok {
			return nil, fs.ErrNotExist
		}
		if len(h) > n {
			h = h[:n]
		}
		return []byte(h), nil
	}
	cases := []struct {
		name    string
		process []string
		login   []string
		exclude []string
		marker  string
		wantBin string
	}{
		{"excluded shim dir first on PATH", []string{shimDir, p("/usr/local/bin")}, nil, []string{shimDir}, marker, real},
		{"marked shim in a custom dir", []string{otherShimDir, p("/usr/local/bin")}, nil, []string{shimDir}, marker, real},
		{"shim dir only on the login PATH", []string{p("/usr/local/bin")}, []string{shimDir, p("/usr/local/bin")}, []string{shimDir}, marker, real},
		// Without the exclusion the shim would win: the guard is what the
		// test is about, so prove the fixture would otherwise pick it.
		{"control: no exclusion picks the shim", []string{otherShimDir, p("/usr/local/bin")}, nil, nil, "", p("/home/u/custom-shims/opencode")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fakeFS{files: map[string]fs.FileMode{
				p("/home/u/.observer/shims/opencode"): exeMode,
				p("/home/u/custom-shims/opencode"):    exeMode,
				real:                                  exeMode,
			}}
			login := tc.login
			env := fsys.env(Env{
				GOOS: "linux", Home: p("/home/u"), ProcessPath: tc.process,
				ReadHead: readHead, ExcludeDirs: tc.exclude, ExcludeMarker: tc.marker,
			})
			if login != nil {
				env.LoginPath = func() ([]string, error) { return login, nil }
			}
			r := Resolve(specOpencode(), env)
			if r.Bin != tc.wantBin {
				t.Fatalf("Bin = %q, want %q (considered %+v)", r.Bin, tc.wantBin, r.Considered)
			}
			for _, d := range r.LoginOnlyDirs {
				if d == shimDir && len(tc.exclude) > 0 {
					t.Fatalf("the shim dir leaked into LoginOnlyDirs: %v", r.LoginOnlyDirs)
				}
			}
		})
	}
}
