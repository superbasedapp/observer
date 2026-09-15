package kimicode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultRoots_KimiCodeHomeOverride covers the $KIMI_CODE_HOME env-var
// override (audit IDE-18 / plan class C7): the kimi-code bundle resolves
// its storage root from KIMI_CODE_HOME before falling back to
// ~/.kimi-code, so an operator who relocated the home must still be
// watched. The override contributes `$KIMI_CODE_HOME/sessions` FIRST, and
// the per-cross-mount-home defaults are still emitted alongside it.
func TestDefaultRoots_KimiCodeHomeOverride(t *testing.T) {
	kh := t.TempDir()
	t.Setenv("KIMI_CODE_HOME", kh)
	roots := defaultRoots()
	want := filepath.Clean(filepath.Join(kh, "sessions"))
	if len(roots) == 0 || roots[0] != want {
		t.Fatalf("defaultRoots() = %v, want first element %q", roots, want)
	}
	seen := map[string]int{}
	for _, r := range roots {
		seen[r]++
		if seen[r] > 1 {
			t.Errorf("defaultRoots() repeated %q: %v", r, roots)
		}
	}
	var sawDefault bool
	for _, r := range roots {
		if strings.HasSuffix(filepath.ToSlash(r), "/.kimi-code/sessions") {
			sawDefault = true
		}
	}
	if !sawDefault {
		t.Errorf("defaultRoots() = %v, want it to still contain a ~/.kimi-code/sessions default", roots)
	}
}

// TestDefaultRoots_NoKimiCodeHome pins the unset case: only the per-home
// defaults, and never an empty entry.
func TestDefaultRoots_NoKimiCodeHome(t *testing.T) {
	t.Setenv("KIMI_CODE_HOME", "")
	roots := defaultRoots()
	if len(roots) == 0 {
		t.Fatal("defaultRoots() returned no roots")
	}
	for _, r := range roots {
		if r == "" {
			t.Fatal("defaultRoots() emitted an empty root")
		}
		if !strings.HasSuffix(filepath.ToSlash(r), "/.kimi-code/sessions") {
			t.Errorf("defaultRoots() = %q, want every root to end in /.kimi-code/sessions", r)
		}
	}
}

// TestIsSessionFile_KimiCodeHomeRoot pins that a wire trace living under a
// relocated $KIMI_CODE_HOME still matches. matchesShape never hardcoded
// the `.kimi-code` segment (the install root is the watch-root gate's
// job), so this is a regression pin on that division of labour.
func TestIsSessionFile_KimiCodeHomeRoot(t *testing.T) {
	kh := t.TempDir()
	root := filepath.Join(kh, "sessions")
	a := NewWithOptions(nil, root)

	wire := filepath.Join(root, "wd_demo_ab12cd34ef56",
		"session_11111111-1111-4111-8111-111111111111", "agents", "main", "wire.jsonl")
	if !a.IsSessionFile(wire) {
		t.Errorf("IsSessionFile(%q) = false, want true under a KIMI_CODE_HOME root", wire)
	}
	for _, reject := range []string{
		filepath.Join(root, "wd_demo_ab12cd34ef56", "session_11111111-1111-4111-8111-111111111111", "state.json"),
		filepath.Join(kh, "session_index.jsonl"),
	} {
		if a.IsSessionFile(reject) {
			t.Errorf("IsSessionFile(%q) = true, want false", reject)
		}
	}
}

// TestDefaultRoots_KimiCodeHomeAbsolutized is the Q1 regression pin:
// whatever shape $KIMI_CODE_HOME arrives in, the root it contributes must
// be ABSOLUTE. fsnotify resolves a relative root against the DAEMON's
// working directory (never the operator's shell cwd, and not stable
// across runs), so a relative env value travelling verbatim into
// WatchPaths would silently watch the wrong place — or nothing at all.
func TestDefaultRoots_KimiCodeHomeAbsolutized(t *testing.T) {
	abs := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	cases := []struct {
		name string
		env  string
		want string // "" = the env contributes no root at all
	}{
		{"absolute", abs, filepath.Clean(filepath.Join(abs, "sessions"))},
		{"bare relative", "kimi-home", filepath.Clean(filepath.Join(cwd, "kimi-home", "sessions"))},
		{"dot relative", filepath.Join(".", "kimi-home"), filepath.Clean(filepath.Join(cwd, "kimi-home", "sessions"))},
		{"parent relative", filepath.Join("..", "kimi-home"), filepath.Clean(filepath.Join(cwd, "..", "kimi-home", "sessions"))},
		{"unset", "", ""},
		{"blank", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KIMI_CODE_HOME", tc.env)
			roots := defaultRoots()
			for _, r := range roots {
				if !filepath.IsAbs(r) {
					t.Errorf("defaultRoots() emitted the relative root %q (KIMI_CODE_HOME=%q): %v", r, tc.env, roots)
				}
			}
			if tc.want == "" {
				for _, r := range roots {
					if !strings.HasSuffix(filepath.ToSlash(r), "/.kimi-code/sessions") {
						t.Errorf("KIMI_CODE_HOME=%q contributed %q; want only per-home defaults", tc.env, r)
					}
				}
				return
			}
			if len(roots) == 0 || roots[0] != tc.want {
				t.Errorf("defaultRoots() = %v, want first element %q", roots, tc.want)
			}
		})
	}
}
