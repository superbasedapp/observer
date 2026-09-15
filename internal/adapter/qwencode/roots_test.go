package qwencode

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultRoots_QwenHomeOverride covers the $QWEN_HOME env-var override
// (audit IDE-18 / plan class C7): the Qwen Code bundle resolves its storage
// root from QWEN_HOME before falling back to ~/.qwen, so an operator who
// relocated the home must still be watched. The override contributes
// `$QWEN_HOME/projects` FIRST, and the per-cross-mount-home defaults are
// still emitted alongside it.
func TestDefaultRoots_QwenHomeOverride(t *testing.T) {
	qh := t.TempDir()
	t.Setenv("QWEN_HOME", qh)
	roots := defaultRoots()
	want := filepath.Clean(filepath.Join(qh, "projects"))
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
		if strings.HasSuffix(filepath.ToSlash(r), "/.qwen/projects") {
			sawDefault = true
		}
	}
	if !sawDefault {
		t.Errorf("defaultRoots() = %v, want it to still contain a ~/.qwen/projects default", roots)
	}
}

// TestDefaultRoots_NoQwenHome pins the unset case: only the per-home
// defaults, and never an empty entry.
func TestDefaultRoots_NoQwenHome(t *testing.T) {
	t.Setenv("QWEN_HOME", "")
	roots := defaultRoots()
	if len(roots) == 0 {
		t.Fatal("defaultRoots() returned no roots")
	}
	for _, r := range roots {
		if r == "" {
			t.Fatal("defaultRoots() emitted an empty root")
		}
		if !strings.HasSuffix(filepath.ToSlash(r), "/.qwen/projects") {
			t.Errorf("defaultRoots() = %q, want every root to end in /.qwen/projects", r)
		}
	}
}

// TestIsSessionFile_QwenHomeRoot pins that a transcript living under a
// relocated $QWEN_HOME (no `.qwen` path segment at all) still matches: the
// shape check must not hardcode the home segment — the watch-root gate
// enforces the install root. It also pins that the top-level
// `journal.jsonl`, which lives outside any `chats/` directory, is NOT a
// session log.
func TestIsSessionFile_QwenHomeRoot(t *testing.T) {
	qh := t.TempDir()
	root := filepath.Join(qh, "projects")
	a := NewWithOptions(nil, root)

	transcript := filepath.Join(root, "-tmp-proj", "chats", "11111111-2222-4333-8444-555555555555.jsonl")
	if !a.IsSessionFile(transcript) {
		t.Errorf("IsSessionFile(%q) = false, want true under a QWEN_HOME root", transcript)
	}
	for _, reject := range []string{
		filepath.Join(qh, "journal.jsonl"),
		filepath.Join(root, "-tmp-proj", "journal.jsonl"),
		filepath.Join(root, "-tmp-proj", "chats", "11111111-2222-4333-8444-555555555555.runtime.jsonl"),
		filepath.Join(root, "-tmp-proj", "chats", "11111111-2222-4333-8444-555555555555.runtime.json"),
	} {
		if a.IsSessionFile(reject) {
			t.Errorf("IsSessionFile(%q) = true, want false", reject)
		}
	}
}

// TestDefaultRoots_QwenHomeAbsolutized is the Q1 regression pin: whatever
// shape $QWEN_HOME arrives in, the root it contributes must be ABSOLUTE.
// fsnotify resolves a relative root against the DAEMON's working
// directory (never the operator's shell cwd, and not stable across
// runs), so a relative env value travelling verbatim into WatchPaths
// would silently watch the wrong place — or nothing at all.
func TestDefaultRoots_QwenHomeAbsolutized(t *testing.T) {
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
		{"absolute", abs, filepath.Clean(filepath.Join(abs, "projects"))},
		{"bare relative", "qwen-home", filepath.Clean(filepath.Join(cwd, "qwen-home", "projects"))},
		{"dot relative", filepath.Join(".", "qwen-home"), filepath.Clean(filepath.Join(cwd, "qwen-home", "projects"))},
		{"parent relative", filepath.Join("..", "qwen-home"), filepath.Clean(filepath.Join(cwd, "..", "qwen-home", "projects"))},
		{"unset", "", ""},
		{"blank", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QWEN_HOME", tc.env)
			roots := defaultRoots()
			for _, r := range roots {
				if !filepath.IsAbs(r) {
					t.Errorf("defaultRoots() emitted the relative root %q (QWEN_HOME=%q): %v", r, tc.env, roots)
				}
			}
			if tc.want == "" {
				for _, r := range roots {
					if !strings.HasSuffix(filepath.ToSlash(r), "/.qwen/projects") {
						t.Errorf("QWEN_HOME=%q contributed %q; want only per-home defaults", tc.env, r)
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
