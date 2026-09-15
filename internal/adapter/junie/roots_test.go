package junie

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultRoots_JunieHomeOverride covers the $JUNIE_HOME env-var
// override (2026-09-02 IDE audit §3.11 / plan ticket U2): the decompiled
// Junie plugin jar resolves its session store from
// `${JUNIE_HOME:-~/.junie}/sessions`, so an operator who relocated the
// home must still be watched. The override contributes
// `$JUNIE_HOME/sessions` FIRST, and the per-cross-mount-home
// `~/.junie/sessions` defaults are still emitted alongside it.
func TestDefaultRoots_JunieHomeOverride(t *testing.T) {
	jh := t.TempDir()
	t.Setenv("JUNIE_HOME", jh)
	roots := defaultRoots()
	want := filepath.Clean(filepath.Join(jh, "sessions"))
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
		if strings.HasSuffix(filepath.ToSlash(r), "/.junie/sessions") {
			sawDefault = true
		}
	}
	if !sawDefault {
		t.Errorf("defaultRoots() = %v, want it to still contain a ~/.junie/sessions default", roots)
	}
}

// TestDefaultRoots_NoJunieHome pins the unset case: only the per-home
// `~/.junie/sessions` defaults, never an empty entry, and no change in
// shape from before JUNIE_HOME support existed.
func TestDefaultRoots_NoJunieHome(t *testing.T) {
	t.Setenv("JUNIE_HOME", "")
	roots := defaultRoots()
	if len(roots) == 0 {
		t.Fatal("defaultRoots() returned no roots")
	}
	for _, r := range roots {
		if r == "" {
			t.Fatal("defaultRoots() emitted an empty root")
		}
		if !strings.HasSuffix(filepath.ToSlash(r), "/.junie/sessions") {
			t.Errorf("defaultRoots() = %q, want every root to end in /.junie/sessions", r)
		}
	}
}

// TestDefaultRoots_JunieHomeAbsolutized is the same Q1-class regression
// pin qwencode's QWEN_HOME and kimicode's KIMI_CODE_HOME carry: whatever
// shape $JUNIE_HOME arrives in, the root it contributes must be
// ABSOLUTE. fsnotify resolves a relative root against the DAEMON's
// working directory (never the operator's shell cwd, and not stable
// across runs), so a relative env value travelling verbatim into
// WatchPaths would silently watch the wrong place — or nothing at all.
func TestDefaultRoots_JunieHomeAbsolutized(t *testing.T) {
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
		{"bare relative", "junie-home", filepath.Clean(filepath.Join(cwd, "junie-home", "sessions"))},
		{"dot relative", filepath.Join(".", "junie-home"), filepath.Clean(filepath.Join(cwd, "junie-home", "sessions"))},
		{"parent relative", filepath.Join("..", "junie-home"), filepath.Clean(filepath.Join(cwd, "..", "junie-home", "sessions"))},
		{"unset", "", ""},
		{"blank", "   ", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JUNIE_HOME", tc.env)
			roots := defaultRoots()
			for _, r := range roots {
				if !filepath.IsAbs(r) {
					t.Errorf("defaultRoots() emitted the relative root %q (JUNIE_HOME=%q): %v", r, tc.env, roots)
				}
			}
			if tc.want == "" {
				for _, r := range roots {
					if !strings.HasSuffix(filepath.ToSlash(r), "/.junie/sessions") {
						t.Errorf("JUNIE_HOME=%q contributed %q; want only per-home defaults", tc.env, r)
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

// TestIsSessionFile_JunieHomeRoot pins the relocated-store shape (ticket
// U2 point 2): a session log living under a JUNIE_HOME-relocated root
// (no `.junie` path segment at all) still matches, because the shape
// check falls back to "exactly two levels below one of the adapter's
// watch roots" when the literal `/.junie/sessions/` substring is absent.
// The off-limits siblings (index.jsonl, state.json) stay rejected even
// under the relocated root, since they fail the basename check before
// the relocated-shape fallback is ever consulted.
func TestIsSessionFile_JunieHomeRoot(t *testing.T) {
	jh := t.TempDir()
	root := filepath.Join(jh, "sessions")
	a := NewWithOptions(nil, root)

	log := filepath.Join(root, "session-abc", "events.jsonl")
	if !a.IsSessionFile(log) {
		t.Errorf("IsSessionFile(%q) = false, want true under a JUNIE_HOME root", log)
	}

	for _, reject := range []string{
		filepath.Join(root, "index.jsonl"),                                    // sibling index, one level up from a session dir
		filepath.Join(root, "session-abc", "state.json"),                      // resume snapshot
		filepath.Join(root, "session-abc", "transcript.md"),                   // human-readable render
		filepath.Join(root, "session-abc", "task-1", ".matterhorn", "x.json"), // scratch dir
		filepath.Join(root, "session-abc", "sub", "events.jsonl"),             // right basename, wrong depth (3 levels below root)
		filepath.Join(jh, "events.jsonl"),                                     // right basename, one level ABOVE root (not under root at all)
	} {
		if a.IsSessionFile(reject) {
			t.Errorf("IsSessionFile(%q) = true, want false", reject)
		}
	}
}

// TestMatchesShape_RelocatedRootDedupedAgainstDefault covers the case
// where JUNIE_HOME happens to equal one of the cross-mount default
// homes' `.junie` directory: defaultRoots must not emit the same
// watch-path twice (would double-parse every event).
func TestMatchesShape_RelocatedRootDedupedAgainstDefault(t *testing.T) {
	home := t.TempDir()
	junieHome := filepath.Join(home, ".junie")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("JUNIE_HOME", junieHome)

	roots := defaultRoots()
	seen := map[string]int{}
	for _, r := range roots {
		seen[filepath.Clean(r)]++
	}
	for r, n := range seen {
		if n > 1 {
			t.Errorf("defaultRoots() = %v, root %q appeared %d times, want deduped", roots, r, n)
		}
	}
}
