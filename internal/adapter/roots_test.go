package adapter

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// NOTE ON PARALLELISM — deliberately NONE in this file.
//
// Every test here exercises DedupRootsByIdentity / rootIdentityKey,
// which read the package-level `caseInsensitiveFS` toggle
// (internal/adapter/match.go), and TestRootIdentityKey WRITES it to
// cover both branches on any host. A writer plus parallel readers of an
// unsynchronised package var is a data race the moment the phase
// ordering that currently separates them changes (a sequential reader
// added here, a sibling test file releasing its parallel tests earlier,
// t.Parallel added to the writer). The toggle cannot be parameterised
// away from the test side alone — rootIdentityKey takes no
// case-sensitivity argument — so the whole file stays sequential
// instead. These tests are string manipulation over a handful of
// t.TempDir entries; serialising them costs milliseconds.
//
// If `caseInsensitiveFS` ever becomes an explicit parameter on an
// unexported helper, parallelism can come back with it.

// TestDedupRootsByIdentity_Strings is the table-driven string layer:
// empties dropped, `.`/`..` segments and trailing separators folded,
// order preserved (first occurrence wins). None of these paths exist,
// which also pins the "non-existent roots are RETAINED" rule
// (Invariant #48).
func TestDedupRootsByIdentity_Strings(t *testing.T) {
	base := filepath.Join(string(filepath.Separator), "synthetic", "roots")
	a := filepath.Join(base, "alpha")
	b := filepath.Join(base, "beta")

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "nil input",
			in:   nil,
			want: nil,
		},
		{
			name: "empty entries dropped",
			in:   []string{"", a, ""},
			want: []string{a},
		},
		{
			name: "exact duplicate spelling",
			in:   []string{a, a, b},
			want: []string{a, b},
		},
		{
			name: "trailing separator folds",
			in:   []string{a, a + string(filepath.Separator)},
			want: []string{a},
		},
		{
			name: "dot segment folds",
			in:   []string{a, a + string(filepath.Separator) + "."},
			want: []string{a},
		},
		{
			name: "dotdot segment folds",
			in: []string{
				a,
				a + string(filepath.Separator) + "sub" + string(filepath.Separator) + "..",
			},
			want: []string{a},
		},
		{
			name: "order preserved, first wins",
			in:   []string{b, a, b, a},
			want: []string{b, a},
		},
		{
			name: "non-existent roots retained",
			in:   []string{a, b},
			want: []string{a, b},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DedupRootsByIdentity(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("DedupRootsByIdentity(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("DedupRootsByIdentity(%v)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestDedupRootsByIdentity_NeverAliasesInput pins that the returned
// slice is fresh — callers may sort/append to it without corrupting an
// adapter's own root slice.
func TestDedupRootsByIdentity_NeverAliasesInput(t *testing.T) {
	in := []string{filepath.Join(string(filepath.Separator), "synthetic", "one")}
	got := DedupRootsByIdentity(in)
	if len(got) != 1 {
		t.Fatalf("got %v want 1 entry", got)
	}
	got[0] = "mutated"
	if in[0] == "mutated" {
		t.Fatal("DedupRootsByIdentity returned a slice aliasing its input")
	}
}

// TestDedupRootsByIdentity_CaseInsensitiveDuplicate pins that two
// spellings differing only in case fold on Windows + macOS (the
// caseInsensitiveFS platforms) and stay distinct on Linux.
func TestDedupRootsByIdentity_CaseInsensitiveDuplicate(t *testing.T) {
	base := t.TempDir()
	lower := filepath.Join(base, "cowork")
	if err := os.MkdirAll(lower, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	upper := filepath.Join(base, "COWORK")

	got := DedupRootsByIdentity([]string{lower, upper})
	switch runtime.GOOS {
	case "windows", "darwin":
		if len(got) != 1 {
			t.Fatalf("case-insensitive host: got %v want 1 entry", got)
		}
		if got[0] != lower {
			t.Fatalf("got[0]=%q want %q (first occurrence wins)", got[0], lower)
		}
	default:
		if len(got) != 2 {
			t.Fatalf("case-sensitive host: got %v want 2 entries", got)
		}
	}
}

// TestDedupRootsByIdentity_SymlinkAlias is the identity layer: a
// directory reachable under two spellings (one of them a symlink)
// collapses to the first spelling. This is the portable stand-in for
// the Windows MSIX reparse point (%APPDATA%\Claude → Packages\Claude_*\
// LocalCache\Roaming\Claude) that motivated the helper — os.Symlink
// needs SeCreateSymbolicLinkPrivilege on Windows, so the test skips
// when the host refuses.
func TestDedupRootsByIdentity_SymlinkAlias(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "LocalCache", "Roaming", "Claude", "local-agent-mode-sessions")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	alias := filepath.Join(base, "Roaming-Claude-sessions")
	if err := os.Symlink(target, alias); err != nil {
		t.Skipf("os.Symlink unsupported on this host (privilege?): %v", err)
	}

	got := DedupRootsByIdentity([]string{target, alias})
	if len(got) != 1 {
		t.Fatalf("got %v want 1 entry (symlink alias should fold)", got)
	}
	if got[0] != target {
		t.Fatalf("got[0]=%q want %q (first occurrence wins)", got[0], target)
	}

	// Reversed order: the symlink spelling wins when it comes first.
	got = DedupRootsByIdentity([]string{alias, target})
	if len(got) != 1 || got[0] != alias {
		t.Fatalf("reversed: got %v want [%q]", got, alias)
	}
}

// TestDedupRootsByIdentity_MixedExistingAndMissing pins the combined
// shape the cowork adapter actually produces: an existing MSIX-style
// root, its alias, and a second home's root that does not exist on
// this box. The alias folds; the missing root survives.
func TestDedupRootsByIdentity_MixedExistingAndMissing(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "sessions")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	missing := filepath.Join(base, "other-home", "sessions")

	in := []string{target, target + string(filepath.Separator), missing, missing}
	got := DedupRootsByIdentity(in)
	if len(got) != 2 {
		t.Fatalf("got %v want 2 entries", got)
	}
	if got[0] != target || got[1] != missing {
		t.Fatalf("got %v want [%q %q]", got, target, missing)
	}
}

// TestDedupRootsByIdentity_FileRootsKeepStringLayer pins that a
// non-directory root (aider's per-repo transcript FILE paths) is
// carried through the string layer only — two distinct files are two
// roots.
func TestDedupRootsByIdentity_FileRootsKeepStringLayer(t *testing.T) {
	base := t.TempDir()
	one := filepath.Join(base, "a.aider.chat.history.md")
	two := filepath.Join(base, "b.aider.chat.history.md")
	for _, p := range []string{one, two} {
		if err := os.WriteFile(p, []byte("# chat\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	got := DedupRootsByIdentity([]string{one, two, one})
	if len(got) != 2 || got[0] != one || got[1] != two {
		t.Fatalf("got %v want [%q %q]", got, one, two)
	}
}

// TestRootIdentityKey pins the case-fold rule against the shared
// caseInsensitiveFS toggle, on both branches, regardless of host.
func TestRootIdentityKey(t *testing.T) {
	orig := caseInsensitiveFS
	t.Cleanup(func() { caseInsensitiveFS = orig })

	p := filepath.Join(string(filepath.Separator), "Synthetic", "Roots")

	caseInsensitiveFS = true
	if got := rootIdentityKey(p); got != strings.ToLower(p) {
		t.Fatalf("case-insensitive: rootIdentityKey(%q)=%q want %q", p, got, strings.ToLower(p))
	}

	caseInsensitiveFS = false
	if got := rootIdentityKey(p); got != p {
		t.Fatalf("case-sensitive: rootIdentityKey(%q)=%q want %q", p, got, p)
	}
}

// TestAbsEnvRoot pins the four call-site behaviours AbsEnvRoot folds
// together: unset and blank both yield "", an already-absolute value
// passes through cleaned, and a relative value is anchored against the
// process cwd via filepath.Abs (not returned relative, and not "").
// t.Setenv scopes each case to this test and forbids t.Parallel, which
// matches this file's existing sequential-only convention.
func TestAbsEnvRoot(t *testing.T) {
	const envName = "OBSERVER_TEST_ABS_ENV_ROOT"

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	abs := filepath.Join(t.TempDir(), "sub")

	tests := []struct {
		name  string
		unset bool
		value string
		want  func() string
	}{
		{
			name:  "unset",
			unset: true,
			want:  func() string { return "" },
		},
		{
			name:  "blank",
			value: "   ",
			want:  func() string { return "" },
		},
		{
			name:  "absolute",
			value: abs,
			want:  func() string { return filepath.Clean(abs) },
		},
		{
			name:  "relative",
			value: filepath.Join("relative", "sub"),
			want:  func() string { return filepath.Join(cwd, "relative", "sub") },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unset {
				if err := os.Unsetenv(envName); err != nil {
					t.Fatalf("os.Unsetenv: %v", err)
				}
			} else {
				t.Setenv(envName, tc.value)
			}
			if got, want := AbsEnvRoot(envName), tc.want(); got != want {
				t.Errorf("AbsEnvRoot(%q) = %q want %q", envName, got, want)
			}
		})
	}
}
