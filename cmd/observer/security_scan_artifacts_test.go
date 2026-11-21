//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestResolveArtifactDirs pins `observer security scan --artifacts`: a
// relative directory is read against the project root, an absolute one
// must lie inside it, and each must exist; the child gets them relative,
// forward slashes, sorted.
func TestResolveArtifactDirs(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"build/out", "release", "file-not-dir"} {
		p := filepath.Join(root, filepath.FromSlash(d))
		if d == "file-not-dir" {
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	cases := []struct {
		name  string
		in    []string
		want  []string
		error string
	}{
		{name: "none", in: nil, want: []string{}},
		{name: "relative and absolute, sorted", in: []string{"release", filepath.Join(root, "build", "out")}, want: []string{"build/out", "release"}},
		{name: "duplicates folded", in: []string{"release", "./release/"}, want: []string{"release"}},
		{name: "missing", in: []string{"nope"}, error: "not a directory"},
		{name: "a file", in: []string{"file-not-dir"}, error: "not a directory"},
		{name: "outside the project", in: []string{outside}, error: "inside the project"},
		{name: "the project root itself", in: []string{"."}, error: "inside the project"},
		{name: "leaves the project", in: []string{".."}, error: "inside the project"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveArtifactDirs(root, tc.in)
			if tc.error != "" {
				if err == nil || !strings.Contains(err.Error(), tc.error) {
					t.Fatalf("err %v, want %q", err, tc.error)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("got %q %v, want %q", got, err, tc.want)
			}
		})
	}
}
