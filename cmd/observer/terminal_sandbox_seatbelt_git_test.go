//go:build !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"
)

// TestSeatbeltGitIsolationEnv pins D-MU4's env composition: one
// GIT_CONFIG_GLOBAL, pointing into the run's TMPDIR (an inherited value is
// replaced), whose config names a run-local, empty ignore file and a
// run-local, empty attributes file (MACUSER merge L3: git otherwise reads
// ~/.config/git/attributes, which the blinded home denies).
func TestSeatbeltGitIsolationEnv(t *testing.T) {
	tmp := "/private/var/folders/xy/abc/T/obsbx-tmp/run1"
	in := []string{"PATH=/usr/bin", "GIT_CONFIG_GLOBAL=/Users/dev/.gitconfig", "HOME=/Users/dev"}
	env, files := seatbeltWithGitIsolation(in, tmp)
	var globals []string
	for _, kv := range env {
		if strings.HasPrefix(kv, "GIT_CONFIG_GLOBAL=") {
			globals = append(globals, kv)
		}
	}
	if want := "GIT_CONFIG_GLOBAL=" + tmp + "/" + seatbeltGitConfigName; !slices.Equal(globals, []string{want}) {
		t.Fatalf("GIT_CONFIG_GLOBAL entries = %v, want [%s]", globals, want)
	}
	if !slices.Contains(env, "PATH=/usr/bin") || !slices.Contains(env, "HOME=/Users/dev") {
		t.Errorf("other entries lost: %v", env)
	}
	if len(files) != 3 {
		t.Fatalf("files = %+v", files)
	}
	for _, f := range files {
		if !strings.HasPrefix(f.Path, tmp+"/") {
			t.Errorf("run file %s is outside the run's TMPDIR", f.Path)
		}
	}
	if want := `excludesFile = "` + tmp + "/" + seatbeltGitIgnoreName + `"`; !strings.Contains(files[0].Content, want) {
		t.Errorf("git config = %q, want it to name %s", files[0].Content, want)
	}
	if want := `attributesFile = "` + tmp + "/observer-gitattributes" + `"`; !strings.Contains(files[0].Content, want) {
		t.Errorf("git config = %q, want it to name %s", files[0].Content, want)
	}
	for _, f := range files[1:] {
		if f.Content != "" {
			t.Errorf("%s must be empty, got %q", f.Path, f.Content)
		}
	}
}
