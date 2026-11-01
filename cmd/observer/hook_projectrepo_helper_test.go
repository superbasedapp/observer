package main

import (
	"os"
	"path/filepath"
	"testing"
)

// projectHookRepo is a git working tree whose origin is remote, and a
// subdirectory of it (the agent's cwd). No git process runs. Untagged:
// hook_reporoot_test.go uses it too, and that file builds without the
// Codex adapter (RB1: the sbo_omit_adapter_codex vet failed).
func projectHookRepo(t *testing.T, remote string) (root, cwd string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cwd = filepath.Join(root, "services", "api")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFileT(t, filepath.Join(root, ".git", "config"), "[remote \"origin\"]\n\turl = "+remote+"\n")
	return root, cwd
}
