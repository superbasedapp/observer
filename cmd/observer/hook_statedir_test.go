package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHookStateDirResolver: the `observer hook --config` forensics logs go
// to the directory of that config's db_path (live proof 2026-10-21), and an
// unloadable config answers "" so the hook package keeps its default.
func TestHookStateDirResolver(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dbDir := filepath.Join(root, "custom-home")
	cfgPath := filepath.Join(root, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dbDir, "observer.db")) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hookStateDirResolver(cfgPath)(); filepath.Clean(got) != filepath.Clean(dbDir) {
		t.Errorf("resolver = %q, want the db_path directory %q", got, dbDir)
	}
	bad := filepath.Join(root, "bad.toml")
	if err := os.WriteFile(bad, []byte("[observer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := hookStateDirResolver(bad)(); got != "" {
		t.Errorf("unloadable config resolved to %q, want \"\"", got)
	}
}
