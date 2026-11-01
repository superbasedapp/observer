//go:build !sbo_omit_security

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The IaC tests' config writer, shared by the Trivy-only daemon test and
// the Trivy and KICS tests (R-008).

// iacConfig writes a config with the given [components] block ("" for an
// existing install with none) and returns its path; HOME and the user
// cache point at temporary directories.
func iacConfig(t *testing.T, block string) string {
	t.Helper()
	home := t.TempDir()
	// Every profile root stays in the throwaway home: the inert test
	// walks os.UserHomeDir(), which on Windows is USERPROFILE (FU-20).
	pinToolHomesAt(t, home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n" + block
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
