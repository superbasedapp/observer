//go:build !sbo_omit_security

package secsvc

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteHookNeverWritesThroughAPlantedLink is RB1 sweep finding P4: the
// temporary file used to sit at the predictable name <hook>.observer-tmp,
// so a link planted there in a hooks directory that is repository content
// sent Observer's hook text (and the executable bit) to its target.
func TestWriteHookNeverWritesThroughAPlantedLink(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(dir, "pre-commit")
	if err := os.Symlink(victim, hook+".observer-tmp"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeHook(hook, "#!/bin/sh\nexit 0\n", 0o755); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("the planted link's target was overwritten: %q", b)
	}
	if fi, _ := os.Stat(victim); fi.Mode().Perm()&0o100 != 0 {
		t.Fatalf("the planted link's target was made executable: %v", fi.Mode())
	}
	if b, err := os.ReadFile(hook); err != nil || string(b) != "#!/bin/sh\nexit 0\n" {
		t.Fatalf("hook = %q, %v", b, err)
	}
	if fi, err := os.Lstat(hook); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o700 != 0o700 {
		t.Fatalf("hook is not a regular executable file: %v, %v", fi, err)
	}
}
