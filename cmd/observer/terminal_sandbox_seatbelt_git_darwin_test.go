//go:build darwin && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSeatbeltGitRunFilesWritten pins D-MU4's helper step on a Mac: the
// run-local git files are written 0600 in the run's TMPDIR, never over an
// existing file and never through a planted link.
func TestSeatbeltGitRunFilesWritten(t *testing.T) {
	tmp := t.TempDir()
	_, files := seatbeltWithGitIsolation(nil, tmp)
	for _, f := range files {
		if err := writeSeatbeltRunFile(f); err != nil {
			t.Fatalf("write %s: %v", f.Path, err)
		}
		fi, err := os.Lstat(f.Path)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v err %v", f.Path, fi.Mode(), err)
		}
		if err := writeSeatbeltRunFile(f); err == nil {
			t.Errorf("%s written twice", f.Path)
		}
	}
	other := t.TempDir()
	target := filepath.Join(other, "victim")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(other, seatbeltGitConfigName)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeSeatbeltRunFile(seatbeltRunFile{Path: link, Content: "x"}); err == nil {
		t.Error("wrote through a planted link")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("link target changed: %q", b)
	}
}
