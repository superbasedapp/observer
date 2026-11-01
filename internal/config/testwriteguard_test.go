package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestConfigWritersRefuseOutsideTempDir (FU-118): inside a test binary the
// config writers (WriteToml and MigrateFile through writeBytesAtomic,
// RestoreBackup, and a profile write and delete) refuse a path outside the OS
// temp directory before they create anything, and the same writes under
// t.TempDir() still work.
func TestConfigWritersRefuseOutsideTempDir(t *testing.T) {
	outside := filepath.Join(filepath.VolumeName(os.TempDir())+string(os.PathSeparator), "observer-config-write-guard-never-created")
	if _, err := os.Stat(outside); err == nil {
		t.Skipf("%s exists; refusing to run", outside)
	}
	t.Cleanup(func() {
		for _, v := range testwriteguard.TakeViolationsForTest() {
			if !strings.HasPrefix(v, outside) {
				t.Errorf("unexpected refused write %s", v)
			}
		}
	})
	writers := []struct {
		name  string
		write func(dir string) error
	}{
		{"WriteToml", func(dir string) error { return WriteToml(filepath.Join(dir, "config.toml"), Config{}) }},
		{"RestoreBackup", func(dir string) error { return RestoreBackup(filepath.Join(dir, "config.toml")) }},
		{"profile delete", func(dir string) error { return ProfileStore{Dir: filepath.Join(dir, "profiles")}.Delete("mine") }},
	}
	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			if err := w.write(outside); !errors.Is(err, testwriteguard.ErrRefused) {
				t.Errorf("write outside temp = %v, want testwriteguard.ErrRefused", err)
			}
			if _, err := os.Stat(outside); !os.IsNotExist(err) {
				t.Fatalf("%s created %s", w.name, outside)
			}
		})
	}
	// Under the temp dir the writer runs (a missing backup or profile is its
	// own error, never a refusal).
	dir := t.TempDir()
	if err := WriteToml(filepath.Join(dir, "config.toml"), Config{}); err != nil {
		t.Fatalf("WriteToml under t.TempDir: %v", err)
	}
	if err := (ProfileStore{Dir: filepath.Join(dir, "profiles")}).Delete("mine"); errors.Is(err, testwriteguard.ErrRefused) {
		t.Fatalf("profile delete under t.TempDir was refused: %v", err)
	}
}
