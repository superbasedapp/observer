package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestWriteBytesAtomicPermissions pins MHC-2 (codebase audit 2026-09-16): the
// config file AND its .bak sibling must both be owner-only (0o600). The backup
// is a byte-for-byte copy of a file whose schema marks several keys secret
// (routing.key_pool, email.password, browser.listener.token), so a
// world-readable .bak beside an owner-only original discloses them to every
// local account.
//
// Table-driven over the two writes one call produces: the renamed target and
// the backup it left behind.
func TestWriteBytesAtomicPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")

	// First write: no prior file, so no .bak is produced.
	if err := writeBytesAtomic(path, []byte("[email]\npassword = \"s3cret\"\n")); err != nil {
		t.Fatalf("writeBytesAtomic (first): %v", err)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("first write must not create a .bak; stat err = %v", err)
	}

	// Second write: the first file becomes the .bak.
	if err := writeBytesAtomic(path, []byte("[email]\npassword = \"rotated\"\n")); err != nil {
		t.Fatalf("writeBytesAtomic (second): %v", err)
	}

	for _, tc := range []struct {
		name string
		path string
	}{
		{"live config", path},
		{"backup", path + ".bak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fi, err := os.Stat(tc.path)
			if err != nil {
				t.Fatalf("stat %s: %v", tc.path, err)
			}
			if got := fi.Mode().Perm(); got != 0o600 {
				t.Errorf("%s mode = %#o, want 0600 — a config copy must never be group/world readable", tc.path, got)
			}
		})
	}

	// Sanity: the backup really is the previous content, so the mode
	// assertion above is not vacuous.
	bak, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("read .bak: %v", err)
	}
	if string(bak) != "[email]\npassword = \"s3cret\"\n" {
		t.Errorf(".bak content = %q, want the pre-write config", string(bak))
	}
}
