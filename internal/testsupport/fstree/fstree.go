package fstree

import (
	"os"
	"path/filepath"
	"testing"
)

// Write writes files under a new t.TempDir() and returns that root.
// Directories are created with mode 0o755 and files with mode 0o644.
func Write(t testing.TB, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, files, 0o755, 0o644)
	return root
}

// WriteIn writes files under root, which may already exist and hold files,
// with the modes Write uses.
func WriteIn(t testing.TB, root string, files map[string]string) {
	t.Helper()
	write(t, root, files, 0o755, 0o644)
}

// WritePrivate is Write with owner-only modes: directories 0o700 and files
// 0o600.
func WritePrivate(t testing.TB, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	write(t, root, files, 0o700, 0o600)
	return root
}

func write(t testing.TB, root string, files map[string]string, dirMode, fileMode os.FileMode) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), dirMode); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), fileMode); err != nil {
			t.Fatal(err)
		}
	}
}
