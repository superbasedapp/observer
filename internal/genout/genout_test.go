package genout

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFile(t *testing.T) {
	cases := []struct {
		name string
		rel  string
	}{
		{"existing directory", "out.sql"},
		{"missing parent directories", filepath.Join("nested", "dir", "out.sql")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.rel)
			data := []byte("-- generated\n")
			if err := WriteFile(path, data); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if !bytes.Equal(got, data) {
				t.Errorf("read back %q, want %q", got, data)
			}
			if runtime.GOOS == "windows" {
				return
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			// os.WriteFile applies the umask; 0644 is the most it can be.
			if perm := info.Mode().Perm(); perm&^0o644 != 0 {
				t.Errorf("mode %v, want at most 0644", perm)
			}
		})
	}
}

func TestWriteFileOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")
	if err := WriteFile(path, []byte("old and longer\n")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new\n" {
		t.Errorf("read back %q, want %q", got, "new\n")
	}
}

func TestWriteFileReportsAFailure(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The parent "directory" is a regular file, so MkdirAll must fail.
	if err := WriteFile(filepath.Join(blocker, "out.sql"), []byte("x")); err == nil {
		t.Error("WriteFile under a regular file: want an error")
	}
}
