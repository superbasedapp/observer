package fsatomic

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustOwnerOnly(t *testing.T, path string) {
	t.Helper()
	ok, err := IsOwnerOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatalf("%s is not owner-only", path)
	}
}

// TestCreateOwnerOnly: a new file is owner-only, and an existing path is
// refused with fs.ErrExist (a planted file is never written through).
func TestCreateOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "token")
	f, err := CreateOwnerOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("secret\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	mustOwnerOnly(t, p)
	if _, err := CreateOwnerOnly(p); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second create: %v, want fs.ErrExist", err)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "secret\n" {
		t.Fatalf("read back %q, %v", b, err)
	}
}

// TestCreateTempOwnerOnly: the temp file follows the pattern and is
// owner-only.
func TestCreateTempOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	f, err := CreateTempOwnerOnly(dir, ".secret-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	name := f.Name()
	_ = f.Close()
	base := filepath.Base(name)
	if filepath.Dir(name) != dir || !strings.HasPrefix(base, ".secret-") || !strings.HasSuffix(base, ".tmp") {
		t.Fatalf("temp name %s does not follow the pattern", name)
	}
	mustOwnerOnly(t, name)
	if _, err := CreateTempOwnerOnly(dir, "a/b*"); err == nil {
		t.Fatal("a pattern with a separator was accepted")
	}
}

// TestWriteFileOwnerOnly: with OwnerOnly a write replaces a broadly
// readable file with an owner-only one.
func TestWriteFileOwnerOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(p, []byte("new"), Options{OwnerOnly: true}); err != nil {
		t.Fatal(err)
	}
	mustOwnerOnly(t, p)
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
}
