package fsatomic

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestFileIsOwnerOnlyReadsTheHandle (WINFIX4 audit finding 5): the check
// reads the open file, so the file judged is the file read; a broadly
// readable file is refused through its handle too.
func TestFileIsOwnerOnlyReadsTheHandle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "key")
	f, err := CreateOwnerOnly(p)
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	r, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if ok, err := FileIsOwnerOnly(r); err != nil || !ok {
		t.Fatalf("an owner-only file read through its handle: %v %v", ok, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	wide := filepath.Join(dir, "wide")
	if err := os.WriteFile(wide, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := os.Open(wide)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()
	if ok, _ := FileIsOwnerOnly(w); ok {
		t.Fatal("a 0644 file passed")
	}
}
