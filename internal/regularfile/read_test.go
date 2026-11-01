package regularfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRead: a regular file within the cap is read, one past it, a
// directory and a missing file are refused (the FIFO case is pinned by
// internal/agentconfigsvc's reader tests, which run through the shim).
func TestRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	if err := os.WriteFile(p, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(p, 5); err != nil || string(b) != "12345" {
		t.Errorf("Read at the cap = %q, %v", b, err)
	}
	if _, err := Read(p, 4); err == nil {
		t.Error("a file past the cap was read")
	}
	if _, err := Read(dir, 10); err == nil {
		t.Error("a directory was read")
	}
	if _, err := Read(filepath.Join(dir, "missing"), 10); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file err = %v, want ErrNotExist", err)
	}
}

// TestReadNoFollow: a regular file within the cap is read with the open
// descriptor's FileInfo; a symlink (even to a regular file), a directory,
// a file past the cap and a missing file are refused.
func TestReadNoFollow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.json")
	if err := os.WriteFile(p, []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, fi, err := ReadNoFollow(p, 5)
	if err != nil || string(b) != "12345" || fi == nil || !fi.Mode().IsRegular() || fi.Size() != 5 {
		t.Fatalf("ReadNoFollow at the cap = %q, %v, %v", b, fi, err)
	}
	if _, _, err := ReadNoFollow(p, 4); !errors.Is(err, ErrTooLarge) {
		t.Errorf("past the cap: %v, want ErrTooLarge", err)
	}
	if _, _, err := ReadNoFollow(dir, 10); !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory: %v, want ErrNotRegular", err)
	}
	if _, _, err := ReadNoFollow(filepath.Join(dir, "missing"), 10); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v, want ErrNotExist", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(p, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if _, _, err := ReadNoFollow(link, 10); !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "is not a regular file") {
		t.Errorf("symlink: %v, want ErrNotRegular", err)
	}
	if b, err := Read(link, 10); err != nil || string(b) != "12345" {
		t.Errorf("Read still follows a link: %q, %v", b, err)
	}
}

// TestReadRefusalsWrapSentinels pins the two sentinels (callers tell a
// changed file from an unreadable one by them) and the unchanged messages.
func TestReadRefusalsWrapSentinels(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(dir, 64); !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "is not a regular file") {
		t.Errorf("directory: %v", err)
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, 65), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(big, 64); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "larger than 64 bytes") {
		t.Errorf("over the cap: %v", err)
	}
}
