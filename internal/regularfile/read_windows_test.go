//go:build windows

package regularfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestOpenNoFollowRefusesAReparsePoint: on Windows the no-follow open opens
// a symbolic link as itself (FILE_FLAG_OPEN_REPARSE_POINT) and refuses it,
// for a link to a regular file and a link to a directory alike, and a
// directory is refused too; a regular file opens. Skipped where the test
// cannot create a symbolic link (no developer mode, no privilege).
func TestOpenNoFollowRefusesAReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openNoFollow(target, nil)
	if err != nil {
		t.Fatalf("a regular file: %v", err)
	}
	_ = f.Close()
	if _, err := openNoFollow(dir, nil); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a directory: %v, want ErrNotRegular", err)
	}
	fileLink := filepath.Join(dir, "file-link.json")
	if err := os.Symlink(target, fileLink); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if f, err := openNoFollow(fileLink, nil); err == nil {
		_ = f.Close()
		t.Fatal("openNoFollow opened a symbolic link to a file")
	} else if !errors.Is(err, ErrNotRegular) {
		t.Errorf("a link to a file: %v, want ErrNotRegular", err)
	}
	if _, _, err := ReadNoFollow(fileLink, 64); !errors.Is(err, ErrNotRegular) {
		t.Errorf("ReadNoFollow through a link: %v, want ErrNotRegular", err)
	}
	dirLink := filepath.Join(dir, "dir-link")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Skipf("directory symlink: %v", err)
	}
	if f, err := openNoFollow(dirLink, nil); err == nil {
		_ = f.Close()
		t.Fatal("openNoFollow opened a symbolic link to a directory")
	}
}
