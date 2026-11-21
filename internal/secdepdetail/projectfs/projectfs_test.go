package projectfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secdepdetail"
)

func TestRead(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "big.lock"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		rel  string
		max  int64
		want error
		body string
	}{
		{"inside", "go.sum", 100, nil, "abc"},
		{"empty rel", "", 100, secdepdetail.ErrOutsideProject, ""},
		{"dotdot", "../x", 100, secdepdetail.ErrOutsideProject, ""},
		{"nested dotdot", "a/../../x", 100, secdepdetail.ErrOutsideProject, ""},
		{"absolute", filepath.Join(outside, "secret"), 100, secdepdetail.ErrOutsideProject, ""},
		{"slash rooted", "/etc/passwd", 100, secdepdetail.ErrOutsideProject, ""},
		{"too large", "big.lock", 5, secdepdetail.ErrFileTooLarge, ""},
	}
	for _, tc := range cases {
		b, err := Read(root, tc.rel, tc.max)
		if tc.want != nil {
			if !errors.Is(err, tc.want) {
				t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
			}
			continue
		}
		if err != nil || string(b) != tc.body {
			t.Errorf("%s: %q, %v", tc.name, b, err)
		}
	}
	if _, err := Read(root, "missing.lock", 100); err == nil || errors.Is(err, secdepdetail.ErrOutsideProject) {
		t.Errorf("missing file: %v, want an unreadable error", err)
	}
	if _, err := Read(root, ".", 100); err == nil {
		t.Error("a directory was read")
	}
	// A symlink escaping the root (skipped where symlinks are unavailable).
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link.lock")); err == nil {
		if _, err := Read(root, "link.lock", 100); !errors.Is(err, secdepdetail.ErrOutsideProject) {
			t.Errorf("symlink escape: %v", err)
		}
	}
}
