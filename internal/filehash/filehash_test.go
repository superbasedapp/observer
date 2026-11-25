package filehash

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestSHA256: the digest of known bytes, of an empty file, and an
// unwrapped not-exist error for a missing file.
func TestSHA256(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body, want string
	}{
		{"abc", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	for _, tc := range cases {
		p := filepath.Join(dir, tc.name)
		if err := os.WriteFile(p, []byte(tc.body), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := SHA256(p)
		if err != nil || got != tc.want {
			t.Errorf("%s: SHA256 = %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	_, err := SHA256(filepath.Join(dir, "missing"))
	var pe *fs.PathError
	if !errors.As(err, &pe) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: err = %v, want an unwrapped *fs.PathError for ErrNotExist", err)
	}
}
