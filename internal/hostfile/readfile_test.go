package hostfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// TestReadFileKeepsModeAndNotExist (FU-178): the no-follow read keeps the
// file's own permission bits and still answers a missing file as a new one
// (0600, not existing, no error).
func TestReadFileKeepsModeAndNotExist(t *testing.T) {
	dir := t.TempDir()
	b, mode, exists, err := readFile(filepath.Join(dir, "absent.json"))
	if err != nil || exists || b != nil || mode != 0o600 {
		t.Fatalf("missing file = %q, %o, %v, %v; want nil, 600, false, nil", b, mode, exists, err)
	}
	p := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(p, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	b, mode, exists, err = readFile(p)
	if err != nil || !exists || string(b) != "{}\n" {
		t.Fatalf("regular file = %q, %v, %v", b, exists, err)
	}
	if runtime.GOOS != "windows" && mode != 0o640 {
		t.Errorf("mode = %o, want 640", mode)
	}
}

// TestReadFileRefusesALinkAtThePath (FU-178): a symbolic link at the file's
// path is refused as ErrLink and its target is never read.
func TestReadFileRefusesALinkAtThePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.json")
	if err := os.WriteFile(target, []byte(`{"secret":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "settings.json")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	b, _, exists, err := readFile(p)
	if !errors.Is(err, ErrLink) || b != nil || exists {
		t.Fatalf("link at the path = %q, %v, %v; want ErrLink and nothing read", b, exists, err)
	}
}

// TestReadFileRefusesAFIFO (FU-178): a FIFO at the path is refused without
// blocking on a writer.
func TestReadFileRefusesAFIFO(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if err := mkfifo(p); err != nil {
		t.Skipf("no FIFO on this OS: %v", err)
	}
	b, _, exists, err := readFile(p)
	if !errors.Is(err, regularfile.ErrNotRegular) || b != nil || exists {
		t.Fatalf("FIFO at the path = %q, %v, %v; want a not-regular refusal", b, exists, err)
	}
}
