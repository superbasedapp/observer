package host

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

func TestInspect(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	file := filepath.Join(dir, "tool")
	if err := os.WriteFile(file, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	realFile, _ := filepath.EvalSymlinks(file)
	facts, err := Inspect(file)
	if err != nil || !facts.Exists || facts.Symlink || !facts.Regular || facts.Real != realFile {
		t.Fatalf("regular file: %+v %v", facts, err)
	}
	if facts, err := Inspect(filepath.Join(dir, "missing")); err != nil || facts.Exists {
		t.Fatalf("missing: %+v %v", facts, err)
	}
	if facts, err := Inspect(dir); err != nil || !facts.Exists || facts.Regular {
		t.Fatalf("directory: %+v %v", facts, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if facts, err := Inspect(link); err != nil || !facts.Symlink || !facts.Regular || facts.Real != realFile {
		t.Fatalf("symlink: %+v %v", facts, err)
	}
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	if facts, err := Inspect(dangling); err != nil || !facts.Exists || !facts.Symlink || facts.Regular || facts.Real != "" {
		t.Fatalf("dangling: %+v %v", facts, err)
	}
}

func TestHashFile(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(file)
	// SHA-256("abc").
	if err != nil || got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("HashFile = %q %v", got, err)
	}
	if _, err := HashFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("hashing a missing file did not fail")
	}
}

func TestPlatformNamesEveryCap(t *testing.T) {
	t.Parallel()
	p := NewExecutor().Platform()
	if p.GOOS != runtime.GOOS {
		t.Fatalf("GOOS %q", p.GOOS)
	}
	for _, c := range []extrun.Cap{extrun.CapWall, extrun.CapStdout, extrun.CapStderr} {
		if p.Caps[c] == "" {
			t.Errorf("wall and output caps must be held on every OS; %s is not", c)
		}
	}
}
