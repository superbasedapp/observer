package shellwrapsvc

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

func TestLookPathSkipsShims(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX executables")
	}
	root := t.TempDir()
	shims, real := filepath.Join(root, "shims"), filepath.Join(root, "real")
	writeFile(t, filepath.Join(shims, "sbotool"), "#!/bin/sh\n# "+shellwrap.ShimMarker+" v1 tool=x command=sbotool\n", 0o755)
	writeFile(t, filepath.Join(real, "sbotool"), "#!/bin/sh\necho real\n", 0o755)

	t.Setenv("PATH", shims+string(filepath.ListSeparator)+real)
	got, err := LookPath("sbotool")
	if err != nil || got != filepath.Join(real, "sbotool") {
		t.Fatalf("LookPath = %q, %v", got, err)
	}

	t.Setenv("PATH", shims)
	if got, err := LookPath("sbotool"); err == nil {
		t.Fatalf("only a shim on PATH must be not-found, got %q", got)
	}

	t.Setenv("PATH", real)
	if got, err := LookPath("sbotool"); err != nil || got != filepath.Join(real, "sbotool") {
		t.Fatalf("plain lookup = %q, %v", got, err)
	}
}
