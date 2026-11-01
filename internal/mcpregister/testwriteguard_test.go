package mcpregister

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// outsideTempRoot is a path outside the OS temp directory that no test may
// create (incident 2026-10-21).
func outsideTempRoot(t *testing.T) string {
	t.Helper()
	p := filepath.Join(filepath.VolumeName(os.TempDir())+string(os.PathSeparator), "observer-test-write-guard-never-created")
	if _, err := os.Stat(p); err == nil {
		t.Skipf("%s exists; refusing to run", p)
	}
	// The refusals the caller provokes on purpose are taken off
	// testwriteguard's package-level record, so testwriteguard.Run (TestMain)
	// still fails on any unexpected one.
	t.Cleanup(func() {
		for _, v := range testwriteguard.TakeViolationsForTest() {
			if !strings.HasPrefix(v, p) {
				t.Errorf("unexpected refused write %s", v)
			}
		}
	})
	return p
}

// TestWritersRefuseOutsideTempDir: inside a test binary the MCP writers'
// two file chokepoints (write and remove) refuse a non-temp path before
// they create anything, and work under t.TempDir().
func TestWritersRefuseOutsideTempDir(t *testing.T) {
	outside := outsideTempRoot(t)
	ops := []struct {
		name string
		do   func(path string) error
	}{
		{"writeFileSync", func(path string) error { return writeFileSync(path, []byte("{}\n"), 0o600, 0o755) }},
		{"writeCredentialMCPFile", func(path string) error { return writeCredentialMCPFile(path, []byte("{}\n")) }},
		{"removeConfigFile", func(path string) error { return removeConfigFile(path, []byte("{}\n")) }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			if err := op.do(filepath.Join(outside, ".claude.json")); !errors.Is(err, testwriteguard.ErrRefused) {
				t.Errorf("outside temp: error = %v, want testwriteguard.ErrRefused", err)
			}
			if _, err := os.Stat(outside); err == nil {
				_ = os.RemoveAll(outside)
				t.Fatalf("%s created %s", op.name, outside)
			}
			path := filepath.Join(t.TempDir(), "sub", ".claude.json")
			if op.name == "removeConfigFile" {
				if err := writeFileSync(path, []byte("{}\n"), 0o600, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := op.do(path); err != nil {
				t.Errorf("under t.TempDir(): %v", err)
			}
		})
	}
}

// TestRegistrarRefusesOutsideTempDir drives Register/Unregister with a
// pinned non-temp home: every target that reaches a write is refused and
// nothing is created there.
func TestRegistrarRefusesOutsideTempDir(t *testing.T) {
	outside := outsideTempRoot(t)
	r, err := NewRegistrar(RegisterOptions{BinaryPath: "/opt/observer/bin/observer", HomeDir: outside, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	refused := 0
	for _, tool := range []string{"claude-code", "cursor", "codex", "opencode"} {
		res := r.Register(tool)
		if res.Skipped {
			continue
		}
		if !errors.Is(res.Error, testwriteguard.ErrRefused) {
			t.Errorf("Register(%s) outside temp: error = %v, want testwriteguard.ErrRefused", tool, res.Error)
			continue
		}
		refused++
	}
	if refused == 0 {
		t.Error("no MCP target reached the write guard")
	}
	if _, err := os.Stat(outside); err == nil {
		_ = os.RemoveAll(outside)
		t.Fatalf("a registrar created %s", outside)
	}
}
