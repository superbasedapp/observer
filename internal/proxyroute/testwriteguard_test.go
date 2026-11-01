package proxyroute

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/routeprov"
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

// TestWritersRefuseOutsideTempDir: inside a test binary every proxy-route
// write path refuses a non-temp path before it creates anything, and the
// same writes under t.TempDir() still work.
func TestWritersRefuseOutsideTempDir(t *testing.T) {
	outside := outsideTempRoot(t)
	writers := []struct {
		name  string
		write func(dir string) error
	}{
		{"writeClaudeSettings", func(dir string) error {
			return writeClaudeSettings(filepath.Join(dir, ".claude"), filepath.Join(dir, ".claude", "settings.json"),
				map[string]json.RawMessage{"env": json.RawMessage(`{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8820"}`)})
		}},
		{"writeFileKeepMode", func(dir string) error {
			return writeFileKeepMode(filepath.Join(dir, "config.toml"), []byte("model_provider = \"x\"\n"))
		}},
		{"saveProvenance", func(dir string) error {
			return saveProvenance(filepath.Join(dir, ".observer", "route_provenance.json"), routeprov.File{})
		}},
	}
	for _, w := range writers {
		t.Run(w.name, func(t *testing.T) {
			if err := w.write(outside); !errors.Is(err, testwriteguard.ErrRefused) {
				t.Errorf("write outside temp = %v, want testwriteguard.ErrRefused", err)
			}
			if _, err := os.Stat(outside); err == nil {
				_ = os.RemoveAll(outside)
				t.Fatalf("%s created %s", w.name, outside)
			}
			if err := w.write(t.TempDir()); err != nil {
				t.Errorf("write under t.TempDir() = %v", err)
			}
		})
	}
}

// TestRegistrarRefusesOutsideTempDir drives the public registrars with a
// pinned non-temp home: each refuses and nothing is created there.
func TestRegistrarRefusesOutsideTempDir(t *testing.T) {
	outside := outsideTempRoot(t)
	r, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: outside})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.RegisterClaudeCode(); !errors.Is(res.Error, testwriteguard.ErrRefused) {
		t.Errorf("RegisterClaudeCode outside temp: error = %v, want testwriteguard.ErrRefused", res.Error)
	}
	if _, err := os.Stat(outside); err == nil {
		_ = os.RemoveAll(outside)
		t.Fatalf("a registrar created %s", outside)
	}

	home := t.TempDir()
	ok, err := NewRegistrar(RegisterOptions{ProxyPort: 8820, HomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	if res := ok.RegisterClaudeCode(); res.Error != nil {
		t.Fatalf("RegisterClaudeCode under t.TempDir(): %v", res.Error)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Errorf("temp-home registration wrote nothing: %v", err)
	}
}
