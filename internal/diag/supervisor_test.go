package diag

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/supervisor"
)

// TestCheckSupervisor: no maintained routes is OK; maintained routes with a
// supervisor template installed is OK; maintained routes with none is a
// warning that points at the templates. Doctor's own environment never
// counts.
func TestCheckSupervisor(t *testing.T) {
	home := t.TempDir()
	none := supervisor.Probe{GOOS: "linux", Exists: func(string) bool { return false }, Getenv: func(string) string { return "set" }}
	if c := checkSupervisor(home, none); c.Status != StatusOK {
		t.Fatalf("no maintained routes: %+v", c)
	}
	dir := filepath.Join(home, ".observer")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	rec := `{"version":1,"records":[{"tool":"claude-code","config_path":"x","value":"http://127.0.0.1:8820","writer":"managed","written_at":"2026-10-18T00:00:00Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, proxyroute.ProvenanceFileName), []byte(rec), 0o600); err != nil {
		t.Fatal(err)
	}
	if !proxyroute.ManagedRoutesMaintained(home) {
		t.Fatal("fixture is not read as maintained routes")
	}
	if c := checkSupervisor(home, none); c.Status != StatusWarn || len(c.Details) != 2 {
		t.Fatalf("maintained, no supervisor (env must not count): %+v", c)
	}
	unit := filepath.Join(home, ".config", "systemd", "user", supervisor.SystemdUnit)
	installed := supervisor.Probe{GOOS: "linux", Exists: func(p string) bool { return p == unit }}
	if c := checkSupervisor(home, installed); c.Status != StatusOK {
		t.Fatalf("maintained, unit installed: %+v", c)
	}
}
