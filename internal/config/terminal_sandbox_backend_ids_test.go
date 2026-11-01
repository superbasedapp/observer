package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// TestEveryRegistryBackendIDLoads (Linux live check 2026-10-23, LIN-1 F1):
// every id of the backend registry loads as a [terminal.sandbox].backends
// entry through the real loader (process_lite's underscore included); as
// the bwrap-only backend key, bwrap loads and any other id is refused with
// a reason that names the backends key to use instead. A malformed id is
// still refused, so the rule is in force.
func TestEveryRegistryBackendIDLoads(t *testing.T) {
	load := func(t *testing.T, key, value string) error {
		t.Helper()
		body := "[terminal.sandbox]" + "\n" + key + " = " + value + "\n"
		_, err := Load(LoadOptions{GlobalPath: govTempConfig(t, t.TempDir(), body), Env: noEnv})
		return err
	}
	ids := sandboxbackend.IDs()
	if len(ids) == 0 {
		t.Fatal("the registry lists no backend")
	}
	for _, id := range ids {
		if err := load(t, "backends", `["`+id+`"]`); err != nil {
			t.Errorf("backends = [%q]: %v", id, err)
		}
		err := load(t, "backend", `"`+id+`"`)
		switch {
		case id == sandboxbackend.BackendBwrap:
			if err != nil {
				t.Errorf("backend = %q: %v", id, err)
			}
		case err == nil:
			t.Errorf("backend = %q loaded; the key is bwrap-only", id)
		case !strings.Contains(err.Error(), "terminal.sandbox.backends"):
			t.Errorf("backend = %q: the refusal does not name the backends key: %v", id, err)
		}
	}
	if err := load(t, "backends", `["oci.runc"]`); err == nil {
		t.Fatal("a malformed backend id loaded")
	}
}

// TestLoadUnreadableConfigIsAReadError (LIN-1 F3): a config file that exists
// but cannot be read loads as a *ReadError naming its path, with the
// loader's usual message; a missing file still loads the defaults.
func TestLoadUnreadableConfigIsAReadError(t *testing.T) {
	dir := t.TempDir() // reading a directory fails
	_, err := Load(LoadOptions{GlobalPath: dir, Env: noEnv})
	var re *ReadError
	if !errors.As(err, &re) || re.Path != dir || !strings.HasPrefix(err.Error(), "config.Load: read "+dir+": ") {
		t.Fatalf("Load(dir) = %v", err)
	}
	if _, err := Load(LoadOptions{GlobalPath: filepath.Join(dir, "missing.toml"), Env: noEnv}); err != nil {
		t.Fatalf("a missing config: %v", err)
	}
}
