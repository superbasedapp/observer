//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// sandboxOpenShellSettingsInventory is the [terminal.sandbox.openshell]
// inventory (lane O1A). Every key is local-only in this release: rule W3 of
// the OpenShell plan adds no org rail, and each names this machine's own
// gateway or files. Its node home is the Settings card's OpenShell panel
// (SandboxOpenShellPanel.tsx, lane O4).
var sandboxOpenShellSettingsInventory = map[string]adminHome{
	"gateway_mode": {Local: "the developer's own choice of gateway; an org judges the mode through the terminals.isolation floor gateway_modes (lane O4) and never sets it"},
	"endpoint":     {Local: "a loopback address of this machine's own gateway; an org has no fleet-wide value for it"},
	"version":      {Local: "the developer's own pin of the OpenShell they installed; the tested-version table refuses every untested version anyway"},
	"state_dir":    {Local: "a machine path; an org has no fleet-wide value for it"},
}

// TestSandboxOpenShellSettingsInventory walks every
// [terminal.sandbox.openshell] key: each has a row, and no local-only key is
// a settings.pin row.
func TestSandboxOpenShellSettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxOpenShellPanel.tsx"))
	if err != nil {
		t.Fatalf("read the panel: %v", err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxOpenShellConfig{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		if key == "" || key == "-" {
			continue
		}
		seen[key] = true
		home, ok := sandboxOpenShellSettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox.openshell].%s has no inventory row", key)
			continue
		}
		if !strings.Contains(string(panel), `"`+key+`"`) {
			t.Errorf("[terminal.sandbox.openshell].%s has no node home in the OpenShell panel", key)
		}
		if home.Local == "" {
			t.Errorf("[terminal.sandbox.openshell].%s: every key is local-only in this release", key)
		}
		if nodegov.IsPinnableKey(sandboxPinPrefix + "openshell." + key) {
			t.Errorf("[terminal.sandbox.openshell].%s: a local-only key is a settings.pin row", key)
		}
	}
	for key := range sandboxOpenShellSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no [terminal.sandbox.openshell] key", key)
		}
	}
}
