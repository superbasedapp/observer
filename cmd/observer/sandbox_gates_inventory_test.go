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

// sandboxGatesSettingsInventory is lane GATES-SBX's settings inventory: each
// key, its node home (the panel file that shows or edits it) and its admin
// home. The re-adoption keys and the MXC tier floor have a nodegov pin row
// since lane LEFT2-SBX (R-034); the wslc and hcs admin homes are still owed
// and recorded in docs/security.md SBX-BE-9. A wslc or hcs row names the
// panel's editable() call for the key, since the panel edits those values
// (dashboard CLI parity plan lane L3) rather than only showing them.
var sandboxGatesSettingsInventory = map[string]struct{ panel, field, admin string }{
	"readopt.bound_minutes":      {"SandboxCredentialsPanel.tsx", "bound_minutes", "pin: terminal.sandbox.readopt.bound_minutes (lowering only)"},
	"readopt.checkpoint_cap_mib": {"SandboxCredentialsPanel.tsx", "checkpoint_cap_mib", "pin: terminal.sandbox.readopt.checkpoint_cap_mib (lowering only)"},
	"windows.mxc_tier":           {"SandboxWindowsTiersPanel.tsx", "windows?.mxc_tier", "pin: terminal.sandbox.windows.mxc_tier (restrictive only)"},
	"wslc.path":                  {"SandboxWindowsTiersPanel.tsx", `editable("wslc.path")`, "owed: a machine path, a per-node override only"},
	"wslc.image":                 {"SandboxWindowsTiersPanel.tsx", `editable("wslc.image")`, "owed: a nodegov pin row (restrictive only)"},
	"hcs.utility_vm_image":       {"SandboxWindowsTiersPanel.tsx", `editable("hcs.utility_vm_image")`, "owed: a machine path, a per-node override only"},
}

// TestSandboxGatesSettingsInventory: every key of the lane's blocks has an
// inventory row whose panel names it, and every row names a real key.
func TestSandboxGatesSettingsInventory(t *testing.T) {
	blocks := map[string]any{
		"readopt": config.TerminalSandboxReadoptConfig{},
		"wslc":    config.TerminalSandboxWSLCConfig{},
		"hcs":     config.TerminalSandboxHCSConfig{},
		"windows": config.TerminalSandboxWindowsConfig{},
	}
	seen := map[string]bool{}
	for block, v := range blocks {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			key := block + "." + strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
			seen[key] = true
			row, ok := sandboxGatesSettingsInventory[key]
			if !ok {
				t.Errorf("%s has no inventory row", key)
				continue
			}
			b, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", row.panel))
			if err != nil || !strings.Contains(string(b), row.field) || row.admin == "" {
				t.Errorf("%s: %s does not show %s (%v)", key, row.panel, row.field, err)
			}
		}
	}
	for key := range sandboxGatesSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %s names no key", key)
		}
	}
}

// TestSandboxGatesPinRows (R-034): every inventory row whose admin home is a
// pin names a real nodegov pin row with that direction.
func TestSandboxGatesPinRows(t *testing.T) {
	rows := map[string]nodegov.PinnableKey{}
	for _, k := range nodegov.PinnableKeys {
		rows[k.Key] = k
	}
	for key, row := range sandboxGatesSettingsInventory {
		pin, ok := strings.CutPrefix(row.admin, "pin: ")
		if !ok {
			continue
		}
		name, dir, _ := strings.Cut(pin, " ")
		k, found := rows[name]
		if !found || name != "terminal.sandbox."+key {
			t.Errorf("%s names pin row %s, which nodegov lacks or which is not its key", key, name)
			continue
		}
		want := map[string]string{"(lowering only)": string(nodegov.DirLoweringOnly), "(restrictive only)": string(nodegov.DirRestrictiveOnly)}[dir]
		if string(k.Direction) != want {
			t.Errorf("%s: pin row direction %q, want %q", name, k.Direction, want)
		}
	}
}
