//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSandboxModuleRootRemoval pins the sandbox module's own root-removal
// rule (plans decision log P-057, the SBX-P3A merge's F6 ruling): core
// componentstate keeps a removed module active while a selected child
// requires it, so `remove = ["terminals.sandbox"]` written before the
// terminals.sandbox.oci driver row existed would otherwise leave the sandbox
// on; the module's own resolution (sandboxModuleActive) switches it off, and
// so do its inert overlay and its driver selection. A block that adds the
// driver by name keeps the core answer.
func TestSandboxModuleRootRemoval(t *testing.T) {
	requireUnstampedBuild(t)
	cases := []struct {
		name string
		sec  config.ComponentsConfig
		want bool
	}{
		{"no block", config.ComponentsConfig{}, true},
		{"the root removed", config.ComponentsConfig{Remove: []string{sandboxComponent}}, false},
		{"the root and the driver removed", config.ComponentsConfig{Remove: []string{sandboxComponent, "terminals.sandbox.oci"}}, false},
		{"the driver added by name", config.ComponentsConfig{Add: []string{"terminals.sandbox.oci"}, Remove: []string{sandboxComponent}}, true},
		{"only the driver removed", config.ComponentsConfig{Remove: []string{"terminals.sandbox.oci"}}, true},
		{"terminals removed", config.ComponentsConfig{Remove: []string{"terminals", sandboxComponent, "terminals.sandbox.oci", "benchmark"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := componentstate.Resolve(tc.sec, fullNodeIDs())
			if got := sandboxModuleActive(snap); got != tc.want {
				t.Fatalf("sandboxModuleActive = %v, want %v (core ModuleActive %v, issues %v)", got, tc.want, snap.ModuleActive(sandboxComponent), snap.Issues)
			}
			cfg := config.Default()
			cfg.Terminal.Sandbox.Enabled = true
			if got := applyInertOverlay(cfg, snap).Terminal.Sandbox.Enabled; got != tc.want {
				t.Fatalf("inert overlay leaves the sandbox enabled = %v, want %v", got, tc.want)
			}
			if !tc.want && sandboxDriverSelected(snap, "terminals.sandbox.oci") {
				t.Fatal("a driver is selected while its module is removed")
			}
		})
	}
	// The core answer is unchanged: the removed root stays active in the
	// snapshot while its driver child is selected.
	core := componentstate.Resolve(config.ComponentsConfig{Remove: []string{sandboxComponent}}, fullNodeIDs())
	if !core.ModuleActive(sandboxComponent) {
		t.Log("the driver child is not selected in this build's base; the core keep-active case is not exercised here")
	}
}

// TestSandboxRootRemovalStatusAndConfig (SBX-P3A follow-up): with the module
// root removed, `observer components status` (and doctor, and start's
// warnings) say the module is off from the same sandboxModuleActive decision
// instead of core's "stays active because terminals.sandbox.oci requires
// it", and config.Load sets aside an invalid [terminal.sandbox] instead of
// failing, as it does for any inactive component.
func TestSandboxRootRemovalStatusAndConfig(t *testing.T) {
	requireUnstampedBuild(t)
	sel := config.ComponentsConfig{Remove: []string{sandboxComponent}}
	snap := componentstate.Resolve(sel, fullNodeIDs())
	if sandboxModuleActive(snap) {
		t.Fatal("the removed root is active")
	}
	issues := strings.Join(componentIssues(snap), ";")
	if strings.Contains(issues, "stays active because") && strings.Contains(issues, `"terminals.sandbox" stays active`) {
		t.Fatalf("status still says the removed root stays active: %s", issues)
	}
	if snap.ModuleActive(sandboxComponent) && !strings.Contains(issues, `"terminals.sandbox" switches the module off`) {
		t.Fatalf("status does not say the module is off: %s", issues)
	}
	v := componentStateView(snap)
	for _, r := range v.Components {
		if (r.ID == sandboxComponent || strings.HasPrefix(r.ID, sandboxComponent+".")) && r.State == components.StateActive {
			t.Errorf("status lists %s as active while the module is removed", r.ID)
		}
	}
	active := 0
	for _, r := range v.Components {
		if r.State == components.StateActive {
			active++
		}
	}
	if active != v.ActiveCount {
		t.Errorf("active count %d, rows say %d", v.ActiveCount, active)
	}
	var buf bytes.Buffer
	renderComponentState(&buf, v)
	if strings.Contains(buf.String(), `"terminals.sandbox" stays active`) {
		t.Fatalf("rendered status: %s", buf.String())
	}
	if !moduleRuleActive(snap, "core") {
		t.Fatal("the module rule switched off an unrelated component")
	}
	for _, id := range []string{sandboxComponent, "terminals.sandbox.oci"} {
		if moduleRuleActive(snap, id) {
			t.Errorf("%s is active under the module rule", id)
		}
	}

	// The driver added by name keeps the core answer, and the core line.
	keep := componentstate.Resolve(config.ComponentsConfig{Add: []string{"terminals.sandbox.oci"}, Remove: []string{sandboxComponent}}, fullNodeIDs())
	if !moduleRuleActive(keep, sandboxComponent) || len(componentIssues(keep)) != len(keep.Issues) {
		t.Fatalf("an added driver must keep the module and its issues: %v", componentIssues(keep))
	}

	// config.Load through the registered gate.
	load := func(body string) (config.Config, error) {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return config.Load(config.LoadOptions{GlobalPath: path, Env: func(string) string { return "" }, GovernanceSidecar: config.NoGovernanceSidecar})
	}
	const bad = "[terminal.sandbox]\nbackend = \"no-such-backend\"\nenabled = true\n"
	cfg, err := load("[components]\nremove = [\"terminals.sandbox\"]\n" + bad)
	if err != nil {
		t.Fatalf("an invalid [terminal.sandbox] of a removed module must not fail Load: %v", err)
	}
	if len(cfg.Inert) != 1 || !strings.Contains(cfg.Inert[0], "[terminal.sandbox]") {
		t.Fatalf("Inert = %q", cfg.Inert)
	}
	if cfg.Terminal.Sandbox.Enabled {
		t.Fatal("the set-aside section kept its values")
	}
	// The module active (no block): today's strict error.
	if _, err := load(bad); err == nil || !strings.Contains(err.Error(), "terminal.sandbox.backend") {
		t.Fatalf("an active module's bad section must fail Load: %v", err)
	}
}

// TestComponentsStatusFollowsTheDriverOptIn (live check InstaBox
// 2026-10-22, D1): with no [components] block the OCI driver is off by its
// opt-in rule, so `observer components status` and the active count say
// so; a block that adds it makes it active in both.
func TestComponentsStatusFollowsTheDriverOptIn(t *testing.T) {
	requireUnstampedBuild(t)
	const oci = "terminals.sandbox.oci"
	if _, ok := sandboxDriverRegs["oci-runc"]; !ok {
		t.Skip("the OCI driver is not in this build")
	}
	legacy := componentstate.Resolve(config.ComponentsConfig{}, fullNodeIDs())
	if sandboxDriverSelected(legacy, oci) || moduleRuleActive(legacy, oci) {
		t.Fatal("the OCI driver is active with no [components] block")
	}
	v := componentStateView(legacy)
	found := false
	for _, r := range v.Components {
		if r.ID == oci {
			found = true
			if r.State == components.StateActive || r.Because != componentOptInBecause {
				t.Fatalf("status row %+v", r)
			}
		}
	}
	if !found {
		t.Fatal("no status row for the OCI driver")
	}
	active := 0
	for _, r := range v.Components {
		if r.State == components.StateActive {
			active++
		}
	}
	if active != v.ActiveCount || v.ActiveCount >= v.CompiledCount {
		t.Fatalf("active count %d of %d, rows say %d", v.ActiveCount, v.CompiledCount, active)
	}
	var buf bytes.Buffer
	renderComponentState(&buf, v)
	if strings.Contains(buf.String(), "every component this build contains is active") {
		t.Fatalf("status claims every component is active: %s", buf.String())
	}
	added := componentstate.Resolve(config.ComponentsConfig{Add: []string{oci}}, fullNodeIDs())
	if !moduleRuleActive(added, oci) {
		t.Fatal("a block that adds the driver does not make it active")
	}
	for _, r := range componentStateView(added).Components {
		if r.ID == oci && r.State != components.StateActive {
			t.Fatalf("added driver row %+v", r)
		}
	}
}

// TestDashboardsWireTheComponentView (P-057 follow-up, lane SBX-P3B): both
// dashboards (`observer start` and `observer dashboard`) hand the Components
// page the same view `observer components status` prints, so the page follows
// the sandbox root removal instead of building its own view from core.
func TestDashboardsWireTheComponentView(t *testing.T) {
	for _, f := range []string{"start.go", "dashboard.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "ComponentStateView: componentStateView,") {
			t.Errorf("%s does not wire ComponentStateView to componentStateView", f)
		}
	}
}
