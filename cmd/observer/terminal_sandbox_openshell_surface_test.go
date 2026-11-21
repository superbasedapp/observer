//go:build !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestGatewayBindMountsDisclosureD3: the D3 wording per mode (decision
// OB-040): managed says Observer owns its private gateway's config and
// never touches yours; external says Observer never writes your gateway
// config and the opt-in is your own step.
func TestGatewayBindMountsDisclosureD3(t *testing.T) {
	managed := sandboxDisclosureText(sandboxbackend.DiscloseGatewayBindMounts, vocab.GatewayManagedLocal)
	if !strings.Contains(managed, "own private gateway only, whose config it owns") || !strings.Contains(managed, "never read or written") {
		t.Errorf("managed wording = %q", managed)
	}
	external := sandboxDisclosureText(sandboxbackend.DiscloseGatewayBindMounts, vocab.GatewayExternal)
	if !strings.Contains(external, "Observer never writes your gateway config") || !strings.Contains(external, "every sandbox it runs") {
		t.Errorf("external wording = %q", external)
	}
}

// TestOpenShellSurfaceModes: the probe reports the config's effective mode
// in the closed vocabulary, one case per row of the config's mode table,
// and always carries the D4 prerequisite.
func TestOpenShellSurfaceModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  config.TerminalSandboxOpenShellConfig
		want vocab.GatewayMode
	}{
		{"empty is managed", config.TerminalSandboxOpenShellConfig{}, vocab.GatewayManagedLocal},
		{"managed", config.TerminalSandboxOpenShellConfig{GatewayMode: "managed"}, vocab.GatewayManagedLocal},
		{"external", config.TerminalSandboxOpenShellConfig{GatewayMode: "external"}, vocab.GatewayExternal},
		{"empty with an endpoint is external", config.TerminalSandboxOpenShellConfig{Endpoint: "https://127.0.0.1:17670"}, vocab.GatewayExternal},
		{"external with an endpoint", config.TerminalSandboxOpenShellConfig{GatewayMode: "external", Endpoint: "https://127.0.0.1:17670"}, vocab.GatewayExternal},
		{"an invalid mode reports none", config.TerminalSandboxOpenShellConfig{GatewayMode: "shared"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := openShellSurface(sandboxselect.Probe{}, tc.cfg)
			if p.GatewayMode != tc.want {
				t.Fatalf("mode = %q, want %q", p.GatewayMode, tc.want)
			}
			if !strings.Contains(p.Prerequisite, "docker group, which is root-equivalent") || !strings.Contains(p.Prerequisite, "rootless Podman 5") {
				t.Fatalf("prerequisite = %q", p.Prerequisite)
			}
		})
	}
}

// TestOpenShellRowServesDisclosures: the backend list carries the row's
// three disclosures with the managed sentences by default.
func TestOpenShellRowServesDisclosures(t *testing.T) {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendOpenShell)
	got := sandboxDisclosuresFor(row, vocab.GatewayManagedLocal)
	if len(got) != len(row.Discloses) {
		t.Fatalf("disclosures = %+v", got)
	}
	for _, d := range got {
		if d.Text == "" {
			t.Errorf("%s has no sentence", d.ID)
		}
	}
}

// TestOpenShellFloorJudgesGatewayMode: under gateway_modes =
// [managed_local] the launch-time re-check refuses an external-mode node,
// naming the org setting, and lets a managed one through; with no floor
// either mode passes (lane O4, the node half of O4-L1's floor check).
func TestOpenShellFloorJudgesGatewayMode(t *testing.T) {
	cfg := sandboxOnCfg()
	cfg.Backends = []string{sandboxbackend.BackendOpenShell}
	cfg.Egress = string(vocab.TierProxyOnly)
	ext := config.TerminalSandboxOpenShellConfig{GatewayMode: config.OpenShellGatewayExternal}
	managed := config.TerminalSandboxOpenShellConfig{}
	if err := (&openShellDriver{r: &sandboxRuntime{}, cfg: ext}).floor(cfg); err != nil {
		t.Fatalf("no floor: %v", err)
	}
	publishFloorsForTest(t, `{"gateway_modes":["managed_local"],"floor_accepts_beta":true}`, true)
	err := (&openShellDriver{r: &sandboxRuntime{}, cfg: ext}).floor(cfg)
	if err == nil || !strings.Contains(err.Error(), "gateway_mode_not_allowed") || !strings.Contains(err.Error(), "Allowed sandbox gateway modes") {
		t.Fatalf("external under a managed-only floor: %v", err)
	}
	if err := (&openShellDriver{r: &sandboxRuntime{}, cfg: managed}).floor(cfg); err != nil {
		t.Fatalf("managed under a managed-only floor: %v", err)
	}
}

// TestOpenShellSurfaceServesVersionPins: the probe serves the tested
// versions as the pin picker's choices (audit finding O4-A6), so the
// dashboard never carries its own list.
func TestOpenShellSurfaceServesVersionPins(t *testing.T) {
	p := openShellSurface(sandboxselect.Probe{}, config.TerminalSandboxOpenShellConfig{})
	tested := sandboxopenshell.TestedVersions()
	if len(p.VersionPins) != len(tested) || len(tested) == 0 {
		t.Fatalf("pins = %q, tested = %d", p.VersionPins, len(tested))
	}
	for i, r := range tested {
		if p.VersionPins[i] != r.Version.String() {
			t.Errorf("pin %d = %q, want %q", i, p.VersionPins[i], r.Version.String())
		}
	}
}
