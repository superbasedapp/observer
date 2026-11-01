//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// TestSandboxPinPostureWire runs the registered evaluator through the
// accept gate's seam (nodegov.CheckPinPosture) against a node's own config:
// an individually safe pin set that would leave the node no backend is
// refused as a weaker auto class, an empty host intersection applies as "no
// host" (remote clone off, never wider), and a tightening passes.
func TestSandboxPinPostureWire(t *testing.T) {
	skipDriverOffHost(t, "bwrap")
	own := config.Default()
	own.Terminal.Sandbox.Enabled = true
	own.Terminal.Sandbox.Backends = []string{"bwrap"}
	own.Terminal.Sandbox.RemoteAllowedHosts = []string{"git.example"}
	own.Terminal.Sandbox.AllowRemoteClone = true
	own.Terminal.Sandbox.ExtraRWBinds = []string{"/srv"}
	if why := sandboxPinsNotApplicable(own); why != "" {
		t.Skipf("the sandbox module is not active in this test's config: %s", why)
	}
	prev := loadOwnSandboxConfig
	loadOwnSandboxConfig = func() (config.Config, error) { return own, nil }
	defer func() { loadOwnSandboxConfig = prev }()

	cases := []struct {
		name     string
		pins     map[string]any
		wantAxis string
	}{
		{"masks and an emptied rw bind list tighten", map[string]any{
			"terminal.sandbox.mask_paths": []string{"/mnt/c"}, "terminal.sandbox.extra_rw_binds": []string{},
		}, ""},
		{"a backends filter that keeps bwrap", map[string]any{"terminal.sandbox.backends": []string{"bwrap", "oci-runc"}}, ""},
		{"a backends filter removing every entry leaves no backend", map[string]any{"terminal.sandbox.backends": []string{"oci-runc"}}, sandboxselect.AxisAutoClass},
		{"a disjoint host list (empty intersection) allows no host", map[string]any{"terminal.sandbox.remote_allowed_hosts": []string{"evil.example"}}, ""},
		{"a shared host narrows", map[string]any{"terminal.sandbox.remote_allowed_hosts": []string{"git.example", "evil.example"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			axis, err := nodegov.CheckPinPosture(tc.pins)
			if axis != tc.wantAxis || (tc.wantAxis != "") != (err != nil) {
				t.Fatalf("axis %q err %v, want %q", axis, err, tc.wantAxis)
			}
		})
	}
}

// TestSandboxPinsNotApplicableKeepTheBody is SBX-P1B merge audit finding 3:
// on a default node (the sandbox off) a node.governance body with a backends
// pin without bwrap beside a guard pin and a share pin passes the accept
// gate's posture check (checkPolicyPosture), so the guard and share pins
// apply; the sandbox pins are recorded as not applicable.
func TestSandboxPinsNotApplicableKeepTheBody(t *testing.T) {
	own := config.Default()
	prev := loadOwnSandboxConfig
	loadOwnSandboxConfig = func() (config.Config, error) { return own, nil }
	defer func() { loadOwnSandboxConfig = prev }()
	if why := sandboxPinsNotApplicable(own); why == "" {
		t.Fatal("a default node reads the sandbox pins as applicable")
	}
	body := `{"schema":2,"pinned":{"terminal.sandbox.backends":["oci-runc"],"terminal.sandbox.mask_paths":["/mnt/c"],"guard.enabled":true},"share":{"routing_summary":true}}`
	spec, _, err := nodegov.CompileBody([]byte(body), 1<<16)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if axis, err := checkPolicyPosture(policyfam.FamilyNodeGovernance, spec); axis != "" || err != nil {
		t.Fatalf("a not-applicable sandbox pin refused the body: axis %q err %v", axis, err)
	}
	if v, ok := spec.Share["routing_summary"]; !ok || v != true {
		t.Fatalf("the share pin is not in the accepted body: %v", spec.Share)
	}
	after, out := config.ApplyGovernancePinsTo(own, nodegov.SpecPins(spec))
	if !after.Guard.Enabled {
		t.Fatalf("the guard pin did not apply: applied %v skipped %v", out.Applied, out.Skipped)
	}

	// The sandbox on is still not applicable while the module is inactive.
	on := config.Default()
	on.Terminal.Sandbox.Enabled = true
	if sandboxPinsNotApplicableRows[0].holds(on) && sandboxPinsNotApplicable(on) != sandboxPinsNotApplicableRows[0].reason {
		t.Fatalf("an inactive module is not the reason: %q", sandboxPinsNotApplicable(on))
	}
}

// TestSandboxPinKeysOwned: the module registered every [terminal.sandbox]
// pin row.
func TestSandboxPinKeysOwned(t *testing.T) {
	keys := sandboxPinKeys()
	if len(keys) < 13 {
		t.Fatalf("only %d sandbox pin keys: %v", len(keys), keys)
	}
	found := false
	for _, o := range nodegov.PinPostureOwners() {
		found = found || o == sandboxPinOwner
	}
	if !found {
		t.Fatal("the sandbox module did not register its pin posture evaluator")
	}
	_ = sandboxselect.PostureAxes
}

// TestSandboxLaunchRefusedNamingEmptiedBackendPin is SBX-P1B merge audit
// finding 2 at the launch: an organization backends pin that left no backend
// (the overlay's PinnedNoBackend) enables nothing, and a sandboxed launch is
// refused naming the pin, never run on the developer's own list.
func TestSandboxLaunchRefusedNamingEmptiedBackendPin(t *testing.T) {
	cfg := config.Default().Terminal.Sandbox
	cfg.Enabled = true
	cfg.Backends = []string{"bwrap"}
	cfg.PinnedNoBackend = "terminal.sandbox.backends"
	if got := sandboxEnabledBackends(cfg); len(got) != 0 {
		t.Fatalf("an emptied pin still enables %v", got)
	}
	err := sandboxLocalFloor(cfg)
	if err == nil || !strings.Contains(err.Error(), "terminal.sandbox.backends") {
		t.Fatalf("the launch was not refused naming the pin: %v", err)
	}
}

// TestSandboxCannotRunRefusal is SBX-P1B merge audit finding 4 on the node: a
// machine that must run terminals sandboxed and cannot run a sandbox is
// refused with a reason naming the org setting and why, not the generic
// "retry with sandbox enabled"; a machine that can run one keeps the generic
// reason; a sandboxed request is unaffected.
func TestSandboxCannotRunRefusal(t *testing.T) {
	nf := newNodeFeaturesHandle()
	nf.recordApplied(3, "bh", nodefeatures.PolicySpec{
		Terminals: nodefeatures.TerminalsRule{FeatureRule: nodefeatures.FeatureRule{Governed: true, Enabled: true}, SandboxRequired: true},
	})
	prev := sandboxCannotRunHere
	defer func() { sandboxCannotRunHere = prev }()

	sandboxCannotRunHere = func() string { return "the Sandboxes and VMs module is not active (blocked or deactivated)" }
	ok, why := nf.TerminalAllowed(false)
	if ok || !strings.Contains(why, "cannot run a sandbox") || !strings.Contains(why, "isolation floor") ||
		!strings.Contains(why, "module is not active") {
		t.Fatalf("a machine that cannot sandbox: %v %q", ok, why)
	}
	if ok, _ := nf.TerminalAllowed(true); !ok {
		t.Fatal("a sandboxed request was refused")
	}

	sandboxCannotRunHere = func() string { return "" }
	if ok, why := nf.TerminalAllowed(false); ok || strings.Contains(why, "cannot run a sandbox") || !strings.Contains(why, "retry with sandbox enabled") {
		t.Fatalf("a machine that can sandbox: %v %q", ok, why)
	}

	if why := sandboxCannotRunReason(config.Default(), sandboxbackend.HostMacOS); !strings.Contains(why, "no sandbox backend") &&
		!strings.Contains(why, "module is not active") {
		t.Fatalf("macOS: %q", why)
	}
}

// TestLaunchFloorReadsEffectiveEgress: the launch re-check judges the floors
// against the egress tier the run builds, not the configured one.
func TestLaunchFloorReadsEffectiveEgress(t *testing.T) {
	// On a host with no shipped row (native Windows: mxc-process is beta)
	// only a floor that accepts beta can be met at all, which the product
	// enforces (beta_below_floor); the floor then also accepts beta, so the
	// test judges the egress tier everywhere (Windows 11 Pro rerun
	// 2026-10-25: the met floor was refused for the beta rule, a test
	// assumption, not a product fault).
	floors := `{"min_egress":"proxy_only"}`
	if !sandboxHostHasShippedRow() {
		floors = `{"min_egress":"proxy_only","floor_accepts_beta":true}`
	}
	publishFloorsForTest(t, floors, true)
	cfg := config.Default().Terminal.Sandbox
	cfg.Enabled = true
	cfg.Egress = "proxy_only"
	if err := sandboxLocalFloor(launchFloorConfig(cfg, "proxy_only")); err != nil {
		t.Fatalf("a met floor refused: %v", err)
	}
	err := sandboxLocalFloor(launchFloorConfig(cfg, "internet"))
	if err == nil || !strings.Contains(err.Error(), `"Minimum network tier"`) {
		t.Fatalf("the configured tier was read instead of the built one: %v", err)
	}
}

// TestLiveCapabilitiesFollowModuleActive: a node whose [components] leaves
// the sandbox module inactive advertises none of the terminals.isolation
// tokens, so a floor needing them NACKs there.
func TestLiveCapabilitiesFollowModuleActive(t *testing.T) {
	toks := terminalsisolation.LiveCapabilities()
	if len(toks) == 0 {
		t.Skip("the family advertises no live token in this build")
	}
	has := func(caps []string, tok string) bool {
		for _, c := range caps {
			if c == tok {
				return true
			}
		}
		return false
	}
	all := nodeLiveCapabilitiesFor(nil, nil)
	off := nodeLiveCapabilitiesFor(nil, func(id string) bool { return id != sandboxComponent })
	for _, tok := range toks {
		if !has(all, tok) {
			t.Errorf("%s not advertised with the module active", tok)
		}
		if has(off, tok) {
			t.Errorf("%s advertised with the module inactive", tok)
		}
	}
}

// sandboxHostHasShippedRow reports whether an offered, shipped backend row
// runs on this host.
func sandboxHostHasShippedRow() bool {
	host := sandboxHostKind()
	for _, row := range sandboxbackend.Offered() {
		if row.RunsOn(host) && row.Maturity == sandboxbackend.MaturityShipped {
			return true
		}
	}
	return false
}
