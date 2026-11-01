//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// publishFloorsForTest installs a compiled terminals.isolation body through
// the same dispatch the poller uses and clears it at the end of the test.
func publishFloorsForTest(t *testing.T, body string, enforce bool) {
	t.Helper()
	spec, _, err := terminalsisolation.CompileBody([]byte(body), 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	inert := ""
	if !enforce {
		inert = "not_preauthorized"
	}
	isolationFloorsPublish(orgclient.PolicyResourceResult{
		Status: orgclient.PRApplied, Family: policyfam.FamilyTerminalsIsolation, Version: 3,
		BodyHash: "h", EnforceAllowed: enforce, InertReason: inert, Spec: spec,
	})
	t.Cleanup(isolationFloorsClear)
}

func sandboxOnCfg() config.TerminalSandboxConfig {
	cfg := config.Default().Terminal.Sandbox
	cfg.Enabled = true
	return cfg
}

// TestIsolationFloorsFeedSelection: accepted floors reach sandboxselect.Floors
// on both the probe list and the launch-time check; a floor bwrap cannot meet
// refuses naming the org setting; no floor, or an inert body, changes nothing.
func TestIsolationFloorsFeedSelection(t *testing.T) {
	skipDriverOffHost(t, "bwrap")
	cfg := sandboxOnCfg()
	av := sandbox.Availability{Available: true, Verdict: sandboxselect.VerdictAvailable, BackendVersion: "0.8.0"}

	if f := sandboxOrgFloors(); f.InForce() {
		t.Fatalf("floors in force with no body: %+v", f)
	}
	if err := sandboxLocalFloor(cfg); err != nil && strings.Contains(err.Error(), "organization") {
		t.Fatalf("no body yet refused by the org: %v", err)
	}

	publishFloorsForTest(t, `{"min_isolation":"container"}`, false)
	if f := sandboxOrgFloors(); f.InForce() {
		t.Fatal("an inert (not preauthorized) body applied floors")
	}

	publishFloorsForTest(t, `{"min_isolation":"container"}`, true)
	in := sandboxSelectInput(cfg, av, []string{"live"}, sandboxbackend.BackendBwrap, vocab.TierInternet)
	if in.Floors.OrgMinClass != vocab.ClassContainer {
		t.Fatalf("floors not fed: %+v", in.Floors)
	}
	var bw dashapi.SandboxBackendAvail
	for _, b := range sandboxBackendList(cfg, av, []string{"live"}, vocab.TierInternet) {
		if b.ID == sandboxbackend.BackendBwrap {
			bw = b
		}
	}
	if bw.Available || bw.Verdict != sandboxselect.VerdictBelowOrgFloor {
		t.Fatalf("bwrap row under a container floor: %+v", bw)
	}
	legacy := reconcileLegacyProbe(av, []dashapi.SandboxBackendAvail{bw})
	if legacy.Available {
		t.Fatal("the legacy probe fields still offer a sandbox the floor refuses")
	}
	err := sandboxLocalFloor(cfg)
	if err == nil || !strings.Contains(err.Error(), `"Minimum isolation"`) || !errors.Is(err, dashapi.ErrLaunchSandboxRequired) {
		t.Fatalf("launch under an unmet floor: %v", err)
	}

	publishFloorsForTest(t, `{"min_isolation":"process","min_egress":"proxy_only"}`, true)
	cfg.Egress = "internet"
	if err := sandboxLocalFloor(cfg); err == nil || !strings.Contains(err.Error(), `"Minimum network tier"`) {
		t.Fatalf("internet tier under a proxy_only floor: %v", err)
	}
	cfg.Egress = "proxy_only"
	if err := sandboxLocalFloor(cfg); err != nil {
		t.Fatalf("a met floor refused: %v", err)
	}
}

// TestIsolationFloorsImplySandboxRequired: min_isolation, allowed_backends and
// min_egress refuse an unsandboxed terminal naming the floor; the qualifying
// floors alone do not; a sandboxed request is never refused here.
func TestIsolationFloorsImplySandboxRequired(t *testing.T) {
	nf := newNodeFeaturesHandle()
	if ok, _ := nf.TerminalAllowed(false); !ok {
		t.Fatal("no floor refused an unsandboxed terminal")
	}
	cases := []struct {
		body  string
		allow bool
		label string
	}{
		{`{"min_isolation":"process"}`, false, "Minimum isolation"},
		{`{"allowed_backends":["bwrap"]}`, false, "Allowed sandbox backends"},
		{`{"min_egress":"internet"}`, false, "Minimum network tier"},
		{`{"require_full_capture":true}`, true, ""},
	}
	for _, tc := range cases {
		publishFloorsForTest(t, tc.body, true)
		ok, reason := nf.TerminalAllowed(false)
		if ok != tc.allow || (tc.label != "" && !strings.Contains(reason, tc.label)) {
			t.Errorf("%s: allowed %v reason %q", tc.body, ok, reason)
		}
		if ok, _ := nf.TerminalAllowed(true); !ok {
			t.Errorf("%s: a sandboxed request was refused", tc.body)
		}
		isolationFloorsClear()
	}
}

// TestIsolationFloorsPointReader: the policy-state row is enum-only and
// reads off / enforce / observe from the holder.
func TestIsolationFloorsPointReader(t *testing.T) {
	now := func() time.Time { return time.Unix(1, 0) }
	read := newIsolationFloorsPointReader(nil, now)
	f, _ := read(context.Background())
	if f.HasOrgRail || f.EnforceMode != "off" {
		t.Fatalf("no body: %+v", f)
	}
	publishFloorsForTest(t, `{"min_isolation":"process"}`, true)
	f, _ = read(context.Background())
	if !f.HasOrgRail || f.EnforceMode != "enforce" || f.RunningVersion != 3 {
		t.Fatalf("applied: %+v", f)
	}
	publishFloorsForTest(t, `{"min_isolation":"process"}`, false)
	f, _ = read(context.Background())
	if f.EnforceMode != "observe" || f.InertReason == "" {
		t.Fatalf("inert: %+v", f)
	}
}

// TestManagedBackfillOffersTerminalsIsolation: the family's compiler is
// linked and the write hold is released (plans decision P-047): the managed
// write offers it, into the module keys a released binary ignores
// (org_managed_hold_test.go), never into accept_families.
func TestManagedBackfillOffersTerminalsIsolation(t *testing.T) {
	if !policyfam.IsFamilyLinked(policyfam.FamilyTerminalsIsolation) {
		t.Fatal("terminals.isolation must be linked in a build with the sandbox module")
	}
	got := linkedManagedFamilies([]string{policyfam.FamilyNodeFeatures, policyfam.FamilyTerminalsIsolation})
	if len(got) != 2 || got[1] != policyfam.FamilyTerminalsIsolation {
		t.Fatalf("linkedManagedFamilies = %v, want node.features and terminals.isolation", got)
	}
	if lines := managedPolicyKeyLinesText(got); strings.Contains(lines, `accept_families = ["node.features", "terminals.isolation"]`) || !strings.Contains(lines, `accept_module_families = ["terminals.isolation"]`) {
		t.Fatalf("terminals.isolation must go to the module keys: %s", lines)
	}
}

// TestSandboxOrgView: the probe API's org view lists the floors in force by
// their admin label, and is absent when the organization sets nothing.
func TestSandboxOrgView(t *testing.T) {
	prev := daemonConfigPath()
	setDaemonConfigPath(t.TempDir() + "/config.toml")
	defer setDaemonConfigPath(prev)
	if v := sandboxOrgView(); v != nil {
		t.Fatalf("org view with nothing set: %+v", v)
	}
	publishFloorsForTest(t, `{"min_isolation":"container","allowed_backends":["bwrap"]}`, true)
	v := sandboxOrgView()
	if v == nil || len(v.Floors) != 2 || v.Floors[0].Label != "Minimum isolation" || v.Floors[0].Value != "container" {
		t.Fatalf("org view: %+v", v)
	}
}
