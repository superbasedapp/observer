package agentlaunch

import (
	"strings"
	"testing"
)

// TestLoopbackExposureRows: one case per row of the exposure table, plus
// the rows that must not gate (a box with its own network namespace, an
// unsandboxed run).
func TestLoopbackExposureRows(t *testing.T) {
	cases := []struct {
		name string
		run  BoxRun
		rule string // "" = not exposed
	}{
		{"X1 unsandboxed run", BoxRun{RunID: "r", Class: "none", Tier: "host"}, ""},
		{"X1 unrecorded run", BoxRun{RunID: "r"}, ""},
		{"X2 landlock denies Observer's ports", BoxRun{RunID: "r", Class: "process", Backend: "process_lite", Tier: "host", DeniesObserverPorts: true}, ""},
		{"X3 bwrap host tier", BoxRun{RunID: "r", Class: "process", Backend: "bwrap", Tier: "host"}, "X3-host-tier"},
		{"X4 mxc process container", BoxRun{RunID: "r", Class: "process", Backend: "mxc-process", Tier: "proxy_only", HostLoopbackRelay: true}, "X4-host-loopback-relay"},
		{"X4 mxc appcontainer", BoxRun{RunID: "r", Class: "process", Backend: "mxc-appcontainer", Tier: "none", HostLoopbackRelay: true}, "X4-host-loopback-relay"},
		{"bwrap internet tier: own netns", BoxRun{RunID: "r", Class: "process", Backend: "bwrap", Tier: "internet"}, ""},
		{"oci container", BoxRun{RunID: "r", Class: "container", Backend: "oci-runc", Tier: "proxy_only"}, ""},
		{"seatbelt", BoxRun{RunID: "r", Class: "process", Backend: "seatbelt", Tier: "internet"}, ""},
		{"unknown backend, isolated tier", BoxRun{RunID: "r", Class: "process", Backend: "nope", Tier: "none"}, ""},
		// The OpenShell rows (fold audit L2, lane FX5): neither offers the
		// host tier nor rides host loopback (the registry side is pinned in
		// cmd/observer, TestOpenShellRowsAreNotLoopbackExposed), so no row
		// decides for them on any tier they offer. The local row's box runs
		// on this machine's engine; the org row's on the org's machines.
		{"openshell internet", BoxRun{RunID: "r", Class: "container", Backend: "openshell", Tier: "internet"}, ""},
		{"openshell proxy_only", BoxRun{RunID: "r", Class: "container", Backend: "openshell", Tier: "proxy_only"}, ""},
		{"openshell none", BoxRun{RunID: "r", Class: "container", Backend: "openshell", Tier: "none"}, ""},
		{"openshell-org internet", BoxRun{RunID: "r", Class: "container", Backend: "openshell-org", Tier: "internet"}, ""},
		{"openshell-org proxy_only", BoxRun{RunID: "r", Class: "container", Backend: "openshell-org", Tier: "proxy_only"}, ""},
		{"openshell-org none", BoxRun{RunID: "r", Class: "container", Backend: "openshell-org", Tier: "none"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := LoopbackExposure([]BoxRun{tc.run})
			if tc.rule == "" {
				if ok {
					t.Fatalf("exposed by %s, want not exposed", e.Rule)
				}
				return
			}
			if !ok || e.Rule != tc.rule || e.Run.RunID != "r" {
				t.Fatalf("exposure = %+v %v, want rule %s", e, ok, tc.rule)
			}
			if !strings.Contains(e.Reason(), "observer launch") || !strings.Contains(e.Reason(), "LAUNCH-1") {
				t.Fatalf("reason %q does not name the way out", e.Reason())
			}
		})
	}
}

// TestLoopbackExposureFirstExposedRun: an isolated run before an exposed
// one does not hide it.
func TestLoopbackExposureFirstExposedRun(t *testing.T) {
	e, ok := LoopbackExposure([]BoxRun{
		{RunID: "safe", Class: "process", Backend: "bwrap", Tier: "internet"},
		{RunID: "open", Class: "process", Backend: "bwrap", Tier: "host"},
	})
	if !ok || e.Run.RunID != "open" {
		t.Fatalf("got %+v %v", e, ok)
	}
	if _, ok := LoopbackExposure(nil); ok {
		t.Fatal("no runs, exposed")
	}
}
