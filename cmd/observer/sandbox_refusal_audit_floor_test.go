//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestRefusalAuditFloorReachesSelection (lane N4): the published floor
// reaches the selector's floors, is a qualifying floor (an unsandboxed
// terminal is not refused by it alone), and a drop by it names the org
// setting by its admin label.
func TestRefusalAuditFloorReachesSelection(t *testing.T) {
	spec, _, err := terminalsisolation.CompileBody([]byte(`{"require_refusal_audit":true}`), 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	f := sandboxFloorsFromSpec(spec, true)
	if !f.RequireRefusalAudit || !f.InForce() {
		t.Fatalf("floors %+v", f)
	}
	if f := sandboxFloorsFromSpec(spec, false); f.RequireRefusalAudit {
		t.Fatal("no spec in force still set the floor")
	}

	publishFloorsForTest(t, `{"require_refusal_audit":true}`, true)
	defer isolationFloorsClear()
	nf := newNodeFeaturesHandle()
	if ok, reason := nf.TerminalAllowed(false); !ok {
		t.Fatalf("require_refusal_audit alone refused an unsandboxed terminal: %s", reason)
	}

	row, _ := sandboxbackend.Get(sandboxbackend.BackendProcessLite)
	in := sandboxselect.Input{Floors: f}
	d, dropped := sandboxselect.FloorDrop(row, in, false)
	if !dropped || d.Verdict != sandboxselect.VerdictRefusalAuditRequired {
		t.Fatalf("process_lite under the floor: %+v %v", d, dropped)
	}
	if msg := isolationFloorMessage(d); !strings.Contains(msg, `"Require refusal audit"`) {
		t.Fatalf("the refusal does not name the floor: %s", msg)
	}
}

// TestBwrapRefusalAuditTiersMatchTheTierTable (audit finding N4-A1): the
// bwrap row audits a tier exactly when the tier table gives the run its own
// network namespace. A tier that starts the egress gateway (whose refusals
// reach the daemon) is audited; the shared-namespace host tier starts no
// gateway and is never audited; proxy_only and none leave no way out but
// the forwarded model proxy.
func TestBwrapRefusalAuditTiersMatchTheTierTable(t *testing.T) {
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	for _, tier := range row.Net.Egress {
		p, err := sandbox.ResolveEgress(string(tier))
		if err != nil {
			t.Fatalf("%s: %v", tier, err)
		}
		if got := row.Net.AuditsRefusalsOn(tier); got != p.UnshareNet {
			t.Errorf("%s: audited %v, but the tier's own namespace is %v", tier, got, p.UnshareNet)
		}
		if p.Gateway && !row.Net.AuditsRefusalsOn(tier) {
			t.Errorf("%s: the tier starts the gateway but is not audited", tier)
		}
	}
	if row.Net.AuditsRefusalsOn(vocab.TierHost) {
		t.Error("bwrap audits the host tier, which starts no gateway")
	}
}

// TestBwrapLaunchFloorByTierUnderRefusalAudit (F-015 R5, audit finding
// N4-R5): with require_refusal_audit published, the bwrap launch re-check
// (sandboxLocalFloor over the tier the run builds) refuses the host tier,
// naming the floor and the tier, and lets every tier with its own network
// namespace run. One case per tier the row offers.
func TestBwrapLaunchFloorByTierUnderRefusalAudit(t *testing.T) {
	// A host with no shipped row judges bwrap as beta (S4b), so the floor
	// also accepts beta there and the test judges the tier everywhere (the
	// TestLaunchFloorReadsEffectiveEgress pattern).
	body := `{"require_refusal_audit":true}`
	if !sandboxHostHasShippedRow() {
		body = `{"require_refusal_audit":true,"floor_accepts_beta":true}`
	}
	publishFloorsForTest(t, body, true)
	cfg := sandboxOnCfg()
	cases := []struct {
		tier    string
		refused bool
	}{
		{"host", true},
		{"internet", false},
		{"proxy_only", false},
		{"none", false},
	}
	row, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	if len(cases) != len(row.Net.Egress) {
		t.Fatalf("the cases cover %d tiers, the bwrap row offers %v", len(cases), row.Net.Egress)
	}
	for _, c := range cases {
		t.Run(c.tier, func(t *testing.T) {
			if !row.OffersTier(vocab.Tier(c.tier)) {
				t.Fatalf("the bwrap row does not offer %s", c.tier)
			}
			err := sandboxLocalFloor(launchFloorConfig(cfg, c.tier))
			if !c.refused {
				if err != nil {
					t.Fatalf("an audited tier was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("the host tier ran under require_refusal_audit")
			}
			msg := err.Error()
			for _, want := range []string{`"Require refusal audit"`, sandboxselect.VerdictRefusalAuditRequired, "the " + c.tier + " tier"} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal does not name %q: %s", want, msg)
				}
			}
		})
	}
}
