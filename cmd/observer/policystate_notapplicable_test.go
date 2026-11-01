package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// gen8RejectingPoster models a gen7 server: it 400s a report carrying the
// gen8 not_applicable list.
type gen8RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen8RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if row.FamilyNotApplicable != nil {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen8RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// securityRowOf finds the security.scanning row.
func securityRowOf(t *testing.T, rep orgcontract.PolicyStateReport) orgcontract.PolicyStateRow {
	t.Helper()
	for _, row := range rep.Rows {
		if row.EnforcementPoint == policystate.PointNodeSecurity {
			return row
		}
	}
	t.Fatal("no security.scanning row")
	return orgcontract.PolicyStateRow{}
}

// TestReporter_FamilyNotApplicable (gen8, SECP-10, lane LEFT-SHARED): the
// held floor's not_applicable keys ride the security.scanning row only, and
// only while a floor is running; a gen7 server refuses them and the reporter
// sends the gen7 shape (everything else kept) and latches there; a node
// whose keys all apply sends the same bytes as before with no probe; every
// older projection clears the list.
func TestReporter_FamilyNotApplicable(t *testing.T) {
	na := []orgcontract.FamilyKeyNotApplicable{{Key: "require.commit_gate", Reason: "individual_node"}}
	held := func(context.Context) (policystate.PointFacts, error) {
		f := policystate.PointFacts{LastSeen: time.Now(), HasOrgRail: true, CachedAcceptedVersion: 3, RunningVersion: 3}
		f.EffectiveHash, f.EnforceMode = "h", "enforce"
		return f, nil
	}
	readers := gen2Readers(t)
	readers[policystate.PointNodeSecurity] = withFamilyNotApplicable(held, func() []orgcontract.FamilyKeyNotApplicable { return na })
	fp := &gen8RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 2 {
		t.Fatalf("posted %d times, want 2 (gen8 rejected, gen7 accepted)", len(fp.calls))
	}
	if got := securityRowOf(t, fp.calls[0]).FamilyNotApplicable; len(got) != 1 || got[0] != na[0] {
		t.Fatalf("the full snapshot's security row = %+v", got)
	}
	for _, row := range fp.calls[0].Rows {
		if row.EnforcementPoint != policystate.PointNodeSecurity && row.FamilyNotApplicable != nil {
			t.Fatalf("the list rode a %s row", row.EnforcementPoint)
		}
	}
	if securityRowOf(t, fp.calls[1]).FamilyNotApplicable != nil || !rep.latched.Load() || !rep.latchGen7.Load() || rep.latchGen6.Load() {
		t.Fatalf("gen7 rung: %+v latched %v gen7 %v", securityRowOf(t, fp.calls[1]), rep.latched.Load(), rep.latchGen7.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 || securityRowOf(t, fp.calls[2]).FamilyNotApplicable != nil {
		t.Fatalf("a latched gen7 send must go straight out without the list, got %d calls", len(fp.calls))
	}

	// Every key applies: no gen8 content, so a gen7 server takes the first
	// send and nothing latches.
	readers = gen2Readers(t)
	readers[policystate.PointNodeSecurity] = withFamilyNotApplicable(held, func() []orgcontract.FamilyKeyNotApplicable { return nil })
	fp = &gen8RejectingPoster{}
	rep = newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 1 || rep.latched.Load() {
		t.Fatalf("all keys apply: %d calls, latched %v", len(fp.calls), rep.latched.Load())
	}

	// No floor running: the row carries no list even when keys would say so.
	none := func(context.Context) (policystate.PointFacts, error) {
		return policystate.PointFacts{LastSeen: time.Now(), EnforceMode: "off"}, nil
	}
	f, _ := withFamilyNotApplicable(none, func() []orgcontract.FamilyKeyNotApplicable { return na })(context.Background())
	if f.FamilyNotApplicable != nil {
		t.Fatalf("no floor running, yet a list: %+v", f.FamilyNotApplicable)
	}
	rows := []orgcontract.PolicyStateRow{{EnforcementPoint: policystate.PointNodeSecurity, FamilyNotApplicable: na}}
	for name, proj := range map[string]func([]orgcontract.PolicyStateRow) []orgcontract.PolicyStateRow{
		"gen7": projectGen7, "gen6": projectGen6, "gen5": projectGen5, "gen4": projectGen4, "gen3": projectGen3, "gen2": projectGen2, "gen1": projectGen1,
	} {
		if got := proj(rows)[0]; got.FamilyNotApplicable != nil {
			t.Fatalf("%s projection kept the gen8 field: %+v", name, got)
		}
	}
}
