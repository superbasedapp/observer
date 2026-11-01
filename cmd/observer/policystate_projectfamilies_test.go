package main

import (
	"context"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// gen6RejectingPoster models a gen5 server: it 400s a report carrying the
// gen6 project family section status.
type gen6RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen6RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if row.ProjectFamilyStatus != nil {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen6RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// TestReporter_ProjectFamilyStatus pins the gen6 field (lane sec-p3): it
// rides the guard row only beside the gen5 list; a gen5 server gets the same
// snapshot with only the family status stripped (the gen5 list kept) and the
// reporter latches there; every older projection strips it; a cut family
// list sets the gen7 family truncation flag (lane SEC-P4; it set the shared
// flag before).
func TestReporter_ProjectFamilyStatus(t *testing.T) {
	sections := []orgcontract.ProjectSectionState{{OrgProjectID: "p1", Status: orgcontract.ProjectSectionApplied}}
	family := []orgcontract.ProjectFamilySectionState{{OrgProjectID: "p1", Family: "security.scanning", Version: 4, Status: orgcontract.ProjectFamilyApplied}}
	readers := gen2Readers(t)
	readers[policystate.PointGuard] = withProjectFamilyStatus(projectSectionReportReader(guard.ProjectSectionReport{Sections: sections}),
		func() ([]orgcontract.ProjectFamilySectionState, bool) { return family, true })
	fp := &gen6RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	// Since lane SEC-P4 the full snapshot carries the gen7 family truncation
	// flag, so the ladder first tries the gen6 shape (the flag folded into
	// the section flag), which this gen5 server also refuses.
	if len(fp.calls) != 3 {
		t.Fatalf("posted %d times, want 3 (gen7 and gen6 rejected, gen5 accepted)", len(fp.calls))
	}
	full := guardRowOf(t, fp.calls[0])
	if len(full.ProjectFamilyStatus) != 1 || full.ProjectSectionTruncated || !full.ProjectFamilyTruncated {
		t.Fatalf("the full snapshot = %+v, want the family list with its own truncation flag", full)
	}
	if g6 := guardRowOf(t, fp.calls[1]); !g6.ProjectSectionTruncated || g6.ProjectFamilyTruncated {
		t.Fatalf("the gen6 shape = %+v, want the flag folded into the section flag", g6)
	}
	fp.calls = fp.calls[1:]
	for _, row := range fp.calls[0].Rows {
		if row.EnforcementPoint != policystate.PointGuard && row.ProjectFamilyStatus != nil {
			t.Fatalf("the family status rode a %s row", row.EnforcementPoint)
		}
	}
	gen5 := guardRowOf(t, fp.calls[1])
	if gen5.ProjectFamilyStatus != nil || len(gen5.ProjectSectionStatus) != 1 {
		t.Fatalf("gen5 rung guard row = %+v, want no family status and the gen5 list kept", gen5)
	}
	if !rep.latched.Load() || !rep.latchGen5.Load() || rep.latchGen4.Load() {
		t.Fatalf("latch = %v gen5 %v gen4 %v, want a gen5 latch", rep.latched.Load(), rep.latchGen5.Load(), rep.latchGen4.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 || guardRowOf(t, fp.calls[2]).ProjectFamilyStatus != nil || guardRowOf(t, fp.calls[2]).ProjectFamilyTruncated {
		t.Fatalf("a latched gen5 send must go straight out without the family status, got %d calls", len(fp.calls))
	}
	rows := []orgcontract.PolicyStateRow{{EnforcementPoint: policystate.PointGuard, ProjectFamilyStatus: family}}
	for name, proj := range map[string]func([]orgcontract.PolicyStateRow) []orgcontract.PolicyStateRow{
		"gen5": projectGen5, "gen4": projectGen4, "gen3": projectGen3, "gen2": projectGen2, "gen1": projectGen1,
	} {
		if got := proj(rows)[0]; got.ProjectFamilyStatus != nil {
			t.Fatalf("%s projection kept the gen6 field: %+v", name, got)
		}
	}
}

// gen7RejectingPoster models a gen6 server: it 400s a report carrying the
// gen7 family truncation flag.
type gen7RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen7RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if row.ProjectFamilyTruncated {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen7RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// TestReporter_ProjectFamilyTruncatedLatchesGen6 (lane SEC-P4 decision 11):
// a gen6 server refuses the gen7 flag; the reporter sends the gen6 shape
// (family list kept, the flag folded into the section flag, which a gen6
// server reads for both lists) and latches there; a list that fits sends
// the gen7 shape unchanged with no probe; every older projection clears
// the flag.
func TestReporter_ProjectFamilyTruncatedLatchesGen6(t *testing.T) {
	sections := []orgcontract.ProjectSectionState{{OrgProjectID: "p1", Status: orgcontract.ProjectSectionApplied}}
	family := []orgcontract.ProjectFamilySectionState{{OrgProjectID: "p1", Family: "security.scanning", Version: 4, Status: orgcontract.ProjectFamilyApplied}}
	readers := gen2Readers(t)
	readers[policystate.PointGuard] = withProjectFamilyStatus(projectSectionReportReader(guard.ProjectSectionReport{Sections: sections}),
		func() ([]orgcontract.ProjectFamilySectionState, bool) { return family, true })
	fp := &gen7RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 2 {
		t.Fatalf("posted %d times, want 2 (gen7 rejected, gen6 accepted)", len(fp.calls))
	}
	g6 := guardRowOf(t, fp.calls[1])
	if len(g6.ProjectFamilyStatus) != 1 || !g6.ProjectSectionTruncated || g6.ProjectFamilyTruncated {
		t.Fatalf("gen6 rung guard row = %+v, want the family list, the folded flag and no gen7 field", g6)
	}
	if !rep.latched.Load() || !rep.latchGen6.Load() || rep.latchGen5.Load() {
		t.Fatalf("latch = %v gen6 %v gen5 %v, want a gen6 latch", rep.latched.Load(), rep.latchGen6.Load(), rep.latchGen5.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 || guardRowOf(t, fp.calls[2]).ProjectFamilyTruncated {
		t.Fatalf("a latched gen6 send must fold the flag, got %d calls", len(fp.calls))
	}

	// A family list that fits: no gen7 content, so a gen6 server takes the
	// first send.
	readers = gen2Readers(t)
	readers[policystate.PointGuard] = withProjectFamilyStatus(projectSectionReportReader(guard.ProjectSectionReport{Sections: sections}),
		func() ([]orgcontract.ProjectFamilySectionState, bool) { return family, false })
	fp = &gen7RejectingPoster{}
	rep = newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 1 || rep.latched.Load() {
		t.Fatalf("a list that fits: %d calls, latched %v", len(fp.calls), rep.latched.Load())
	}
	rows := []orgcontract.PolicyStateRow{{EnforcementPoint: policystate.PointGuard, ProjectFamilyTruncated: true}}
	for name, proj := range map[string]func([]orgcontract.PolicyStateRow) []orgcontract.PolicyStateRow{
		"gen6": projectGen6, "gen5": projectGen5, "gen4": projectGen4, "gen3": projectGen3, "gen2": projectGen2, "gen1": projectGen1,
	} {
		if got := proj(rows)[0]; got.ProjectFamilyTruncated {
			t.Fatalf("%s projection kept the gen7 field: %+v", name, got)
		}
	}
	if !projectGen6(rows)[0].ProjectSectionTruncated || projectGen5(rows)[0].ProjectSectionTruncated {
		t.Fatal("only the gen6 projection folds the flag; gen5 keeps the section flag's own meaning")
	}
}
