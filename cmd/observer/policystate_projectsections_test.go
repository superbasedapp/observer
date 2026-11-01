package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policystate"
)

// gen5RejectingPoster models a gen4 server: it 400s a report carrying the
// gen5 per-section project status.
type gen5RejectingPoster struct {
	mu    sync.Mutex
	calls []orgcontract.PolicyStateReport
}

func (p *gen5RejectingPoster) PostPolicyState(_ context.Context, rep orgcontract.PolicyStateReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, rep)
	for _, row := range rep.Rows {
		if row.ProjectSectionStatus != nil {
			return orgclient.ErrPolicyAckRejected
		}
	}
	return nil
}

func (p *gen5RejectingPoster) ManagedMachineIdentity(context.Context) string {
	return "org-salted-machine-id"
}

// projectSectionGuardReader is a guard reader carrying the gen4 tamper record
// and the gen5 per-section status.
func projectSectionGuardReader(status []orgcontract.ProjectSectionState) policystate.PointReader {
	return projectSectionReportReader(guard.ProjectSectionReport{Sections: status})
}

// projectSectionReportReader is projectSectionGuardReader over a whole
// report (the list and its truncated flag).
func projectSectionReportReader(rep guard.ProjectSectionReport) policystate.PointReader {
	tamper := &orgcontract.GuardTamperReport{Repairs: 1, LastAt: "2026-10-16T07:00:00Z", LastKind: orgcontract.GuardTamperOrgBundle}
	return withProjectSectionStatus(withGuardTamper(newGuardPointReader(
		guardBundleCheckFrom(&fakeBundleVerifier{check: orgclient.CachedBundleCheck{Integrity: orgcontract.BundleIntegrityVerified}}, "/x/b.json"),
		func() guardRunning { return guardRunning{RunningVersion: 4, EffectiveHash: psHex64, Mode: "enforce"} },
		func() orgclient.GuardFetchOutcome { return orgclient.GuardFetchOutcome{} },
		nil,
		time.Now,
	), func(context.Context) *orgcontract.GuardTamperReport { return tamper }),
		func() guard.ProjectSectionReport { return rep })
}

func guardRowOf(t *testing.T, rep orgcontract.PolicyStateReport) orgcontract.PolicyStateRow {
	t.Helper()
	for _, row := range rep.Rows {
		if row.EnforcementPoint == policystate.PointGuard {
			return row
		}
	}
	t.Fatal("no guard row")
	return orgcontract.PolicyStateRow{}
}

// TestReporter_ProjectSectionStatus pins the gen5 field (lane sec-p2b): it
// rides the guard row only; a gen4 server gets the same snapshot with only
// the per-section status stripped (the gen4 tamper record kept) and the
// reporter latches there; a node with no project delivery sends no gen5
// content, so an older server sees nothing new and no rung is probed.
func TestReporter_ProjectSectionStatus(t *testing.T) {
	status := []orgcontract.ProjectSectionState{
		{OrgProjectID: "p1", Status: orgcontract.ProjectSectionApplied},
		{OrgProjectID: "p2", Status: orgcontract.ProjectSectionNotDelivered},
	}
	readers := gen2Readers(t)
	readers[policystate.PointGuard] = projectSectionGuardReader(status)
	fp := &gen5RejectingPoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if len(fp.calls) != 2 {
		t.Fatalf("posted %d times, want 2 (gen5 rejected, gen4 accepted)", len(fp.calls))
	}
	full := guardRowOf(t, fp.calls[0])
	if len(full.ProjectSectionStatus) != 2 {
		t.Fatalf("the full snapshot must carry the status: %+v", full)
	}
	for _, row := range fp.calls[0].Rows {
		if row.EnforcementPoint != policystate.PointGuard && row.ProjectSectionStatus != nil {
			t.Fatalf("the status rode a %s row", row.EnforcementPoint)
		}
	}
	gen4 := guardRowOf(t, fp.calls[1])
	if gen4.ProjectSectionStatus != nil || gen4.GuardTamper == nil {
		t.Fatalf("gen4 rung guard row = %+v, want no project status and the tamper record kept", gen4)
	}
	if !rep.latched.Load() || !rep.latchGen4.Load() || rep.latchGen3.Load() {
		t.Fatalf("latch = %v gen4 %v gen3 %v, want a gen4 latch", rep.latched.Load(), rep.latchGen4.Load(), rep.latchGen3.Load())
	}
	rep.report(context.Background())
	if len(fp.calls) != 3 || guardRowOf(t, fp.calls[2]).ProjectSectionStatus != nil {
		t.Fatalf("a latched gen4 send must go straight out without the status, got %d calls", len(fp.calls))
	}

	// Every projection older than gen5 strips it.
	rows := []orgcontract.PolicyStateRow{{EnforcementPoint: policystate.PointGuard, ProjectSectionStatus: status, ProjectSectionTruncated: true}}
	for name, proj := range map[string]func([]orgcontract.PolicyStateRow) []orgcontract.PolicyStateRow{
		"gen4": projectGen4, "gen3": projectGen3, "gen2": projectGen2, "gen1": projectGen1,
	} {
		if got := proj(rows)[0]; got.ProjectSectionStatus != nil || got.ProjectSectionTruncated {
			t.Fatalf("%s projection kept a gen5 field: %+v", name, got)
		}
	}

	// No project delivery: nil status, one send, no probe.
	readers2 := gen2Readers(t)
	readers2[policystate.PointGuard] = projectSectionGuardReader(nil)
	fp2 := &gen5RejectingPoster{}
	rep2 := newPolicyStateReporter(fp2, readers2, seqCounter(t), "v", true, nil)
	rep2.report(context.Background())
	if len(fp2.calls) != 1 || rep2.latched.Load() {
		t.Fatalf("a node with no project delivery posted %d times (latched %v), want 1 unlatched", len(fp2.calls), rep2.latched.Load())
	}
}

// TestReporter_ProjectSectionTruncated pins SEC-P2B audit finding 2 on the
// node: a cut list rides the guard row with its truncated flag, and a gen5
// server takes it in one send (no rung probed, nothing latched).
func TestReporter_ProjectSectionTruncated(t *testing.T) {
	status := []orgcontract.ProjectSectionState{{OrgProjectID: "p1", Status: orgcontract.ProjectSectionApplied}}
	readers := gen2Readers(t)
	readers[policystate.PointGuard] = projectSectionReportReader(guard.ProjectSectionReport{Sections: status, Truncated: true})
	fp := &fakePoster{}
	rep := newPolicyStateReporter(fp, readers, seqCounter(t), "v", true, nil)
	rep.report(context.Background())
	if fp.callCount() != 1 || rep.latched.Load() {
		t.Fatalf("posted %d times (latched %v), want one unlatched send", fp.callCount(), rep.latched.Load())
	}
	row := guardRowOf(t, fp.last)
	if !row.ProjectSectionTruncated || len(row.ProjectSectionStatus) != 1 {
		t.Fatalf("guard row = %+v, want the list and the truncated flag", row)
	}
	for _, r := range fp.last.Rows {
		if r.EnforcementPoint != policystate.PointGuard && r.ProjectSectionTruncated {
			t.Fatalf("the flag rode a %s row", r.EnforcementPoint)
		}
	}
}
