package main

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestEnrolDashboardLinkReEnrolAfterLeave is the operator's 2026-10-09 path
// (D-503): a MANAGED enrolment with a governance grant, Leave from the
// dashboard, then enrol AGAIN from the dashboard with the enrolment LINK. The
// CLI recovered with the same link; the dashboard must too, and every leave
// artifact (the plan rows, the org notice line, the individual-node line) must
// reach the page.
func TestEnrolDashboardLinkReEnrolAfterLeave(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyManaged, []string{govern.AuthorityDashboardVisibility, govern.AuthorityEnforceBudget})
	// The demo estate shape: HAProxy answers the public /healthz itself, so
	// the old /healthz-only probe refused this real org server on the page
	// while the CLI (no probe) enrolled with the same link.
	org.frontEndHealthz = true
	d, st, _ := testEnrolDashboard(t)
	link := dashapi.EnrolRequest{Method: "link", Link: org.url + "/enrol/" + idpTestEnrolCode}

	out, err := d.Enrol(ctx, link)
	if err != nil {
		t.Fatalf("first Enrol: %v", err)
	}
	if out.PendingGrant == nil {
		t.Fatalf("first managed enrol parked no grant: %+v", out)
	}
	if _, err := d.DecideGrant(ctx, out.PendingGrant.OfferID, true); err != nil {
		t.Fatalf("DecideGrant: %v", err)
	}
	ov, err := d.Overview(ctx)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	var fence bool
	for _, s := range ov.LeaveSteps {
		fence = fence || s.ID == "generation_fence"
	}
	if !fence || ov.LeaveSteps[len(ov.LeaveSteps)-1].Phase != "kept" {
		t.Fatalf("overview carries no structured leave plan: %+v", ov.LeaveSteps)
	}

	lv, err := d.Leave(ctx, dashapi.SwitchOptions{})
	if err != nil || !lv.WasEnrolled {
		t.Fatalf("Leave = (%+v, %v)", lv, err)
	}
	var sawIndividual bool
	for _, n := range lv.Notes {
		if strings.Contains(n.Text, "plain individual node") {
			sawIndividual = true
		}
	}
	if !sawIndividual {
		t.Fatalf("leave notes do not say the outcome: %+v", lv.Notes)
	}
	if enr, _ := st.LoadEnrolment(ctx); enr != nil {
		t.Fatal("Leave left the enrolment row")
	}

	again, err := d.Enrol(ctx, link)
	if err != nil {
		t.Fatalf("dashboard re-enrol with the link after Leave failed (the CLI succeeds with the same link): %v", err)
	}
	if !again.Managed || again.PendingGrant == nil {
		t.Fatalf("re-enrol outcome = %+v, want managed with a parked grant", again)
	}
	if _, err := d.DecideGrant(ctx, again.PendingGrant.OfferID, true); err != nil {
		t.Fatalf("DecideGrant after re-enrol: %v", err)
	}
	if enr, _ := st.LoadEnrolment(ctx); enr == nil {
		t.Fatal("re-enrol wrote no enrolment row")
	}
}

// TestEnrolDashboardProbeFailureShowsWhatAnswered: when the probe does refuse,
// the page shows what the server actually answered, never only a generic
// sentence (T-718).
func TestEnrolDashboardProbeFailureShowsWhatAnswered(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyIndividual, nil)
	org.healthzOK = false
	d, _, _ := testEnrolDashboard(t)
	_, err := d.Enrol(ctx, dashapi.EnrolRequest{Method: "link", Link: org.url + "/enrol/" + idpTestEnrolCode})
	if err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("probe refusal = %v, want the answered status in the message", err)
	}
	if org.enrolCalls != 0 {
		t.Fatal("a refused probe still sent the code")
	}
}
