package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestOrgPricingPublicationFencesReenrollmentAndUnenrollment(t *testing.T) {
	ctx := context.Background()
	st, _ := feedTestStore(t)
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: "org-1", OrgServerURL: "https://org.example.test",
		UserID: "member-one", EnrolledAt: "2026-09-14T01:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("CurrentBudgetIdentity: active=%v err=%v", active, err)
	}
	engine := cost.NewEngine(config.IntelligenceConfig{})
	h := newOrgPricingHandle(engine, config.Config{Guard: config.GuardConfig{Budget: config.GuardBudgetConfig{FromOrg: true}}}, slog.Default(), st)
	row := orgcontract.PricingPolicyRow{Model: "m", InputPerMTok: orgcontract.Rate(8), OutputPerMTok: orgcontract.Rate(16)}
	h.publish(orgclient.PricingFetchOutcome{
		State: orgcontract.PricingFetchVerified, Body: orgcontract.PricingPolicyBody{
			Version: 1, Rows: []orgcontract.PricingPolicyRow{row},
		}, HaveBody: true, Binding: identity.Binding,
	})
	if !engine.HasOrgPricing() || engine.Table().EnrollmentBinding() != identity.Binding {
		t.Fatalf("current enrollment pricing was not composed: binding=%q has=%v", engine.Table().EnrollmentBinding(), engine.HasOrgPricing())
	}

	// A delayed body from the first member must clear the old table and never
	// replace it after another enrollment has become current.
	enr, err := st.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		t.Fatalf("LoadEnrolment: %+v err=%v", enr, err)
	}
	orgKey := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
	if _, err := st.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatal(err)
	}
	enr.UserID = "member-two"
	enr.EnrolledAt = "2026-09-14T02:00:00Z"
	if err := st.WriteEnrolment(ctx, *enr); err != nil {
		t.Fatal(err)
	}
	newIdentity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active || newIdentity.Binding == identity.Binding {
		t.Fatalf("replacement identity: %+v active=%v err=%v", newIdentity, active, err)
	}
	h.publish(orgclient.PricingFetchOutcome{
		State: orgcontract.PricingFetchVerified, Body: orgcontract.PricingPolicyBody{
			Version: 1, Rows: []orgcontract.PricingPolicyRow{row},
		}, HaveBody: true, Binding: identity.Binding,
	})
	if engine.HasOrgPricing() {
		t.Fatal("delayed old enrollment body remained in the live engine")
	}
	if got := engine.Table().EnrollmentBinding(); got != newIdentity.Binding {
		t.Fatalf("cleared engine binding = %q, want current %q", got, newIdentity.Binding)
	}

	// A bodyless same-binding transport failure keeps the last verified table
	// in force. This is the ordinary fail-open path.
	h.publish(orgclient.PricingFetchOutcome{
		State: orgcontract.PricingFetchVerified, Body: orgcontract.PricingPolicyBody{
			Version: 2, Rows: []orgcontract.PricingPolicyRow{row},
		}, HaveBody: true, Binding: newIdentity.Binding,
	})
	// A delayed bodyless result from the first enrollment must not clear the
	// replacement table that is already in force.
	h.publish(orgclient.PricingFetchOutcome{
		State: orgcontract.PricingFetchUnreachable, Binding: identity.Binding,
	})
	if !engine.HasOrgPricing() || engine.Table().EnrollmentBinding() != newIdentity.Binding {
		t.Fatal("delayed old bodyless outcome displaced the replacement table")
	}
	h.publish(orgclient.PricingFetchOutcome{State: orgcontract.PricingFetchUnreachable, Binding: newIdentity.Binding})
	if !engine.HasOrgPricing() || engine.Table().EnrollmentBinding() != newIdentity.Binding {
		t.Fatal("same-binding transport failure displaced the verified table")
	}

	if err := st.DeleteEnrolment(ctx); err != nil {
		t.Fatal(err)
	}
	h.publish(orgclient.PricingFetchOutcome{State: orgcontract.PricingFetchNotEnrolled, Binding: newIdentity.Binding})
	if engine.HasOrgPricing() {
		t.Fatal("unenrollment left org pricing in the live engine")
	}
}
