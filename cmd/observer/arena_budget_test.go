package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestArenaBudgetAdmissionRefusesManagedHardBudget(t *testing.T) {
	t.Parallel()
	cfgPath, _ := writeManagedBudgetLaunchFixture(t, true, "enforce")

	err := arenaBudgetAdmissionSeam(cfgPath)(context.Background(), "claude-code", "http://127.0.0.1:8820")
	if !errors.Is(err, errBudgetLaunchUncontrolled) {
		t.Fatalf("Arena admission error = %v, want managed hard-budget refusal", err)
	}
}

func TestArenaBudgetAdmissionAllowsIndividualNode(t *testing.T) {
	t.Parallel()
	cfgPath, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(enrolment *store.Enrolment) {
		enrolment.Tenancy = orgcontract.TenancyIndividual
	})
	rewriteBudgetLaunchGrant(t, dbPath, func(grant *store.EnrolmentGrant) {
		grant.ConsentMode = govern.ConsentInteractive
		grant.ExpiresAt = time.Now().UTC().Add(-time.Hour)
		grant.SignedExpiresAt = grant.ExpiresAt
	})

	if err := arenaBudgetAdmissionSeam(cfgPath)(context.Background(), "claude-code", ""); err != nil {
		t.Fatalf("individual Arena admission refused: %v", err)
	}
}
