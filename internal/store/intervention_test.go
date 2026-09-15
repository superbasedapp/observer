package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestInterventionFenceUsesOneConnectionAndExcludesWriters(t *testing.T) {
	st, database := newTestStore(t)
	ctx := context.Background()
	enr := Enrolment{OrgID: "org", OrgServerURL: "https://org.example.test", UserID: "member-one", Tenancy: "managed"}
	if err := st.WriteEnrolment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BumpEnrolmentGeneration(ctx, "org-key", false); err != nil {
		t.Fatal(err)
	}
	if err := st.WriteEnrolmentGrant(ctx, EnrolmentGrant{OrgKey: "org-key", OrgID: "org", Generation: 1, Authority: []string{"enforce.budget"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordGuardPolicyState(ctx, GuardPolicyStateRow{Layer: "org", Path: "pin", ContentHash: "key-hash", LoadedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	deadline, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	sentinel := errors.New("operation refused")
	absent := OrgBudgetWitness{Known: true}
	err := st.WithInterventionFence(deadline, "org-key", "pin", absent, nil, func(s InterventionAuthority) error {
		if s.Enrolment == nil || s.Enrolment.UserID != "member-one" || !s.HaveGeneration || s.Generation.Generation != 1 || !s.HaveGrant || s.KeyPinSHA256 != "key-hash" {
			t.Fatalf("fenced snapshot incomplete: %+v", s)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("callback error lost: %v", err)
	}
	// A separate pooled connection models another CLI/daemon writer. Its
	// short busy timeout makes the exclusion assertion deterministic.
	database.SetMaxOpenConns(2)
	writer, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ExecContext(ctx, "PRAGMA busy_timeout = 1"); err != nil {
		t.Fatal(err)
	}
	err = st.WithInterventionFence(deadline, "org-key", "pin", absent, nil, func(InterventionAuthority) error {
		_, writeErr := writer.ExecContext(ctx, "UPDATE org_enrolment SET user_id = 'replacement' WHERE id = 1")
		if writeErr == nil || !strings.Contains(strings.ToLower(writeErr.Error()), "locked") {
			t.Fatalf("identity writer was not excluded during operation: %v", writeErr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ExecContext(ctx, "UPDATE org_enrolment SET user_id = 'replacement' WHERE id = 1"); err != nil {
		t.Fatalf("fence did not release: %v", err)
	}
	current, err := st.LoadEnrolment(ctx)
	if err != nil || current.UserID != "replacement" {
		t.Fatalf("post-operation enrollment: %+v err=%v", current, err)
	}
}

func TestInterventionFenceRejectsExactBudgetDocumentChange(t *testing.T) {
	st, database := newTestStore(t)
	ctx := context.Background()
	enr := Enrolment{
		OrgID: "org", OrgServerURL: "https://org.example.test",
		UserID: "member-one", EnrolledAt: "2026-09-14T01:00:00Z", Tenancy: "managed",
	}
	if err := st.WriteEnrolment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	generation, err := st.BumpEnrolmentGeneration(ctx, "org-key", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteEnrolmentGrant(ctx, EnrolmentGrant{OrgKey: "org-key", OrgID: "org", Generation: generation, Authority: []string{"enforce.budget"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordGuardPolicyState(ctx, GuardPolicyStateRow{Layer: "org", Path: "pin", ContentHash: "key-hash", LoadedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	identity := OrgBudgetIdentity{
		OrgKey: "org-key", OrgID: enr.OrgID, OrgServerURL: enr.OrgServerURL,
		UserID: enr.UserID, EnrolledAt: enr.EnrolledAt, Generation: generation, Binding: "member-one-generation-one",
	}
	oldDoc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{
		Version: 7, CapTokens: 100, ResolvedScope: "member:one",
	}}
	oldWitness, err := st.SaveOrgBudgetWithWitness(ctx, oldDoc, `"same-version-old"`, "key-hash", identity)
	if err != nil || !oldWitness.Valid() || !oldWitness.Present {
		t.Fatalf("old witness=%+v err=%v", oldWitness, err)
	}

	// Same policy version, different signed-document body. Version fencing
	// alone cannot distinguish a team-membership cap change.
	newDoc := oldDoc
	newDoc.CapTokens = 1_000
	newWitness, err := st.SaveOrgBudgetWithWitness(ctx, newDoc, `"same-version-new"`, "key-hash", identity)
	if err != nil || !newWitness.Valid() || newWitness == oldWitness {
		t.Fatalf("new witness=%+v old=%+v err=%v", newWitness, oldWitness, err)
	}
	deadline, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	actions := 0
	err = st.WithInterventionFence(deadline, "org-key", "pin", oldWitness, nil, func(InterventionAuthority) error {
		actions++
		return nil
	})
	if !errors.Is(err, ErrOrgBudgetWitnessChanged) || actions != 0 {
		t.Fatalf("stale body reached callback: actions=%d err=%v", actions, err)
	}
	if err := st.WithInterventionFence(deadline, "org-key", "pin", newWitness, nil, func(InterventionAuthority) error {
		actions++
		return nil
	}); err != nil || actions != 1 {
		t.Fatalf("current body refused: actions=%d err=%v", actions, err)
	}
	expectedPricing, err := loadOrgPricingWitness(ctx, database)
	if err != nil || !expectedPricing.Valid() || expectedPricing.Present {
		t.Fatalf("initial pricing witness=%+v err=%v", expectedPricing, err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE org_pricing_cache SET body_json = '{"changed":true}' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	err = st.WithInterventionFence(deadline, "org-key", "pin", newWitness, &expectedPricing, func(InterventionAuthority) error {
		actions++
		return nil
	})
	if !errors.Is(err, ErrOrgPricingWitnessChanged) || actions != 1 {
		t.Fatalf("changed pricing reached callback: actions=%d err=%v", actions, err)
	}

	absent, err := st.ClearOrgBudgetForIdentityWithWitness(ctx, identity)
	if err != nil || absent != (OrgBudgetWitness{Known: true}) {
		t.Fatalf("known absence=%+v err=%v", absent, err)
	}
	err = st.WithInterventionFence(deadline, "org-key", "pin", newWitness, nil, func(InterventionAuthority) error {
		actions++
		return nil
	})
	if !errors.Is(err, ErrOrgBudgetWitnessChanged) || actions != 1 {
		t.Fatalf("cleared body reached stale callback: actions=%d err=%v", actions, err)
	}
}
