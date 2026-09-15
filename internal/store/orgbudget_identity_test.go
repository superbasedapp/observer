package store

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestOrgBudgetWritesAndClearsAreEnrollmentFenced(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, _ := newTestStore(t)
	const orgKey = "org-key"

	first := Enrolment{
		OrgID: "org-1", OrgServerURL: "https://org.example.test",
		UserID: "member-one", EnrolledAt: "2026-09-14T01:00:00Z",
	}
	if err := st.WriteEnrolment(ctx, first); err != nil {
		t.Fatal(err)
	}
	firstGeneration, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatal(err)
	}
	firstIdentity := OrgBudgetIdentity{
		OrgKey: orgKey, OrgID: first.OrgID, OrgServerURL: first.OrgServerURL,
		UserID: first.UserID, EnrolledAt: first.EnrolledAt,
		Generation: firstGeneration, Binding: "binding-one",
	}
	firstDoc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{Version: 1}}
	if err := st.SaveOrgBudget(ctx, firstDoc, `"same"`, "key", firstIdentity); err != nil {
		t.Fatalf("save first identity: %v", err)
	}

	second := first
	second.UserID = "member-two"
	second.EnrolledAt = "2026-09-14T02:00:00Z"
	secondGeneration, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteEnrolment(ctx, second); err != nil {
		t.Fatal(err)
	}
	secondIdentity := OrgBudgetIdentity{
		OrgKey: orgKey, OrgID: second.OrgID, OrgServerURL: second.OrgServerURL,
		UserID: second.UserID, EnrolledAt: second.EnrolledAt,
		Generation: secondGeneration, Binding: "binding-two",
	}
	secondDoc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{Version: 2}}
	if err := st.SaveOrgBudget(ctx, secondDoc, `"same"`, "key", secondIdentity); err != nil {
		t.Fatalf("save second identity: %v", err)
	}

	if err := st.SaveOrgBudget(ctx, firstDoc, `"late"`, "key", firstIdentity); !errors.Is(err, ErrOrgBudgetIdentityChanged) {
		t.Fatalf("late first save error = %v, want identity change", err)
	}
	if err := st.ClearOrgBudgetForIdentity(ctx, firstIdentity); !errors.Is(err, ErrOrgBudgetIdentityChanged) {
		t.Fatalf("late first clear error = %v, want identity change", err)
	}
	got, err := st.LoadOrgBudget(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Have || got.Version != 2 || got.Binding != secondIdentity.Binding || got.ETag != `"same"` {
		t.Fatalf("current member budget was changed by a late operation: %+v", got)
	}
}

func TestLoadOrgBudgetMarksLegacyRowsUnbound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, database := newTestStore(t)
	doc := orgcontract.BudgetPolicyDoc{BudgetPolicyBody: orgcontract.BudgetPolicyBody{Version: 7}}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE org_budget_cache
   SET version = 7, etag = '"legacy"', org_key_fingerprint = 'key',
       body_json = ?, fetched_at = '2026-09-14T01:00:00Z'
 WHERE id = 1`, string(blob)); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadOrgBudget(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Have || got.Version != 7 || got.Binding != "" {
		t.Fatalf("legacy cache = %+v, want readable but unbound", got)
	}
}
