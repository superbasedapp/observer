package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestSaveOrgPricingIsEnrollmentFencedAndRetainsDocument(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, _ := newTestStore(t)
	first := Enrolment{
		OrgID: "org-1", OrgServerURL: "https://org.example.test",
		UserID: "member-one", EnrolledAt: "2026-09-14T01:00:00Z",
	}
	if err := st.WriteEnrolment(ctx, first); err != nil {
		t.Fatal(err)
	}
	orgSum := sha256.Sum256([]byte("https://org.example.test\x00org-1"))
	orgKey := hex.EncodeToString(orgSum[:])
	firstGeneration, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatal(err)
	}
	firstIdentity := OrgBudgetIdentity{
		OrgKey: orgKey, OrgID: first.OrgID, OrgServerURL: first.OrgServerURL,
		UserID: first.UserID, EnrolledAt: first.EnrolledAt,
		Generation: firstGeneration, Binding: "binding-one",
	}
	doc := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{
			Version: 4,
			Rows:    []orgcontract.PricingPolicyRow{{Model: "m", InputPerMTok: orgcontract.Rate(3)}},
		},
		Signature: "signed-document",
	}
	if err := st.SaveOrgPricing(ctx, doc, "fingerprint", orgcontract.PricingFetchVerified, firstIdentity); err != nil {
		t.Fatalf("SaveOrgPricing: %v", err)
	}
	got, err := st.LoadOrgPricing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Compare the SIGNED CONTENT (body + signature), not the whole Document by
	// reflect.DeepEqual: a reloaded document legitimately carries the unexported
	// rawRows that json.Unmarshal repopulates so re-verification works over the
	// bytes the org signed (Phase 0 / P2-0), and rawRows is not part of the
	// document's meaning here.
	if got.Binding != firstIdentity.Binding ||
		!reflect.DeepEqual(got.Document.PricingPolicyBody, doc.PricingPolicyBody) ||
		got.Document.Signature != doc.Signature {
		t.Fatalf("cache provenance/document = binding %q doc %+v, want %q %+v", got.Binding, got.Document, firstIdentity.Binding, doc)
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
	secondIdentity := firstIdentity
	secondIdentity.UserID = second.UserID
	secondIdentity.EnrolledAt = second.EnrolledAt
	secondIdentity.Generation = secondGeneration
	secondIdentity.Binding = "binding-two"
	secondDoc := doc
	secondDoc.Version = 5
	if err := st.SaveOrgPricing(ctx, secondDoc, "fingerprint", orgcontract.PricingFetchVerified, secondIdentity); err != nil {
		t.Fatalf("save replacement identity: %v", err)
	}
	if err := st.SaveOrgPricing(ctx, doc, "fingerprint", orgcontract.PricingFetchVerified, firstIdentity); !errors.Is(err, ErrOrgPricingIdentityChanged) {
		t.Fatalf("late first save error = %v, want identity change", err)
	}
	got, err = st.LoadOrgPricing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Binding != secondIdentity.Binding || got.Version != secondDoc.Version {
		t.Fatalf("late old save changed replacement cache: %+v", got)
	}
}

func TestLoadOrgPricingMarksLegacyRowsUnbound(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	st, database := newTestStore(t)
	doc := orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{Version: 7},
		Signature:         "legacy-signature",
	}
	blob, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `
UPDATE org_pricing_cache
   SET version = 7, org_key_fingerprint = 'legacy-key',
       body_json = ?, fetched_at = '2026-09-14T01:00:00Z', state = ?
 WHERE id = 1`, string(blob), orgcontract.PricingFetchVerified); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadOrgPricing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Compare the SIGNED CONTENT, not the whole Document: a reloaded document
	// legitimately carries the unexported rawRows json.Unmarshal repopulates
	// (Phase 0 / P2-0), which is not part of the document's meaning here.
	if !got.Have || got.Binding != "" ||
		!reflect.DeepEqual(got.Document.PricingPolicyBody, doc.PricingPolicyBody) ||
		got.Document.Signature != doc.Signature {
		t.Fatalf("legacy cache = %+v, want readable unbound document", got)
	}
}
