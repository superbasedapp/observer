package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestEnrolment_RoundTripAndDelete(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Not enrolled: LoadEnrolment is (nil, nil), never an error.
	got, err := s.LoadEnrolment(ctx)
	if err != nil {
		t.Fatalf("LoadEnrolment (empty): %v", err)
	}
	if got != nil {
		t.Fatalf("LoadEnrolment (empty) = %+v, want nil", got)
	}

	want := Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.acme.example",
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: "2026-05-26T10:00:00Z", BearerKeyID: "sbo-org-bearer-v1",
		// The zero value is normalised to individual by WriteEnrolment; set
		// it here so the struct comparison below reflects what is stored.
		Tenancy: orgcontract.TenancyIndividual,
	}
	if err := s.WriteEnrolment(ctx, want); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}

	got, err = s.LoadEnrolment(ctx)
	if err != nil {
		t.Fatalf("LoadEnrolment: %v", err)
	}
	if got == nil || *got != want {
		t.Fatalf("LoadEnrolment = %+v, want %+v", got, want)
	}
	if got.IsManaged() {
		t.Error("an individual enrolment reported IsManaged() = true")
	}

	// Re-write upgrades the singleton in place (id = 1 stays unique).
	want.OrgName = "Acme Corp"
	if err := s.WriteEnrolment(ctx, want); err != nil {
		t.Fatalf("WriteEnrolment (upgrade): %v", err)
	}
	got, _ = s.LoadEnrolment(ctx)
	if got == nil || got.OrgName != "Acme Corp" {
		t.Fatalf("LoadEnrolment after upgrade = %+v, want OrgName=Acme Corp", got)
	}

	// Delete returns to the not-enrolled state; deleting again is a no-op.
	if err := s.DeleteEnrolment(ctx); err != nil {
		t.Fatalf("DeleteEnrolment: %v", err)
	}
	if got, _ := s.LoadEnrolment(ctx); got != nil {
		t.Fatalf("LoadEnrolment after delete = %+v, want nil", got)
	}
	if err := s.DeleteEnrolment(ctx); err != nil {
		t.Fatalf("DeleteEnrolment (idempotent): %v", err)
	}
}

// TestEnrolment_ManagedTenancyRoundTrip pins that the managed class survives
// WriteEnrolment/LoadEnrolment and that IsManaged reflects it — the durable
// node-side truth the T8 transparency banner reads.
func TestEnrolment_ManagedTenancyRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.WriteEnrolment(ctx, Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "u",
		UserID: "u", UserEmail: "e@acme.example", BearerKeyID: "k",
		Tenancy: orgcontract.TenancyManaged,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	got, err := s.LoadEnrolment(ctx)
	if err != nil || got == nil {
		t.Fatalf("LoadEnrolment: %v (got=%+v)", err, got)
	}
	if got.Tenancy != orgcontract.TenancyManaged {
		t.Fatalf("Tenancy = %q, want %q", got.Tenancy, orgcontract.TenancyManaged)
	}
	if !got.IsManaged() {
		t.Error("a managed enrolment reported IsManaged() = false")
	}
}

// WriteEnrolment defaults EnrolledAt to now when the caller leaves it empty.
func TestWriteEnrolment_DefaultsEnrolledAt(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if err := s.WriteEnrolment(ctx, Enrolment{
		OrgID: "o", OrgName: "n", OrgServerURL: "u", UserID: "uid", UserEmail: "e", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	got, _ := s.LoadEnrolment(ctx)
	if got == nil || got.EnrolledAt == "" {
		t.Fatalf("EnrolledAt was not defaulted: %+v", got)
	}
}

// TestDeleteEnrolment_ClearsOrgDistributionCaches is security finding 3
// leg (a): unenrolment must not leave the departed org's signed
// distribution state behind.
//
// Two distinct harms if it does, and they compound. The announcement
// cache keeps rendering the old org's banner on a node that has left.
// And both cached rows carry that org's TOFU-PINNED KEY, so the next
// enrolment — into a different org, with a different key — is refused
// by the node's own key-change guard: an operator action (leaving)
// poisons the next one (joining).
func TestDeleteEnrolment_ClearsOrgDistributionCaches(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.WriteEnrolment(ctx, Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.example",
		UserID: "u", UserEmail: "e@acme.example", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	if err := s.UpsertOrgAnnouncement(ctx, OrgAnnouncementRow{
		Version: 7, Body: `{"id":"x"}`, BodyHash: "h", Signature: "sig",
		ServerPubkey: "old-org-key", ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgAnnouncement: %v", err)
	}
	if err := s.UpsertOrgRoutingPolicy(ctx, OrgRoutingPolicyRow{
		Version: 3, Body: "[routing]\n", BodyHash: "h", Signature: "sig",
		ServerPubkey: "old-org-key", ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgRoutingPolicy: %v", err)
	}
	// The org's signed price document (finding F6): the org's rates are the
	// org's, so leaving the org must drop them too, or a departed node with
	// [guard.budget].from_org still set keeps pricing captured turns at the dead
	// org's negotiated rates forever (cost is stamped at capture, never re-priced).
	in := 100.0
	if err := s.SaveOrgPricing(ctx, orgcontract.PricingPolicyDoc{
		PricingPolicyBody: orgcontract.PricingPolicyBody{
			Version: 9,
			Rows:    []orgcontract.PricingPolicyRow{{Model: "claude-opus-4-8", InputPerMTok: &in, Source: "negotiated"}},
		},
		Signature: "c2lnbmVk",
	}, "old-org-fingerprint", orgcontract.PricingFetchVerified); err != nil {
		t.Fatalf("SaveOrgPricing: %v", err)
	}

	if err := s.DeleteEnrolment(ctx); err != nil {
		t.Fatalf("DeleteEnrolment: %v", err)
	}

	if row, ok, err := s.GetOrgAnnouncement(ctx); err != nil || ok {
		t.Errorf("announcement cache survived unenrolment: %+v ok=%v err=%v", row, ok, err)
	}
	if row, ok, err := s.GetOrgRoutingPolicy(ctx); err != nil || ok {
		t.Errorf("routing-policy cache survived unenrolment: %+v ok=%v err=%v", row, ok, err)
	}
	// pricing_feed_cache is the node's OWN standalone data and must be LEFT
	// alone; org_pricing_cache is the org's and must be cleared.
	if cached, err := s.LoadOrgPricing(ctx); err != nil || cached.Have {
		t.Errorf("org pricing document survived unenrolment: have=%v err=%v", cached.Have, err)
	}
	// Idempotent: a second unenrol on already-clean state is a no-op.
	if err := s.DeleteEnrolment(ctx); err != nil {
		t.Fatalf("DeleteEnrolment (idempotent): %v", err)
	}
}
