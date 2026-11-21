package store

import (
	"context"
	"testing"
)

// TestSetEnrolmentConnection (agent migration 255, Getting started v2 lane 8
// job 2): `observer connect` records the connection's name and online
// address on the enrolment it made; they survive a reload (a daemon
// restart), are written only for the enrolment's own org, and are cleared by
// the next enrolment.
func TestSetEnrolmentConnection(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if ok, err := s.SetEnrolmentConnection(ctx, "org-1", "Acme", "https://acme.example"); err != nil || ok {
		t.Fatalf("not enrolled: ok=%v err=%v, want nothing written", ok, err)
	}
	if err := s.WriteEnrolment(ctx, Enrolment{OrgID: "org-1", OrgName: "acme", OrgServerURL: "https://acme.example", UserID: "u", UserEmail: "e@x", BearerKeyID: "k"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SetEnrolmentConnection(ctx, "org-other", "Other", "https://other.example"); err != nil || ok {
		t.Fatalf("another org: ok=%v err=%v, want nothing written", ok, err)
	}
	if ok, err := s.SetEnrolmentConnection(ctx, "org-1", " your personal dashboard ", "https://acme.example/"); err != nil || !ok {
		t.Fatalf("own org: ok=%v err=%v", ok, err)
	}
	got, err := s.LoadEnrolment(ctx)
	if err != nil || got == nil || got.DisplayName != "your personal dashboard" || got.OnlineURL != "https://acme.example/" {
		t.Fatalf("reloaded = %+v, %v", got, err)
	}
	// A new enrolment (here, the same org again) clears them; the next
	// connect writes them again.
	if err := s.WriteEnrolment(ctx, Enrolment{OrgID: "org-1", OrgName: "acme", OrgServerURL: "https://acme.example", UserID: "u", UserEmail: "e@x", BearerKeyID: "k"}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LoadEnrolment(ctx); err != nil || got.DisplayName != "" || got.OnlineURL != "" {
		t.Fatalf("after a new enrolment = %+v, %v", got, err)
	}
}
