package store

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestEnrolmentOwnerManagedRoundTrip pins agent migration 261 (finding F12):
// the owner-managed fact is stored by WriteEnrolment, read back by
// LoadEnrolment, and a re-enrol overwrites it in both directions.
func TestEnrolmentOwnerManagedRoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	base := Enrolment{
		OrgID: "org-1", OrgName: "Me", OrgServerURL: "https://me.example",
		UserID: "u", UserEmail: "me@example.com", BearerKeyID: "k",
		Tenancy: orgcontract.TenancyManaged,
	}
	for _, step := range []struct {
		name  string
		owner bool
	}{
		{"personal org enrolment stores true", true},
		{"a re-enrol into a team org overwrites it with false", false},
		{"a re-enrol back into the personal org sets it again", true},
	} {
		e := base
		e.OwnerManaged = step.owner
		if err := s.WriteEnrolment(ctx, e); err != nil {
			t.Fatalf("%s: WriteEnrolment: %v", step.name, err)
		}
		got, err := s.LoadEnrolment(ctx)
		if err != nil || got == nil {
			t.Fatalf("%s: LoadEnrolment: %v (%+v)", step.name, err, got)
		}
		if got.OwnerManaged != step.owner {
			t.Fatalf("%s: OwnerManaged = %v, want %v", step.name, got.OwnerManaged, step.owner)
		}
	}
}

// TestSetEnrolmentOwnerManaged pins the push-acknowledgment refresh: it
// changes only the enrolment of the org that sent it, only when the value
// differs, reports whether it changed, and is a no-op when not enrolled.
func TestSetEnrolmentOwnerManaged(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if changed, err := s.SetEnrolmentOwnerManaged(ctx, "org-1", true); err != nil || changed {
		t.Fatalf("not enrolled: changed=%v err=%v, want a no-op", changed, err)
	}
	if err := s.WriteEnrolment(ctx, Enrolment{
		OrgID: "org-1", OrgName: "Me", OrgServerURL: "https://me.example",
		UserID: "u", UserEmail: "me@example.com", BearerKeyID: "k", Tenancy: orgcontract.TenancyManaged,
	}); err != nil {
		t.Fatal(err)
	}
	for _, st := range []struct {
		name    string
		orgID   string
		value   bool
		changed bool
		want    bool
	}{
		{"another org's acknowledgment is refused", "org-2", true, false, false},
		{"the enrolled org heals an old enrolment", "org-1", true, true, true},
		{"the same value again changes nothing", "org-1", true, false, true},
		{"an explicit false clears it", "org-1", false, true, false},
	} {
		changed, err := s.SetEnrolmentOwnerManaged(ctx, st.orgID, st.value)
		if err != nil || changed != st.changed {
			t.Fatalf("%s: changed=%v err=%v, want changed=%v", st.name, changed, err, st.changed)
		}
		enr, err := s.LoadEnrolment(ctx)
		if err != nil || enr == nil || enr.OwnerManaged != st.want {
			t.Fatalf("%s: enrolment = %+v (%v), want owner_managed %v", st.name, enr, err, st.want)
		}
		if enr.OrgID != "org-1" || enr.OrgName != "Me" || enr.Tenancy != orgcontract.TenancyManaged {
			t.Fatalf("%s: the refresh touched more than owner_managed: %+v", st.name, enr)
		}
	}
}
