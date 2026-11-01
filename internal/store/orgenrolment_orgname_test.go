package store

import (
	"context"
	"testing"
)

// TestSetEnrolmentOrgName pins the T-862 write: it relabels only the
// enrolment of the org that sent the name, reports whether anything changed,
// and is a no-op when the node is not enrolled.
func TestSetEnrolmentOrgName(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if changed, err := s.SetEnrolmentOrgName(ctx, "org-1", "Acme Robotics"); err != nil || changed {
		t.Fatalf("not enrolled: changed=%v err=%v, want a no-op", changed, err)
	}
	if err := s.WriteEnrolment(ctx, Enrolment{
		OrgID: "org-1", OrgName: "localhost:8443", OrgServerURL: "https://org.acme.example",
		UserID: "scim-42", UserEmail: "dev@acme.example", BearerKeyID: "k",
	}); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name, orgID, newName string
		changed              bool
		want                 string
	}{
		{"another org's name is refused", "org-2", "Other Org", false, "localhost:8443"},
		{"the enrolled org's rename lands", "org-1", "Acme Robotics", true, "Acme Robotics"},
		{"the same name again changes nothing", "org-1", "Acme Robotics", false, "Acme Robotics"},
	}
	for _, st := range steps {
		changed, err := s.SetEnrolmentOrgName(ctx, st.orgID, st.newName)
		if err != nil || changed != st.changed {
			t.Fatalf("%s: changed=%v err=%v, want changed=%v", st.name, changed, err, st.changed)
		}
		enr, err := s.LoadEnrolment(ctx)
		if err != nil || enr == nil || enr.OrgName != st.want {
			t.Fatalf("%s: enrolment = %+v (%v), want org name %q", st.name, enr, err, st.want)
		}
		if enr.OrgID != "org-1" || enr.UserID != "scim-42" {
			t.Fatalf("%s: the rename touched more than the name: %+v", st.name, enr)
		}
	}
}
