package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestEnrolmentStatus_Tenancy pins demo bug #3: /api/enrolment/status names
// the enrolment KIND, read through orgclient.NodeManaged, so the top-bar chip
// can say "Enrolled (individual)" or "Managed by <org>" instead of a bare
// "Enrolled in <org>". One row per kind, plus the not-enrolled case that omits
// it.
func TestEnrolmentStatus_Tenancy(t *testing.T) {
	cases := []struct {
		name     string
		enrolled bool
		tenancy  string // the org_enrolment row's class ("" writes no row)
		want     string
	}{
		{"individual enrolment", true, orgcontract.TenancyIndividual, orgcontract.TenancyIndividual},
		{"managed enrolment", true, orgcontract.TenancyManaged, orgcontract.TenancyManaged},
		{"not enrolled omits the kind", false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newEnrolmentServer(t, &fakeEnrolment{state: orgclient.EnrolmentState{Enrolled: c.enrolled, OrgID: "org-1", OrgName: "Acme"}})
			if c.tenancy != "" {
				if err := store.New(srv.opts.DB).WriteEnrolment(context.Background(), store.Enrolment{
					OrgID: "org-1", OrgName: "Acme", OrgServerURL: "https://org.acme.example",
					UserID: "u1", UserEmail: "dev@acme.example", Tenancy: c.tenancy,
				}); err != nil {
					t.Fatal(err)
				}
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/enrolment/status", nil))
			var resp enrolmentStatusResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Tenancy != c.want {
				t.Fatalf("tenancy = %q, want %q (%s)", resp.Tenancy, c.want, rec.Body.String())
			}
		})
	}
}
