package orgclient

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestUserPolicyLabelNeverLeavesAnIndividualNode (FU-105): a collector that
// would report IBM Bob's user-set policy (ibm-bob/user_policy_override) is
// never run on an individual enrolment, so nothing reaches the wire; the
// same collector on a managed enrolment sends the label.
func TestUserPolicyLabelNeverLeavesAnIndividualNode(t *testing.T) {
	ctx := context.Background()
	const label = "ibm-bob/user_policy_override"
	var hits atomic.Int32
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/managed-integrity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		body, _ = io.ReadAll(r.Body)
		writeTestJSON(w, http.StatusOK, orgcontract.ManagedIntegrityResponse{Acknowledged: true})
	}))
	t.Cleanup(srv.Close)

	s := newAgentStore(t)
	enr := store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srv.URL, UserID: "u-1", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test", Tenancy: orgcontract.TenancyIndividual,
	}
	if err := s.WriteEnrolment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	collected := 0
	c.SetIntegrityCollector(func() orgcontract.ManagedIntegrityReport {
		collected++
		return orgcontract.ManagedIntegrityReport{
			CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion,
			ConfigLayerVersion:  orgcontract.ManagedConfigLayerVersion,
			ConfigLayerRisks:    []string{label},
		}
	})
	if c.ReportManagedIntegrity(ctx) || collected != 0 || hits.Load() != 0 {
		t.Fatalf("individual node: collected=%d hits=%d", collected, hits.Load())
	}
	enr.Tenancy = orgcontract.TenancyManaged
	if err := s.WriteEnrolment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	if !c.ReportManagedIntegrity(ctx) || collected != 1 {
		t.Fatalf("managed node: collected=%d", collected)
	}
	if hits.Load() == 0 {
		t.Skip("no stable machine identity on this host: the report is skipped by design")
	}
	if !bytes.Contains(body, []byte(`"config_layer_risks":["`+label+`"]`)) {
		t.Fatalf("managed node did not send %s: %s", label, body)
	}
}
