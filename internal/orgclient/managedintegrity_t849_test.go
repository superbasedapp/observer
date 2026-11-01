package orgclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestReportManagedIntegrityIsManagedOnly pins the T-849 owner the push cycle
// and the policy-state heartbeat share: an individual enrolment never runs
// the collector or sends anything; a managed one sends the collector's report,
// located risks included (T-847).
func TestReportManagedIntegrityIsManagedOnly(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	var got orgcontract.ManagedIntegrityReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/managed-integrity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		writeTestJSON(w, http.StatusOK, orgcontract.ManagedIntegrityResponse{Acknowledged: true})
	}))
	t.Cleanup(srv.Close)

	s := newAgentStore(t)
	enr := store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srv.URL, UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test", Tenancy: orgcontract.TenancyIndividual,
	}
	if err := s.WriteEnrolment(ctx, enr); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	if c.ReportManagedIntegrity(ctx) {
		t.Fatal("no collector: must not report")
	}
	collected := 0
	c.SetIntegrityCollector(func() orgcontract.ManagedIntegrityReport {
		collected++
		return orgcontract.ManagedIntegrityReport{
			CaptureCheckVersion: orgcontract.ManagedCaptureCheckVersion,
			CaptureRisks:        []string{orgcontract.CaptureRiskHookConfigMissing},
			CaptureRiskItems: []orgcontract.CaptureRiskItem{
				{Risk: orgcontract.CaptureRiskHookConfigMissing, Tool: "cursor", File: "~/.cursor/hooks.json"},
			},
		}
	})
	if c.ReportManagedIntegrity(ctx) || collected != 0 || hits.Load() != 0 {
		t.Fatalf("individual node: reported=%v collected=%d hits=%d", true, collected, hits.Load())
	}
	if c.IsManagedEnrolment(ctx) {
		t.Fatal("individual enrolment read as managed")
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
	if len(got.CaptureRiskItems) != 1 || got.CaptureRiskItems[0].Tool != "cursor" || got.CaptureRiskItems[0].File != "~/.cursor/hooks.json" {
		t.Fatalf("located risk lost on the wire: %+v", got.CaptureRiskItems)
	}
}
