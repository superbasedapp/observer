package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSwitchedNodeAsksTheManagedEndpoints (operator rulings P-204 and P-205):
// a node whose org switched it to enterprise names its machine, declares
// managed on an access request, needs no developer consent for org intel,
// binds its machine once and reports integrity, and asks the change-key and
// exec seal routes; before the switch and after the switch back it does
// none of that. Against an org server that does not serve it as managed (an
// older one, 403 managed_only) the change key stays self-certified and the
// seal key backs off, quietly.
func TestSwitchedNodeAsksTheManagedEndpoints(t *testing.T) {
	ctx := context.Background()
	var binds, integrity, changeKey, execSeal atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/agent/managed-bind":
			binds.Add(1)
			_ = json.NewEncoder(w).Encode(orgcontract.ManagedBindResponse{Status: orgcontract.ManagedBindBound})
		case "/api/agent/managed-integrity":
			integrity.Add(1)
			_ = json.NewEncoder(w).Encode(orgcontract.ManagedIntegrityResponse{})
		case orgcontract.AgentChangeKeyPath:
			changeKey.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": managedOnlyCode})
		case orgcontract.AgentExecSealKeyPath:
			execSeal.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": managedOnlyCode})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	s := newAgentStore(t)
	pub, priv := seedEnrolledNode(t, s, srv.URL, "org-1")
	c := newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz"})
	c.SetIntegrityCollector(func() orgcontract.ManagedIntegrityReport { return orgcontract.ManagedIntegrityReport{} })
	mid, _ := machineid.ForOrg("org-1")
	_, keyPriv, _ := ed25519.GenerateKey(rand.Reader)

	tenancy := func() string {
		t.Helper()
		out, err := c.PrepareAccessRequest(ctx, orgcontract.AccessRequestCreate{
			Message: "need it", RequestType: accessgrant.TypeGuardExemption,
			Payload: &orgcontract.AccessRequestPayload{RuleID: "R-171", Breadth: accessgrant.BreadthRule},
			Context: &orgcontract.AccessRequestContext{RuleID: "R-171"},
		}, false)
		if err != nil {
			t.Fatal(err)
		}
		return out.Context.Tenancy
	}
	expectIndividual := func(phase string) {
		t.Helper()
		if got := tenancy(); got != orgcontract.TenancyIndividual {
			t.Errorf("%s: access request declares %q, want individual", phase, got)
		}
		if got := c.ManagedMachineIdentity(ctx); got != "" {
			t.Errorf("%s: machine identity %q, want none", phase, got)
		}
		enr, _ := s.LoadEnrolment(ctx)
		if _, machine := c.accessGrantSubject(ctx, enr); machine != "" {
			t.Errorf("%s: grant subject names machine %q", phase, machine)
		}
		if ok, err := c.intelSendConsented(ctx, "org-1"); err != nil || ok {
			t.Errorf("%s: org intel needs no consent = %v err=%v, want consent needed", phase, ok, err)
		}
		if _, err := c.EnrolChangeKey(ctx, keyPriv, mid, time.Now()); !errors.Is(err, ErrChangeKeyIndividual) {
			t.Errorf("%s: change key err = %v, want individual", phase, err)
		}
		if _, err := c.RegisterExecSealKey(ctx, keyPriv, mid, time.Now()); !errors.Is(err, ErrExecSealIndividual) {
			t.Errorf("%s: exec seal err = %v, want individual", phase, err)
		}
		if c.ReportManagedIntegrity(ctx) {
			t.Errorf("%s: an individual node reported integrity", phase)
		}
	}
	expectIndividual("before the switch")
	if n := changeKey.Load() + execSeal.Load() + binds.Load() + integrity.Load(); n != 0 {
		t.Fatalf("an individual node asked the managed routes %d times", n)
	}

	acceptSwitch(t, c, priv, pub, srv.URL, "org-1", 1, []string{govern.AuthorityEnforceBudget})
	if got := tenancy(); got != orgcontract.TenancyManaged {
		t.Errorf("switched: access request declares %q, want managed", got)
	}
	if mid != "" {
		if got := c.ManagedMachineIdentity(ctx); got != mid {
			t.Errorf("switched: machine identity %q, want %q", got, mid)
		}
		enr, _ := s.LoadEnrolment(ctx)
		if _, machine := c.accessGrantSubject(ctx, enr); machine == "" {
			t.Error("switched: grant subject names no machine")
		}
	}
	if ok, err := c.intelSendConsented(ctx, "org-1"); err != nil || !ok {
		t.Errorf("switched: org intel needs no consent = %v err=%v, want true", ok, err)
	}
	if _, err := c.EnrolChangeKey(ctx, keyPriv, mid, time.Now()); !errors.Is(err, ErrChangeKeyIndividual) || changeKey.Load() != 1 {
		t.Errorf("switched, server says managed_only: change key err=%v calls=%d, want self-certified after one call", err, changeKey.Load())
	}
	if _, err := c.RegisterExecSealKey(ctx, keyPriv, mid, time.Now()); !errors.Is(err, ErrExecSealNotManagedHere) || execSeal.Load() != 1 {
		t.Errorf("switched, server says managed_only: exec seal err=%v calls=%d, want not-managed-here after one call", err, execSeal.Load())
	}
	if mid != "" {
		for i := 0; i < 2; i++ {
			if !c.ReportManagedIntegrity(ctx) {
				t.Fatal("switched: integrity not reported")
			}
		}
		if binds.Load() != 1 || integrity.Load() != 2 {
			t.Errorf("switched: binds=%d integrity=%d, want one bind and two reports", binds.Load(), integrity.Load())
		}
	}

	acceptSwitch(t, c, priv, pub, srv.URL, "org-1", 2, nil)
	expectIndividual("after the switch back")
}
